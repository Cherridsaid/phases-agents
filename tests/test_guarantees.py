"""Garanties que la suite laissait passer.

Chaque test de ce fichier existe parce qu'une campagne de mutation a montré
que la garantie correspondante pouvait être désactivée sans qu'un seul test
ne devienne rouge. Une garantie annoncée mais non testée n'est pas une
garantie : c'est une intention.

Protocole pour en ajouter un : casser la garantie dans le code, vérifier que
ce fichier rougit, restaurer.
"""

from __future__ import annotations

import datetime
import json
import os
import pathlib
import shutil
import stat

import pytest

import detector
import planner
import registry
from validator import (
    redact_sensitive_text,
    validate_skill_gap_rules,
    validate_skill_package,
)

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "skills" / "hello-python"
TODAY = datetime.date(2026, 8, 27)


def _example_with_frontmatter(tmp_path, old, new):
    """Copie le package d'exemple en remplaçant une ligne de frontmatter."""
    target = tmp_path / "pkg"
    shutil.copytree(EXAMPLE, target)
    md_path = target / "SKILL.md"
    md = md_path.read_text(encoding="utf-8")
    assert old in md, f"frontmatter attendu absent : {old!r}"
    md_path.write_text(md.replace(old, new, 1), encoding="utf-8", newline="\n")
    return validate_skill_package(str(target), today=TODAY)


def test_posix_symlink_is_detected(tmp_path, monkeypatch):
    """La branche POSIX doit reconnaître un lien symbolique.

    Sous Windows cette ligne n'est jamais exécutée, donc aucun test ne la
    couvrait ; sous Linux les tests de liens sont ignorés faute de privilège.
    La branche est forcée ici pour que la garantie tienne des deux côtés.
    """
    target = tmp_path / "normal.py"
    target.write_text("print(1)\n", encoding="utf-8")
    linked = os.path.normcase(os.path.abspath(target))
    real_lstat = detector.os.lstat
    symlink_mode = os.stat_result(
        (stat.S_IFLNK | 0o777, 0, 0, 1, 0, 0, 0, 0, 0, 0))

    def fake_lstat(path, *args, **kwargs):
        if os.path.normcase(os.path.abspath(os.fspath(path))) == linked:
            return symlink_mode
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(detector.os, "name", "posix")
    monkeypatch.setattr(detector.os, "lstat", fake_lstat)
    assert detector._is_reparse_point(str(target)) is True


def test_scan_limit_stops_exploration(tmp_path, monkeypatch):
    """Dépasser le plafond de fichiers doit rendre SCAN_LIMIT, pas un profil."""
    for index in range(4):
        (tmp_path / f"module_{index}.py").write_text(
            "print(1)\n", encoding="utf-8")
    monkeypatch.setattr(detector, "_MAX_FILES_SCANNED", 2)
    profile = detector.detect_profile(str(tmp_path))
    assert profile["blocked"] is True
    assert profile["issues"] == ["SCAN_LIMIT"]


def test_unknown_license_is_rejected(tmp_path):
    """La licence est une liste blanche : une valeur hors liste échoue."""
    result = _example_with_frontmatter(
        tmp_path, "license: Apache-2.0", "license: GPL-3.0-only")
    codes = {issue.code for issue in result.issues}
    assert result.valid is False
    assert "MANIFEST_MISMATCH" in codes


def test_known_license_still_accepted(tmp_path):
    """Anti fail-closed : la liste blanche ne rejette pas ses propres valeurs."""
    result = _example_with_frontmatter(
        tmp_path, "license: Apache-2.0", "license: MIT")
    assert result.valid, [f"{i.code} {i.message}" for i in result.issues]


def _b3_registry(root, forbidden):
    """Registre à un skill, dont on choisit les capacités interdites."""
    from tests.b1_helpers import write_skill

    write_skill(root, "audit-python")
    manifest_path = root / "audit-python" / "phases.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["forbidden_capabilities"] = list(forbidden)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")
    from skill_loader import discover_skills

    built = registry.build_registry(discover_skills([root], TODAY))
    assert built.ok, [issue.code for issue in built.issues]
    return built.registry


def _python_target(path):
    path.mkdir()
    (path / "app.py").write_text("value = 1\n", encoding="utf-8")
    return detector.detect_profile(str(path))


def test_b3_blocks_a_forbidden_client_capability(tmp_path):
    """B3 doit refuser un skill dont une capacité interdite est présente.

    B1 appliquait la règle, B3 ne l'appliquait pas : il suffisait de déclarer
    la capacité interdite pour que le skill soit quand même sélectionné.
    """
    roots = tmp_path / "skills"
    roots.mkdir()
    reg = _b3_registry(roots, ("web",))
    profile = _python_target(tmp_path / "project")

    result = planner.build_b3_plan(
        profile, reg, ["filesystem_read", "web"])
    assert result.plan is not None, [i.code for i in result.issues]
    plan = result.plan.to_public()
    assert plan["skills_selected"] == []
    blocked = plan["skills_blocked"]
    assert [entry["skill_id"] for entry in blocked] == ["audit-python"]
    assert "FORBIDDEN_CLIENT_CAPABILITY_PRESENT" in blocked[0]["reason_codes"]


def test_b3_still_selects_when_nothing_is_forbidden(tmp_path):
    """Anti fail-closed : la nouvelle garde ne bloque pas tout le monde."""
    roots = tmp_path / "skills"
    roots.mkdir()
    reg = _b3_registry(roots, ())
    profile = _python_target(tmp_path / "project")

    result = planner.build_b3_plan(
        profile, reg, ["filesystem_read", "web"])
    assert result.plan is not None, [i.code for i in result.issues]
    selected = [s["skill_id"]
                for s in result.plan.to_public()["skills_selected"]]
    assert selected == ["audit-python"]


def test_third_party_capability_name_is_not_a_secret(tmp_path):
    """Un nom de capacité légitime mais long était refusé comme secret.

    La grammaire acceptait `pci_dss_4_0_compliance`, le scan de secrets le
    rejetait : le vocabulaire se disait ouvert sans l'être.
    """
    target = tmp_path / "pkg"
    shutil.copytree(EXAMPLE, target)
    manifest_path = target / "phases.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["schema_version"] = "1.1"
    manifest["provides_capabilities"] = ["pci_dss_4_0_compliance"]
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")

    result = validate_skill_package(str(target), today=TODAY)
    assert result.valid, [f"{i.code} {i.message}" for i in result.issues]


MISTYPED_CAPABILITY_FIELDS = [
    ("forbidden_capabilities", 5),
    ("forbidden_capabilities", {"web": True}),
    ("requires_capabilities", 7),
    ("provides_capabilities", 3),
    ("optional_capabilities", "web"),
]


@pytest.mark.parametrize("field,value", MISTYPED_CAPABILITY_FIELDS)
def test_mistyped_manifest_never_crashes(tmp_path, field, value):
    """Un manifeste mal typé se rejette, il ne fait pas tomber le serveur.

    Un entier nu là où une liste est attendue levait `TypeError: 'int' object
    is not iterable` : le processus stdio mourait et le client MCP perdait la
    session entière, pas seulement l'appel fautif.
    """
    target = tmp_path / "pkg"
    shutil.copytree(EXAMPLE, target)
    manifest_path = target / "phases.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest[field] = value
    if field == "provides_capabilities":
        manifest["schema_version"] = "1.1"
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8")

    result = validate_skill_package(str(target), today=TODAY)
    assert result.valid is False


SECRET_LIKE = [
    "zzqaiosfodnn7example",
    "zq_demo_51h8xq2ezvkylo2c0abcdefgh",
    "zqp_abcdefghijklmnopqrstuvwxyz012345",
    "aws_secret_zzqaiosfodnn7examplekeyxyz",
]
READABLE_IDENTIFIERS = [
    "pci_dss_4_0_compliance",
    "iso_27001_2022_audit",
    "gdpr_article_32_review",
    "acme_stock_audit",
]


@pytest.mark.parametrize("value", SECRET_LIKE)
def test_secret_is_detected_even_where_a_name_is_expected(value):
    """Le scan ne doit pas se relâcher parce qu'un champ attend un nom.

    Une liste blanche par champ déclarait sûre toute valeur respectant la
    grammaire : un secret en minuscules y passait. La distinction porte
    désormais sur la STRUCTURE, pas sur l'emplacement.
    """
    assert redact_sensitive_text(value) != value


@pytest.mark.parametrize("value", READABLE_IDENTIFIERS)
def test_readable_identifier_is_not_a_secret(value):
    """Anti fail-closed : un nom lisible à segments courts reste accepté."""
    assert redact_sensitive_text(value) == value


def test_third_party_gap_rules_are_accepted():
    """Un catalogue tiers doit pouvoir déclarer ses propres lacunes."""
    rules = {
        "schema_id": "SKILL_GAP_RULES",
        "version": "1.0.0",
        "description": "Regles d'un catalogue tiers.",
        "rules": [{
            "gap_id": "GAP-ACME-001",
            "required_facts": ["has_api"],
            "capability": "pci_dss_4_0_compliance",
            "severity": "warning",
            "reason_code": "NO_INSTALLED_SKILL_FOR_CAPABILITY",
        }],
    }
    assert validate_skill_gap_rules(rules) == []


def test_malformed_gap_identifiers_are_still_rejected():
    """Ouvert ne veut pas dire libre : la forme reste imposée des deux côtés."""
    def _rules(**over):
        rule = {
            "gap_id": "GAP-ACME-001",
            "required_facts": ["has_api"],
            "capability": "acme_audit",
            "severity": "warning",
            "reason_code": "NO_INSTALLED_SKILL_FOR_CAPABILITY",
        }
        rule.update(over)
        return {"schema_id": "SKILL_GAP_RULES", "version": "1.0.0",
                "description": "x", "rules": [rule]}

    assert "GAP_RULE_ID_INVALID" in {
        i.code for i in validate_skill_gap_rules(_rules(gap_id="gap acme!"))}
    assert "GAP_CAPABILITY_UNKNOWN" in {
        i.code for i in validate_skill_gap_rules(_rules(capability="Acme!"))}
    assert "GAP_FACT_UNKNOWN" in {
        i.code for i in validate_skill_gap_rules(
            _rules(required_facts=["fait_invente"]))}


def test_invisible_character_in_owner_is_rejected(tmp_path):
    """`owner` est libre mais pas invisible : un caractère de format ferait
    passer deux identités distinctes pour la même à l'œil nu.

    Ce test vérifie le comportement, pas une ligne : la garantie est tenue
    deux fois, par `_norm_unicode` qui retire déjà Cc/Cf et par le contrôle
    de catégorie explicite. Muter l'une des deux ne le fait donc pas rougir,
    et c'est voulu.
    """
    result = _example_with_frontmatter(
        tmp_path, "owner: exemple", "owner: exem​ple")
    codes = {issue.code for issue in result.issues}
    assert result.valid is False
    assert "MANIFEST_MISMATCH" in codes
