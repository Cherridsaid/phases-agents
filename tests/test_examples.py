"""Le package d'exemple livré doit rester valide.

C'est le seul package que découvre un utilisateur qui clone le dépôt : s'il
cesse d'être valide, la démarche documentée dans le README ne marche plus.
"""

from __future__ import annotations

import datetime
import json
import pathlib
import shutil

from phases_agents.validator import redact_sensitive_text, validate_skill_package

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "skills" / "hello-python"
TODAY = datetime.date(2026, 8, 27)


def test_shipped_example_package_is_valid():
    result = validate_skill_package(str(EXAMPLE), today=TODAY)
    assert result.valid, [
        f"{i.level} {i.code} {i.message}" for i in result.issues
    ]


def test_symbolic_schema_reference_is_not_a_secret():
    """`core:X.json` est la syntaxe imposée par output_schema : un SKILL.md
    doit pouvoir citer sa propre sortie sans être accusé de fuite."""
    line = "Sortie conforme à `core:FINDING_SCHEMA.json`."
    assert redact_sensitive_text(line) == line


def test_symbolic_prefix_does_not_whitewash_a_secret():
    """Anti fail-open : le préfixe `core:` ne blanchit pas ce qui le suit."""
    forged = "core:EVIL_AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    assert redact_sensitive_text(forged) != forged


def _mutated_package(tmp_path, mutate):
    target = tmp_path / "pkg"
    shutil.copytree(EXAMPLE, target)
    manifest_path = target / "phases.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    mutate(manifest)
    manifest_path.write_text(
        json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8", newline="\n")
    return validate_skill_package(str(target), today=TODAY)


def test_third_party_capability_is_accepted(tmp_path):
    """Un catalogue tiers doit pouvoir nommer ce qu'il apporte : une liste
    fermée de capacités fournies bloquerait tout auteur hors de ce dépôt."""
    result = _mutated_package(tmp_path, lambda m: m.update(
        schema_version="1.1", provides_capabilities=["acme_stock_audit"]))
    assert result.valid, [f"{i.code} {i.message}" for i in result.issues]


def test_malformed_capability_is_rejected(tmp_path):
    """Ouvert ne veut pas dire libre : la forme reste imposée."""
    result = _mutated_package(tmp_path, lambda m: m.update(
        schema_version="1.1", provides_capabilities=["Acme Stock!"]))
    assert "MANIFEST_CAPABILITY_FORM" in {i.code for i in result.issues}


def test_manifest_version_rules_hold(tmp_path):
    """La règle 1.0/1.1 vit dans le validator, pas dans le schéma : elle doit
    donc être vérifiée ici, sinon rien ne la protège."""
    missing = _mutated_package(
        tmp_path / "a", lambda m: m.update(schema_version="1.1"))
    assert "MANIFEST_SCHEMA_VERSION" in {i.code for i in missing.issues}
    unexpected = _mutated_package(
        tmp_path / "b",
        lambda m: m.update(provides_capabilities=["acme_stock_audit"]))
    assert "MANIFEST_SCHEMA_VERSION" in {i.code for i in unexpected.issues}


def test_third_party_owner_is_accepted():
    """Un catalogue tiers doit pouvoir signer ses propres packages."""
    md = (EXAMPLE / "SKILL.md").read_text(encoding="utf-8")
    assert "owner: exemple" in md, "l'exemple doit démontrer un owner tiers"
    result = validate_skill_package(str(EXAMPLE), today=TODAY)
    assert [i for i in result.issues if i.code == "MANIFEST_MISMATCH"] == []
