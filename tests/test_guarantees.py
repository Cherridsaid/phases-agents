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
    validate_b3_plan,
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
    ("forbidden_capabilities", [None]),
    ("forbidden_capabilities", [{"web": True}]),
    ("requires_capabilities", 7),
    ("requires_capabilities", [{"a": 1}]),
    ("provides_capabilities", 3),
    ("optional_capabilities", "web"),
    ("optional_capabilities", [["web"]]),
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
    # Secrets STRUCTURÉS : segments <= 12 chars mêlant lettres et chiffres.
    # Un mot lisible ne mélange pas les deux dans un même segment.
    "zxb_2f8h3k9d_1a2b3c4d5e6f",
    "zq_demo_a1b2c3d4e5f6",
    "zqp_16c7e42f_292c6912_e7710c83",
    "zzqa_2b3c4d5e_6f7g8h9i_0j1k2l3m",
    # Segment etire : 15 caracteres d'un bloc, ce n'est plus un mot.
    "zq_demo_abcdefghijkl123",
    # PREMIER segment etire : la borne de 12 caracteres vaut aussi en tete.
    # Sans ce cas, relacher la borne du premier segment laissait la suite
    # verte (mutant survivant de la campagne du 2026-08-28).
    "abcdefghijklmnop_ab_cd",
]
READABLE_IDENTIFIERS = [
    "pci_dss_4_0_compliance",
    "iso_27001_2022_audit",
    "gdpr_article_32_review",
    "acme_stock_audit",
    # Mots techniques a bloc numerique unique, final ou interne : lisibles.
    "oauth2_token_security",
    "web3_contract_audit",
    "sha256_digest_check",
    "iso27001_compliance_audit",
    "log4j_dependency_audit",
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


def _plan_with_gap(tmp_path):
    """Plan B3 réel dont skills_missing est non vide, par le chemin utilisateur.

    Le chemin est celui d'un client : detector -> planner -> to_public().
    La lacune vient de la règle d'exemple GAP-EXAMPLE (fait uses_payments,
    capacité example_domain_audit qu'aucun skill installé ne fournit).
    """
    roots = tmp_path / "skills"
    roots.mkdir()
    reg = _b3_registry(roots, ())
    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("value = 1\n", encoding="utf-8")
    (project / ".phases-profile.json").write_text(
        json.dumps({"schema_version": "1.0",
                    "facts": ["has_python", "uses_payments"]}) + "\n",
        encoding="utf-8")
    profile = detector.detect_profile(str(project))
    result = planner.build_b3_plan(profile, reg, ["filesystem_read", "web"])
    assert result.plan is not None, [i.code for i in result.issues]
    plan = result.plan.to_public()
    assert plan["skills_missing"], "fixture : GAP-EXAMPLE doit produire une lacune"
    return plan


B3_GAP_MUTATIONS = [
    ("gap_id", "gap-example"),          # minuscules : forme invalide
    ("gap_id", "GAP EXAMPLE!"),         # caractères hors grammaire
    ("gap_id", "G" + "A" * 70),         # longueur excessive
    ("capability", "Example-Domain!"),  # forme invalide
    ("capability", "a" * 70),           # longueur excessive
]


@pytest.mark.parametrize("field,value", B3_GAP_MUTATIONS)
def test_b3_plan_rejects_malformed_gap_identifiers(tmp_path, field, value):
    """validate_b3_plan doit imposer la forme des lacunes, comme le registre.

    Le test précédent visait validate_skill_gap_rules (le registre) : le
    validateur public du plan acceptait ces cinq mutations. Ce test emprunte
    la surface réelle : planner -> to_public() -> validate_b3_plan.
    """
    plan = _plan_with_gap(tmp_path)
    assert validate_b3_plan(plan) == [], "le plan légitime doit passer"
    plan["skills_missing"][0][field] = value
    codes = {issue.code for issue in validate_b3_plan(plan)}
    assert codes & {"PLAN_GAP_ID_INVALID", "PLAN_GAP_CAPABILITY_INVALID"}, codes


def test_un_module_qui_leve_ne_tue_pas_la_session(monkeypatch, capsys):
    """Une exception imprévue coûte un appel, jamais la session entière.

    La boucle stdio appelait ``handle_message`` sans filet : une exception
    d'un module remontait hors de ``main`` et tuait le processus. Le client
    MCP perdait toute sa session, pas seulement l'appel fautif.
    """
    import io
    import server

    def exploser(_message, _runtime):
        raise RuntimeError("panne imprevue d'un module")

    monkeypatch.setattr(server, "handle_message", exploser)
    ecrites: list[dict] = []
    monkeypatch.setattr(server, "_write_response",
                        lambda response: ecrites.append(response) is None)
    monkeypatch.setattr(server, "_startup_runtime", lambda _a: (None, True))
    requete = json.dumps({"jsonrpc": "2.0", "id": 7,
                          "method": "tools/list"}) + "\n"
    faux_stdin = type("S", (), {"buffer": io.BytesIO(
        (requete * 2).encode("utf-8"))})()
    monkeypatch.setattr(server, "sys", type("M", (), {
        "stdin": faux_stdin, "stderr": sys_stderr_double(),
        "argv": ["server.py"]})())

    code = server.main([])

    assert code == 0, "la boucle doit se terminer normalement sur EOF"
    assert len(ecrites) == 2, "les DEUX appels doivent recevoir une reponse"
    for reponse in ecrites:
        assert reponse["error"]["code"] == -32603
        assert reponse["id"] == 7


def sys_stderr_double():
    """stderr jetable : la trace doit être écrite, sans polluer la sortie."""
    import io

    class _Err(io.StringIO):
        def flush(self):
            pass

    return _Err()


def test_plan_rendu_par_le_serveur_passe_son_propre_validateur(tmp_path):
    """Le plan livré au client doit rester valide APRÈS l'enveloppe serveur.

    Le scan de secrets prenait les codes du plan pour des secrets : le client
    recevait ``<contenu-sensible-masque>`` à la place de
    ``OPTIONAL_CAPABILITY_UNAVAILABLE:filesystem_search`` et le plan échouait
    son propre validateur (ENUM). Invisible aux tests qui appellent
    ``to_public()`` sans traverser ``server._tool_envelope``.
    """
    import server
    import skill_runtime

    roots = tmp_path / "skills"
    roots.mkdir()
    shutil.copytree(EXAMPLE, roots / "hello-python")
    config = tmp_path / "skills-roots.json"
    config.write_text(
        json.dumps({"config_version": "1.0",
                    "roots": [{"id": "t", "path": str(roots)}]}),
        encoding="utf-8")
    runtime = skill_runtime.load_skill_runtime_config(str(config)).runtime
    assert runtime is not None

    project = tmp_path / "project"
    project.mkdir()
    (project / "app.py").write_text("value = 1\n", encoding="utf-8")

    message = {
        "jsonrpc": "2.0", "id": 1, "method": "tools/call",
        "params": {"name": "phases_agents_plan", "arguments": {
            "root_ids": ["t"], "target": str(project),
            "today": TODAY.isoformat(),
            # Capacité optionnelle NON déclarée -> le skill produit une
            # limitation, qui est le champ qui était masqué.
            "client_capabilities": ["filesystem_read"],
            "plan_version": "B3"}}}
    response = server.handle_message(message, runtime)
    assert response["result"]["isError"] is False, response
    plan = json.loads(response["result"]["content"][0]["text"])["plan"]

    limitations = plan["skills_selected"][0]["limitations"]
    assert limitations == ["OPTIONAL_CAPABILITY_UNAVAILABLE:filesystem_search"], \
        limitations
    issues = validate_b3_plan(plan)
    assert issues == [], [f"{i.code} {i.path}" for i in issues]


def test_b3_plan_survives_unhashable_gap_entries(tmp_path):
    """Un plan malformé se rejette, il ne fait pas tomber le serveur.

    Une capacité de lacune non-chaîne (liste) rendait le tuple de clé non
    hachable : set(missing_keys) levait TypeError au lieu de produire une
    erreur de validation.
    """
    plan = _plan_with_gap(tmp_path)
    plan["skills_missing"][0]["capability"] = ["example_domain_audit"]
    issues = validate_b3_plan(plan)
    assert issues, "un plan malformé doit produire au moins une erreur"


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
