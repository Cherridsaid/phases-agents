"""Tests du validator — phases-agents.

Chaque test construit une fixture minimale sur disque (tmp_path) et verifie que
le validator ACCEPTE ce qui est conforme et REJETTE ce qui ne l'est pas, avec
le bon code d'erreur. Determinisme : toute date est injectee via `today`.
"""

from __future__ import annotations

import datetime
import json
import os
import subprocess
import sys

import pytest

from phases_agents.validator import (
    Issue,
    SKILL_REQUIRED_SECTIONS,
    _has_invisible_or_mixed,
    _legal_freshness_verdict,
    _parse_frontmatter,
    _parse_iso_date,
    _safe_relpath,
    _trusted_rules_for_tests,
    _url_host,
    validate_finding,
    validate_report,
    validate_skill,
)

CORE_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "src", "phases_agents", "core")
TODAY = datetime.date(2026, 7, 27)
# Registre par defaut : couvre les rule_id des fixtures (R6-004).
# SEC-001 = _valid_finding, R1 = _legal_basis, REG-1 = fixtures juridiques.
KNOWN_RULES = _trusted_rules_for_tests({
    "SEC-001": "en_vigueur",
    "R1": "en_vigueur",
    "REG-1": "en_vigueur",
})


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vf(finding, finding_schema, **kw):
    """validate_finding avec le contrat R6-001/R6-004 satisfait par defaut.

    Les tests qui EPROUVENT le contrat (today/known_rules invalides) appellent
    `validate_finding` directement : ce helper ne masque jamais un rejet, il
    fournit seulement les parametres requis quand le test porte sur autre chose.
    """
    kw.setdefault("today", TODAY)
    kw.setdefault("known_rules", KNOWN_RULES)
    return validate_finding(finding, finding_schema, **kw)


def _vs(skill_dir, core_dir, **kw):
    """validate_skill avec `today` fourni par defaut (R6-001)."""
    kw.setdefault("today", TODAY)
    return validate_skill(skill_dir, core_dir, **kw)


def _write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8", newline="\n")


def _write_json(path, obj):
    _write(path, json.dumps(obj, indent=2, ensure_ascii=False) + "\n")


def _valid_manifest(**over):
    m = {
        "schema_version": "1.0", "id": "audit-security", "version": "0.1.0",
        "title": "Audit de securite", "description": "Audit statique local, lecture seule.",
        "domain": "security", "project_types": ["web", "python"], "platforms": ["generic"],
        "activation": {"any": ["has_source_code"]}, "exclusions": [],
        "requires_capabilities": ["filesystem_read"], "optional_capabilities": [],
        "forbidden_capabilities": ["web", "target_code_execution"],
        "execution_mode": "read_only", "human_approval": "not_required_for_audit",
        "rules_path": "rules", "references_path": "references",
        "scripts_path": "scripts", "tests_path": "tests",
        "files": ["scripts/helper.py"],
        "output_schema": "core:FINDING_SCHEMA.json",
    }
    m.update(over)
    return m


def _valid_skill_md(name="audit-security", version="0.1.0"):
    sections = [
        "Loi centrale", "Ce que ce skill fait", "Ce que ce skill ne fait pas",
        "Conditions d'activation", "Conditions d'exclusion", "Capacites necessaires",
        "Interdictions", "Methode d'audit", "Contrat de preuve", "Format de sortie",
        "Conditions de blocage", "Limites connues", "Exemples d'entree",
        "Exemple de sortie attendue",
    ]
    body = "\n".join(f"## {s}\n\nTexte.\n" for s in sections)
    return ("---\n" f"name: {name}\n"
            "description: Audit statique local de securite\n"
            f"version: {version}\n"
            "owner: phases-agents\n"
            "license: Apache-2.0\n"
            "---\n\n" f"# {name}\n\n{body}")


def _make_skill(tmp_path, manifest=None, skill_md=None,
                with_dirs=("rules", "references", "scripts", "tests"),
                fill_dirs=True):
    d = tmp_path / "audit-security"
    d.mkdir()
    for sub in with_dirs:
        (d / sub).mkdir()
        if fill_dirs:
            # Chaque dossier recoit un VRAI fichier (pas un .keep placeholder).
            if sub == "rules":
                _write_json(d / sub / "r.json", {"rule_id": "SEC-001"})
            elif sub == "scripts":
                _write(d / sub / "helper.py", "# ok\n")
            else:
                _write(d / sub / "content.txt", "x\n")
    _write_json(d / "phases.json", manifest if manifest is not None else _valid_manifest())
    _write(d / "SKILL.md", skill_md if skill_md is not None else _valid_skill_md())
    return d


def _strong_evidence():
    return [{"type": "file", "path": "app.py", "line": 3,
             "excerpt": "key = \"abc***\"", "method": "grep statique"}]


def _valid_finding(**over):
    f = {
        "finding_id": "SEC-001", "skill_id": "audit-security", "rule_id": "SEC-001",
        "title": "Exemple", "domain": "security", "status": "OBSERVED",
        "severity": "P3_LOW", "confidence": "MEDIUM",
        "scope": {"environment": "unknown", "platform": "generic", "component": "app"},
        "evidence": [{"type": "file", "path": "app.py", "line": 1,
                      "excerpt": "x = 1", "method": "lecture"}],
        "impact": {"confidentiality": "LOW", "integrity": "LOW",
                   "availability": "NONE", "legal": "NONE"},
        "remediation": {"mode": "PROPOSE_ONLY", "required_gate": "HUMAN_APPROVAL",
                        "summary": "Corriger."},
        "limitations": [], "references": [],
    }
    f.update(over)
    return f


def _legal_basis(**over):
    lb = {
        "rule_id": "R1", "jurisdiction": "EU", "authority": "Parlement europeen",
        "source_url": "https://eur-lex.europa.eu/legal-content/FR/",
        "verified_on": "2026-07-01", "freshness_window_days": 180,
        "live_check": {"done": True, "method": "web_search",
                       "checked_at": "2026-07-27", "result": "en_vigueur"},
    }
    lb.update(over)
    return lb


@pytest.fixture
def finding_schema():
    with open(os.path.join(CORE_DIR, "FINDING_SCHEMA.json"), encoding="utf-8") as fh:
        return json.load(fh)


def _codes(issues):
    return {i.code for i in issues if i.level == "error"}


def _errors(issues):
    return [i for i in issues if i.level == "error"]


# ---------------------------------------------------------------------------
# Petites fonctions pures
# ---------------------------------------------------------------------------

class TestPureHelpers:
    def test_url_host_simple(self):
        assert _url_host("https://eur-lex.europa.eu/x") == "eur-lex.europa.eu"

    def test_url_host_with_userinfo_and_port(self):
        assert _url_host("https://u@eur-lex.europa.eu:443/x") == "eur-lex.europa.eu"

    def test_url_host_no_scheme(self):
        assert _url_host("eur-lex.europa.eu/x") == ""

    def test_parse_iso_date_ok(self):
        assert _parse_iso_date("2026-07-27") == datetime.date(2026, 7, 27)

    def test_parse_iso_date_impossible(self):
        assert _parse_iso_date("2026-13-40") is None

    def test_parse_iso_date_garbage(self):
        assert _parse_iso_date("pas-une-date") is None

    def test_freshness_ok(self):
        assert _legal_freshness_verdict("2026-07-01", 180, TODAY) == "ok"

    def test_freshness_stale(self):
        assert _legal_freshness_verdict("2020-01-01", 180, TODAY) == "stale"

    def test_freshness_future(self):
        assert _legal_freshness_verdict("2027-01-01", 180, TODAY) == "future"

    def test_freshness_invalid(self):
        assert _legal_freshness_verdict("n/a", 180, TODAY) == "invalid_date"

    def test_invisible_detected(self):
        assert _has_invisible_or_mixed("a​b") is True

    def test_mixed_separators_detected(self):
        assert _has_invisible_or_mixed("a/b\\c") is True

    def test_clean_path_ok(self):
        assert _has_invisible_or_mixed("rules/x.json") is False


# ---------------------------------------------------------------------------
# _safe_relpath
# ---------------------------------------------------------------------------

class TestSafeRelpath:
    def test_normal(self, tmp_path):
        assert _safe_relpath(str(tmp_path), "rules/x.json") is not None

    def test_dotdot_refused(self, tmp_path):
        assert _safe_relpath(str(tmp_path), "../outside") is None

    def test_absolute_refused(self, tmp_path):
        assert _safe_relpath(str(tmp_path), os.path.join(str(tmp_path), "x")) is None

    def test_drive_letter_refused(self, tmp_path):
        assert _safe_relpath(str(tmp_path), "C:/Windows/x") is None

    def test_mixed_separators_refused(self, tmp_path):
        assert _safe_relpath(str(tmp_path), "rules\\x/y.json") is None

    def test_invisible_refused(self, tmp_path):
        assert _safe_relpath(str(tmp_path), "rules/x​y.json") is None

    def test_symlink_final_refused(self, tmp_path):
        real = tmp_path / "real"
        real.mkdir()
        link = tmp_path / "link"
        try:
            os.symlink(real, link)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks non disponibles")
        assert _safe_relpath(str(tmp_path), "link") is None

    def test_symlink_parent_refused(self, tmp_path):
        # A-006 : un lien sur un PARENT doit etre refuse aussi.
        outside = tmp_path / "outside"
        outside.mkdir()
        real_sub = tmp_path / "base" / "real"
        real_sub.mkdir(parents=True)
        link_parent = tmp_path / "base" / "linked"
        try:
            os.symlink(outside, link_parent)
        except (OSError, NotImplementedError):
            pytest.skip("symlinks non disponibles")
        assert _safe_relpath(str(tmp_path / "base"), "linked/child.json") is None

    @pytest.mark.skipif(os.name != "nt", reason="jonction Windows uniquement")
    def test_windows_junction_final_refused(self, tmp_path):
        base = tmp_path / "base"
        target = tmp_path / "outside"
        junction = base / "linked"
        base.mkdir()
        target.mkdir()
        made = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert made.returncode == 0, made.stderr or made.stdout
        try:
            assert _safe_relpath(str(base), "linked") is None
        finally:
            os.rmdir(junction)

    @pytest.mark.skipif(os.name != "nt", reason="jonction Windows uniquement")
    def test_windows_junction_parent_refused(self, tmp_path):
        base = tmp_path / "base"
        target = tmp_path / "outside"
        junction = base / "linked"
        base.mkdir()
        target.mkdir()
        made = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(target)],
            capture_output=True,
            text=True,
            check=False,
        )
        assert made.returncode == 0, made.stderr or made.stdout
        try:
            assert _safe_relpath(str(base), "linked/child.json") is None
        finally:
            os.rmdir(junction)


# ---------------------------------------------------------------------------
# Frontmatter
# ---------------------------------------------------------------------------

class TestFrontmatter:
    def test_flat_ok(self):
        issues = []
        data = _parse_frontmatter("---\nname: x\nversion: 0.1.0\n---\nbody", issues, "p")
        assert data == {"name": "x", "version": "0.1.0"}
        assert not issues

    def test_nested_refused(self):
        issues = []
        _parse_frontmatter("---\nname: x\n  sub: y\n---\n", issues, "p")
        assert "FRONTMATTER_NESTED" in _codes(issues)

    def test_list_value_refused(self):
        issues = []
        _parse_frontmatter("---\ntags: - a\n---\n", issues, "p")
        assert "FRONTMATTER_NESTED" in _codes(issues)

    def test_unclosed_refused(self):
        issues = []
        _parse_frontmatter("---\nname: x\n", issues, "p")
        assert "FRONTMATTER" in _codes(issues)

    def test_duplicate_key_refused(self):
        issues = []
        _parse_frontmatter("---\nname: a\nname: b\n---\n", issues, "p")
        assert "FRONTMATTER_DUP" in _codes(issues)


# ---------------------------------------------------------------------------
# validate_skill
# ---------------------------------------------------------------------------

class TestValidateSkill:
    def test_valid_skill_passes(self, tmp_path):
        d = _make_skill(tmp_path)
        issues = _vs(str(d), CORE_DIR, today=TODAY)
        assert _errors(issues) == [], f"erreurs inattendues: {_errors(issues)}"

    def test_missing_skill_dir(self, tmp_path):
        assert "SKILL_DIR" in _codes(_vs(str(tmp_path / "nope"), CORE_DIR))

    def test_unknown_manifest_property_rejected(self, tmp_path):
        m = _valid_manifest(); m["surprise"] = True
        d = _make_skill(tmp_path, manifest=m)
        assert "UNKNOWN_PROPERTY" in _codes(_vs(str(d), CORE_DIR))

    def test_missing_manifest_property_rejected(self, tmp_path):
        m = _valid_manifest(); del m["activation"]
        d = _make_skill(tmp_path, manifest=m)
        assert "REQUIRED" in _codes(_vs(str(d), CORE_DIR))

    def test_execution_mode_not_read_only_rejected(self, tmp_path):
        d = _make_skill(tmp_path, manifest=_valid_manifest(execution_mode="read_write"))
        assert "ENUM" in _codes(_vs(str(d), CORE_DIR))

    def test_output_schema_dotdot_rejected(self, tmp_path):
        d = _make_skill(tmp_path, manifest=_valid_manifest(output_schema="../../../core/FINDING_SCHEMA.json"))
        assert "OUTPUT_SCHEMA_PATH" in _codes(_vs(str(d), CORE_DIR))

    def test_output_schema_unknown_symbolic_rejected(self, tmp_path):
        # A-005 : schema symbolique qui n'existe pas dans core/.
        d = _make_skill(tmp_path, manifest=_valid_manifest(output_schema="core:NOPE.json"))
        assert "OUTPUT_SCHEMA_UNKNOWN" in _codes(_vs(str(d), CORE_DIR))

    def test_unknown_activation_fact_rejected(self, tmp_path):
        # A-005 : fact invente.
        m = _valid_manifest(activation={"any": ["has_time_machine"]})
        d = _make_skill(tmp_path, manifest=m)
        assert "UNKNOWN_FACT" in _codes(_vs(str(d), CORE_DIR))

    def test_ghost_rules_dir(self, tmp_path):
        d = _make_skill(tmp_path, with_dirs=("references", "scripts", "tests"))
        assert "GHOST_PATH" in _codes(_vs(str(d), CORE_DIR))

    def test_empty_dir_rejected(self, tmp_path):
        # A-005 : dossier annonce mais vide.
        d = _make_skill(tmp_path, fill_dirs=False)
        assert "EMPTY_PATH" in _codes(_vs(str(d), CORE_DIR))

    def test_frontmatter_manifest_mismatch(self, tmp_path):
        d = _make_skill(tmp_path, skill_md=_valid_skill_md(name="autre-nom"))
        assert "MANIFEST_MISMATCH" in _codes(_vs(str(d), CORE_DIR))

    def test_missing_body_section(self, tmp_path):
        md = _valid_skill_md().replace("## Limites connues\n\nTexte.\n", "")
        d = _make_skill(tmp_path, skill_md=md)
        assert "SKILL_SECTION" in _codes(_vs(str(d), CORE_DIR))

    def test_all_required_sections_hidden_in_hostile_html_are_rejected(
            self, tmp_path):
        templates = (
            ('<script src="a<b">', "</script>"),
            ('<div title="a<b">', "</div>"),
            ('<div"x">', "</div>"),
            ("<div=1>", "</div>"),
            ("<div title='a<b'>", "</div>"),
            ('<div title="a>b">', "</div>"),
            ('<div title="a<b<c">', "</div>"),
            ('<div data-x="<tag>">', "</div>"),
            ('<script data-x="<script>">', "</script>"),
        )
        prefix = _valid_skill_md().split("## ", 1)[0]
        blocks = []
        for index, section in enumerate(SKILL_REQUIRED_SECTIONS):
            opening, closing = templates[index % len(templates)]
            blocks.append(
                f"{opening}\n## {section}\n\nTexte masque.\n{closing}\n")
        skill_md = prefix + "\n".join(blocks)
        d = _make_skill(tmp_path, skill_md=skill_md)

        issues = _vs(str(d), CORE_DIR, today=TODAY)
        actual = [
            (issue.level, issue.code, issue.path, issue.message)
            for issue in issues
        ]
        expected = sorted(
            (
                "error",
                "SKILL_SECTION",
                "SKILL.md",
                f"titre de section absent: {section}",
            )
            for section in SKILL_REQUIRED_SECTIONS
        )
        assert len(SKILL_REQUIRED_SECTIONS) == 14
        assert all(f"## {section}\n" in skill_md
                   for section in SKILL_REQUIRED_SECTIONS)
        assert actual == expected

    def test_inline_html_and_code_cannot_promote_required_sections(
            self, tmp_path):
        templates = (
            "<span>## {section}</span>",
            "<br>## {section}",
            '<a href="x">## {section}</a>',
            "<em>## {section}</em>",
            "<!--x-->## {section}",
            "`code`## {section}",
            "<div>cache</div>## {section}",
            "<textarea>\n## {section}\nTexte masque.\n</textarea>",
            "<plaintext>\n## {section}\nTexte masque.\n</plaintext>",
            "<span>\n## {section}\nTexte masque.\n</span>",
            "<![CDATA[\n## {section}\nTexte masque.\n]]>",
            "<?processor\n## {section}\nTexte masque.\n?>",
            "<!DOCTYPE html\n## {section}\nTexte masque.\n>",
            "<div_>\n## {section}\nTexte masque.\n</div_>",
        )
        prefix = _valid_skill_md().split("## ", 1)[0]
        blocks = [
            templates[index % len(templates)].format(section=section)
            + "\nTexte.\n"
            for index, section in enumerate(SKILL_REQUIRED_SECTIONS)
        ]
        skill_md = prefix + "\n".join(blocks)
        d = _make_skill(tmp_path, skill_md=skill_md)

        issues = _vs(str(d), CORE_DIR, today=TODAY)
        actual = [
            (issue.level, issue.code, issue.path, issue.message)
            for issue in issues
        ]
        expected = sorted(
            (
                "error",
                "SKILL_SECTION",
                "SKILL.md",
                f"titre de section absent: {section}",
            )
            for section in SKILL_REQUIRED_SECTIONS
        )
        assert all(f"## {section}" in skill_md
                   for section in SKILL_REQUIRED_SECTIONS)
        assert actual == expected

    def test_markdown_autolinks_do_not_hide_visible_sections(self, tmp_path):
        autolinks = (
            "<https://example.com>",
            "<mailto:user@example.com>",
            "<user@example.com>",
        )
        md = _valid_skill_md().replace(
            "# audit-security\n\n",
            "# audit-security\n\n" + "\n".join(autolinks) + "\n\n",
            1,
        )
        d = _make_skill(tmp_path, skill_md=md)
        assert _errors(_vs(str(d), CORE_DIR, today=TODAY)) == []

    def test_invalid_email_like_html_cannot_hide_sections(self, tmp_path):
        prefix = _valid_skill_md().split("## ", 1)[0]
        blocks = [
            (
                "<div@example..com>\n"
                f"## {section}\n"
                "Texte masque.\n"
                "</div@example..com>\n"
            )
            for section in SKILL_REQUIRED_SECTIONS
        ]
        d = _make_skill(tmp_path, skill_md=prefix + "".join(blocks))

        issues = _vs(str(d), CORE_DIR, today=TODAY)
        actual = [
            (issue.level, issue.code, issue.path, issue.message)
            for issue in issues
        ]
        expected = sorted(
            (
                "error",
                "SKILL_SECTION",
                "SKILL.md",
                f"titre de section absent: {section}",
            )
            for section in SKILL_REQUIRED_SECTIONS
        )
        assert actual == expected

    @pytest.mark.parametrize("placement", (
        "section_1",
        "section_3",
        "section_7",
        "section_14",
        "multiple",
    ))
    def test_comparison_prose_preserves_all_required_sections(
            self, tmp_path, placement):
        sections = list(SKILL_REQUIRED_SECTIONS)
        positions = {
            "section_1": (0,),
            "section_3": (2,),
            "section_7": (6,),
            "section_14": (13,),
            "multiple": (0, 2, 6, 13),
        }[placement]
        if placement == "section_14":
            sections[-2], sections[-1] = sections[-1], sections[-2]
        phrases = (
            "Si x<y alors continuer.",
            "Le type List<String> est utilise.",
            "Contrainte 3<x<7.",
            "Si a<b et c>d alors continuer.",
        )
        inserted = {
            SKILL_REQUIRED_SECTIONS[position]: phrases[index % len(phrases)]
            for index, position in enumerate(positions)
        }
        body = []
        for section in sections:
            body.append(f"## {section}\n\nTexte.\n")
            if section in inserted:
                body.append(inserted[section] + "\n")
        prefix = _valid_skill_md().split("## ", 1)[0]
        skill_md = prefix + "".join(body)
        d = _make_skill(tmp_path, skill_md=skill_md)

        headings = [
            line[3:] for line in skill_md.splitlines()
            if line.startswith("## ")
        ]
        assert len(headings) == len(SKILL_REQUIRED_SECTIONS) == 14
        assert set(headings) == set(SKILL_REQUIRED_SECTIONS)
        for section, phrase in inserted.items():
            assert f"## {section}\n\nTexte.\n{phrase}\n" in skill_md
        issues = _vs(str(d), CORE_DIR, today=TODAY)
        assert [issue for issue in issues
                if issue.code == "SKILL_SECTION"] == []
        assert _errors(issues) == []

    def test_large_comparison_skill_completes_under_timeout(self, tmp_path):
        section_payload = (
            "Si x<y, List<String> et 3<x<7 restent du texte. " * 40_000
        )[:42_000]
        prefix = _valid_skill_md().split("## ", 1)[0]
        body = "".join(
            f"## {section}\n\n{section_payload}\n"
            for section in SKILL_REQUIRED_SECTIONS
        )
        skill_md = prefix + body
        d = _make_skill(tmp_path, skill_md=skill_md)
        code = (
            "import datetime,json,sys\n"
            "from phases_agents import validator\n"
            "issues=validator.validate_skill("
            "sys.argv[1],sys.argv[2],today=datetime.date(2026,7,27))\n"
            "errors=[(i.code,i.path,i.message) for i in issues "
            "if i.level=='error']\n"
            "print(json.dumps(errors,ensure_ascii=False))\n"
            "raise SystemExit(bool(errors))\n"
        )
        env = os.environ.copy()
        pythonpath = env.get("PYTHONPATH")
        # Le paquet vit sous src/ : sans lui sur le chemin, la sonde
        # n'importe rien. Les modules s'importent en relatif desormais.
        source_root = os.path.dirname(os.path.dirname(CORE_DIR))
        env["PYTHONPATH"] = (
            source_root
            if not pythonpath
            else source_root + os.pathsep + pythonpath
        )
        result = subprocess.run(
            [sys.executable, "-c", code, str(d), CORE_DIR],
            cwd=os.path.dirname(CORE_DIR),
            env=env,
            capture_output=True,
            text=True,
            timeout=15,
            check=False,
        )
        assert result.returncode == 0, result.stderr or result.stdout
        assert json.loads(result.stdout) == []

    def test_bom_rejected(self, tmp_path):
        d = _make_skill(tmp_path)
        (d / "phases.json").write_bytes(b"\xef\xbb\xbf" + (d / "phases.json").read_bytes())
        assert "BOM" in _codes(_vs(str(d), CORE_DIR))

    def test_oversize_skill_md_rejected(self, tmp_path):
        # Cas adversarial : SKILL > 2 Mio -> blocage.
        d = _make_skill(tmp_path)
        (d / "SKILL.md").write_bytes(b"#" * (2 * 1024 * 1024 + 1))
        assert "TOO_LARGE" in _codes(_vs(str(d), CORE_DIR))

    # --- Regles juridiques ---

    def _legal_skill(self, tmp_path, rule):
        m = _valid_manifest(domain="compliance", id="audit-compliance")
        d = _make_skill(tmp_path, manifest=m, skill_md=_valid_skill_md(name="audit-compliance"))
        _write_json(d / "rules" / "consent-rule.json", rule)
        return d

    def _legal_rule(self, **over):
        r = {"rule_id": "REG-1", "jurisdiction": "EU",
             "source_url": "https://eur-lex.europa.eu/legal-content/FR/",
             "verified_on": "2026-07-01", "freshness_window_days": 180,
             "applicability": "traitement de donnees personnelles",
             "confidence": "MEDIUM", "status": "en_vigueur"}
        r.update(over)
        return r

    def test_legal_rule_missing_source(self, tmp_path):
        r = self._legal_rule(); del r["source_url"]
        d = self._legal_skill(tmp_path, r)
        assert "LEGAL_RULE_FIELD" in _codes(_vs(str(d), CORE_DIR, today=TODAY))

    def test_legal_rule_repealed_rejected(self, tmp_path):
        d = self._legal_skill(tmp_path, self._legal_rule(status="abroge"))
        assert "LEGAL_RULE_REPEALED" in _codes(_vs(str(d), CORE_DIR, today=TODAY))

    def test_legal_rule_status_not_normalised(self, tmp_path):
        # Cas adversarial : "ABROGATED" au lieu de "abroge".
        d = self._legal_skill(tmp_path, self._legal_rule(status="ABROGATED"))
        assert "LEGAL_RULE_STATUS" in _codes(_vs(str(d), CORE_DIR, today=TODAY))

    def test_legal_source_not_official(self, tmp_path):
        d = self._legal_skill(tmp_path, self._legal_rule(source_url="https://random-blog.example/compliance"))
        assert "LEGAL_SOURCE" in _codes(_vs(str(d), CORE_DIR, today=TODAY))

    def test_legal_source_empty(self, tmp_path):
        d = self._legal_skill(tmp_path, self._legal_rule(source_url=""))
        assert "LEGAL_SOURCE" in _codes(_vs(str(d), CORE_DIR, today=TODAY))

    def test_legal_date_future_rejected(self, tmp_path):
        d = self._legal_skill(tmp_path, self._legal_rule(verified_on="2027-01-01"))
        assert "LEGAL_DATE" in _codes(_vs(str(d), CORE_DIR, today=TODAY))

    def test_legal_date_impossible_rejected(self, tmp_path):
        d = self._legal_skill(tmp_path, self._legal_rule(verified_on="2026-13-40"))
        assert "LEGAL_DATE" in _codes(_vs(str(d), CORE_DIR, today=TODAY))

    def test_legal_stale_is_error_not_warning(self, tmp_path):
        # A-003 : fraicheur BLOQUANTE (erreur, sortie non nulle).
        d = self._legal_skill(tmp_path, self._legal_rule(verified_on="2020-01-01"))
        issues = _vs(str(d), CORE_DIR, today=TODAY)
        assert "LEGAL_STALE" in _codes(issues)

    def test_legal_freshness_too_large(self, tmp_path):
        d = self._legal_skill(tmp_path, self._legal_rule(freshness_window_days=400))
        assert "LEGAL_FRESHNESS" in _codes(_vs(str(d), CORE_DIR, today=TODAY))

    def test_legal_skill_without_rules_rejected(self, tmp_path):
        # A-005 : skill juridique sans aucune regle.
        m = _valid_manifest(domain="compliance", id="audit-compliance")
        d = tmp_path / "audit-security"; d.mkdir()
        for sub in ("rules", "references", "scripts", "tests"):
            (d / sub).mkdir()
            if sub != "rules":
                _write(d / sub / ".keep", "x\n")
        _write_json(d / "phases.json", m)
        _write(d / "SKILL.md", _valid_skill_md(name="audit-compliance"))
        assert "LEGAL_NO_RULES" in _codes(_vs(str(d), CORE_DIR, today=TODAY))


# ---------------------------------------------------------------------------
# validate_finding
# ---------------------------------------------------------------------------

class TestValidateFinding:
    def test_valid_finding_passes(self, finding_schema):
        issues = _vf(_valid_finding(), finding_schema, today=TODAY)
        assert _errors(issues) == [], f"erreurs inattendues: {_errors(issues)}"

    def test_remediated_rejected_in_v1(self, finding_schema):
        assert "V1_REMEDIATED" in _codes(
            _vf(_valid_finding(status="REMEDIATED"), finding_schema))

    def test_blocked_without_reason_rejected(self, finding_schema):
        # A-007 : BLOCKED exige status_reason.
        f = _valid_finding(status="BLOCKED")
        assert "STATUS_REASON" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_not_applicable_without_reason_rejected(self, finding_schema):
        f = _valid_finding(status="NOT_APPLICABLE")
        assert "STATUS_REASON" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_blocked_with_reason_ok(self, finding_schema):
        f = _valid_finding(status="BLOCKED", status_reason="fichier illisible")
        assert _errors(_vf(f, finding_schema, today=TODAY)) == []

    def test_p4_with_direct_proof_rejected(self, finding_schema):
        # A-007 : P4 interdit si preuve technique directe.
        f = _valid_finding(severity="P4_CONTEXTUAL", evidence=_strong_evidence())
        assert "P4_WITH_PROOF" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_confirmed_without_evidence_rejected(self, finding_schema):
        f = _valid_finding(status="CONFIRMED", evidence=[])
        codes = _codes(_vf(f, finding_schema, today=TODAY))
        assert "CONFIRMED_NO_EVIDENCE" in codes or "EMPTY_EVIDENCE" in codes

    def test_p0_decorative_evidence_rejected(self, finding_schema):
        # A-002 : {"type":"file","path":"decorative"} ne confirme PAS un P0.
        f = _valid_finding(status="CONFIRMED", severity="P0_CRITICAL",
                           evidence=[{"type": "file", "path": "decorative", "method": "x"}])
        codes = _codes(_vf(f, finding_schema, today=TODAY))
        assert "WEAK_EVIDENCE" in codes or "EVIDENCE_WEAK" in codes

    def test_observation_cannot_confirm_p1(self, finding_schema):
        # A-002 : une simple observation ne confirme pas un P1 serieux.
        f = _valid_finding(status="CONFIRMED", severity="P1_HIGH",
                           evidence=[{"type": "observation", "path": "x", "method": "vu"}])
        assert "WEAK_EVIDENCE" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_high_confidence_with_observation_only_rejected(self, finding_schema):
        # A-002 : confidence HIGH exige une preuve forte, pas une observation.
        f = _valid_finding(status="CONFIRMED", severity="P1_HIGH", confidence="HIGH",
                           evidence=[{"type": "observation", "path": "x", "method": "vu"}])
        assert "WEAK_EVIDENCE" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_evidence_negative_line_rejected(self, finding_schema):
        f = _valid_finding(evidence=[{"type": "file", "path": "a.py", "line": -1,
                                      "excerpt": "x", "method": "m"}])
        assert "EVIDENCE_LINE" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_evidence_dotdot_path_rejected(self, finding_schema):
        f = _valid_finding(evidence=[{"type": "file", "path": "../../outside",
                                      "line": 1, "excerpt": "x", "method": "m"}])
        assert "EVIDENCE_PATH" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_unmasked_secret_rejected(self, finding_schema):
        f = _valid_finding(evidence=[{"type": "file", "path": "c.py", "line": 1,
                                      "excerpt": "K = ABCDEFGHIJKLMNOPQRSTUVWXYZ123456",
                                      "method": "m"}])
        assert "SECRET_UNMASKED" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_punctuated_secret_rejected(self, finding_schema):
        # N-003 : la ponctuation ne contourne plus le masquage.
        f = _valid_finding(evidence=[{"type": "file", "path": "c.py", "line": 1,
                                      "excerpt": "K = ABCDEFGHIJKLMNOPQRSTUVWXYZ123456;",
                                      "method": "m"}])
        assert "SECRET_UNMASKED" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_masked_secret_ok(self, finding_schema):
        f = _valid_finding(evidence=[{"type": "file", "path": "c.py", "line": 1,
                                      "excerpt": "K = ABCDEF************************",
                                      "method": "m"}])
        assert _errors(_vf(f, finding_schema, today=TODAY)) == []

    # --- Trois axes juridiques (A-001) ---

    def test_three_axes_complete_ok(self, finding_schema):
        f = _valid_finding(
            domain="compliance", status="HUMAN_REVIEW_REQUIRED", confidence="HIGH",
            observation_status="CONFIRMED", legal_basis_status="UNVERIFIED_CURRENT",
            decision="HUMAN_REVIEW_REQUIRED",
            evidence=[{"type": "absence", "path": "policy.md",
                       "searched_in": ["project-root"], "result": "absent",
                       "method": "os.walk"}],
            legal_basis=_legal_basis(live_check={"done": False}),
        )
        assert _errors(_vf(f, finding_schema, today=TODAY)) == []

    def test_axes_incomplete_rejected(self, finding_schema):
        f = _valid_finding(domain="compliance", observation_status="CONFIRMED",
                           legal_basis=_legal_basis())
        assert "AXES_INCOMPLETE" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_axes_contradiction_rejected(self, finding_schema):
        # decision CONFIRMED avec base juridique non verifiee = contradiction.
        f = _valid_finding(
            domain="compliance", observation_status="CONFIRMED",
            legal_basis_status="UNVERIFIED_CURRENT", decision="CONFIRMED",
            legal_basis=_legal_basis())
        assert "AXES_CONTRADICTION" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_observed_status_decision_confirmed_no_livecheck_rejected(self, finding_schema):
        # Cas adversarial A-001 : status OBSERVED + decision CONFIRMED contourne
        # le live_check. Doit etre rejete.
        f = _valid_finding(
            domain="compliance", status="OBSERVED",
            observation_status="OBSERVED", legal_basis_status="VERIFIED_CURRENT",
            decision="CONFIRMED",
            legal_basis=_legal_basis(live_check={"done": False}))
        assert "LEGAL_NO_LIVE_CHECK" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_legal_domain_case_insensitive(self, finding_schema):
        # Cas adversarial A-003 : 'Compliance' (casse) declenche les controles.
        f = _valid_finding(domain="Compliance")
        assert "LEGAL_BASIS" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_legal_axes_required_for_legal_domain(self, finding_schema):
        # Un finding juridique sans les 3 axes est rejete, meme s'ils sont "optionnels".
        f = _valid_finding(domain="compliance", legal_basis=_legal_basis())
        codes = _codes(_vf(f, finding_schema, today=TODAY))
        assert "AXES_INCOMPLETE" in codes

    def test_legal_basis_wrong_types_rejected(self, finding_schema):
        # source_url: 123, fwd: "180", confidence: {} -> erreurs de type.
        lb = _legal_basis(source_url=123, verified_on=123,
                          freshness_window_days="180")
        f = _valid_finding(domain="compliance",
                           observation_status="OBSERVED",
                           legal_basis_status="VERIFIED_CURRENT",
                           decision="HUMAN_REVIEW_REQUIRED",
                           legal_basis=lb)
        assert "LEGAL_TYPE" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_rule_id_mismatch_legal_basis_rejected(self, finding_schema):
        # finding.rule_id != legal_basis.rule_id
        r = {"skill_id": "audit-security", "version": "0.1.0",
             "findings": [_valid_finding(
                 domain="compliance", rule_id="R-A",
                 observation_status="OBSERVED", legal_basis_status="VERIFIED_CURRENT",
                 decision="HUMAN_REVIEW_REQUIRED",
                 legal_basis=_legal_basis(rule_id="R-B"))]}
        assert "RULE_ID_MISMATCH" in _codes(
            validate_report(r, finding_schema, today=TODAY,
                            known_rules=_trusted_rules_for_tests(
                                {"R-A": "en_vigueur"})))

    # --- Juridique ---

    def test_legal_finding_without_legal_basis_rejected(self, finding_schema):
        assert "LEGAL_BASIS" in _codes(
            _vf(_valid_finding(domain="compliance"), finding_schema, today=TODAY))

    def test_legal_alias_domain_triggers_checks(self, finding_schema):
        # Cas adversarial : alias "compliance" doit declencher les controles juridiques.
        assert "LEGAL_BASIS" in _codes(
            _vf(_valid_finding(domain="compliance"), finding_schema, today=TODAY))

    def test_legal_confirmed_without_live_check_rejected(self, finding_schema):
        f = _valid_finding(domain="compliance", status="CONFIRMED",
                           legal_basis=_legal_basis(live_check={"done": False}))
        assert "LEGAL_NO_LIVE_CHECK" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_live_check_done_only_rejected(self, finding_schema):
        # A-004 : {"done":true} seul ne suffit pas.
        f = _valid_finding(domain="compliance", status="CONFIRMED",
                           legal_basis=_legal_basis(live_check={"done": True}))
        assert "LIVE_CHECK" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_live_check_future_date_rejected(self, finding_schema):
        lb = _legal_basis(live_check={"done": True, "method": "web",
                                      "checked_at": "2027-01-01", "result": "en_vigueur"})
        f = _valid_finding(domain="compliance", status="CONFIRMED", legal_basis=lb)
        assert "LIVE_CHECK" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_legal_source_not_official_rejected(self, finding_schema):
        lb = _legal_basis(source_url="https://blog.example/compliance")
        f = _valid_finding(domain="compliance", legal_basis=lb)
        assert "LEGAL_SOURCE" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_legal_low_confidence_confirmed_rejected(self, finding_schema):
        f = _valid_finding(domain="compliance", status="CONFIRMED", confidence="LOW",
                           legal_basis=_legal_basis())
        assert "LEGAL_LOW_CONFIDENCE" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_unknown_rule_id_rejected_when_registry_given(self, finding_schema):
        f = _valid_finding(rule_id="NOPE-999")
        assert "UNKNOWN_RULE" in _codes(
            _vf(f, finding_schema, today=TODAY, known_rules=KNOWN_RULES))

    def test_unknown_finding_property_rejected(self, finding_schema):
        f = _valid_finding(); f["surprise"] = 1
        assert "UNKNOWN_PROPERTY" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_deterministic_sorted_output(self, finding_schema):
        # A-010 : sortie triee et stable, meme sur un finding a plusieurs erreurs.
        f = _valid_finding(status="REMEDIATED", evidence=[],
                           legal_basis=_legal_basis(live_check={"done": True}))
        f["domain"] = "compliance"
        a = [repr(i) for i in _vf(f, finding_schema, today=TODAY)]
        b = [repr(i) for i in _vf(f, finding_schema, today=TODAY)]
        assert a == b
        keys = [(i.path, i.code, i.message) for i in _vf(f, finding_schema, today=TODAY)]
        assert keys == sorted(keys)


# ---------------------------------------------------------------------------
# validate_report (A-008)
# ---------------------------------------------------------------------------

class TestValidateReport:
    # Registre minimal : SEC-001 est le rule_id des fixtures.
    _RULES = _trusted_rules_for_tests({"SEC-001": "en_vigueur"})

    def _report(self, findings, **over):
        r = {"skill_id": "audit-security", "version": "0.1.0", "findings": findings}
        r.update(over)
        return r

    def test_valid_report_passes(self, finding_schema):
        r = self._report([_valid_finding()])
        assert _errors(validate_report(
            r, finding_schema, today=TODAY, known_rules=self._RULES)) == []

    def test_report_not_object_rejected(self, finding_schema):
        assert "REPORT" in _codes(validate_report(
            [], finding_schema, today=TODAY, known_rules=self._RULES))

    def test_report_missing_fields_rejected(self, finding_schema):
        assert "REQUIRED" in _codes(validate_report(
            {}, finding_schema, today=TODAY, known_rules=self._RULES))

    def test_duplicate_finding_id_rejected(self, finding_schema):
        r = self._report([_valid_finding(), _valid_finding()])
        assert "DUP_FINDING" in _codes(validate_report(
            r, finding_schema, today=TODAY, known_rules=self._RULES))

    def test_skill_mismatch_rejected(self, finding_schema):
        r = self._report([_valid_finding(skill_id="autre-skill")])
        assert "REPORT_SKILL_MISMATCH" in _codes(validate_report(
            r, finding_schema, today=TODAY, known_rules=self._RULES))

    def test_report_catches_remediated(self, finding_schema):
        # Le rejet REMEDIATED doit traverser le niveau rapport.
        r = self._report([_valid_finding(status="REMEDIATED")])
        assert "V1_REMEDIATED" in _codes(validate_report(
            r, finding_schema, today=TODAY, known_rules=self._RULES))

    def test_report_paths_prefixed(self, finding_schema):
        r = self._report([_valid_finding(status="REMEDIATED")])
        issues = validate_report(
            r, finding_schema, today=TODAY, known_rules=self._RULES)
        assert any(i.path.startswith("report.findings[0]") for i in issues)

    def test_empty_report_rejected(self, finding_schema):
        # Cas adversarial A-008 : rapport vide = silence, pas absence de risque.
        r = self._report([])
        assert "EMPTY_REPORT" in _codes(validate_report(
            r, finding_schema, today=TODAY, known_rules=self._RULES))

    def test_report_unknown_property_rejected(self, finding_schema):
        # Cas adversarial A-008 : enveloppe permissive sans schema = accepte.
        # Avec schema, rejete.
        r = self._report([_valid_finding()])
        r["surprise"] = 1
        assert "UNKNOWN_PROPERTY" in _codes(
            validate_report(r, finding_schema, today=TODAY,
                            known_rules=self._RULES))

    def test_report_unknown_rule_rejected_when_registry(self, finding_schema):
        # Cas adversarial A-008 : rule_id inconnu du registre.
        r = self._report([_valid_finding(rule_id="NOPE-999")])
        assert "UNKNOWN_RULE" in _codes(
            validate_report(r, finding_schema, today=TODAY,
                            known_rules=self._RULES))


# ---------------------------------------------------------------------------
# Cas adversariaux supplementaires (revue 2)
# ---------------------------------------------------------------------------

class TestAdversarialSkills:
    def test_section_as_paragraph_rejected(self, tmp_path):
        # Sections en texte courant (pas en titre ##) = rejetees.
        md = ("---\nname: audit-security\ndescription: d\nversion: 0.1.0\n"
              "owner: phases-agents\nlicense: Apache-2.0\n---\n\n"
              "Loi centrale. Ce que ce skill fait. Ce que ce skill ne fait pas. "
              "Conditions d'activation. Conditions d'exclusion. Capacites necessaires. "
              "Interdictions. Methode d'audit. Contrat de preuve. Format de sortie. "
              "Conditions de blocage. Limites connues. Exemples d'entree. "
              "Exemple de sortie attendue.\n")
        d = _make_skill(tmp_path, skill_md=md)
        assert "SKILL_SECTION" in _codes(_vs(str(d), CORE_DIR, today=TODAY))

    def test_declared_file_missing_rejected(self, tmp_path):
        # A-005 : fichiers declares dans manifeste doivent exister.
        m = _valid_manifest(files=["scripts/missing.py"])
        d = _make_skill(tmp_path, manifest=m)
        assert "GHOST_FILE" in _codes(_vs(str(d), CORE_DIR, today=TODAY))

    def test_declared_file_present_ok(self, tmp_path):
        m = _valid_manifest(files=["scripts/helper.py"])
        d = _make_skill(tmp_path, manifest=m)
        _write(d / "scripts" / "helper.py", "# ok\n")
        assert _errors(_vs(str(d), CORE_DIR, today=TODAY)) == []

    def test_secret_split_by_spaces_rejected(self, finding_schema):
        # N-003 : secret divise par espaces.
        f = _valid_finding(evidence=[{"type": "file", "path": "c.py", "line": 1,
                                      "excerpt": "K = ABCDEFGHIJ KLMNOPQRST UVWXYZ123456",
                                      "method": "m"}])
        assert "SECRET_UNMASKED" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_secret_single_star_rejected(self, finding_schema):
        # N-003 : une seule etoile noyee ne masque rien.
        f = _valid_finding(evidence=[{"type": "file", "path": "c.py", "line": 1,
                                      "excerpt": "K = ABCDEFGHIJKLMNOPQRST*VWXYZ123456",
                                      "method": "m"}])
        assert "SECRET_UNMASKED" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_schema_type_list_no_crash(self, finding_schema):
        # N-001 : {"type":[]} ne crash plus.
        bad_schema = {"type": "object", "properties": {"x": {"type": []}}}
        issues = []
        from phases_agents.validator import _check_schema_shape
        _check_schema_shape(bad_schema, issues, "test")
        assert any(i.code == "SCHEMA_KW_TYPE" for i in issues)

    def test_items_string_rejected(self, finding_schema):
        # N-001 : items: "bad" est rejete, pas ignore.
        bad_schema = {"type": "array", "items": "bad"}
        issues = []
        from phases_agents.validator import _check_schema_shape
        _check_schema_shape(bad_schema, issues, "test")
        assert any(i.code == "SCHEMA_KW_TYPE" for i in issues)

    def test_remediation_proposed_needs_gate(self, finding_schema):
        # A-007 : REMEDIATION_PROPOSED avec mode NONE/gate NONE = rejete.
        f = _valid_finding(status="REMEDIATION_PROPOSED",
                           remediation={"mode": "NONE", "required_gate": "NONE",
                                        "summary": "x"})
        assert "REMEDIATION_GATE" in _codes(_vf(f, finding_schema, today=TODAY))

    def _skill_with_impossible_date(self, tmp_path):
        r = {"rule_id": "REG-1", "jurisdiction": "EU",
             "source_url": "https://eur-lex.europa.eu/legal-content/FR/",
             "verified_on": "2026-13-40", "freshness_window_days": 180,
             "applicability": "x", "confidence": "MEDIUM", "status": "en_vigueur"}
        m = _valid_manifest(domain="compliance", id="audit-compliance")
        d = _make_skill(tmp_path, manifest=m, skill_md=_valid_skill_md(name="audit-compliance"))
        _write_json(d / "rules" / "compliance.json", r)
        return d

    def test_legal_date_invalid_rejected(self, tmp_path):
        # A-003 : une date impossible reste rejetee (avec `today` fourni).
        d = self._skill_with_impossible_date(tmp_path)
        assert "LEGAL_DATE" in _codes(_vs(str(d), CORE_DIR, today=TODAY))

    def test_legal_skill_without_today_rejected(self, tmp_path):
        # R6-001 : A-003 revise. Sans `today`, le validator ne valide plus rien
        # en mode degrade : il rejette l'appel lui-meme (TODAY_REQUIRED) au lieu
        # de rendre un verdict juridique partiel sans date de reference.
        d = self._skill_with_impossible_date(tmp_path)
        issues = validate_skill(str(d), CORE_DIR, today=None)
        assert _codes(issues) == {"TODAY_REQUIRED"}


# ---------------------------------------------------------------------------
# Cas adversariaux jury (ultracode) — harnais permanent anti-regression
# ---------------------------------------------------------------------------

class TestJuryAdversarial:
    """Chaque contournement confirme par le jury devient un test permanent."""

    def test_secret_fragmented_by_dots(self, finding_schema):
        f = _valid_finding(evidence=[{"type": "file", "path": "c.py", "line": 1,
                                      "excerpt": "K = ABCDEF.GHIJKL.MNOPQR.STUVWX.YZ123456",
                                      "method": "m"}])
        assert "SECRET_UNMASKED" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_secret_split_2_plus_2_stars(self, finding_schema):
        f = _valid_finding(evidence=[{"type": "file", "path": "c.py", "line": 1,
                                      "excerpt": "K = ABCDEFGHIJ**KLMNOP**QRSTUVWXYZ123456",
                                      "method": "m"}])
        assert "SECRET_UNMASKED" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_canary_documented_tolerated(self, finding_schema):
        f = _valid_finding(evidence=[{"type": "file", "path": "c.py", "line": 1,
                                      "excerpt": "key = TEST-CANARY-NOT-A-REAL-KEY-0000",
                                      "method": "m"}])
        assert "SECRET_UNMASKED" not in _codes(_vf(f, finding_schema, today=TODAY))

    def test_uuid_tolerated(self, finding_schema):
        f = _valid_finding(evidence=[{"type": "file", "path": "c.py", "line": 1,
                                      "excerpt": "id = 550e8400-e29b-41d4-a716-446655440000",
                                      "method": "m"}])
        assert "SECRET_UNMASKED" not in _codes(_vf(f, finding_schema, today=TODAY))

    def test_secret_19_chars_rejected(self, finding_schema):
        f = _valid_finding(evidence=[{"type": "file", "path": "c.py", "line": 1,
                                      "excerpt": "K = ABCDEFGHIJKLMNOPQ12", "method": "m"}])
        assert "SECRET_UNMASKED" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_backslash_dotdot_rejected(self, tmp_path):
        from phases_agents.validator import _safe_relpath
        assert _safe_relpath(str(tmp_path), r"rules\..\rules\x.txt") is None

    def test_ads_rejected(self, tmp_path):
        from phases_agents.validator import _safe_relpath
        assert _safe_relpath(str(tmp_path), "file.txt:hidden") is None

    def test_trailing_dot_rejected(self, tmp_path):
        from phases_agents.validator import _safe_relpath
        assert _safe_relpath(str(tmp_path), "tests.") is None

    def test_trailing_space_rejected(self, tmp_path):
        from phases_agents.validator import _safe_relpath
        assert _safe_relpath(str(tmp_path), "tests ") is None

    def test_unc_rejected(self, tmp_path):
        from phases_agents.validator import _safe_relpath
        assert _safe_relpath(str(tmp_path), r"\\server\share\x") is None

    def test_url_encoded_dotdot_rejected(self, tmp_path):
        from phases_agents.validator import _safe_relpath
        assert _safe_relpath(str(tmp_path), "%2e%2e/outside") is None

    def test_legal_domain_trailing_space(self, finding_schema):
        f = _valid_finding(domain="compliance ")
        assert "LEGAL_BASIS" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_legal_domain_cyrillic(self, finding_schema):
        f = _valid_finding(domain="compliance".replace("a", "а"))
        assert "LEGAL_BASIS" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_freshness_window_366_rejected(self, tmp_path):
        r = {"rule_id": "X", "jurisdiction": "EU", "authority": "Parlement europeen",
             "source_url": "https://eur-lex.europa.eu/x", "verified_on": "2026-01-01",
             "freshness_window_days": 366, "applicability": "x",
             "confidence": "MEDIUM", "status": "en_vigueur"}
        m = _valid_manifest(domain="compliance", id="audit-compliance")
        d = _make_skill(tmp_path, manifest=m, skill_md=_valid_skill_md(name="audit-compliance"))
        _write_json(d / "rules" / "x.json", r)
        assert "LEGAL_FRESHNESS" in _codes(_vs(str(d), CORE_DIR, today=TODAY))

    def test_live_check_method_arbitrary_rejected(self, finding_schema):
        lb = _legal_basis(live_check={"done": True, "method": "telepathy",
                                      "checked_at": "2026-07-27", "result": "en_vigueur"})
        f = _valid_finding(domain="compliance", status="CONFIRMED",
                           observation_status="CONFIRMED",
                           legal_basis_status="VERIFIED_CURRENT", decision="CONFIRMED",
                           legal_basis=lb)
        assert "LIVE_CHECK" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_live_check_checked_at_before_verified_on(self, finding_schema):
        lb = _legal_basis(verified_on="2026-07-01",
                          live_check={"done": True, "method": "web_search",
                                      "checked_at": "2020-01-01", "result": "en_vigueur"})
        f = _valid_finding(domain="compliance", status="CONFIRMED",
                           observation_status="CONFIRMED",
                           legal_basis_status="VERIFIED_CURRENT", decision="CONFIRMED",
                           legal_basis=lb)
        assert "LIVE_CHECK" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_authority_fictional_rejected(self, finding_schema):
        lb = _legal_basis(authority="Ministere de la Magie")
        f = _valid_finding(domain="compliance", status="CONFIRMED",
                           observation_status="CONFIRMED",
                           legal_basis_status="VERIFIED_CURRENT", decision="CONFIRMED",
                           legal_basis=lb)
        assert "LEGAL_AUTHORITY" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_jurisdiction_fictional_rejected(self, finding_schema):
        lb = _legal_basis(jurisdiction="ATLANTIS")
        f = _valid_finding(domain="compliance", status="CONFIRMED",
                           observation_status="CONFIRMED",
                           legal_basis_status="VERIFIED_CURRENT", decision="CONFIRMED",
                           legal_basis=lb)
        assert "LEGAL_JURISDICTION" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_http_source_rejected(self, finding_schema):
        lb = _legal_basis(source_url="http://eur-lex.europa.eu/x")
        f = _valid_finding(domain="compliance", status="CONFIRMED",
                           observation_status="CONFIRMED",
                           legal_basis_status="VERIFIED_CURRENT", decision="CONFIRMED",
                           legal_basis=lb)
        assert "LEGAL_SOURCE" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_userinfo_source_rejected(self, finding_schema):
        lb = _legal_basis(source_url="https://user:pass@eur-lex.europa.eu/x")
        f = _valid_finding(domain="compliance", status="CONFIRMED",
                           observation_status="CONFIRMED",
                           legal_basis_status="VERIFIED_CURRENT", decision="CONFIRMED",
                           legal_basis=lb)
        assert "LEGAL_SOURCE" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_confirmed_p0_low_confidence(self, finding_schema):
        f = _valid_finding(status="CONFIRMED", severity="P0_CRITICAL", confidence="LOW",
                           evidence=_strong_evidence())
        assert "CONFIDENCE_MISMATCH" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_decision_confirmed_with_status_observed(self, finding_schema):
        f = _valid_finding(domain="compliance", status="OBSERVED",
                           observation_status="OBSERVED",
                           legal_basis_status="VERIFIED_CURRENT", decision="CONFIRMED",
                           legal_basis=_legal_basis())
        assert "STATE_INCOHERENT" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_status_confirmed_observation_suspected(self, finding_schema):
        f = _valid_finding(domain="compliance", status="CONFIRMED",
                           observation_status="SUSPECTED",
                           legal_basis_status="VERIFIED_CURRENT", decision="CONFIRMED",
                           legal_basis=_legal_basis(), evidence=_strong_evidence())
        assert "STATE_INCOHERENT" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_status_reason_zwsp_rejected(self, finding_schema):
        f = _valid_finding(status="BLOCKED", status_reason="​")
        assert "STATUS_REASON" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_report_finding_non_dict(self, finding_schema):
        r = {"skill_id": "s", "version": "0.1.0", "findings": ["not-a-dict"]}
        assert "FINDING" in _codes(validate_report(
            r, finding_schema, today=TODAY,
            known_rules=_trusted_rules_for_tests({})))

    def test_report_finding_id_case_dup(self, finding_schema):
        r = {"skill_id": "audit-security", "version": "0.1.0",
             "findings": [_valid_finding(finding_id="FIND-1"),
                          _valid_finding(finding_id="find-1")]}
        assert "DUP_FINDING" in _codes(validate_report(
            r, finding_schema, today=TODAY,
            known_rules=_trusted_rules_for_tests(
                {"SEC-001": "en_vigueur"})))

    def test_schema_cycle_rejected(self):
        from phases_agents.validator import _check_schema_shape
        s = {"type": "object", "properties": {}}
        s["properties"]["self"] = s
        issues = []
        _check_schema_shape(s, issues, "test")
        assert any(i.code == "SCHEMA_CYCLE" for i in issues)

    def test_schema_required_dict_element_rejected(self):
        from phases_agents.validator import _check_schema_shape
        issues = []
        _check_schema_shape({"type": "object", "required": [{}]}, issues, "test")
        assert any(i.code == "SCHEMA_KW_TYPE" for i in issues)

    def test_json_dup_key_rejected(self, tmp_path):
        from phases_agents.validator import _load_json
        p = tmp_path / "x.json"
        p.write_text('{"id":"a","id":"b"}', encoding="utf-8")
        issues = []
        _load_json(str(p), issues, "x")
        assert any(i.code == "DUPLICATE_KEY" for i in issues)

    def test_json_deep_rejected(self, tmp_path):
        from phases_agents.validator import _load_json
        p = tmp_path / "deep.json"
        p.write_text("[" * 5000 + "]" * 5000, encoding="utf-8")
        issues = []
        _load_json(str(p), issues, "deep")
        assert any(i.code == "TOO_DEEP" for i in issues)

    def test_absence_result_case_mixed_accepted(self, finding_schema):
        f = _valid_finding(evidence=[{"type": "absence", "path": "x.md",
                                      "searched_in": ["project-root"], "result": "ABSENT",
                                      "method": "m"}])
        assert "EVIDENCE_WEAK" not in _codes(_vf(f, finding_schema, today=TODAY))

    def test_absence_searched_in_traversal_rejected(self, finding_schema):
        f = _valid_finding(evidence=[{"type": "absence", "path": "x.md",
                                      "searched_in": ["../../etc"], "result": "absent",
                                      "method": "m"}])
        assert "EVIDENCE_PATH" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_absence_searched_in_home_directory_rejected(self, finding_schema):
        """Le tilde designe le repertoire personnel : hors du projet audite.

        `os.path.isabs` ne le voit pas, donc la garde le laissait passer.
        """

        for scope in ("~/secret", "~alice/secret"):
            f = _valid_finding(evidence=[{"type": "absence", "path": "x.md",
                                          "searched_in": [scope],
                                          "result": "absent", "method": "m"}])
            assert "EVIDENCE_PATH" in _codes(_vf(f, finding_schema, today=TODAY)), scope

    def test_absence_searched_in_must_be_a_list(self, finding_schema):
        """L'ancien format chaine est refuse : la migration doit etre prouvee."""

        f = _valid_finding(evidence=[{"type": "absence", "path": "x.md",
                                      "searched_in": "project-root",
                                      "result": "absent", "method": "m"}])
        assert "EVIDENCE_WEAK" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_absence_searched_in_rejects_any_bad_element(self, finding_schema):
        """Un seul element fautif suffit a refuser la liste entiere."""

        f = _valid_finding(evidence=[{"type": "absence", "path": "x.md",
                                      "searched_in": ["src/app.py", "/etc/passwd"],
                                      "result": "absent", "method": "m"}])
        assert "EVIDENCE_PATH" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_absence_searched_in_rejects_non_string_elements(self, finding_schema):
        """Un element non-chaine est refuse, sans lever d'exception.

        La garde isinstance de `_portable_relpath_parts` couvre deja ce cas ;
        le test le verrouille pour que la couverture reste explicite.
        """

        f = _valid_finding(evidence=[{"type": "absence", "path": "x.md",
                                      "searched_in": ["src/app.py", 1],
                                      "result": "absent", "method": "m"}])
        assert "EVIDENCE_PATH" in _codes(_vf(f, finding_schema, today=TODAY))

    def test_absence_searched_in_empty_list_rejected(self, finding_schema):
        """Une liste VIDE ne borne rien : le schema doit dire ce qu'il exige.

        Le mot-cle minItems a ete ajoute au validateur de schema pour que la
        contrainte soit portee par le schema lui-meme, et pas seulement par le
        code qui le consomme.
        """

        f = _valid_finding(evidence=[{"type": "absence", "path": "x.md",
                                      "searched_in": [],
                                      "result": "absent", "method": "m"}])
        codes = _codes(_vf(f, finding_schema, today=TODAY))
        assert "EMPTY_ARRAY" in codes or "EVIDENCE_WEAK" in codes

    def test_line_too_high_rejected(self, finding_schema):
        f = _valid_finding(evidence=[{"type": "file", "path": "a.py", "line": 99999999,
                                      "excerpt": "x", "method": "m"}])
        assert "EVIDENCE_LINE" in _codes(_vf(f, finding_schema, today=TODAY))
