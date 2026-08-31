"""Tests permanents de l'audit-security.

Corpus fixe. Aucun acces reseau. Aucune donnee reelle.
"""

from __future__ import annotations

import ast
import datetime
import hashlib
import json
import os
import pathlib
import subprocess
import sys
from types import SimpleNamespace

import pytest

from phases_agents import detector
from phases_agents import server
from phases_agents import validator
ROOT = pathlib.Path(__file__).resolve().parents[1]
# Les modules vivent dans le paquet depuis le layout src.
PKG = ROOT / "src" / "phases_agents"


def _source_env():
    """Environnement ou le paquet sous src/ est importable par un sous-processus."""
    env = os.environ.copy()
    pythonpath = env.get("PYTHONPATH")
    source_root = str(ROOT / "src")
    env["PYTHONPATH"] = (
        source_root
        if not pythonpath
        else source_root + os.pathsep + pythonpath
    )
    return env

TODAY = datetime.date(2026, 7, 29)
TRUSTED_RULES = validator._trusted_rules_for_tests({"R1": "en_vigueur"})


def _codes(issues):
    return {issue.code for issue in issues if issue.level == "error"}


def _valid_finding(**changes):
    finding = {
        "finding_id": "SEC-TEST",
        "skill_id": "audit-security",
        "rule_id": "R1",
        "title": "Constat local",
        "domain": "security",
        "status": "OBSERVED",
        "severity": "P3_LOW",
        "confidence": "MEDIUM",
        "scope": {
            "environment": "local",
            "platform": "windows",
            "component": "validator",
        },
        "evidence": [{
            "type": "file",
            "path": "app.py",
            "line": 1,
            "excerpt": "x = 1",
            "method": "lecture",
        }],
        "impact": {
            "confidentiality": "LOW",
            "integrity": "LOW",
            "availability": "NONE",
            "legal": "NONE",
        },
        "remediation": {
            "mode": "NONE",
            "summary": "Aucune action produit.",
        },
        "limitations": [],
        "references": [],
    }
    finding.update(changes)
    return finding


def _validate(finding):
    return validator.validate_finding(
        finding,
        today=TODAY,
        known_rules=TRUSTED_RULES,
    )


def _aws_synthetic():
    return "AK" + "IA" + "I0SF0DNN7SYNTHETIC"


def _stripe_synthetic():
    return "sk_" + "live_" + "51SyntheticOnly987654321"


def _bearer_synthetic():
    return "Bearer " + "eyJhbGciOiJub25lIn0.synthetic.signature"


def _run_server(payload: bytes):
    env = os.environ.copy()
    pythonpath = env.get("PYTHONPATH")
    source_root = str(ROOT / "src")
    env["PYTHONPATH"] = (
        source_root
        if not pythonpath
        else source_root + os.pathsep + pythonpath
    )
    return subprocess.run(
        [sys.executable, "-m", "phases_agents.server"],
        input=payload,
        capture_output=True,
        cwd=ROOT,
        env=env,
        timeout=10,
    )


class TestSec001PathConfinement:
    @pytest.mark.parametrize("hostile", [
        "../outside",
        "..\\outside",
        "folder/../../outside",
        "folder\\..\\..\\outside",
        "C:\\Windows\\file",
        "C:relative",
        "\\\\server\\share\\file",
        "\\\\?\\C:\\Windows\\file",
        "file.txt:stream",
        "folder.",
        "folder ",
        "folder//file.py",
        "folder/./file.py",
        "a\x00b.py",
        "folder／..／outside",
        "CON",
        "aux.txt",
    ])
    def test_hostile_evidence_paths_are_rejected(self, hostile):
        finding = _valid_finding(evidence=[{
            "type": "file",
            "path": hostile,
            "line": 1,
            "excerpt": "x = 1",
            "method": "lecture",
        }])
        assert "EVIDENCE_PATH" in _codes(_validate(finding))

    def test_backslash_only_relative_path_is_supported(self):
        finding = _valid_finding(evidence=[{
            "type": "file",
            "path": "folder\\app.py",
            "line": 1,
            "excerpt": "x = 1",
            "method": "lecture",
        }])
        assert _codes(_validate(finding)) == set()

    @pytest.mark.skipif(os.name != "nt", reason="jonction Windows")
    def test_detector_blocks_parent_junction(self, tmp_path):
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        root.mkdir()
        outside.mkdir()
        (outside / "package.json").write_text("{}", encoding="utf-8")
        junction = root / "escape"
        made = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(junction), str(outside)],
            capture_output=True,
            text=True,
        )
        assert made.returncode == 0, made.stderr
        try:
            profile = detector.detect_profile(str(root))
            assert profile["blocked"] is True
            assert profile["issues"] == ["REPARSE_POINT"]
            assert "web" not in profile["types"]
        finally:
            if junction.exists():
                os.rmdir(junction)

    def test_detector_blocks_hardlink_escape(self, tmp_path):
        root = tmp_path / "root"
        outside = tmp_path / "outside"
        root.mkdir()
        outside.mkdir()
        source = outside / "Cargo.toml"
        source.write_text(
            '[dependencies]\nanchor-lang = "1"\n',
            encoding="utf-8",
        )
        linked = root / "Cargo.toml"
        os.link(source, linked)
        profile = detector.detect_profile(str(root))
        assert profile["blocked"] is True
        assert profile["issues"] == ["UNSAFE_FILE"]
        assert "solana" not in profile["types"]


class TestSec002BoundedFileLoading:
    def test_read_is_bounded_after_size_race(self, tmp_path, monkeypatch):
        target = tmp_path / "growing.json"
        target.write_bytes(b"x" * (validator._MAX_JSON_BYTES + 100))
        real_lstat = validator.os.lstat
        real = real_lstat(target)
        fake = SimpleNamespace(
            st_mode=real.st_mode,
            st_nlink=real.st_nlink,
            st_size=0,
            st_dev=real.st_dev,
            st_ino=real.st_ino,
            st_file_attributes=getattr(real, "st_file_attributes", 0),
        )

        def stale_lstat(path):
            if os.path.normcase(os.fspath(path)) == os.path.normcase(str(target)):
                return fake
            return real_lstat(path)

        monkeypatch.setattr(validator.os, "lstat", stale_lstat)
        issues = []
        result = validator._read_bytes(
            str(target),
            issues,
            "rapport",
            validator._MAX_JSON_BYTES,
        )
        assert result is None
        assert _codes(issues) == {"TOO_LARGE"}

    def test_detector_permission_error_is_blocked(self, tmp_path, monkeypatch):
        monkeypatch.setattr(
            detector.os,
            "scandir",
            lambda path: (_ for _ in ()).throw(PermissionError("denied")),
        )
        profile = detector.detect_profile(str(tmp_path))
        assert profile["blocked"] is True
        assert profile["issues"] == ["DIRECTORY_UNREADABLE"]

    def test_detector_deleted_file_is_blocked(self, tmp_path, monkeypatch):
        target = tmp_path / "main.rs"
        target.write_text("use anchor_lang::prelude::*;", encoding="utf-8")
        real_open = open

        def racing_open(path, *args, **kwargs):
            if os.path.normcase(os.fspath(path)) == os.path.normcase(str(target)):
                target.unlink(missing_ok=True)
            return real_open(path, *args, **kwargs)

        monkeypatch.setattr("builtins.open", racing_open)
        profile = detector.detect_profile(str(tmp_path))
        assert profile["blocked"] is True
        assert profile["issues"] == ["READ_ERROR"]

    def test_detector_rechecks_filename_only_marker(self, tmp_path, monkeypatch):
        target = tmp_path / "application.apk"
        target.write_bytes(b"synthetic")
        real_safe_info = detector._safe_file_info
        calls = 0

        def changed_after_walk(path, root):
            nonlocal calls
            if os.path.normcase(os.fspath(path)) == os.path.normcase(str(target)):
                calls += 1
                if calls == 1:
                    return None, "FILE_CHANGED"
            return real_safe_info(path, root)

        monkeypatch.setattr(detector, "_safe_file_info", changed_after_walk)
        profile = detector.detect_profile(str(tmp_path))
        assert profile["blocked"] is True
        assert profile["issues"] == ["FILE_CHANGED"]
        assert "apk" not in profile["types"]



class TestSec002HardlinkExemptionForPackageData:
    """Correctif uvx : uv installe les fichiers du paquet en LIENS DURS vers
    son cache (``st_nlink`` >= 2). La defense anti-lien-dur de ``_read_bytes``
    ne doit s'effacer QUE pour les donnees officielles scellees (``core/`` et
    ``registry/``), jamais pour un fichier de skill sous une racine. Sans ce
    correctif, le serveur est inerte sous son runtime declare ; sans cette
    limite, la defense SEC-001/SEC-002 serait desarmee pour l'entree hostile.
    """

    def _hardlinked(self, tmp_path):
        original = tmp_path / "original.json"
        original.write_text('{"schema_id": "X"}', encoding="utf-8")
        linked = tmp_path / "linked.json"
        os.link(original, linked)
        assert os.stat(linked).st_nlink == 2
        return linked

    def test_user_skill_hardlink_is_still_rejected(self, tmp_path):
        # Hors des dossiers officiels : la defense reste entiere. Un lien dur
        # est refuse, c'est la protection contre l'echange entre stat et open.
        linked = self._hardlinked(tmp_path)
        issues = []
        result = validator._read_bytes(
            str(linked), issues, "skill", validator._MAX_JSON_BYTES)
        assert result is None
        assert "PATH_UNSAFE" in _codes(issues)

    def test_package_data_hardlink_is_accepted(self, tmp_path, monkeypatch):
        # Dans le dossier core officiel (ici deplace sur tmp_path) : un lien
        # dur est LU. C'est exactement ce que produit `uvx` a l'installation.
        monkeypatch.setattr(validator, "_DEFAULT_CORE_DIR", str(tmp_path))
        linked = self._hardlinked(tmp_path)
        issues = []
        result = validator._read_bytes(
            str(linked), issues, "schema", validator._MAX_JSON_BYTES)
        assert result == b'{"schema_id": "X"}'
        assert issues == []

    def test_registry_dir_hardlink_is_accepted(self, tmp_path, monkeypatch):
        # Meme exemption pour le registre officiel.
        monkeypatch.setattr(validator, "_DEFAULT_REGISTRY_DIR", str(tmp_path))
        linked = self._hardlinked(tmp_path)
        issues = []
        result = validator._read_bytes(
            str(linked), issues, "profile-facts.json",
            validator._MAX_JSON_BYTES)
        assert result == b'{"schema_id": "X"}'
        assert issues == []

    def test_exemption_lifts_only_the_link_check(self, tmp_path, monkeypatch):
        # L'exemption ne touche QUE le test de lien. Un non-fichier regulier
        # (repertoire) dans le dossier officiel reste refuse.
        monkeypatch.setattr(validator, "_DEFAULT_CORE_DIR", str(tmp_path))
        directory = tmp_path / "notafile.json"
        directory.mkdir()
        issues = []
        result = validator._read_bytes(
            str(directory), issues, "schema", validator._MAX_JSON_BYTES)
        assert result is None
        assert "PATH_UNSAFE" in _codes(issues)


class TestSec004HostileDataLimits:
    def test_public_finding_cycle_is_structured(self):
        finding = _valid_finding()
        finding["cycle"] = finding
        issues = _validate(finding)
        assert _codes(issues) == {"PAYLOAD_CYCLE"}

    def test_public_report_cycle_is_structured(self):
        report = {}
        report["cycle"] = report
        issues = validator.validate_report(
            report,
            today=TODAY,
            known_rules=TRUSTED_RULES,
        )
        assert _codes(issues) == {"PAYLOAD_CYCLE"}

    def test_public_finding_size_is_bounded(self):
        finding = _valid_finding(title="ordinary words " * 150_000)
        assert _codes(_validate(finding)) == {"TOO_LARGE"}

    def test_public_finding_depth_is_bounded(self):
        nested = {}
        cursor = nested
        for _ in range(validator._MAX_JSON_DEPTH + 5):
            cursor["child"] = {}
            cursor = cursor["child"]
        finding = _valid_finding(extra=nested)
        assert _codes(_validate(finding)) == {"TOO_DEEP"}

    def test_public_surrogate_key_is_structured(self):
        finding = _valid_finding()
        finding["\ud800"] = "x"
        assert _codes(_validate(finding)) == {"ENCODING"}

    def test_public_huge_integer_is_structured(self):
        finding = _valid_finding()
        finding["evidence"][0]["line"] = 10 ** 5_000
        assert _codes(_validate(finding)) == {"TOO_LARGE"}

    def test_fixed_type_corpus_never_raises(self):
        corpus = [
            None,
            True,
            0,
            1.5,
            b"bytes",
            "",
            [],
            {},
            {"value": None},
        ]
        for value in corpus:
            finding_result = validator.validate_finding(
                value,
                today=TODAY,
                known_rules=TRUSTED_RULES,
            )
            report_result = validator.validate_report(
                value,
                today=TODAY,
                known_rules=TRUSTED_RULES,
            )
            skill_result = validator.validate_skill(value, today=TODAY)
            detector_result = detector.detect_profile(value)
            server_result = server.handle_message(value)
            assert isinstance(finding_result, list)
            assert isinstance(report_result, list)
            assert isinstance(skill_result, list)
            assert isinstance(detector_result, dict)
            assert isinstance(server_result, dict)


class TestSec005RegexComplexity:
    @pytest.mark.parametrize(("content", "expected"), [
        ("<a", "<a"),
        ("<div", "<div"),
        ("<" * 64, "<" * 64),
        (">" * 64, ">" * 64),
        ("[" * 64, "[" * 64),
        ("`" * 64, ""),
        ("```\nsecret\n", "\n\n"),
        (
            "Avant <span>visible</span> apres",
            "Avant " + " " * len("<span>") + "visible"
            + " " * len("</span>") + " apres",
        ),
        (
            "Avant <div class=\"x\">cache</div> apres",
            "Avant " + " " * len('<div class="x">cache</div>') + " apres",
        ),
        ("<div>texte</div>", " " * len("<div>texte</div>")),
        (
            "<div title='x'>texte</div>",
            " " * len("<div title='x'>texte</div>"),
        ),
        (
            '<span data-x="a>b">texte</span>',
            " " * len('<span data-x="a>b">') + "texte"
            + " " * len("</span>"),
        ),
        ("<script>contenu</script>", " " * len("<script>contenu</script>")),
        ("<style>contenu</style>", " " * len("<style>contenu</style>")),
        (
            "Avant </div> apres",
            "Avant " + " " * len("</div>") + " apres",
        ),
        ("<br>", " " * len("<br>")),
        ("<br/>", " " * len("<br/>")),
        (
            "Avant <!-- cache --> apres",
            "Avant " + " " * len("<!-- cache -->") + " apres",
        ),
        (
            "Avant `code` apres",
            "Avant " + " " * len("`code`") + " apres",
        ),
        ("## Loi centrale\nTexte normal\n",
         "## Loi centrale\nTexte normal\n"),
        ("é漢🙂" * 64, "é漢🙂" * 64),
    ])
    def test_markdown_html_corpus_has_exact_output(self, content, expected):
        assert validator._strip_markdown_code(content) == expected

    @pytest.mark.parametrize("phrase", (
        "Si x<y alors on applique la regle.",
        "Le type List<String> est utilise.",
        "Contrainte 3<x<7 imposee.",
        "Si a<b et c>d alors continuer.",
        "Un mot <b>important non ferme.",
        "La relation alpha<beta est vraie.",
        "Une valeur n<m peut etre comparee.",
        "Si x<y, la condition est vraie.",
        "Le type List<String> contient du texte.",
        "La formule 3<x<7 est valide.",
        "a<b et c>d.",
        "foo<bar.",
        "texte <inconnu sans fermeture.",
    ))
    def test_technical_prose_keeps_following_heading(self, phrase):
        text = f"{phrase}\n\n## Section suivante\nContenu visible.\n"
        cleaned = validator._strip_markdown_code(text)
        assert "## Section suivante" in cleaned
        assert "Contenu visible." in cleaned
        if "<b>" not in phrase:
            assert phrase in cleaned

    @pytest.mark.parametrize("opening", (
        '<script src="a<b"',
        '<div title="a<b',
        "<style",
        "  <SCRIPT",
        "   <DIV",
    ))
    def test_incomplete_content_blocks_remain_fail_closed(self, opening):
        text = f"{opening}\n## Titre cache\nContenu masque.\n"
        cleaned = validator._strip_markdown_code(text)
        assert cleaned.startswith(opening)
        assert "## Titre cache" not in cleaned
        assert "Contenu masque." not in cleaned

    @pytest.mark.parametrize("tag", (
        "<br>",
        "<hr>",
        '<img src="x">',
        "<wbr>",
    ))
    def test_void_html_never_masks_following_heading(self, tag):
        text = f"{tag}\n## Section suivante\nContenu visible.\n"
        cleaned = validator._strip_markdown_code(text)
        assert "## Section suivante" in cleaned
        assert "Contenu visible." in cleaned

    def test_content_tag_adjacent_to_text_remains_fail_closed(self):
        text = "x<script\n## Titre cache\nContenu masque.\n"
        cleaned = validator._strip_markdown_code(text)
        assert "## Titre cache" not in cleaned
        assert "Contenu masque." not in cleaned

    def test_quoted_attribute_html_never_exposes_hidden_heading(self):
        hostile_blocks = (
            '<script src="a<b">## Loi centrale</script>',
            '<div title="a<b">## Loi centrale</div>',
            '<div"x">## Loi centrale</div>',
            '<div=1>## Loi centrale</div>',
            "<div title='a<b'>## Loi centrale</div>",
            '<div title="a>b">## Loi centrale</div>',
            '<div title="a<b<c">## Loi centrale</div>',
            '<div data-x="<tag>">## Loi centrale</div>',
            '<script data-x="<script>">## Loi centrale</script>',
            '<div title="a<b"/>## Loi centrale</div>',
        )
        for content in hostile_blocks:
            cleaned = validator._strip_markdown_code(content)
            assert "## Loi centrale" not in cleaned
            assert cleaned.strip() == ""

    def test_ambiguous_html_blocks_fail_closed_across_lines(self):
        hostile_blocks = (
            "<div title=a<b>## Loi centrale</div>",
            "<script src=a<b>## Loi centrale</script>",
            '<script src="a<b"\n>\n## Loi centrale\n</script>',
            '<div title="a>b\n">\n## Loi centrale\n</div>',
        )
        for content in hostile_blocks:
            assert "## Loi centrale" not in validator._strip_markdown_code(
                content)
        for tag in (
                "plaintext", "listing", "noscript", "object", "canvas",
                "audio", "video", "svg", "math", "code", "colgroup",
                "future-container", "future_container", "div_", "futureé",
                "élement"):
            content = f"<{tag}>\n## Loi centrale\n</{tag}>"
            assert "## Loi centrale" not in validator._strip_markdown_code(
                content)
        for tag in ("span", "a", "em", "strong", "ruby"):
            content = f"<{tag}>\n## Loi centrale\n</{tag}>"
            assert "## Loi centrale" not in validator._strip_markdown_code(
                content)
        for content in (
                "<![CDATA[\n## Loi centrale\n]]>",
                "<?processor\n## Loi centrale\n?>",
                "<!DOCTYPE html\n## Loi centrale\n>"):
            assert "## Loi centrale" not in validator._strip_markdown_code(
                content)

    def test_removed_markup_never_promotes_hidden_heading(self):
        hostile_lines = (
            "<span>## Loi centrale</span>",
            "<br>## Loi centrale",
            '<a href="x">## Loi centrale</a>',
            "<em>## Loi centrale</em>",
            "<!--x-->## Loi centrale",
            "`code`## Loi centrale",
            "<div>cache</div>## Loi centrale",
        )
        for content in hostile_lines:
            cleaned = validator._strip_markdown_code(content)
            assert len(cleaned) == len(content)
            assert not cleaned.startswith("## Loi centrale")
        inline_with_void = "<span>a<br>b</span>"
        cleaned = validator._strip_markdown_code(inline_with_void)
        assert len(cleaned) == len(inline_with_void)
        assert cleaned.replace(" ", "") == "ab"
        for autolink in (
                "<https://example.com>",
                "<mailto:user@example.com>",
                "<user@example.com>"):
            content = autolink + "\n## Loi centrale\nTexte."
            cleaned = validator._strip_markdown_code(content)
            assert len(cleaned) == len(content)
            assert cleaned.startswith(autolink)
            assert cleaned.splitlines()[1] == "## Loi centrale"

    def test_invalid_email_like_tags_fail_closed(self):
        invalid_domains = (
            "example..com",
            "example-.com",
            "-example.com",
            f"{'a' * 64}.com",
        )
        for domain in invalid_domains:
            content = (
                f"<div@{domain}>\n"
                "## Loi centrale\n"
                "Texte masque.\n"
                f"</div@{domain}>"
            )
            cleaned = validator._strip_markdown_code(content)
            assert "## Loi centrale" not in cleaned
            assert cleaned.strip() == ""

    def test_long_html_tag_does_not_expose_hidden_markdown(self):
        ordinary = "<div class=\"x\">cache</div>"
        long_block = (
            "<div data-value=\"" + "x" * 100_000 + "\">\n"
            "## Loi centrale\n"
            "Texte cache.\n"
            "</div>\n"
        )
        assert validator._strip_markdown_code(ordinary).strip() == ""
        stripped = validator._strip_markdown_code(long_block)
        assert "## Loi centrale" not in stripped
        assert "Texte cache." not in stripped

    def test_unclosed_html_growth_completes_under_safety_timeout(self):
        code = (
            "import json\n"
            "from time import perf_counter\n"
            "from phases_agents import validator\n"
            "times = []\n"
            "corpora = (('<a', True), ('<div', False), "
            "(\"<a href='\", True), "
            "('<script src=\"a<b\"', False), "
            "('<div title=\"a<b\"', False), "
            "('x<y ', True), ('List<String> ', True), "
            "('3<x<7 ', True))\n"
            "for prefix, visible in corpora:\n"
            "    for chars in (16000, 64000, 256000, 1000000, 2000000):\n"
            "        repeats = (chars + len(prefix) - 1) // len(prefix)\n"
            "        text = (prefix * repeats)[:chars]\n"
            "        started = perf_counter()\n"
            "        cleaned = validator._strip_markdown_code(text)\n"
            "        elapsed = perf_counter() - started\n"
            "        assert len(cleaned) == len(text)\n"
            "        if visible:\n"
            "            assert cleaned == text\n"
            "        else:\n"
            "            assert cleaned.startswith(prefix)\n"
            "            assert len(cleaned.rstrip()) <= len(prefix) * 2\n"
            "        times.append((prefix, chars, elapsed))\n"
            "print(json.dumps(times))\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", code],
            capture_output=True,
            text=True,
            cwd=ROOT,
            env=_source_env(),
            timeout=30,
        )
        assert result.returncode == 0, result.stderr
        times = json.loads(result.stdout)
        assert len(times) == 40
        assert all(
            isinstance(row[2], float) and row[2] >= 0 for row in times)
        for offset in range(0, 40, 5):
            rows = times[offset:offset + 5]
            for previous, current in zip(rows, rows[1:]):
                size_ratio = current[1] / previous[1]
                assert current[2] <= (
                    previous[2] * (size_ratio * 1.75) + 0.05)

    def test_mutation_quote_abort_exposes_hidden_heading(self, monkeypatch):
        original = validator._scan_html_tag

        def vulnerable(content, start):
            nested = content.find("<", start + 1)
            closing = content.find(">", start + 1)
            if nested >= 0 and (closing < 0 or nested < closing):
                return None
            return original(content, start)

        monkeypatch.setattr(validator, "_scan_html_tag", vulnerable)
        cleaned = validator._strip_markdown_code(
            '<script src="a<b">## Loi centrale</script>')
        assert "## Loi centrale" in cleaned
        with pytest.raises(AssertionError):
            assert cleaned.strip() == ""

    def test_mutation_arms_every_incomplete_candidate(self, monkeypatch):
        monkeypatch.setattr(
            validator,
            "_should_arm_ambiguous_html",
            lambda *args, **kwargs: True,
        )
        text = (
            "Si x<y alors on applique la regle.\n\n"
            "## Section suivante\n"
            "Contenu visible.\n"
        )
        cleaned = validator._strip_markdown_code(text)
        assert "## Section suivante" not in cleaned
        with pytest.raises(AssertionError):
            assert "## Section suivante" in cleaned

    def test_html_scan_access_budget_and_unbounded_mutation(self):
        class CountedText:
            def __init__(self, text):
                self.text = text
                self.reads = 0

            def __len__(self):
                return len(self.text)

            def __getitem__(self, key):
                self.reads += 1
                return self.text[key]

        def access_count(scan, prefix, chars):
            repeats = (chars + len(prefix) - 1) // len(prefix)
            wrapped = CountedText((prefix * repeats)[:chars])
            index = 0
            while index < len(wrapped):
                if wrapped[index] == "<":
                    result = scan(wrapped, index)
                    if result is not None:
                        next_index = result[3]
                        index = max(index + 1, next_index)
                        continue
                index += 1
            return wrapped.reads

        prefixes = (
            "<a",
            "<div",
            "<a href='",
            '<script src="a<b"',
            '<div title="a<b"',
            "x<y ",
            "List<String> ",
            "3<x<7 ",
        )
        for prefix in prefixes:
            for chars in (128, 512, 2_048, 8_192):
                assert access_count(
                    validator._scan_html_tag, prefix, chars) <= chars * 5 + 32

        def vulnerable(content, start):
            length = len(content)
            index = start + 1
            closing = False
            if index < length and content[index] == "/":
                closing = True
                index += 1
            if index >= length or not content[index].isalpha():
                return None
            name_start = index
            index += 1
            while index < length and (
                    content[index].isalnum() or content[index] == "-"):
                index += 1
            tag = content[name_start:index].lower()
            while index < length:
                if content[index] == ">":
                    return tag, closing, False, index + 1, True
                index += 1
            return None

        with pytest.raises(AssertionError):
            assert access_count(vulnerable, "<a", 512) <= 512 * 5 + 32


class TestSec006SecretRedaction:
    @pytest.mark.parametrize("secret_factory", [
        _aws_synthetic,
        _stripe_synthetic,
        _bearer_synthetic,
    ])
    def test_issue_output_never_repeats_detected_secret(self, secret_factory):
        secret = secret_factory()
        finding = _valid_finding(status=secret)
        output = "\n".join(repr(issue) for issue in _validate(finding))
        assert "SECRET_UNMASKED" in output
        assert secret not in output

    def test_cli_never_repeats_detected_secret(self, tmp_path):
        secret = _stripe_synthetic()
        report = {
            "skill_id": "audit-security",
            "version": "0.1.0",
            "findings": [_valid_finding(status=secret)],
        }
        target = tmp_path / "report.json"
        target.write_text(json.dumps(report), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "phases_agents.validator",
                str(target),
                "--today",
                "2026-07-29",
            ],
            capture_output=True,
            text=True,
            cwd=ROOT,
            env=_source_env(),
        )
        assert result.returncode == 1
        assert "SECRET_UNMASKED" in result.stdout
        assert secret not in result.stdout + result.stderr

    def test_server_unknown_method_never_echoes_secret(self):
        secret = _bearer_synthetic()
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": secret,
        }
        result = _run_server((json.dumps(request) + "\n").encode())
        output = (result.stdout + result.stderr).decode(
            "utf-8",
            errors="replace",
        )
        assert result.returncode == 0
        assert secret not in output
        assert "Method not found" in output

    def test_detector_masks_secret_in_target(self):
        secret = _aws_synthetic()
        profile = detector.detect_profile(
            str(ROOT / ("missing-" + secret)))
        assert secret not in json.dumps(profile)

    def test_secret_in_url_is_rejected_and_redacted(self):
        secret = _stripe_synthetic()
        finding = _valid_finding(
            references=["https://example.invalid/?token=" + secret])
        issues = _validate(finding)
        rendered = "\n".join(repr(issue) for issue in issues)
        assert "SECRET_UNMASKED" in rendered
        assert secret not in rendered

    def test_secret_in_loader_path_is_not_exposed(self, tmp_path):
        secret = _stripe_synthetic()
        issues = []
        validator._read_bytes(
            str(tmp_path / secret),
            issues,
            "rapport",
            100,
        )
        rendered = "\n".join(repr(issue) for issue in issues)
        assert secret not in rendered


class TestSec007TrustedSchemasAndRegistries:
    def test_public_api_rejects_fabricated_registry(self):
        issues = validator.validate_finding(
            _valid_finding(rule_id="FAKE-CURRENT"),
            today=TODAY,
            known_rules={"FAKE-CURRENT": "en_vigueur"},
        )
        assert _codes(issues) == {"RULES_REGISTRY"}

    def test_cli_rejects_substituted_registry(self, tmp_path):
        registry = tmp_path / "registry"
        registry.mkdir()
        (registry / "rules.json").write_text(json.dumps({
            "schema_id": "RULES_REGISTRY",
            "version": "0.1.0",
            "description": "fixture",
            "rules": [{
                "rule_id": "FAKE-CURRENT",
                "status": "en_vigueur",
            }],
        }), encoding="utf-8")
        (registry / "profile-facts.json").write_text(json.dumps({
            "schema_id": "PROFILE_FACTS",
            "version": "0.1.0",
            "description": "fixture",
            "facts": [],
        }), encoding="utf-8")
        report = tmp_path / "report.json"
        report.write_text(json.dumps({
            "skill_id": "audit-security",
            "version": "0.1.0",
            "findings": [_valid_finding(rule_id="FAKE-CURRENT")],
        }), encoding="utf-8")
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "phases_agents.validator",
                str(report),
                "--today",
                "2026-07-29",
                "--registry",
                str(registry),
            ],
            capture_output=True,
            text=True,
            cwd=ROOT,
            env=_source_env(),
        )
        assert result.returncode == 1
        assert "RULES_REGISTRY" in result.stdout
        assert "UNKNOWN_RULE" not in result.stdout

    def test_public_api_rejects_permissive_schema(self):
        issues = validator.validate_finding(
            _valid_finding(),
            finding_schema={"type": "object"},
            today=TODAY,
            known_rules=TRUSTED_RULES,
        )
        assert {"SCHEMA_ID", "SCHEMA_VERSION"} <= _codes(issues)

    def test_skill_rejects_alternate_core_before_reading(
            self, tmp_path, monkeypatch):
        alternate = tmp_path / "untrusted-core"
        alternate.mkdir()

        def forbidden_read(*args, **kwargs):
            raise AssertionError("untrusted core must not be read")

        monkeypatch.setattr(validator, "_load_schema", forbidden_read)
        issues = validator.validate_skill(
            str(tmp_path),
            core_dir=str(alternate),
            today=TODAY,
        )
        assert _codes(issues) == {"SCHEMA_INTEGRITY"}

    @pytest.mark.parametrize(("content", "expected"), [
        ('{"x":NaN}', "JSON"),
        ('{"x":1,"x":2}', "DUPLICATE_KEY"),
    ])
    def test_json_loader_rejects_nonstandard_inputs(
            self, tmp_path, content, expected):
        target = tmp_path / "hostile.json"
        target.write_text(content, encoding="utf-8")
        issues = []
        assert validator._load_json(
            str(target), issues, "hostile.json") is None
        assert expected in _codes(issues)

    def test_json_loader_rejects_invalid_utf8(self, tmp_path):
        target = tmp_path / "hostile.json"
        target.write_bytes(b'{"x":"\xff"}')
        issues = []
        assert validator._load_json(
            str(target), issues, "hostile.json") is None
        assert _codes(issues) == {"ENCODING"}


class TestSec009McpServer:
    @pytest.mark.parametrize("payload", [
        b"\xff\n",
        b'{"jsonrpc":"2.0","id":NaN,"method":"ping"}\n',
        b'{"jsonrpc":"2.0","id":1,"method":"bad","method":"ping"}\n',
        b'{"jsonrpc":"2.0","id":1,"method":"ping","\\ud800":"x"}\n',
        ("[" * 5_000 + "0" + "]" * 5_000 + "\n").encode(),
    ])
    def test_transport_hostile_json_has_no_traceback(self, payload):
        result = _run_server(payload)
        assert result.returncode == 0
        assert b"Traceback" not in result.stderr
        response = json.loads(result.stdout)
        assert response["error"]["code"] in {-32700, -32600}

    def test_oversized_request_is_bounded(self):
        payload = (
            b'{"jsonrpc":"2.0","id":1,"method":"'
            + b"A" * (server._MAX_REQUEST_BYTES + 1)
            + b'"}\n'
        )
        result = _run_server(payload)
        assert result.returncode == 0
        assert len(result.stdout) < 512
        response = json.loads(result.stdout)
        assert response["error"]["code"] == -32600

    def test_extra_tool_argument_is_rejected(self):
        response = server.handle_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "phases_agents_plan",
                "arguments": {
                    "target": str(ROOT),
                    "extra": "ignored-before-security-audit",
                },
            },
        })
        assert response["error"] == {
            "code": -32602,
            "message": "Invalid params: unknown argument",
        }

    def test_secret_request_id_is_not_echoed(self):
        secret = _stripe_synthetic()
        response = server.handle_message({
            "jsonrpc": "2.0",
            "id": secret,
            "method": "ping",
        })
        rendered = json.dumps(response)
        assert secret not in rendered
        assert response["id"] is None

    def test_secret_target_is_rejected_without_echo(self):
        secret = _aws_synthetic()
        response = server.handle_message({
            "jsonrpc": "2.0",
            "id": 1,
            "method": "tools/call",
            "params": {
                "name": "phases_agents_plan",
                "arguments": {
                    "target": str(ROOT / secret),
                },
            },
        })
        rendered = json.dumps(response)
        assert response["error"]["code"] == -32602
        assert secret not in rendered

    def test_direct_cycle_is_rejected(self):
        request = {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "ping",
        }
        request["cycle"] = request
        response = server.handle_message(request)
        assert response["error"]["code"] == -32600

    def test_huge_direct_integer_is_rejected(self):
        response = server.handle_message({
            "jsonrpc": "2.0",
            "id": 10 ** 5_000,
            "method": "ping",
        })
        assert response["id"] is None
        assert response["error"]["code"] == -32600

    def test_response_bytes_are_deterministic(self):
        request = (
            json.dumps({
                "jsonrpc": "2.0",
                "id": 7,
                "method": "ping",
            }, sort_keys=True)
            + "\n"
        ).encode()
        first = _run_server(request)
        second = _run_server(request)
        assert first.returncode == second.returncode == 0
        assert first.stdout == second.stdout
        assert first.stderr == second.stderr == b""
        assert hashlib.sha256(first.stdout).digest() == hashlib.sha256(
            second.stdout).digest()


class TestSec010Detector:
    def test_profile_order_is_independent_from_creation_order(self, tmp_path):
        roots = [tmp_path / "one", tmp_path / "two"]
        orders = [("b.py", "a.py"), ("a.py", "b.py")]
        profiles = []
        for root, order in zip(roots, orders):
            root.mkdir()
            for name in order:
                (root / name).write_text("", encoding="utf-8")
            profiles.append(detector.detect_profile(str(root)))
        for key in ("types", "languages", "markers", "blocked", "issues"):
            assert profiles[0][key] == profiles[1][key]


class TestSec012RuntimeEnvironment:
    def test_runtime_imports_are_stdlib_or_local(self):
        local_modules = {
            "capabilities", "detector", "planner", "registry", "skill_loader",
            "profile_facts", "skill_gaps", "skill_runtime", "skill_types",
            "validator",
        }
        for name in (
                "validator.py", "server.py", "detector.py",
                "skill_loader.py", "skill_runtime.py",
                "registry.py", "planner.py"):
            tree = ast.parse((PKG / name).read_text(encoding="utf-8"))
            imported = set()
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    imported.update(alias.name.split(".", 1)[0]
                                    for alias in node.names)
                elif isinstance(node, ast.ImportFrom) and node.module:
                    imported.add(node.module.split(".", 1)[0])
            unexpected = imported - set(sys.stdlib_module_names) - local_modules
            assert unexpected == set()

    def test_runtime_has_no_process_or_network_import(self):
        forbidden = {
            "subprocess", "socket", "requests", "urllib",
            "http", "ftplib", "telnetlib",
        }
        for name in (
                "validator.py", "server.py", "detector.py",
                "skill_loader.py", "registry.py", "planner.py"):
            tree = ast.parse((PKG / name).read_text(encoding="utf-8"))
            imported = {
                node.names[0].name.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.Import)
            }
            imported |= {
                node.module.split(".", 1)[0]
                for node in ast.walk(tree)
                if isinstance(node, ast.ImportFrom) and node.module
            }
            assert imported.isdisjoint(forbidden)

    def test_pyproject_runtime_dependencies_are_empty(self):
        import tomllib

        data = tomllib.loads(
            (ROOT / "pyproject.toml").read_text(encoding="utf-8"))
        assert data["project"]["dependencies"] == []

    def test_validator_never_uses_implicit_clock(self):
        tree = ast.parse(
            (PKG / "validator.py").read_text(encoding="utf-8"))
        implicit_calls = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            function = node.func
            if (isinstance(function, ast.Attribute)
                    and function.attr == "today"):
                implicit_calls.append(node.lineno)
        assert implicit_calls == []
