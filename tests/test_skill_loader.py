"""Contrat et types internes B1, puis tests du loader."""

from __future__ import annotations

import datetime
import dataclasses
import json
import os
import subprocess

import pytest

import skill_loader
from skill_loader import discover_skills
from skill_types import (
    DEFAULT_SKILL_LIMITS,
    SkillLimits,
    SkillState,
    ValidatedSkill,
    _discovery_skills,
    _is_validated_skill,
    _make_validated_skill,
    canonical_skill_id,
    limits_error,
)
from tests.b1_helpers import write_skill
from validator import (
    Issue,
    SkillPackageValidation,
    _is_trusted_skill_package_validation,
    validate_skill_package,
)


TODAY = datetime.date(2026, 7, 27)


class TestB1001ContractAndTypes:
    @pytest.mark.parametrize(
        ("value", "expected"),
        [
            ("audit-security", "audit-security"),
            ("Audit_Security", "audit_security"),
            ("sécurité", "sécurité"),
            ("", None),
            ("   ", None),
            ("../skill", None),
            ("skill/name", None),
            ("skill\\name", None),
            ("CON", None),
            ("skill.", None),
            ("skill\u200b", None),
            ("se\u0301curite\u0301", None),
        ],
    )
    def test_identity_is_portable(self, value, expected):
        assert canonical_skill_id(value) == expected

    def test_limits_are_frozen(self):
        with pytest.raises((AttributeError, TypeError)):
            DEFAULT_SKILL_LIMITS.max_roots = 99

    @pytest.mark.parametrize(
        "limits",
        [
            None,
            {},
            SkillLimits(max_roots=0),
            SkillLimits(max_packages=1_001),
            SkillLimits(max_depth=2),
            SkillLimits(max_result_bytes=True),
        ],
    )
    def test_limits_cannot_increase_or_malform(self, limits):
        assert limits_error(limits) == "SKILL_LIMITS"

    def test_validator_returns_exact_validated_snapshot(self, tmp_path):
        package = write_skill(tmp_path, "audit-security")
        original = (package / "SKILL.md").read_text(encoding="utf-8")

        result = validate_skill_package(package, today=TODAY)

        assert type(result) is SkillPackageValidation
        assert result.valid is True
        assert result.issues == ()
        assert json.loads(result.manifest_json)["id"] == "audit-security"
        assert result.skill_md == original
        assert _is_trusted_skill_package_validation(result)
        with pytest.raises(AttributeError):
            result._skill_md = "remplace"

        (package / "SKILL.md").write_text("remplace", encoding="utf-8")
        assert result.skill_md == original

    def test_invalid_snapshot_never_exposes_content(self, tmp_path):
        package = write_skill(tmp_path, "audit-security")
        (package / "SKILL.md").write_text("invalide", encoding="utf-8")

        result = validate_skill_package(package, today=TODAY)

        assert result.valid is False
        assert result.manifest_json is None
        assert result.skill_md is None
        assert {issue.code for issue in result.issues} >= {"FRONTMATTER"}

    def test_manual_validation_object_cannot_issue_snapshot(self):
        fake = SkillPackageValidation(
            [],
            json.dumps({
                "id": "fake",
                "version": "0.1.0",
                "title": "Fake",
                "description": "Fake local.",
                "domain": "security",
                "project_types": ["python"],
                "platforms": ["generic"],
                "activation": {"any": ["has_source_code"]},
                "exclusions": [],
                "requires_capabilities": ["filesystem_read"],
                "optional_capabilities": [],
                "forbidden_capabilities": ["web"],
            }),
            "contenu arbitraire",
        )
        assert _is_trusted_skill_package_validation(fake) is False
        snapshot, codes = _make_validated_skill(
            fake,
            "root[0]/fake",
            "fake",
        )
        assert snapshot is None
        assert codes == ("SKILL_SNAPSHOT",)


class TestB1002SkillLoader:
    def test_valid_skill_is_discovered_and_sealed(self, tmp_path):
        package = write_skill(tmp_path, "audit-security")

        report = discover_skills([tmp_path], TODAY)
        snapshots = _discovery_skills(report)

        assert report.complete is True
        assert report.fatal_codes == ()
        assert len(report.records) == len(snapshots) == 1
        assert report.records[0].state is SkillState.VALID
        assert report.records[0].relative_path == "root[0]/audit-security"
        assert _is_validated_skill(snapshots[0])
        assert snapshots[0].content == (
            package / "SKILL.md").read_text(encoding="utf-8")
        assert not hasattr(report, "skills")

    def test_public_result_has_no_absolute_path_or_content(self, tmp_path):
        package = write_skill(tmp_path, "audit-security")

        rendered = json.dumps(
            discover_skills([tmp_path], TODAY).to_public(),
            sort_keys=True,
        )

        assert str(tmp_path) not in rendered
        assert str(package) not in rendered
        assert "Loi centrale" not in rendered

    def test_empty_root_is_complete(self, tmp_path):
        report = discover_skills([tmp_path], TODAY)
        assert report.complete is True
        assert report.records == ()
        assert _discovery_skills(report) == ()

    def test_empty_root_list_is_fail_closed(self):
        report = discover_skills([], TODAY)
        assert report.complete is False
        assert report.fatal_codes == ("SKILL_ROOT",)
        assert report.records == ()

    @pytest.mark.parametrize(
        "roots",
        [None, True, 1, 1.5, "C:\\skills", {}, {1}, b"x"],
    )
    def test_bad_roots_type_is_fail_closed(self, roots):
        report = discover_skills(roots, TODAY)
        assert report.complete is False
        assert report.fatal_codes == ("SKILL_ROOT",)
        assert _discovery_skills(report) == ()

    def test_relative_root_is_rejected(self):
        report = discover_skills(["relative"], TODAY)
        assert report.fatal_codes == ("SKILL_ROOT",)

    def test_absent_root_is_rejected(self, tmp_path):
        report = discover_skills([tmp_path / "absent"], TODAY)
        assert report.fatal_codes == ("SKILL_ROOT",)

    def test_file_root_is_rejected(self, tmp_path):
        root = tmp_path / "file"
        root.write_text("x", encoding="utf-8")
        report = discover_skills([root], TODAY)
        assert report.fatal_codes == ("SKILL_ROOT",)

    def test_duplicate_root_is_rejected(self, tmp_path):
        report = discover_skills([tmp_path, tmp_path], TODAY)
        assert report.fatal_codes == ("SKILL_ROOT_DUPLICATE",)

    def test_multiple_valid_roots_are_stably_discovered(self, tmp_path):
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir()
        second.mkdir()
        write_skill(first, "zeta")
        write_skill(second, "alpha")
        report = discover_skills([first, second], TODAY)
        assert report.complete is True
        assert [record.skill_id for record in report.records] == [
            "zeta",
            "alpha",
        ]

    def test_root_limit_is_enforced(self, tmp_path):
        roots = []
        for index in range(17):
            root = tmp_path / str(index)
            root.mkdir()
            roots.append(root)
        report = discover_skills(roots, TODAY)
        assert report.fatal_codes == ("SKILL_ROOT_LIMIT",)

    @pytest.mark.parametrize(
        ("today", "code"),
        [
            (None, "TODAY_REQUIRED"),
            ("", "TODAY_INVALID"),
            ("bad", "TODAY_INVALID"),
            (123, "TODAY_INVALID"),
            (datetime.datetime(2026, 7, 27), "TODAY_INVALID"),
        ],
    )
    def test_today_is_explicit(self, tmp_path, today, code):
        report = discover_skills([tmp_path], today)
        assert report.fatal_codes == (code,)

    def test_missing_skill_md_is_invalid(self, tmp_path):
        package = write_skill(tmp_path, "audit-security")
        (package / "SKILL.md").unlink()
        report = discover_skills([tmp_path], TODAY)
        assert report.records[0].state is SkillState.INVALID
        assert report.records[0].error_codes == ("SKILL_MISSING",)
        assert _discovery_skills(report) == ()

    def test_missing_manifest_is_invalid(self, tmp_path):
        package = write_skill(tmp_path, "audit-security")
        (package / "phases.json").unlink()
        report = discover_skills([tmp_path], TODAY)
        assert report.records[0].state is SkillState.INVALID
        assert report.records[0].error_codes == ("MANIFEST_MISSING",)
        assert _discovery_skills(report) == ()

    def test_invalid_utf8_is_invalid(self, tmp_path):
        package = write_skill(tmp_path, "audit-security")
        (package / "SKILL.md").write_bytes(b"\xff")
        report = discover_skills([tmp_path], TODAY)
        assert report.records[0].state is SkillState.INVALID
        assert "ENCODING" in report.records[0].error_codes

    def test_configured_content_limit_is_enforced(self, tmp_path):
        write_skill(tmp_path, "audit-security")
        report = discover_skills(
            [tmp_path],
            TODAY,
            SkillLimits(max_skill_md_bytes=10),
        )
        assert report.records[0].state is SkillState.TOO_LARGE
        assert report.records[0].error_codes == ("TOO_LARGE",)

    def test_result_limit_is_enforced(self, tmp_path):
        write_skill(tmp_path, "audit-security")
        report = discover_skills(
            [tmp_path],
            TODAY,
            SkillLimits(max_result_bytes=1),
        )
        assert report.fatal_codes == ("SKILL_RESULT_LIMIT",)
        assert report.records == ()
        assert _discovery_skills(report) == ()

    def test_snapshot_memory_limit_is_enforced(self, tmp_path):
        write_skill(tmp_path, "audit-security")
        report = discover_skills(
            [tmp_path],
            TODAY,
            SkillLimits(max_snapshot_bytes=1),
        )
        assert report.fatal_codes == ("SKILL_SNAPSHOT_LIMIT",)
        assert _discovery_skills(report) == ()

    def test_snapshot_limit_serializes_every_stored_field(self, tmp_path):
        package = write_skill(tmp_path, "audit-security")
        manifest_path = package / "phases.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["optional_capabilities"] = [
            "browser",
            "dependency_installation",
            "filesystem_search",
            "filesystem_write",
            "human_question",
            "shell",
        ]
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        baseline = discover_skills([tmp_path], TODAY)
        snapshot = _discovery_skills(baseline)[0]
        payload = {
            descriptor.name: getattr(snapshot, descriptor.name)
            for descriptor in dataclasses.fields(ValidatedSkill)
        }
        exact_size = len(json.dumps(
            [payload],
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8"))
        old_partial_size = (
            len(snapshot.content.encode("utf-8"))
            + len(json.dumps(
                snapshot.summary(),
                ensure_ascii=True,
                allow_nan=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8"))
        )
        assert set(payload) == set(ValidatedSkill.__dataclass_fields__)
        assert old_partial_size < exact_size - 1

        accepted = discover_skills(
            [tmp_path],
            TODAY,
            SkillLimits(max_snapshot_bytes=exact_size),
        )
        rejected = discover_skills(
            [tmp_path],
            TODAY,
            SkillLimits(max_snapshot_bytes=exact_size - 1),
        )

        assert accepted.complete is True
        assert len(_discovery_skills(accepted)) == 1
        assert rejected.fatal_codes == ("SKILL_SNAPSHOT_LIMIT",)
        assert _discovery_skills(rejected) == ()

    def test_root_entry_limit_is_fail_closed(self, tmp_path):
        (tmp_path / "one").mkdir()
        (tmp_path / "two").mkdir()
        report = discover_skills(
            [tmp_path],
            TODAY,
            SkillLimits(max_entries_per_root=1),
        )
        assert report.fatal_codes == ("SKILL_ROOT_LIMIT",)
        assert report.records == ()

    def test_listing_error_is_fail_closed(self, tmp_path, monkeypatch):
        def denied(_path):
            raise PermissionError("denied")

        monkeypatch.setattr(skill_loader.os, "scandir", denied)
        report = discover_skills([tmp_path], TODAY)
        assert report.fatal_codes == ("SKILL_DISCOVERY",)
        assert _discovery_skills(report) == ()

    def test_unreadable_package_is_reported(self, tmp_path, monkeypatch):
        write_skill(tmp_path, "audit-security")
        unreadable = SkillPackageValidation(
            [Issue("error", "READ", "lecture impossible", "SKILL.md")],
            None,
            None,
        )
        monkeypatch.setattr(
            skill_loader,
            "validate_skill_package",
            lambda *_args, **_kwargs: unreadable,
        )
        report = discover_skills([tmp_path], TODAY)
        assert report.records[0].state is SkillState.UNREADABLE
        assert report.records[0].error_codes == ("READ",)
        assert _discovery_skills(report) == ()

    def test_reparse_package_is_blocked(self, tmp_path, monkeypatch):
        package = write_skill(tmp_path, "audit-security")
        original = skill_loader._path_has_reparse_component

        monkeypatch.setattr(
            skill_loader,
            "_path_has_reparse_component",
            lambda path: str(path) == str(package) or original(path),
        )
        report = discover_skills([tmp_path], TODAY)
        assert report.records[0].state is SkillState.BLOCKED
        assert report.records[0].error_codes == ("PATH_UNSAFE",)
        assert _discovery_skills(report) == ()

    def test_real_directory_link_root_is_blocked(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        linked = tmp_path / "linked"
        if os.name == "nt":
            result = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(linked), str(target)],
                capture_output=True,
                text=True,
            )
            assert result.returncode == 0, result.stderr
        else:
            os.symlink(target, linked, target_is_directory=True)
        try:
            report = discover_skills([linked], TODAY)
            assert report.fatal_codes == ("SKILL_ROOT",)
            assert _discovery_skills(report) == ()
        finally:
            if os.path.lexists(linked):
                if os.name == "nt":
                    os.rmdir(linked)
                else:
                    linked.unlink()

    def test_hardlinked_skill_md_is_blocked(self, tmp_path):
        package = write_skill(tmp_path, "audit-security")
        external = tmp_path / "external.md"
        external.write_text(
            (package / "SKILL.md").read_text(encoding="utf-8"),
            encoding="utf-8",
        )
        (package / "SKILL.md").unlink()
        os.link(external, package / "SKILL.md")

        report = discover_skills([tmp_path], TODAY)

        assert report.records[0].state is SkillState.BLOCKED
        assert "PATH_UNSAFE" in report.records[0].error_codes

    def test_nested_package_is_not_discovered(self, tmp_path):
        outer = tmp_path / "outer"
        outer.mkdir()
        write_skill(outer, "nested")

        report = discover_skills([tmp_path], TODAY)

        assert len(report.records) == 1
        assert report.records[0].relative_path == "root[0]/outer"
        assert report.records[0].state is SkillState.INVALID
        assert _discovery_skills(report) == ()

    def test_package_limit_is_fail_closed(self, tmp_path):
        write_skill(tmp_path, "a")
        write_skill(tmp_path, "b")
        report = discover_skills(
            [tmp_path],
            TODAY,
            SkillLimits(max_packages=1),
        )
        assert report.fatal_codes == ("SKILL_PACKAGE_LIMIT",)
        assert _discovery_skills(report) == ()

    def test_hostile_regular_file_is_ignored_not_counted(self, tmp_path):
        (tmp_path / "bad name.txt").write_text("not a package", encoding="utf-8")
        write_skill(tmp_path, "valid")

        report = discover_skills(
            [tmp_path],
            TODAY,
            SkillLimits(max_packages=1),
        )

        assert report.complete is True
        assert [record.relative_path for record in report.records] == [
            "root[0]/valid",
        ]
        assert [skill.skill_id for skill in _discovery_skills(report)] == [
            "valid",
        ]

    def test_hostile_directory_counts_toward_package_limit(self, tmp_path):
        (tmp_path / "bad name").mkdir()
        write_skill(tmp_path, "valid")

        report = discover_skills(
            [tmp_path],
            TODAY,
            SkillLimits(max_packages=1),
        )

        assert report.fatal_codes == ("SKILL_PACKAGE_LIMIT",)
        assert _discovery_skills(report) == ()

    def test_composed_unicode_identifier_is_supported(self, tmp_path):
        write_skill(tmp_path, "sécurité")
        report = discover_skills([tmp_path], TODAY)
        assert report.complete is True
        assert _discovery_skills(report)[0].canonical_id == "sécurité"

    def test_ambiguous_unicode_name_is_blocked(self, tmp_path):
        write_skill(tmp_path, "securite", directory_name="se\u0301curite\u0301")
        report = discover_skills([tmp_path], TODAY)
        assert report.records[0].state is SkillState.BLOCKED
        assert report.records[0].error_codes == ("PATH_UNSAFE",)

    def test_directory_and_manifest_identity_must_match(self, tmp_path):
        write_skill(tmp_path, "audit-security", directory_name="other")
        report = discover_skills([tmp_path], TODAY)
        assert report.records[0].state is SkillState.INVALID
        assert report.records[0].error_codes == ("SKILL_ID_MISMATCH",)

    def test_oversized_public_metadata_is_rejected(self, tmp_path):
        package = write_skill(tmp_path, "audit-security")
        manifest_path = package / "phases.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["title"] = "x" * 257
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False),
            encoding="utf-8",
        )
        report = discover_skills([tmp_path], TODAY)
        assert report.records[0].state is SkillState.INVALID
        assert report.records[0].error_codes == ("SKILL_METADATA",)

    def test_case_collision_is_explicit_and_global(self, tmp_path):
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir()
        second.mkdir()
        write_skill(first, "Audit")
        write_skill(second, "audit")

        report = discover_skills([first, second], TODAY)

        assert report.fatal_codes == ("SKILL_DUPLICATE",)
        assert _discovery_skills(report) == ()
        assert [record.state for record in report.records] == [
            SkillState.DUPLICATE,
            SkillState.DUPLICATE,
        ]

    def test_creation_order_does_not_change_result(self, tmp_path):
        roots = [tmp_path / "first", tmp_path / "second"]
        orders = [("b", "a"), ("a", "b")]
        outputs = []
        for root, order in zip(roots, orders):
            root.mkdir()
            for skill_id in order:
                write_skill(root, skill_id)
            outputs.append(discover_skills([root], TODAY).to_public())
        assert outputs[0] == outputs[1]

    def test_validation_is_called_once_per_package(
            self, tmp_path, monkeypatch):
        write_skill(tmp_path, "a")
        write_skill(tmp_path, "b")
        original = skill_loader.validate_skill_package
        calls = []

        def counted(*args, **kwargs):
            calls.append(str(args[0]))
            return original(*args, **kwargs)

        monkeypatch.setattr(skill_loader, "validate_skill_package", counted)
        report = discover_skills([tmp_path], TODAY)
        assert len(calls) == 2
        assert len(_discovery_skills(report)) == 2

    def test_invalid_skill_never_enters_snapshot_set(self, tmp_path):
        package = write_skill(tmp_path, "audit-security")
        (package / "SKILL.md").write_text("invalide", encoding="utf-8")
        report = discover_skills([tmp_path], TODAY)
        assert report.records[0].state is SkillState.INVALID
        assert _discovery_skills(report) == ()

    @pytest.mark.parametrize(
        "name",
        [
            "evil\\name",
            "file:stream",
            "folder.",
            "folder ",
            "CON",
            "NUL",
            "se\u0301curite\u0301",
            "skill\u200b",
        ],
    )
    def test_nonportable_public_directory_names_are_blocked(self, name):
        assert skill_loader._safe_public_name(name) == "<invalid>"

    def test_hostile_pathlike_and_list_subclass_never_raise(self, tmp_path):
        class ExplodingPath:
            def __fspath__(self):
                raise RuntimeError("boom")

        class ExplodingList(list):
            def __iter__(self):
                raise RuntimeError("boom")

        assert discover_skills([ExplodingPath()], TODAY).fatal_codes == (
            "SKILL_ROOT",
        )
        assert discover_skills(
            ExplodingList([tmp_path]), TODAY).fatal_codes == ("SKILL_ROOT",)

    def test_issue_list_is_bounded_exactly(self, tmp_path, monkeypatch):
        write_skill(tmp_path, "audit-security")
        issues = [
            Issue("error", f"E{index:03d}", "invalide", "SKILL.md")
            for index in range(10)
        ]
        monkeypatch.setattr(
            skill_loader,
            "validate_skill_package",
            lambda *_args, **_kwargs: SkillPackageValidation(
                issues, None, None),
        )
        report = discover_skills(
            [tmp_path],
            TODAY,
            SkillLimits(max_issues_per_skill=3),
        )
        assert report.records[0].error_codes == (
            "E000",
            "E001",
            "ISSUE_LIMIT",
        )

    @pytest.mark.parametrize(
        "roots",
        [
            [None],
            [True],
            [123],
            [[]],
            [{}],
            [b"bytes"],
        ],
    )
    def test_fixed_hostile_root_corpus_never_raises(self, roots):
        report = discover_skills(roots, TODAY)
        assert report.complete is False
        assert _discovery_skills(report) == ()
