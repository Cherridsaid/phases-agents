"""Planner B1 : selection explicite et ordre stable."""

from __future__ import annotations

import datetime
import json
import os

import pytest

from detector import detect_profile
from planner import build_plan
from registry import build_registry
from skill_loader import discover_skills
from tests.b1_helpers import write_skill


TODAY = datetime.date(2026, 7, 27)


def _registry(root, specs):
    for spec in specs:
        write_skill(
            root,
            spec["id"],
            project_types=tuple(spec.get("types", ("python",))),
            platforms=tuple(spec.get("platforms", ("generic",))),
        )
        manifest_path = root / spec["id"] / "phases.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        if "domain" in spec:
            manifest["domain"] = spec["domain"]
        if "requires" in spec:
            manifest["requires_capabilities"] = list(spec["requires"])
        if "forbidden" in spec:
            manifest["forbidden_capabilities"] = list(spec["forbidden"])
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    result = build_registry(discover_skills([root], TODAY))
    assert result.ok, [issue.code for issue in result.issues]
    return result.registry


def _python_profile(target):
    target.mkdir()
    (target / "app.py").write_text("value = 1\n", encoding="utf-8")
    profile = detect_profile(str(target))
    assert profile["types"] == ["python"]
    return profile


class TestB1004Planner:
    def test_empty_profile_is_rejected(self, tmp_path):
        registry = _registry(tmp_path, [])
        result = build_plan({}, registry)
        assert result.plan is None
        assert [issue.code for issue in result.issues] == [
            "PROFILE_INVALID",
        ]

    def test_normal_profile_and_compatible_skill(self, tmp_path):
        roots = tmp_path / "skills"
        roots.mkdir()
        registry = _registry(roots, [{"id": "audit-python"}])
        profile = _python_profile(tmp_path / "project")

        result = build_plan(profile, registry)

        assert result.ok is True
        public = result.plan.to_public()
        assert public["selected_skills"] == [
            {
                "position": 1,
                "prerequisites": [],
                "reason_codes": [
                    "PROJECT_TYPE_MATCH",
                ],
                "skill_id": "audit-python",
            },
        ]
        assert public["steps"] == [
            {
                "action": "PROVIDE_SKILL",
                "position": 1,
                "skill_id": "audit-python",
            },
        ]
        assert public["project_profile"]["markers"] == {
            "python": ["app.py"],
        }

    def test_empty_registry_returns_explicit_empty_plan(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [])
        profile = _python_profile(tmp_path / "project")
        result = build_plan(profile, registry)
        assert result.ok is True
        assert result.plan.selected_skills == ()
        assert result.plan.steps == ()
        assert "NO_COMPATIBLE_SKILL" in result.plan.warnings

    def test_incompatible_skill_is_rejected(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(
            skills,
            [{"id": "audit-web", "types": ("web",)}],
        )
        profile = _python_profile(tmp_path / "project")
        plan = build_plan(profile, registry).plan
        assert plan.selected_skills == ()
        assert plan.rejected_skills[0].reason_codes == (
            "PROJECT_TYPE_MISMATCH",
        )

    def test_multiple_compatible_skills_are_id_sorted(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(
            skills,
            [{"id": "zeta"}, {"id": "alpha"}, {"id": "middle"}],
        )
        profile = _python_profile(tmp_path / "project")
        plan = build_plan(profile, registry).plan
        assert [item.skill_id for item in plan.selected_skills] == [
            "alpha",
            "middle",
            "zeta",
        ]
        assert [item.position for item in plan.selected_skills] == [1, 2, 3]
        assert [
            (step.position, step.action, step.skill_id)
            for step in plan.steps
        ] == [
            (1, "PROVIDE_SKILL", "alpha"),
            (2, "PROVIDE_SKILL", "middle"),
            (3, "PROVIDE_SKILL", "zeta"),
        ]

    def test_platform_constraint_is_exact(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(
            skills,
            [{"id": "windows-only", "platforms": ("windows",)}],
        )
        profile = _python_profile(tmp_path / "project")
        unfiltered_plan = build_plan(profile, registry).plan
        generic_plan = build_plan(
            profile,
            registry,
            {"platforms": ["generic"]},
        ).plan
        windows_plan = build_plan(
            profile,
            registry,
            {"platforms": ["windows"]},
        ).plan
        assert unfiltered_plan.selected_skills[0].skill_id == "windows-only"
        assert generic_plan.rejected_skills[0].reason_codes == (
            "PLATFORM_MISMATCH",
        )
        assert windows_plan.selected_skills[0].skill_id == "windows-only"

    def test_domain_filter_uses_declared_metadata(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(
            skills,
            [
                {"id": "security", "domain": "security"},
                {"id": "quality", "domain": "quality"},
            ],
        )
        profile = _python_profile(tmp_path / "project")
        plan = build_plan(
            profile,
            registry,
            {"domains": ["security"]},
        ).plan
        assert [item.skill_id for item in plan.selected_skills] == [
            "security",
        ]
        assert plan.rejected_skills[0].reason_codes == ("DOMAIN_MISMATCH",)

    def test_capabilities_are_filtered_only_when_explicit(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(
            skills,
            [{"id": "reader", "requires": ("filesystem_read",)}],
        )
        profile = _python_profile(tmp_path / "project")

        implicit = build_plan(profile, registry).plan
        missing = build_plan(
            profile,
            registry,
            {"capabilities": []},
        ).plan
        available = build_plan(
            profile,
            registry,
            {"capabilities": ["filesystem_read"]},
        ).plan

        assert implicit.selected_skills[0].skill_id == "reader"
        assert "CAPABILITIES_NOT_EVALUATED" in implicit.warnings
        assert missing.rejected_skills[0].reason_codes == (
            "CAPABILITY_MISSING",
        )
        assert available.selected_skills[0].skill_id == "reader"
        assert "CAPABILITIES_NOT_EVALUATED" not in available.warnings

    def test_capability_constraints_are_casefolded(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(
            skills,
            [{
                "id": "reader",
                "requires": ("filesystem_read",),
                "forbidden": ("web",),
            }],
        )
        profile = _python_profile(tmp_path / "project")

        accepted = build_plan(
            profile,
            registry,
            {"capabilities": ["FILESYSTEM_READ"]},
        )
        rejected = build_plan(
            profile,
            registry,
            {
                "capabilities": [
                    "FILESYSTEM_READ",
                    "WEB",
                ],
            },
        )

        assert accepted.ok is True
        assert accepted.plan.selected_skills[0].skill_id == "reader"
        assert rejected.ok is True
        assert rejected.plan.selected_skills == ()
        assert rejected.plan.rejected_skills[0].reason_codes == (
            "CAPABILITY_FORBIDDEN",
        )

    def test_explicit_forbidden_capability_rejects_skill(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(
            skills,
            [{
                "id": "reader",
                "requires": ("filesystem_read",),
                "forbidden": ("web",),
            }],
        )
        profile = _python_profile(tmp_path / "project")
        result = build_plan(
            profile,
            registry,
            {
                "capabilities": [
                    "filesystem_read",
                    "web",
                ],
            },
        )
        assert result.ok
        assert result.plan.selected_skills == ()
        assert result.plan.rejected_skills[0].reason_codes == (
            "CAPABILITY_FORBIDDEN",
        )

    def test_activation_and_dependencies_are_not_invented(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [{"id": "audit-python"}])
        profile = _python_profile(tmp_path / "project")
        warnings = build_plan(profile, registry).plan.warnings
        assert "ACTIVATION_FACTS_NOT_EVALUATED" in warnings
        assert "DEPENDENCIES_NOT_DECLARED" in warnings

    def test_profile_target_never_appears_in_plan(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [{"id": "audit-python"}])
        profile = _python_profile(tmp_path / "secret-project-path")
        rendered = json.dumps(
            build_plan(profile, registry).plan.to_public(),
            sort_keys=True,
        )
        assert profile["target"] not in rendered
        assert str(tmp_path) not in rendered

    def test_skill_content_never_appears_in_plan(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [{"id": "audit-python"}])
        profile = _python_profile(tmp_path / "project")
        rendered = json.dumps(
            build_plan(profile, registry).plan.to_public(),
            sort_keys=True,
        )
        assert "Loi centrale" not in rendered
        assert "Contenu local" not in rendered

    def test_skill_script_is_never_executed(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [{"id": "audit-python"}])
        sentinel = tmp_path / "executed"
        script = skills / "audit-python" / "scripts" / "helper.py"
        script.write_text(
            f"from pathlib import Path\nPath({str(sentinel)!r}).touch()\n",
            encoding="utf-8",
        )
        profile = _python_profile(tmp_path / "project")
        assert build_plan(profile, registry).ok is True
        assert sentinel.exists() is False

    def test_blocked_or_missing_profile_is_rejected(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [])
        for profile in (
            {
                "exists": False,
                "blocked": False,
                "issues": [],
                "types": ["inconnu"],
                "languages": [],
                "markers": {},
            },
            {
                "exists": True,
                "blocked": True,
                "issues": ["READ_ERROR"],
                "types": ["inconnu"],
                "languages": [],
                "markers": {},
            },
        ):
            result = build_plan(profile, registry)
            assert result.plan is None
            assert result.issues[0].code == "PROFILE_BLOCKED"

    def test_profile_with_unknown_property_is_rejected(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [])
        profile = {
            "exists": True,
            "blocked": False,
            "issues": [],
            "types": ["python"],
            "languages": ["python"],
            "markers": {},
            "unknown": True,
        }
        assert build_plan(profile, registry).issues[0].code == (
            "PROFILE_INVALID")

    @pytest.mark.parametrize(
        "profile",
        [
            None,
            True,
            1,
            1.5,
            "",
            [],
            (),
            b"x",
            {"exists": "yes"},
        ],
    )
    def test_bad_profile_types_never_raise(self, tmp_path, profile):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [])
        result = build_plan(profile, registry)
        assert result.plan is None
        assert result.issues[0].code == "PROFILE_INVALID"

    def test_cyclic_profile_never_raises(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [])
        cycle = {}
        cycle["cycle"] = cycle
        result = build_plan(cycle, registry)
        assert result.plan is None
        assert result.issues[0].code == "PROFILE_INVALID"

    def test_absolute_marker_is_rejected(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [])
        profile = {
            "exists": True,
            "blocked": False,
            "issues": [],
            "types": ["python"],
            "languages": ["python"],
            "markers": {"python": [str(tmp_path / "app.py")]},
        }
        assert build_plan(profile, registry).issues[0].code == (
            "PROFILE_INVALID")

    @pytest.mark.parametrize(
        "constraints",
        [
            True,
            1,
            [],
            {"unknown": []},
            {"platforms": "generic"},
            {"domains": [None]},
            {"capabilities": [True]},
            {"platforms": ["x"] * 101},
        ],
    )
    def test_bad_constraints_never_raise(self, tmp_path, constraints):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [])
        profile = _python_profile(tmp_path / "project")
        result = build_plan(profile, registry, constraints)
        assert result.plan is None
        assert result.issues[0].code == "PLAN_INVALID"

    def test_bad_registry_is_rejected(self, tmp_path):
        profile = _python_profile(tmp_path / "project")
        result = build_plan(profile, {})
        assert result.plan is None
        assert result.issues[0].code == "REGISTRY_INVALID"

    def test_mapping_and_list_subclasses_are_rejected(self, tmp_path):
        class HostileDict(dict):
            pass

        class HostileList(list):
            pass

        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [])
        profile = _python_profile(tmp_path / "project")
        assert build_plan(HostileDict(profile), registry).issues[0].code == (
            "PROFILE_INVALID")
        assert build_plan(
            profile,
            registry,
            {"platforms": HostileList(["generic"])},
        ).issues[0].code == "PLAN_INVALID"

    def test_property_order_does_not_change_plan(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [{"id": "audit-python"}])
        first = _python_profile(tmp_path / "project")
        second = {key: first[key] for key in reversed(tuple(first))}
        assert build_plan(first, registry).plan.to_public() == (
            build_plan(second, registry).plan.to_public())

    def test_normal_public_plan_stays_within_limit(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [{"id": "audit-python"}])
        profile = _python_profile(tmp_path / "project")

        result = build_plan(profile, registry)
        rendered = json.dumps(
            result.plan.to_public(),
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")

        assert result.ok is True
        assert len(rendered) <= 1 * 1024 * 1024

    def test_unicode_public_plan_over_one_mib_is_rejected(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [])
        profile = {
            "exists": True,
            "blocked": False,
            "issues": [],
            "types": ["python"],
            "languages": ["python"],
            "markers": {
                f"{'法' * 100}{index:04d}": [
                    f"{'界' * 100}{index:04d}",
                ]
                for index in range(1_000)
            },
        }
        assert len(json.dumps(
            profile,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")) > 1 * 1024 * 1024

        result = build_plan(profile, registry)

        assert result.plan is None
        assert [(issue.code, issue.path) for issue in result.issues] == [
            ("PLAN_LIMIT", "plan"),
        ]

    def test_current_directory_does_not_change_plan(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [{"id": "audit-python"}])
        profile = _python_profile(tmp_path / "project")
        first = build_plan(profile, registry).plan.to_public()
        previous = os.getcwd()
        elsewhere = tmp_path / "elsewhere"
        elsewhere.mkdir()
        try:
            os.chdir(elsewhere)
            second = build_plan(profile, registry).plan.to_public()
        finally:
            os.chdir(previous)
        assert first == second

    def test_plan_objects_are_immutable(self, tmp_path):
        skills = tmp_path / "skills"
        skills.mkdir()
        registry = _registry(skills, [{"id": "audit-python"}])
        profile = _python_profile(tmp_path / "project")
        plan = build_plan(profile, registry).plan
        with pytest.raises((AttributeError, TypeError)):
            plan.warnings = ()
