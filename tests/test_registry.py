"""Registre B1 : confiance, collisions et immutabilite."""

from __future__ import annotations

import datetime
from dataclasses import replace

import pytest

from phases_agents import registry as registry_module
from phases_agents.registry import (
    SkillRegistry,
    build_registry,
    get_skill,
    list_skills,
)
from phases_agents.skill_loader import discover_skills
from phases_agents.skill_types import (
    DiscoveryReport,
    SkillLoadRecord,
    SkillState,
    ValidatedSkill,
    _discovery_skills,
    _new_discovery_report,
    _is_validated_skill,
)
from tests.b1_helpers import write_skill


TODAY = datetime.date(2026, 7, 27)


def _build(root, *skill_ids):
    for skill_id in skill_ids:
        write_skill(root, skill_id)
    discovery = discover_skills([root], TODAY)
    result = build_registry(discovery)
    assert result.ok, [issue.code for issue in result.issues]
    return result.registry, discovery


def _combined(*discoveries):
    return _new_discovery_report(
        tuple(record for item in discoveries for record in item.records),
        tuple(
            skill
            for item in discoveries
            for skill in _discovery_skills(item)
        ),
        (),
    )


class TestB1003Registry:
    def test_empty_registry_is_valid(self, tmp_path):
        result = build_registry(discover_skills([tmp_path], TODAY))
        assert result.ok is True
        assert len(result.registry) == 0
        assert list_skills(result.registry).skills == ()

    def test_one_valid_skill(self, tmp_path):
        registry, _ = _build(tmp_path, "audit-security")
        listed = list_skills(registry)
        assert listed.ok is True
        assert [item.skill_id for item in listed.skills] == [
            "audit-security",
        ]

    def test_multiple_skills_are_sorted(self, tmp_path):
        registry, _ = _build(tmp_path, "zeta", "alpha", "middle")
        assert [item.skill_id for item in list_skills(registry).skills] == [
            "alpha",
            "middle",
            "zeta",
        ]

    def test_creation_order_is_irrelevant(self, tmp_path):
        roots = [tmp_path / "first", tmp_path / "second"]
        orders = [("zeta", "alpha"), ("alpha", "zeta")]
        public = []
        for root, order in zip(roots, orders):
            root.mkdir()
            registry, _ = _build(root, *order)
            public.append(list_skills(registry).to_public())
        assert public[0] == public[1]

    def test_lookup_existing_is_case_insensitive(self, tmp_path):
        registry, _ = _build(tmp_path, "Audit-Security")
        result = get_skill(registry, "audit-security")
        assert result.ok is True
        assert result.skill.skill_id == "Audit-Security"

    @pytest.mark.parametrize(
        "skill_id",
        [None, True, 1, "", " ", "../skill", "C:\\skill", []],
    )
    def test_invalid_lookup_is_structured(self, tmp_path, skill_id):
        registry, _ = _build(tmp_path, "audit-security")
        result = get_skill(registry, skill_id)
        assert result.ok is False
        assert [issue.code for issue in result.issues] == ["SKILL_ID"]

    def test_unknown_lookup_is_structured(self, tmp_path):
        registry, _ = _build(tmp_path, "audit-security")
        result = get_skill(registry, "unknown")
        assert result.ok is False
        assert [issue.code for issue in result.issues] == [
            "SKILL_NOT_FOUND",
        ]

    def test_registry_rejects_incomplete_discovery(self, tmp_path):
        discovery = discover_skills([tmp_path / "absent"], TODAY)
        result = build_registry(discovery)
        assert result.registry is None
        assert [issue.code for issue in result.issues] == [
            "REGISTRY_INVALID",
        ]

    def test_invalid_skill_is_never_registered(self, tmp_path):
        package = write_skill(tmp_path, "audit-security")
        (package / "SKILL.md").write_text("invalide", encoding="utf-8")
        discovery = discover_skills([tmp_path], TODAY)
        result = build_registry(discovery)
        assert result.registry is None
        assert [issue.code for issue in result.issues] == [
            "SKILL_INVALID",
        ]
        assert discovery.records[0].state is SkillState.INVALID

    def test_exact_duplicate_blocks_everything(self, tmp_path):
        first = tmp_path / "first"
        first.mkdir()
        _, discovery = _build(first, "audit-security")
        snapshots = _discovery_skills(discovery)
        duplicated = _new_discovery_report(
            discovery.records,
            snapshots + snapshots,
            (),
        )
        result = build_registry(duplicated)
        assert result.registry is None
        assert [issue.code for issue in result.issues] == [
            "SKILL_DUPLICATE",
        ]

    def test_case_collision_blocks_in_both_orders(self, tmp_path):
        roots = [tmp_path / "first", tmp_path / "second"]
        roots[0].mkdir()
        roots[1].mkdir()
        _, upper = _build(roots[0], "Audit")
        _, lower = _build(roots[1], "audit")

        for discovery in (
                _combined(upper, lower),
                _combined(lower, upper)):
            result = build_registry(discovery)
            assert result.registry is None
            assert [issue.code for issue in result.issues] == [
                "SKILL_DUPLICATE",
            ]

    def test_unicode_case_collision_is_rejected(self, tmp_path):
        roots = [tmp_path / "first", tmp_path / "second"]
        roots[0].mkdir()
        roots[1].mkdir()
        _, upper = _build(roots[0], "SÉCURITÉ")
        _, lower = _build(roots[1], "sécurité")
        result = build_registry(_combined(upper, lower))
        assert result.registry is None
        assert [issue.code for issue in result.issues] == [
            "SKILL_DUPLICATE",
        ]

    def test_registry_object_is_immutable(self, tmp_path):
        registry, _ = _build(tmp_path, "audit-security")
        with pytest.raises(AttributeError):
            registry._skills = ()
        with pytest.raises(AttributeError):
            object.__setattr__(registry, "_skills", ())

    def test_returned_summary_cannot_mutate_registry(self, tmp_path):
        registry, _ = _build(tmp_path, "audit-security")
        first = list_skills(registry).to_public()
        first["skills"][0]["title"] = "change"
        second = list_skills(registry).to_public()
        assert second["skills"][0]["title"] != "change"

    def test_lookup_copy_cannot_mutate_registry_snapshot(self, tmp_path):
        registry, _ = _build(tmp_path, "audit-security")
        found = get_skill(registry, "audit-security")
        assert found.ok is True
        original = found.skill.content

        object.__setattr__(found.skill, "content", "MUTATED")

        again = get_skill(registry, "audit-security")
        assert again.ok is True
        assert again.skill is not found.skill
        assert again.skill.content == original
        assert _is_validated_skill(again.skill) is False

    def test_planner_copy_cannot_mutate_registry_snapshot(self, tmp_path):
        registry, _ = _build(tmp_path, "audit-security")
        first = registry_module._validated_registry_skills(registry)
        original = first[0].content

        object.__setattr__(first[0], "content", "MUTATED")

        second = registry_module._validated_registry_skills(registry)
        assert second[0] is not first[0]
        assert second[0].content == original

    def test_direct_registry_construction_is_rejected(self):
        with pytest.raises(TypeError):
            SkillRegistry((), object())

    def test_stolen_constructor_token_does_not_forge_registry(
            self, tmp_path):
        registry, discovery = _build(tmp_path, "audit-security")
        forged = SkillRegistry(
            _discovery_skills(discovery),
            registry_module._REGISTRY_CONSTRUCTOR_TOKEN,
        )
        assert len(forged) == 0
        assert list_skills(forged).issues[0].code == "REGISTRY_INVALID"

    def test_forged_skill_is_rejected(self):
        fake = ValidatedSkill(
            skill_id="fake",
            canonical_id="fake",
            package_ref="root[0]/fake",
            version="0.1.0",
            title="Fake",
            description="Fake",
            domain="security",
            project_types=("python",),
            platforms=("generic",),
            activation_any=("has_source_code",),
            exclusions=(),
            requires_capabilities=("filesystem_read",),
            optional_capabilities=(),
            forbidden_capabilities=(),
            provides_capabilities=(),
            content="fake",
        )
        discovery = _new_discovery_report(
            (
                SkillLoadRecord(
                    0,
                    "root[0]/fake",
                    SkillState.VALID,
                    skill_id="fake",
                ),
            ),
            (fake,),
            (),
        )
        result = build_registry(discovery)
        assert result.registry is None
        assert [issue.code for issue in result.issues] == [
            "REGISTRY_UNVALIDATED",
        ]

    def test_clone_of_genuine_snapshot_is_untrusted(self, tmp_path):
        _, genuine = _build(tmp_path, "audit-security")
        clone = replace(_discovery_skills(genuine)[0])
        forged = _new_discovery_report(
            genuine.records,
            (clone,),
            (),
        )
        result = build_registry(forged)
        assert result.registry is None
        assert result.issues[0].code == "REGISTRY_UNVALIDATED"

    def test_snapshot_requires_matching_valid_record(self, tmp_path):
        _, discovery = _build(tmp_path, "audit-security")
        altered = _new_discovery_report(
            (),
            _discovery_skills(discovery),
            (),
        )
        result = build_registry(altered)
        assert result.registry is None
        assert [issue.code for issue in result.issues] == [
            "REGISTRY_UNVALIDATED",
        ]

    def test_registry_limit_is_enforced_first(self, tmp_path):
        _, discovery = _build(tmp_path, "audit-security")
        huge = _new_discovery_report(
            discovery.records,
            _discovery_skills(discovery) * 1_001,
            (),
        )
        result = build_registry(huge)
        assert result.registry is None
        assert [issue.code for issue in result.issues] == [
            "REGISTRY_LIMIT",
        ]

    @pytest.mark.parametrize(
        "value",
        [None, True, 1, 1.5, "", [], (), {}, {1}, b"x"],
    )
    def test_bad_build_input_never_raises(self, value):
        result = build_registry(value)
        assert result.registry is None
        assert [issue.code for issue in result.issues] == [
            "REGISTRY_INVALID",
        ]

    def test_cyclic_build_input_never_raises(self):
        cycle = []
        cycle.append(cycle)
        result = build_registry(cycle)
        assert result.registry is None
        assert result.issues[0].code == "REGISTRY_INVALID"

    @pytest.mark.parametrize(
        "discovery",
        [
            DiscoveryReport((None,), ()),
            DiscoveryReport([], ()),
            DiscoveryReport((), []),
            DiscoveryReport((), (None,)),
        ],
    )
    def test_malformed_discovery_never_raises(self, discovery):
        result = build_registry(discovery)
        assert result.registry is None
        assert result.issues[0].code == "REGISTRY_INVALID"

    def test_sealed_malformed_record_never_raises(self):
        malformed = _new_discovery_report(
            (
                SkillLoadRecord(
                    0,
                    "root[0]/bad",
                    "VALID",
                    skill_id=[],
                ),
            ),
            (),
            (),
        )
        result = build_registry(malformed)
        assert result.registry is None
        assert result.issues[0].code == "REGISTRY_INVALID"

    @pytest.mark.parametrize("function", [list_skills, get_skill])
    def test_bad_registry_never_raises(self, function):
        if function is get_skill:
            result = function({}, "audit-security")
        else:
            result = function({})
        assert result.ok is False
        assert result.issues[0].code == "REGISTRY_INVALID"
