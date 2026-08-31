"""Registre immuable des snapshots de skills valides."""

from __future__ import annotations

import weakref
from bisect import bisect_left
from dataclasses import dataclass
from typing import Any, NamedTuple

from .skill_types import (
    DiscoveryReport,
    SkillLoadRecord,
    SkillState,
    ValidatedSkill,
    _discovery_skills,
    _is_validated_skill,
    canonical_skill_id,
)
from .validator import Issue


_MAX_REGISTRY_SKILLS = 1_000
_REGISTRY_CONSTRUCTOR_TOKEN = object()


class _StoredSkill(NamedTuple):
    """Etat prive profondement immuable d'un skill valide."""

    skill_id: str
    canonical_id: str
    package_ref: str
    version: str
    title: str
    description: str
    domain: str
    project_types: tuple[str, ...]
    platforms: tuple[str, ...]
    activation_any: tuple[str, ...]
    exclusions: tuple[str, ...]
    requires_capabilities: tuple[str, ...]
    optional_capabilities: tuple[str, ...]
    forbidden_capabilities: tuple[str, ...]
    provides_capabilities: tuple[str, ...]
    content: str


class _RegistryState(NamedTuple):
    skills: tuple[_StoredSkill, ...]
    keys: tuple[str, ...]


def _store_skill(skill: ValidatedSkill) -> _StoredSkill:
    return _StoredSkill(
        skill_id=skill.skill_id,
        canonical_id=skill.canonical_id,
        package_ref=skill.package_ref,
        version=skill.version,
        title=skill.title,
        description=skill.description,
        domain=skill.domain,
        project_types=skill.project_types,
        platforms=skill.platforms,
        activation_any=skill.activation_any,
        exclusions=skill.exclusions,
        requires_capabilities=skill.requires_capabilities,
        optional_capabilities=skill.optional_capabilities,
        forbidden_capabilities=skill.forbidden_capabilities,
        provides_capabilities=skill.provides_capabilities,
        content=skill.content,
    )


def _copy_skill(skill: _StoredSkill) -> ValidatedSkill:
    """Rend une copie de donnees; elle ne constitue pas un sceau de validation."""

    return ValidatedSkill(
        skill_id=skill.skill_id,
        canonical_id=skill.canonical_id,
        package_ref=skill.package_ref,
        version=skill.version,
        title=skill.title,
        description=skill.description,
        domain=skill.domain,
        project_types=skill.project_types,
        platforms=skill.platforms,
        activation_any=skill.activation_any,
        exclusions=skill.exclusions,
        requires_capabilities=skill.requires_capabilities,
        optional_capabilities=skill.optional_capabilities,
        forbidden_capabilities=skill.forbidden_capabilities,
        provides_capabilities=skill.provides_capabilities,
        content=skill.content,
    )


@dataclass(frozen=True, slots=True)
class SkillSummary:
    skill_id: str
    version: str
    title: str
    description: str
    domain: str
    project_types: tuple[str, ...]
    platforms: tuple[str, ...]

    @classmethod
    def from_skill(
            cls, skill: ValidatedSkill | _StoredSkill) -> "SkillSummary":
        return cls(
            skill_id=skill.skill_id,
            version=skill.version,
            title=skill.title,
            description=skill.description,
            domain=skill.domain,
            project_types=skill.project_types,
            platforms=skill.platforms,
        )

    def to_public(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "domain": self.domain,
            "platforms": list(self.platforms),
            "project_types": list(self.project_types),
            "skill_id": self.skill_id,
            "title": self.title,
            "version": self.version,
        }


class SkillRegistry:
    """Conteneur scelle, trie et sans mutateur public."""

    __slots__ = ("__weakref__",)

    def __init__(self, skills: tuple[ValidatedSkill, ...],
                 receipt: object) -> None:
        if receipt is not _REGISTRY_CONSTRUCTOR_TOKEN:
            raise TypeError("SkillRegistry doit etre construit par build_registry")
        if (type(skills) is not tuple
                or len(skills) > _MAX_REGISTRY_SKILLS
                or any(not _is_validated_skill(skill) for skill in skills)):
            raise TypeError("SkillRegistry exige des snapshots valides")
        keys = tuple(skill.canonical_id for skill in skills)
        if keys != tuple(sorted(keys)) or len(keys) != len(set(keys)):
            raise TypeError("SkillRegistry exige des identites uniques et triees")

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("SkillRegistry est immuable")

    def __len__(self) -> int:
        state = _registry_state(self)
        return 0 if state is None else len(state.skills)


def _registry_capability():
    issued: dict[
        int,
        tuple[weakref.ReferenceType[SkillRegistry], _RegistryState],
    ] = {}

    def create(skills: tuple[ValidatedSkill, ...]) -> SkillRegistry:
        registry = SkillRegistry(skills, _REGISTRY_CONSTRUCTOR_TOKEN)
        stored = tuple(_store_skill(skill) for skill in skills)
        state = _RegistryState(
            stored,
            tuple(skill.canonical_id for skill in stored),
        )
        identifier = id(registry)
        reference = weakref.ref(
            registry,
            lambda _reference, key=identifier: issued.pop(key, None),
        )
        issued[identifier] = (reference, state)
        return registry

    def state(value: object) -> _RegistryState | None:
        entry = issued.get(id(value))
        if (type(value) is not SkillRegistry or entry is None
                or entry[0]() is not value):
            return None
        return entry[1]

    return create, state


(_new_registry,
 _registry_state) = _registry_capability()
del _registry_capability


def _trusted_registry(value: object) -> bool:
    return _registry_state(value) is not None


@dataclass(frozen=True, slots=True)
class RegistryBuildResult:
    registry: SkillRegistry | None
    issues: tuple[Issue, ...]

    @property
    def ok(self) -> bool:
        return self.registry is not None and not self.issues


@dataclass(frozen=True, slots=True)
class RegistryListResult:
    skills: tuple[SkillSummary, ...]
    issues: tuple[Issue, ...]

    @property
    def ok(self) -> bool:
        return not self.issues

    def to_public(self) -> dict[str, Any]:
        return {
            "issues": [issue.code for issue in self.issues],
            "skills": [skill.to_public() for skill in self.skills],
        }


@dataclass(frozen=True, slots=True)
class RegistryLookupResult:
    skill: ValidatedSkill | None
    issues: tuple[Issue, ...]

    @property
    def ok(self) -> bool:
        return self.skill is not None and not self.issues


def _issue(code: str, message: str) -> tuple[Issue, ...]:
    return (Issue("error", code, message, "registry"),)


def _validated_registry_skills(value: object) -> tuple[ValidatedSkill, ...] | None:
    """Copies de lecture pour le planner, jamais l'etat du registre."""

    state = _registry_state(value)
    if state is None:
        return None
    return tuple(_copy_skill(skill) for skill in state.skills)


def build_registry(discovery: object) -> RegistryBuildResult:
    """Construit tout le registre, ou rien.

    Une decouverte incomplete, une entree non scellee ou une collision rend le
    resultat invalide. Aucun package n'est choisi arbitrairement.
    """

    if type(discovery) is not DiscoveryReport:
        return RegistryBuildResult(
            None,
            _issue("REGISTRY_INVALID", "decouverte attendue"),
        )
    if (type(discovery.records) is not tuple
            or type(discovery.fatal_codes) is not tuple
            or any(type(code) is not str for code in discovery.fatal_codes)
            or any(type(record) is not SkillLoadRecord
                   for record in discovery.records)):
        return RegistryBuildResult(
            None,
            _issue("REGISTRY_INVALID", "decouverte mal formee"),
        )
    skills = _discovery_skills(discovery)
    if skills is None or type(skills) is not tuple:
        return RegistryBuildResult(
            None,
            _issue("REGISTRY_INVALID", "decouverte non emise par le loader"),
        )
    for record in discovery.records:
        if (type(record.root_index) is not int or record.root_index < 0
                or type(record.relative_path) is not str
                or type(record.state) is not SkillState
                or type(record.error_codes) is not tuple
                or any(type(code) is not str for code in record.error_codes)
                or (record.skill_id is not None
                    and type(record.skill_id) is not str)
                or (record.state is SkillState.VALID
                    and (type(record.skill_id) is not str
                         or bool(record.error_codes)))):
            return RegistryBuildResult(
                None,
                _issue("REGISTRY_INVALID", "resultat de package mal forme"),
            )
    if discovery.fatal_codes:
        return RegistryBuildResult(
            None,
            _issue(
                "REGISTRY_INVALID",
                "decouverte incomplete ou collision detectee",
            ),
        )
    if any(record.state is not SkillState.VALID
           for record in discovery.records):
        return RegistryBuildResult(
            None,
            _issue("SKILL_INVALID", "package invalide dans la decouverte"),
        )
    if len(skills) > _MAX_REGISTRY_SKILLS:
        return RegistryBuildResult(
            None,
            _issue("REGISTRY_LIMIT", "registre trop grand"),
        )

    valid_records = {
        (record.relative_path, record.skill_id)
        for record in discovery.records
        if record.state is SkillState.VALID
    }
    checked: list[ValidatedSkill] = []
    seen: set[str] = set()
    for skill in skills:
        if not _is_validated_skill(skill):
            return RegistryBuildResult(
                None,
                _issue(
                    "REGISTRY_UNVALIDATED",
                    "entree sans preuve de validation",
                ),
            )
        key = canonical_skill_id(skill.skill_id)
        if key is None or key != skill.canonical_id:
            return RegistryBuildResult(
                None,
                _issue("REGISTRY_INVALID", "identite incoherente"),
            )
        if (skill.package_ref, skill.skill_id) not in valid_records:
            return RegistryBuildResult(
                None,
                _issue(
                    "REGISTRY_UNVALIDATED",
                    "snapshot sans resultat de validation correspondant",
                ),
            )
        if key in seen:
            return RegistryBuildResult(
                None,
                _issue("SKILL_DUPLICATE", "identite dupliquee"),
            )
        seen.add(key)
        checked.append(skill)

    ordered = tuple(sorted(
        checked,
        key=lambda skill: (skill.canonical_id, skill.skill_id),
    ))
    if len(valid_records) != len(checked):
        return RegistryBuildResult(
            None,
            _issue("REGISTRY_INVALID", "resultat sans snapshot correspondant"),
        )
    return RegistryBuildResult(_new_registry(ordered), ())


def list_skills(registry: object) -> RegistryListResult:
    """Rend des copies immuables des metadonnees publiques."""

    state = _registry_state(registry)
    if state is None:
        return RegistryListResult(
            (),
            _issue("REGISTRY_INVALID", "registre non fiable"),
        )
    return RegistryListResult(
        tuple(SkillSummary.from_skill(skill) for skill in state.skills),
        (),
    )


def get_skill(registry: object, skill_id: object) -> RegistryLookupResult:
    """Recherche par identite canonique, jamais par chemin."""

    state = _registry_state(registry)
    if state is None:
        return RegistryLookupResult(
            None,
            _issue("REGISTRY_INVALID", "registre non fiable"),
        )
    key = canonical_skill_id(skill_id)
    if key is None:
        return RegistryLookupResult(
            None,
            _issue("SKILL_ID", "identifiant invalide"),
        )
    position = bisect_left(state.keys, key)
    if position >= len(state.keys) or state.keys[position] != key:
        return RegistryLookupResult(
            None,
            _issue("SKILL_NOT_FOUND", "skill inconnu"),
        )
    return RegistryLookupResult(_copy_skill(state.skills[position]), ())
