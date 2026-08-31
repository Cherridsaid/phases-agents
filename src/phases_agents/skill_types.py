"""Types internes immuables de l'etape B1.

Ce module ne decouvre, ne valide et n'execute aucun skill. Il porte uniquement
les limites du produit et les representations scellees transmises entre le
loader, le registre et le planner.
"""

from __future__ import annotations

import json
import os
import re
import unicodedata
import weakref
from dataclasses import dataclass, field, fields
from enum import StrEnum
from typing import Any


class SkillState(StrEnum):
    """Etat public et stable d'un package decouvert."""

    VALID = "VALID"
    INVALID = "INVALID"
    BLOCKED = "BLOCKED"
    DUPLICATE = "DUPLICATE"
    UNREADABLE = "UNREADABLE"
    TOO_LARGE = "TOO_LARGE"


@dataclass(frozen=True, slots=True)
class SkillLimits:
    """Limites configurables, uniquement reductibles par les appelants."""

    max_roots: int = 16
    max_depth: int = 1
    max_packages: int = 1_000
    max_entries_per_root: int = 10_000
    max_skill_md_bytes: int = 256 * 1024
    max_snapshot_bytes: int = 16 * 1024 * 1024
    max_issues_per_skill: int = 100
    max_result_bytes: int = 1 * 1024 * 1024


DEFAULT_SKILL_LIMITS = SkillLimits()

_LIMIT_NAMES = tuple(SkillLimits.__dataclass_fields__)
_ID_RE = re.compile(r"^[^\W_](?:[\w-]{0,62}[^\W_])?$", re.UNICODE)
_PACKAGE_REF_RE = re.compile(r"^root\[(0|[1-9][0-9]{0,5})\]/(.+)$")
_SCALAR_LIMITS = {
    "version": 64,
    "title": 256,
    "description": 2_048,
    "domain": 128,
}
_WINDOWS_RESERVED = {
    "con", "prn", "aux", "nul",
    *(f"com{number}" for number in range(1, 10)),
    *(f"lpt{number}" for number in range(1, 10)),
}


def limits_error(limits: object) -> str | None:
    """Valide des limites sans jamais lever sur une entree publique hostile."""

    if type(limits) is not SkillLimits:
        return "SKILL_LIMITS"
    for name in _LIMIT_NAMES:
        value = getattr(limits, name)
        maximum = getattr(DEFAULT_SKILL_LIMITS, name)
        if type(value) is not int or value < 1 or value > maximum:
            return "SKILL_LIMITS"
    if limits.max_depth != 1:
        return "SKILL_LIMITS"
    return None


def canonical_skill_id(value: object) -> str | None:
    """Rend la cle portable d'un identifiant, ou ``None``.

    Les identifiants sont deja en NFKC. Les variantes de casse partagent une
    cle. Les separateurs, points, controles et noms reserves Windows sont
    refuses. Les lettres Unicode composees restent permises.
    """

    if type(value) is not str or not value or len(value) > 64:
        return None
    if value != value.strip() or unicodedata.normalize("NFKC", value) != value:
        return None
    if any(unicodedata.category(char) in {"Cc", "Cf", "Cs"}
           for char in value):
        return None
    if not _ID_RE.fullmatch(value):
        return None
    key = value.casefold()
    if key in _WINDOWS_RESERVED:
        return None
    return key


@dataclass(frozen=True, slots=True)
class SkillLoadRecord:
    """Resultat public compact d'un package candidat."""

    root_index: int
    relative_path: str
    state: SkillState
    skill_id: str | None = None
    error_codes: tuple[str, ...] = ()

    def to_public(self) -> dict[str, Any]:
        return {
            "error_codes": list(self.error_codes),
            "relative_path": self.relative_path,
            "root_index": self.root_index,
            "skill_id": self.skill_id,
            "state": self.state.value,
        }


@dataclass(frozen=True, slots=True, weakref_slot=True)
class ValidatedSkill:
    """Snapshot scelle d'un package passe par le validator officiel."""

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
    content: str = field(repr=False)

    def summary(self) -> dict[str, Any]:
        return {
            "description": self.description,
            "domain": self.domain,
            "platforms": list(self.platforms),
            "project_types": list(self.project_types),
            "skill_id": self.skill_id,
            "title": self.title,
            "version": self.version,
        }


def _validated_skill_payload(value: ValidatedSkill) -> dict[str, Any]:
    """Rend tous les champs stockes pour une comptabilisation deterministe."""

    if type(value) is not ValidatedSkill:
        raise TypeError("ValidatedSkill requis")
    return {
        descriptor.name: getattr(value, descriptor.name)
        for descriptor in fields(ValidatedSkill)
    }


def _metadata_tuple(value: object) -> tuple[str, ...] | None:
    if not isinstance(value, list) or len(value) > 1_000:
        return None
    result: dict[str, str] = {}
    for item in value:
        if (type(item) is not str or not item
                or len(item) > 500
                or item != item.strip()
                or unicodedata.normalize("NFKC", item) != item
                or any(unicodedata.category(char) in {"Cc", "Cf", "Cs"}
                       for char in item)):
            return None
        key = item.casefold()
        if key in result:
            return None
        result[key] = item
    return tuple(result[key] for key in sorted(result))


def _validated_skill_capability():
    issued: dict[int, weakref.ReferenceType[ValidatedSkill]] = {}

    def issue(validation: object, package_ref: object,
              public_name: object
              ) -> tuple[ValidatedSkill | None, tuple[str, ...]]:
        from .validator import _is_trusted_skill_package_validation

        if (not _is_trusted_skill_package_validation(validation)
                or not validation.valid):
            return None, ("SKILL_SNAPSHOT",)
        if (type(package_ref) is not str or type(public_name) is not str
                or package_ref != package_ref.strip()
                or len(package_ref) > 300
                or package_ref.endswith("/") or os.path.isabs(package_ref)):
            return None, ("SKILL_SNAPSHOT",)
        reference = _PACKAGE_REF_RE.fullmatch(package_ref)
        if (reference is None
                or int(reference.group(1)) >= DEFAULT_SKILL_LIMITS.max_roots
                or reference.group(2) != public_name):
            return None, ("SKILL_SNAPSHOT",)
        try:
            manifest = json.loads(validation.manifest_json)
        except (TypeError, json.JSONDecodeError, RecursionError):
            return None, ("SKILL_SNAPSHOT",)

        skill_id = manifest.get("id")
        key = canonical_skill_id(skill_id)
        directory_key = canonical_skill_id(public_name)
        codes = []
        if key is None:
            codes.append("SKILL_ID")
        elif directory_key != key:
            codes.append("SKILL_ID_MISMATCH")

        tuple_fields = {
            "project_types": _metadata_tuple(manifest.get("project_types")),
            "platforms": _metadata_tuple(manifest.get("platforms")),
            "activation_any": _metadata_tuple(
                manifest.get("activation", {}).get("any")
                if isinstance(manifest.get("activation"), dict) else None),
            "exclusions": _metadata_tuple(manifest.get("exclusions")),
            "requires_capabilities": _metadata_tuple(
                manifest.get("requires_capabilities")),
            "optional_capabilities": _metadata_tuple(
                manifest.get("optional_capabilities")),
            "forbidden_capabilities": _metadata_tuple(
                manifest.get("forbidden_capabilities")),
            "provides_capabilities": _metadata_tuple(
                manifest.get("provides_capabilities", [])),
        }
        if any(value is None for value in tuple_fields.values()):
            codes.append("SKILL_METADATA")
        for field, maximum in _SCALAR_LIMITS.items():
            value = manifest.get(field)
            if (type(value) is not str or not value
                    or len(value) > maximum
                    or value != value.strip()
                    or unicodedata.normalize("NFKC", value) != value
                    or any(unicodedata.category(char) in {"Cc", "Cf", "Cs"}
                           for char in value)):
                codes.append("SKILL_METADATA")
                break
        if codes:
            return None, tuple(sorted(set(codes)))

        snapshot = ValidatedSkill(
            skill_id=skill_id,
            canonical_id=key,
            package_ref=package_ref,
            version=manifest["version"],
            title=manifest["title"],
            description=manifest["description"],
            domain=manifest["domain"],
            content=validation.skill_md,
            **tuple_fields,
        )
        identifier = id(snapshot)
        issued[identifier] = weakref.ref(
            snapshot,
            lambda _reference, key=identifier: issued.pop(key, None),
        )
        return snapshot, ()

    def trusted(value: object) -> bool:
        reference = issued.get(id(value))
        return type(value) is ValidatedSkill and (
            reference is not None and reference() is value
        )

    return issue, trusted


(_make_validated_skill,
 _is_validated_skill) = _validated_skill_capability()
del _validated_skill_capability


@dataclass(frozen=True, slots=True, weakref_slot=True)
class DiscoveryReport:
    """Sortie immuable du loader."""

    records: tuple[SkillLoadRecord, ...]
    fatal_codes: tuple[str, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.fatal_codes

    def to_public(self) -> dict[str, Any]:
        return {
            "complete": self.complete,
            "fatal_codes": list(self.fatal_codes),
            "records": [record.to_public() for record in self.records],
        }


def _discovery_capability():
    """Lie les snapshots au rapport sans les exposer dans l'API publique."""

    issued: dict[
        int,
        tuple[
            weakref.ReferenceType[DiscoveryReport],
            tuple[ValidatedSkill, ...],
        ],
    ] = {}

    def create(records: tuple[SkillLoadRecord, ...],
               skills: tuple[ValidatedSkill, ...],
               fatal_codes: tuple[str, ...]) -> DiscoveryReport:
        report = DiscoveryReport(records, fatal_codes)
        identifier = id(report)
        issued[identifier] = (
            weakref.ref(
                report,
                lambda _reference, key=identifier: issued.pop(key, None),
            ),
            skills,
        )
        return report

    def snapshots(value: object) -> tuple[ValidatedSkill, ...] | None:
        entry = issued.get(id(value))
        if (type(value) is not DiscoveryReport or entry is None
                or entry[0]() is not value):
            return None
        return entry[1]

    return create, snapshots


(_new_discovery_report,
 _discovery_skills) = _discovery_capability()
del _discovery_capability
