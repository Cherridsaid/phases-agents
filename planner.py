"""Planification deterministe des skills valides."""

from __future__ import annotations

import json
import os
import unicodedata
from dataclasses import dataclass
from typing import Any

from capabilities import normalize_client_capabilities
from profile_facts import PROFILE_FACTS
from registry import SkillRegistry, _validated_registry_skills
from skill_gaps import load_skill_gap_rules
from validator import Issue, redact_sensitive_text


PLAN_VERSION = "1.0"
PLAN_VERSION_B3 = "B3"
_MAX_CONSTRAINT_ITEMS = 100
_MAX_CONSTRAINT_CHARS = 128
_MAX_PROFILE_ITEMS = 1_000
_MAX_PUBLIC_PLAN_BYTES = 1 * 1024 * 1024
_PROFILE_TYPES = {
    "apk",
    "inconnu",
    "python",
    "skill_package",
    "solana",
    "web",
}
_PROFILE_LANGUAGES = {"javascript", "python", "rust", "typescript"}


@dataclass(frozen=True, slots=True)
class SelectedSkill:
    skill_id: str
    reason_codes: tuple[str, ...]
    position: int
    prerequisites: tuple[str, ...] = ()

    def to_public(self) -> dict[str, Any]:
        return {
            "position": self.position,
            "prerequisites": list(self.prerequisites),
            "reason_codes": list(self.reason_codes),
            "skill_id": self.skill_id,
        }


@dataclass(frozen=True, slots=True)
class RejectedSkill:
    skill_id: str
    reason_codes: tuple[str, ...]

    def to_public(self) -> dict[str, Any]:
        return {
            "reason_codes": list(self.reason_codes),
            "skill_id": self.skill_id,
        }


@dataclass(frozen=True, slots=True)
class PlanStep:
    position: int
    action: str
    skill_id: str

    def to_public(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "position": self.position,
            "skill_id": self.skill_id,
        }


@dataclass(frozen=True, slots=True)
class SkillPlan:
    project_profile: tuple[tuple[str, object], ...]
    selected_skills: tuple[SelectedSkill, ...]
    rejected_skills: tuple[RejectedSkill, ...]
    warnings: tuple[str, ...]
    steps: tuple[PlanStep, ...]
    plan_version: str = PLAN_VERSION

    def to_public(self) -> dict[str, Any]:
        profile = {}
        for key, value in self.project_profile:
            if key == "markers":
                profile[key] = {
                    marker: list(items)
                    for marker, items in value
                }
            elif isinstance(value, tuple):
                profile[key] = list(value)
            else:
                profile[key] = value
        return {
            "plan_version": self.plan_version,
            "project_profile": profile,
            "rejected_skills": [
                item.to_public() for item in self.rejected_skills
            ],
            "selected_skills": [
                item.to_public() for item in self.selected_skills
            ],
            "steps": [step.to_public() for step in self.steps],
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class PlanBuildResult:
    plan: SkillPlan | None
    issues: tuple[Issue, ...]

    @property
    def ok(self) -> bool:
        return self.plan is not None and not self.issues


@dataclass(frozen=True, slots=True)
class B3SelectedSkill:
    skill_id: str
    position: int
    reason_codes: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    optional_capabilities: tuple[str, ...]
    limitations: tuple[str, ...] = ()

    def to_public(self) -> dict[str, Any]:
        return {
            "limitations": list(self.limitations),
            "optional_capabilities": list(self.optional_capabilities),
            "position": self.position,
            "reason_codes": list(self.reason_codes),
            "required_capabilities": list(self.required_capabilities),
            "skill_id": self.skill_id,
        }


@dataclass(frozen=True, slots=True)
class B3NotApplicableSkill:
    skill_id: str
    reason_codes: tuple[str, ...]

    def to_public(self) -> dict[str, Any]:
        return {
            "reason_codes": list(self.reason_codes),
            "skill_id": self.skill_id,
        }


@dataclass(frozen=True, slots=True)
class B3BlockedSkill:
    skill_id: str
    reason_codes: tuple[str, ...]
    missing_capabilities: tuple[str, ...]

    def to_public(self) -> dict[str, Any]:
        return {
            "missing_capabilities": list(self.missing_capabilities),
            "reason_codes": list(self.reason_codes),
            "skill_id": self.skill_id,
        }


@dataclass(frozen=True, slots=True)
class B3MissingSkill:
    gap_id: str
    capability: str
    severity: str
    reason_code: str
    required_facts: tuple[str, ...]

    def to_public(self) -> dict[str, Any]:
        return {
            "capability": self.capability,
            "gap_id": self.gap_id,
            "reason_code": self.reason_code,
            "required_facts": list(self.required_facts),
            "severity": self.severity,
        }


@dataclass(frozen=True, slots=True)
class B3PlanStep:
    position: int
    skill_id: str
    action: str
    reason_codes: tuple[str, ...]
    required_capabilities: tuple[str, ...]
    gate: int = 0

    def to_public(self) -> dict[str, Any]:
        return {
            "action": self.action,
            "gate": self.gate,
            "position": self.position,
            "reason_codes": list(self.reason_codes),
            "required_capabilities": list(self.required_capabilities),
            "skill_id": self.skill_id,
        }


@dataclass(frozen=True, slots=True)
class B3SkillPlan:
    project_profile: tuple[tuple[str, object], ...]
    client_capabilities: tuple[str, ...]
    skills_selected: tuple[B3SelectedSkill, ...]
    skills_not_applicable: tuple[B3NotApplicableSkill, ...]
    skills_blocked: tuple[B3BlockedSkill, ...]
    skills_missing: tuple[B3MissingSkill, ...]
    warnings: tuple[str, ...]
    steps: tuple[B3PlanStep, ...]
    plan_status: str
    plan_version: str = PLAN_VERSION_B3

    def to_public(self) -> dict[str, Any]:
        profile = {
            key: list(value) if isinstance(value, tuple) else value
            for key, value in self.project_profile
        }
        return {
            "client_capabilities": list(self.client_capabilities),
            "plan_status": self.plan_status,
            "plan_version": self.plan_version,
            "project_profile": profile,
            "skills_blocked": [
                item.to_public() for item in self.skills_blocked
            ],
            "skills_missing": [
                item.to_public() for item in self.skills_missing
            ],
            "skills_not_applicable": [
                item.to_public() for item in self.skills_not_applicable
            ],
            "skills_selected": [
                item.to_public() for item in self.skills_selected
            ],
            "steps": [step.to_public() for step in self.steps],
            "warnings": list(self.warnings),
        }


@dataclass(frozen=True, slots=True)
class B3PlanBuildResult:
    plan: B3SkillPlan | None
    issues: tuple[Issue, ...]

    @property
    def ok(self) -> bool:
        return self.plan is not None and not self.issues


def _error(code: str, message: str, path: str = "plan") -> PlanBuildResult:
    return PlanBuildResult(None, (Issue("error", code, message, path),))


def _b3_error(code: str, message: str,
              path: str = "plan") -> B3PlanBuildResult:
    return B3PlanBuildResult(
        None,
        (Issue("error", code, message, path),),
    )


def _normalized_list(value: object, allowed: set[str] | None = None,
                     maximum: int = _MAX_PROFILE_ITEMS
                     ) -> tuple[str, ...] | None:
    if type(value) is not list or len(value) > maximum:
        return None
    values: dict[str, str] = {}
    for item in value:
        if (type(item) is not str or not item
                or len(item) > _MAX_CONSTRAINT_CHARS
                or item != item.strip()
                or unicodedata.normalize("NFKC", item) != item
                or any(unicodedata.category(char) in {"Cc", "Cf", "Cs"}
                       for char in item)):
            return None
        key = item.casefold()
        if allowed is not None and key not in allowed:
            return None
        if key in values:
            return None
        values[key] = item
    return tuple(values[key] for key in sorted(values))


def _profile_snapshot(profile: object, *,
                      include_facts: bool = False):
    if type(profile) is not dict:
        return None, "PROFILE_INVALID"
    allowed_keys = {
        "target", "exists", "blocked", "issues",
        "types", "languages", "markers", "reason", "facts",
    }
    required_keys = {
        "exists", "blocked", "issues", "types", "languages", "markers",
    }
    if set(profile) - allowed_keys or not required_keys.issubset(profile):
        return None, "PROFILE_INVALID"
    if (type(profile.get("exists")) is not bool
            or type(profile.get("blocked")) is not bool):
        return None, "PROFILE_INVALID"
    if not profile["exists"] or profile["blocked"]:
        return None, "PROFILE_BLOCKED"

    types = _normalized_list(profile.get("types"), _PROFILE_TYPES)
    languages = _normalized_list(
        profile.get("languages"), _PROFILE_LANGUAGES)
    issues = _normalized_list(profile.get("issues"))
    facts = _normalized_list(
        profile.get("facts", []),
        set(PROFILE_FACTS),
    )
    if (types is None or not types or languages is None or issues is None
            or facts is None or issues):
        return None, "PROFILE_INVALID"

    markers = profile.get("markers")
    if type(markers) is not dict or len(markers) > _MAX_PROFILE_ITEMS:
        return None, "PROFILE_INVALID"
    if any(type(key) is not str for key in markers):
        return None, "PROFILE_INVALID"
    public_markers = []
    marker_nodes = 0
    for key in sorted(markers, key=lambda value: (
            value.casefold(), value)):
        if (not key
                or len(key) > _MAX_CONSTRAINT_CHARS
                or redact_sensitive_text(key) != key):
            return None, "PROFILE_INVALID"
        values = _normalized_list(markers[key])
        if values is None:
            return None, "PROFILE_INVALID"
        for value in values:
            if (os.path.isabs(value) or "/" in value or "\\" in value
                    or redact_sensitive_text(value) != value):
                return None, "PROFILE_INVALID"
        marker_nodes += len(values)
        if marker_nodes > _MAX_PROFILE_ITEMS:
            return None, "PROFILE_INVALID"
        public_markers.append((key, values))

    snapshot_items = [
        ("blocked", False),
        ("exists", True),
        ("languages", languages),
        ("markers", tuple(public_markers)),
        ("types", types),
    ]
    if include_facts:
        snapshot_items.insert(2, ("facts", facts))
    return tuple(snapshot_items), None


def _constraints_snapshot(constraints: object):
    if constraints is None:
        constraints = {}
    if type(constraints) is not dict:
        return None
    allowed = {"platforms", "domains", "capabilities"}
    if set(constraints) - allowed:
        return None

    platforms_value = constraints.get("platforms", [])
    domains_value = constraints.get("domains", [])
    capabilities_value = constraints.get("capabilities")
    platforms = _normalized_list(
        platforms_value, maximum=_MAX_CONSTRAINT_ITEMS)
    domains = _normalized_list(
        domains_value, maximum=_MAX_CONSTRAINT_ITEMS)
    capabilities = (
        None
        if capabilities_value is None
        else _normalized_list(
            capabilities_value,
            maximum=_MAX_CONSTRAINT_ITEMS,
        )
    )
    if (platforms is None or domains is None
            or (capabilities_value is not None and capabilities is None)):
        return None
    return {
        "capabilities": (
            None
            if capabilities is None
            else tuple(value.casefold() for value in capabilities)
        ),
        "domains": tuple(value.casefold() for value in domains),
        "platforms": tuple(value.casefold() for value in platforms),
    }


def _calculate_skill_gaps(
        profile_facts: set[str],
        executable_skills: tuple[object, ...],
        ) -> tuple[tuple[B3MissingSkill, ...] | None, str | None]:
    """Calcule les lacunes depuis le registre déjà validé."""

    gap_rules, gap_error = load_skill_gap_rules()
    if gap_error is not None or gap_rules is None:
        return None, gap_error or "GAP_RULES_INVALID"
    covered_capabilities = {
        capability
        for skill in executable_skills
        for capability in skill.provides_capabilities
    }
    return tuple(
        B3MissingSkill(
            gap_id=rule.gap_id,
            capability=rule.capability,
            severity=rule.severity,
            reason_code=rule.reason_code,
            required_facts=rule.required_facts,
        )
        for rule in gap_rules
        if set(rule.required_facts).issubset(profile_facts)
        and rule.capability not in covered_capabilities
    ), None


def build_plan(profile: object, registry: object,
               constraints: object = None) -> PlanBuildResult:
    """Selectionne sans executer, puis ordonne par identite canonique."""

    profile_snapshot, profile_error = _profile_snapshot(profile)
    if profile_error is not None:
        return _error(profile_error, "profil detector invalide")
    skills = _validated_registry_skills(registry)
    if skills is None:
        return _error("REGISTRY_INVALID", "registre non fiable")
    selection = _constraints_snapshot(constraints)
    if selection is None:
        return _error("PLAN_INVALID", "contraintes invalides")

    profile_data = dict(profile_snapshot)
    profile_types = {value.casefold() for value in profile_data["types"]}
    selected = []
    rejected = []
    warnings = {
        "ACTIVATION_FACTS_NOT_EVALUATED",
        "DEPENDENCIES_NOT_DECLARED",
    }
    if selection["capabilities"] is None:
        warnings.add("CAPABILITIES_NOT_EVALUATED")

    for skill in skills:
        reasons = []
        skill_types = {value.casefold() for value in skill.project_types}
        if not (profile_types & skill_types):
            reasons.append("PROJECT_TYPE_MISMATCH")
        skill_platforms = {value.casefold() for value in skill.platforms}
        if (selection["platforms"]
                and not (set(selection["platforms"]) & skill_platforms)):
            reasons.append("PLATFORM_MISMATCH")
        if (selection["domains"]
                and skill.domain.casefold() not in selection["domains"]):
            reasons.append("DOMAIN_MISMATCH")
        if selection["capabilities"] is not None:
            available = set(selection["capabilities"])
            required = {
                value.casefold()
                for value in skill.requires_capabilities
            }
            forbidden = {
                value.casefold()
                for value in skill.forbidden_capabilities
            }
            if not required.issubset(available):
                reasons.append("CAPABILITY_MISSING")
            if forbidden & available:
                reasons.append("CAPABILITY_FORBIDDEN")

        if reasons:
            rejected.append(RejectedSkill(
                skill.skill_id,
                tuple(sorted(reasons)),
            ))
        else:
            match_reasons = ["PROJECT_TYPE_MATCH"]
            if selection["platforms"]:
                match_reasons.append("PLATFORM_MATCH")
            if selection["domains"]:
                match_reasons.append("DOMAIN_MATCH")
            if selection["capabilities"] is not None:
                match_reasons.append("CAPABILITIES_MATCH")
            selected.append((skill, tuple(match_reasons)))

    selected.sort(key=lambda item: (
        item[0].canonical_id, item[0].skill_id))
    rejected.sort(key=lambda item: (
        item.skill_id.casefold(), item.skill_id))
    selected_public = tuple(
        SelectedSkill(
            skill.skill_id,
            match_reasons,
            position,
        )
        for position, (skill, match_reasons) in enumerate(selected, 1)
    )
    steps = tuple(
        PlanStep(item.position, "PROVIDE_SKILL", item.skill_id)
        for item in selected_public
    )
    if not selected_public:
        warnings.add("NO_COMPATIBLE_SKILL")

    plan = SkillPlan(
        project_profile=profile_snapshot,
        selected_skills=selected_public,
        rejected_skills=tuple(rejected),
        warnings=tuple(sorted(warnings)),
        steps=steps,
    )
    public_bytes = json.dumps(
        plan.to_public(),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(public_bytes) > _MAX_PUBLIC_PLAN_BYTES:
        return _error(
            "PLAN_LIMIT",
            "resultat public du plan trop volumineux",
        )
    return PlanBuildResult(plan, ())


def build_b3_plan(
        profile: object,
        registry: object,
        client_capabilities: object = None) -> B3PlanBuildResult:
    """Classe chaque skill sans l'executer.

    Une capacite non declaree n'est jamais presumee disponible. Une capacite
    facultative absente reduit seulement la demarche du LLM.
    """

    profile_snapshot, profile_error = _profile_snapshot(
        profile,
        include_facts=True,
    )
    if profile_error is not None:
        return _b3_error(profile_error, "profil detector invalide")
    skills = _validated_registry_skills(registry)
    if skills is None:
        return _b3_error("REGISTRY_INVALID", "registre non fiable")
    capabilities_declared = client_capabilities is not None
    if capabilities_declared:
        normalized_capabilities, capability_error = (
            normalize_client_capabilities(client_capabilities)
        )
        if capability_error is not None:
            return _b3_error(
                capability_error,
                "capacites client invalides",
                "client_capabilities",
            )
    else:
        normalized_capabilities = ()

    profile_data = dict(profile_snapshot)
    profile_types = {
        value.casefold() for value in profile_data["types"]
    }
    profile_facts = {
        value.casefold() for value in profile_data["facts"]
    }
    selected_candidates = []
    not_applicable = []
    blocked = []
    warnings = set()
    if not capabilities_declared:
        warnings.add("CLIENT_CAPABILITIES_UNDECLARED")
    available = set(normalized_capabilities)
    for skill in skills:
        skill_types = {
            value.casefold() for value in skill.project_types
        }
        if profile_types & skill_types:
            activation_facts = {
                value.casefold() for value in skill.activation_any
            }
            if (activation_facts
                    and not (activation_facts & profile_facts)):
                not_applicable.append(B3NotApplicableSkill(
                    skill.skill_id,
                    ("ACTIVATION_FACT_MISMATCH",),
                ))
                continue
            required = tuple(sorted(skill.requires_capabilities))
            missing_required = tuple(
                capability
                for capability in required
                if capability not in available
            )
            if missing_required:
                blocked.append(B3BlockedSkill(
                    skill_id=skill.skill_id,
                    reason_codes=(
                        "REQUIRED_CLIENT_CAPABILITY_MISSING",
                    ),
                    missing_capabilities=missing_required,
                ))
                continue
            # Une capacite interdite presente chez le client bloque le skill.
            # B1 appliquait deja cette regle ; son absence ici rendait
            # l'interdiction contournable en declarant simplement la capacite.
            present_forbidden = tuple(
                capability
                for capability in sorted(skill.forbidden_capabilities)
                if capability in available
            )
            if present_forbidden:
                blocked.append(B3BlockedSkill(
                    skill_id=skill.skill_id,
                    reason_codes=(
                        "FORBIDDEN_CLIENT_CAPABILITY_PRESENT",
                    ),
                    missing_capabilities=present_forbidden,
                ))
                continue
            missing_optional = tuple(
                capability
                for capability in sorted(skill.optional_capabilities)
                if capability not in available
            )
            reasons = [
                "PROJECT_TYPE_MATCH",
                "REQUIRED_CLIENT_CAPABILITIES_AVAILABLE",
            ]
            limitations = []
            if missing_optional:
                reasons.append("OPTIONAL_CLIENT_CAPABILITY_MISSING")
                warnings.add("OPTIONAL_CLIENT_CAPABILITY_MISSING")
                limitations.extend(
                    f"OPTIONAL_CAPABILITY_UNAVAILABLE:{capability}"
                    for capability in missing_optional
                )
            selected_candidates.append((
                skill,
                tuple(reasons),
                tuple(limitations),
            ))
        else:
            not_applicable.append(B3NotApplicableSkill(
                skill.skill_id,
                ("PROJECT_TYPE_MISMATCH",),
            ))

    selected_candidates.sort(key=lambda item: (
        item[0].canonical_id, item[0].skill_id))
    not_applicable.sort(key=lambda item: (
        item.skill_id.casefold(), item.skill_id))
    blocked.sort(key=lambda item: (
        item.skill_id.casefold(), item.skill_id))
    selected = tuple(
        B3SelectedSkill(
            skill_id=skill.skill_id,
            position=position,
            reason_codes=reasons,
            required_capabilities=skill.requires_capabilities,
            optional_capabilities=skill.optional_capabilities,
            limitations=limitations,
        )
        for position, (skill, reasons, limitations)
        in enumerate(selected_candidates, 1)
    )
    steps = tuple(
        B3PlanStep(
            position=item.position,
            skill_id=item.skill_id,
            action="READ_AND_EXECUTE_SKILL",
            reason_codes=item.reason_codes,
            required_capabilities=item.required_capabilities,
        )
        for item in selected
    )
    missing, gap_error = _calculate_skill_gaps(
        profile_facts,
        tuple(
            skill
            for skill, _reasons, _limitations
            in selected_candidates
        ),
    )
    if gap_error is not None or missing is None:
        return _b3_error(
            gap_error or "GAP_RULES_INVALID",
            "registre de lacunes invalide",
            "skills_missing",
        )
    if missing:
        warnings.add("NO_INSTALLED_SKILL_FOR_CAPABILITY")
    if not selected:
        warnings.add(
            "NO_EXECUTABLE_SKILL"
            if blocked
            else "NO_COMPATIBLE_SKILL"
        )
    public_profile = tuple(
        (key, value)
        for key, value in profile_snapshot
        if key != "markers"
    )
    plan = B3SkillPlan(
        project_profile=public_profile,
        client_capabilities=normalized_capabilities,
        skills_selected=selected,
        skills_not_applicable=tuple(not_applicable),
        skills_blocked=tuple(blocked),
        skills_missing=missing,
        warnings=tuple(sorted(warnings)),
        steps=steps,
        plan_status=(
            "BLOCKED"
            if not selected
            else "PARTIAL"
            if blocked or missing
            else "READY"
        ),
    )
    public_bytes = json.dumps(
        plan.to_public(),
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("utf-8")
    if len(public_bytes) > _MAX_PUBLIC_PLAN_BYTES:
        return _b3_error(
            "PLAN_LIMIT",
            "resultat public du plan trop volumineux",
        )
    return B3PlanBuildResult(plan, ())
