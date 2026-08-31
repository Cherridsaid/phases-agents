"""Chargement borne et memorise des regles de lacunes B3."""

from __future__ import annotations

import json
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .validator import validate_skill_gap_rules


_RULES_PATH = (
    Path(__file__).resolve().parent
    / "core"
    / "SKILL_GAP_RULES.json"
)
_MAX_RULES_BYTES = 64 * 1024


@dataclass(frozen=True, slots=True)
class SkillGapRule:
    gap_id: str
    required_facts: tuple[str, ...]
    capability: str
    severity: str
    reason_code: str


def _reject_duplicate_object(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("cle JSON dupliquee")
        value[key] = item
    return value


def _reject_constant(value):
    raise ValueError(f"constante JSON interdite: {value}")


@lru_cache(maxsize=1)
def load_skill_gap_rules(
        ) -> tuple[tuple[SkillGapRule, ...] | None, str | None]:
    """Charge une fois le registre officiel, sinon échoue fermé."""

    try:
        raw = _RULES_PATH.read_bytes()
    except OSError:
        return None, "GAP_RULES_UNAVAILABLE"
    if len(raw) > _MAX_RULES_BYTES or raw.startswith(b"\xef\xbb\xbf"):
        return None, "GAP_RULES_INVALID"
    try:
        data = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_object,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, ValueError, RecursionError):
        return None, "GAP_RULES_INVALID"
    if validate_skill_gap_rules(data):
        return None, "GAP_RULES_INVALID"

    rules = tuple(sorted(
        (
            SkillGapRule(
                gap_id=item["gap_id"],
                required_facts=tuple(sorted(item["required_facts"])),
                capability=item["capability"],
                severity=item["severity"],
                reason_code=item["reason_code"],
            )
            for item in data["rules"]
        ),
        key=lambda item: (item.capability, item.gap_id),
    ))
    return rules, None
