"""Decouverte locale, bornee et deterministe des packages de skills."""

from __future__ import annotations

import datetime
import json
import os
import stat
import unicodedata
from typing import Iterable

from .skill_types import (
    DEFAULT_SKILL_LIMITS,
    DiscoveryReport,
    SkillLimits,
    SkillLoadRecord,
    SkillState,
    _make_validated_skill,
    _new_discovery_report,
    _validated_skill_payload,
    canonical_skill_id,
    limits_error,
)
from .validator import (
    _is_reparse_point,
    redact_sensitive_text,
    validate_skill_package,
)


_BLOCKING_CODES = {
    "PATH_UNSAFE",
    "SKILL_DIR",
}
_UNREADABLE_CODES = {
    "READ",
}
_TOO_LARGE_CODES = {
    "TOO_LARGE",
}
def _date_code(today: object) -> str | None:
    if today is None:
        return "TODAY_REQUIRED"
    if type(today) is not datetime.date:
        return "TODAY_INVALID"
    return None


def _safe_public_name(name: str) -> str:
    if type(name) is not str:
        return "<invalid>"
    if redact_sensitive_text(name) != name:
        return "<redacted>"
    if (not name or len(name) > 255
            or unicodedata.normalize("NFKC", name) != name
            or any(unicodedata.category(char) in {"Cc", "Cf", "Cs"}
                   for char in name)
            or canonical_skill_id(name) is None):
        return "<invalid>"
    return name


def _path_has_reparse_component(path: str) -> bool:
    """Controle tous les parents existants, sans suivre un lien volontairement."""

    try:
        current = os.path.abspath(path)
    except (OSError, ValueError):
        return True
    while True:
        try:
            if os.path.lexists(current) and _is_reparse_point(current):
                return True
        except (OSError, ValueError):
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def _valid_root_path(root: object) -> str | None:
    if type(root) is not str and not isinstance(root, os.PathLike):
        return None
    try:
        value = os.fspath(root)
    except Exception:
        return None
    if type(value) is not str or not value or len(value) > 32_767:
        return None
    if value != value.strip():
        return None
    if "\x00" in value or any(
            unicodedata.category(char) in {"Cc", "Cf", "Cs"}
            for char in value):
        return None
    try:
        if value.startswith(("\\\\", "//", "\\\\?\\")):
            return None
        if not os.path.isabs(value):
            return None
        return os.path.abspath(value)
    except (OSError, ValueError):
        return None


def _real_within(path: str, root: str) -> bool:
    try:
        real_path = os.path.realpath(path)
        real_root = os.path.realpath(root)
        return os.path.commonpath((real_path, real_root)) == real_root
    except (OSError, ValueError):
        return False


def _bounded_codes(codes: Iterable[str], maximum: int) -> tuple[str, ...]:
    ordered = sorted(set(codes))
    if len(ordered) <= maximum:
        return tuple(ordered)
    return tuple(ordered[:maximum - 1] + ["ISSUE_LIMIT"])


def _record_state(codes: tuple[str, ...]) -> SkillState:
    values = set(codes)
    if values & _TOO_LARGE_CODES:
        return SkillState.TOO_LARGE
    if values & _BLOCKING_CODES:
        return SkillState.BLOCKED
    if values & _UNREADABLE_CODES:
        return SkillState.UNREADABLE
    return SkillState.INVALID


def _validated_from_package(package: str, root_index: int, public_name: str,
                            today: datetime.date, limits: SkillLimits):
    package_ref = f"root[{root_index}]/{public_name}"
    missing = []
    for filename, code in (
            ("SKILL.md", "SKILL_MISSING"),
            ("phases.json", "MANIFEST_MISSING")):
        try:
            if not os.path.lexists(os.path.join(package, filename)):
                missing.append(code)
        except (OSError, ValueError):
            missing.append("READ")
    if missing:
        codes = _bounded_codes(missing, limits.max_issues_per_skill)
        return (
            SkillLoadRecord(
                root_index,
                package_ref,
                _record_state(codes),
                error_codes=codes,
            ),
            None,
        )

    validation = validate_skill_package(package, today=today)
    codes = _bounded_codes(
        (issue.code for issue in validation.issues if issue.level == "error"),
        limits.max_issues_per_skill,
    )
    if not validation.valid:
        return (
            SkillLoadRecord(
                root_index,
                package_ref,
                _record_state(codes),
                error_codes=codes,
            ),
            None,
        )

    if (validation.skill_md is None
            or len(validation.skill_md.encode("utf-8"))
            > limits.max_skill_md_bytes):
        return (
            SkillLoadRecord(
                root_index,
                package_ref,
                SkillState.TOO_LARGE,
                error_codes=("TOO_LARGE",),
            ),
            None,
        )
    snapshot, codes = _make_validated_skill(
        validation, package_ref, public_name)
    if codes:
        return (
            SkillLoadRecord(
                root_index,
                package_ref,
                SkillState.INVALID,
                error_codes=codes,
            ),
            None,
        )
    return (
        SkillLoadRecord(
            root_index,
            package_ref,
            SkillState.VALID,
            skill_id=snapshot.skill_id,
        ),
        snapshot,
    )


def _report(records: tuple[SkillLoadRecord, ...] = (),
            skills=(),
            fatal_codes: tuple[str, ...] = ()) -> DiscoveryReport:
    return _new_discovery_report(records, tuple(skills), fatal_codes)


def _serialized_size(value: object) -> int:
    return len(json.dumps(
        value,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8"))


def _outputs_fit(records: tuple[SkillLoadRecord, ...],
                 skills: tuple,
                 fatal_codes: tuple[str, ...],
                 maximum: int) -> bool:
    report = DiscoveryReport(records, fatal_codes)
    public_discovery = report.to_public()
    summaries = [skill.summary() for skill in skills]
    if _serialized_size({
            "discovery": public_discovery,
            "skills": summaries,
            }) > maximum:
        return False
    discovery_size = _serialized_size(public_discovery)
    get_envelope_overhead = len(b'{"discovery":,"skill":}')
    for skill, summary in zip(skills, summaries):
        document = dict(summary)
        document.update({
            "content": skill.content,
            "validation_level": "STRUCTURALLY_VALIDATED",
        })
        if (discovery_size
                + _serialized_size(document)
                + get_envelope_overhead > maximum):
            return False
    return True


def discover_skills(roots, today: datetime.date | None = None,
                    limits: SkillLimits = DEFAULT_SKILL_LIMITS
                    ) -> DiscoveryReport:
    """Decouvre et valide les enfants directs des racines autorisees.

    Toute erreur de racine est globale et fail-closed. Un package individuel
    invalide reste visible dans ``records`` mais n'apparait jamais dans
    ``skills``.
    """

    date_code = _date_code(today)
    if date_code is not None:
        return _report(fatal_codes=(date_code,))
    limit_code = limits_error(limits)
    if limit_code is not None:
        return _report(fatal_codes=(limit_code,))
    if type(roots) not in (list, tuple):
        return _report(fatal_codes=("SKILL_ROOT",))
    if not roots:
        return _report(fatal_codes=("SKILL_ROOT",))
    if len(roots) > limits.max_roots:
        return _report(fatal_codes=("SKILL_ROOT_LIMIT",))

    normalized_roots: list[str] = []
    root_keys: set[str] = set()
    for root in roots:
        normalized = _valid_root_path(root)
        if normalized is None:
            return _report(fatal_codes=("SKILL_ROOT",))
        try:
            key = os.path.normcase(os.path.realpath(normalized))
        except (OSError, ValueError):
            return _report(fatal_codes=("SKILL_ROOT",))
        if key in root_keys:
            return _report(fatal_codes=("SKILL_ROOT_DUPLICATE",))
        root_keys.add(key)
        normalized_roots.append(normalized)

    records: list[SkillLoadRecord] = []
    skills = []
    fatal_codes: set[str] = set()
    packages_seen = 0
    snapshot_bytes = 2  # Crochets du tableau JSON canonique des snapshots.
    snapshot_count = 0

    for root_index, root in enumerate(normalized_roots):
        if (_path_has_reparse_component(root)
                or not os.path.isdir(root)):
            fatal_codes.add("SKILL_ROOT")
            continue
        try:
            root_stat = os.stat(root, follow_symlinks=False)
            if not stat.S_ISDIR(root_stat.st_mode):
                fatal_codes.add("SKILL_ROOT")
                continue
            with os.scandir(root) as iterator:
                entries = []
                for index, entry in enumerate(iterator, 1):
                    if index > limits.max_entries_per_root:
                        fatal_codes.add("SKILL_ROOT_LIMIT")
                        entries = []
                        break
                    entries.append(entry.name)
        except (OSError, ValueError):
            fatal_codes.add("SKILL_DISCOVERY")
            continue

        for entry_name in sorted(entries, key=lambda value: (
                unicodedata.normalize("NFKC", value).casefold(), value)):
            full = os.path.join(root, entry_name)
            try:
                is_directory = os.path.isdir(full)
                exists = os.path.lexists(full)
            except (OSError, ValueError):
                public_name = _safe_public_name(entry_name)
                records.append(SkillLoadRecord(
                    root_index,
                    f"root[{root_index}]/{public_name}",
                    SkillState.UNREADABLE,
                    error_codes=("READ",),
                ))
                continue
            if not exists or not is_directory:
                continue

            packages_seen += 1
            if packages_seen > limits.max_packages:
                fatal_codes.add("SKILL_PACKAGE_LIMIT")
                break
            public_name = _safe_public_name(entry_name)
            package_ref = f"root[{root_index}]/{public_name}"
            if public_name in {"<redacted>", "<invalid>"}:
                records.append(SkillLoadRecord(
                    root_index,
                    package_ref,
                    SkillState.BLOCKED,
                    error_codes=("PATH_UNSAFE",),
                ))
                continue
            if (_path_has_reparse_component(full)
                    or not _real_within(full, root)):
                records.append(SkillLoadRecord(
                    root_index,
                    package_ref,
                    SkillState.BLOCKED,
                    error_codes=("PATH_UNSAFE",),
                ))
                continue
            record, snapshot = _validated_from_package(
                full, root_index, public_name, today, limits)
            records.append(record)
            if snapshot is not None:
                if snapshot_count:
                    snapshot_bytes += 1  # Virgule du tableau JSON canonique.
                snapshot_bytes += _serialized_size(
                    _validated_skill_payload(snapshot))
                snapshot_count += 1
                if snapshot_bytes > limits.max_snapshot_bytes:
                    fatal_codes.add("SKILL_SNAPSHOT_LIMIT")
                    skills = []
                    break
                skills.append(snapshot)
        if fatal_codes & {"SKILL_PACKAGE_LIMIT", "SKILL_SNAPSHOT_LIMIT"}:
            break

    by_identity: dict[str, list[int]] = {}
    for index, skill in enumerate(skills):
        by_identity.setdefault(skill.canonical_id, []).append(index)
    duplicate_indexes = {
        index
        for indexes in by_identity.values()
        if len(indexes) > 1
        for index in indexes
    }
    if duplicate_indexes:
        duplicate_refs = {skills[index].package_ref for index in duplicate_indexes}
        fatal_codes.add("SKILL_DUPLICATE")
        records = [
            SkillLoadRecord(
                record.root_index,
                record.relative_path,
                SkillState.DUPLICATE,
                skill_id=record.skill_id,
                error_codes=("SKILL_DUPLICATE",),
            )
            if record.relative_path in duplicate_refs else record
            for record in records
        ]
        skills = [
            skill for index, skill in enumerate(skills)
            if index not in duplicate_indexes
        ]

    records.sort(key=lambda record: (
        record.root_index,
        record.relative_path.casefold(),
        record.relative_path,
        record.state.value,
    ))
    skills.sort(key=lambda skill: (skill.canonical_id, skill.skill_id))
    ordered_records = tuple(records)
    ordered_codes = tuple(sorted(fatal_codes))
    ordered_skills = () if fatal_codes else tuple(skills)
    if not _outputs_fit(
            ordered_records,
            ordered_skills,
            ordered_codes,
            limits.max_result_bytes):
        return _report(fatal_codes=("SKILL_RESULT_LIMIT",))
    return _report(ordered_records, ordered_skills, ordered_codes)
