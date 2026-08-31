"""Configuration de confiance et cache MCP des registres de skills.

Les chemins de racines restent dans cet état privé. Les appels MCP ne
manipulent que des identifiants courts. Le cache vérifie un instantané de
métadonnées avant chaque réutilisation et reconstruit sans conserver un ancien
registre lorsqu'un changement est observé.
"""

from __future__ import annotations

import datetime
import hashlib
import json
import os
import stat
import threading
import unicodedata
import weakref
from dataclasses import dataclass, field

if os.name == "nt":
    import ctypes
    from ctypes import wintypes

    _KERNEL32 = ctypes.WinDLL("kernel32", use_last_error=True)
    _FIND_FIRST_CHANGE = _KERNEL32.FindFirstChangeNotificationW
    _FIND_FIRST_CHANGE.argtypes = [
        wintypes.LPCWSTR,
        wintypes.BOOL,
        wintypes.DWORD,
    ]
    _FIND_FIRST_CHANGE.restype = wintypes.HANDLE
    _FIND_CLOSE_CHANGE = _KERNEL32.FindCloseChangeNotification
    _FIND_CLOSE_CHANGE.argtypes = [wintypes.HANDLE]
    _FIND_CLOSE_CHANGE.restype = wintypes.BOOL
    _WAIT_FOR_SINGLE_OBJECT = _KERNEL32.WaitForSingleObject
    _WAIT_FOR_SINGLE_OBJECT.argtypes = [wintypes.HANDLE, wintypes.DWORD]
    _WAIT_FOR_SINGLE_OBJECT.restype = wintypes.DWORD

from .registry import SkillRegistry, build_registry
from .skill_loader import (
    _path_has_reparse_component,
    _valid_root_path,
    discover_skills,
)
from .skill_types import DEFAULT_SKILL_LIMITS, canonical_skill_id
from .validator import _is_reparse_point, redact_sensitive_text


ROOT_CONFIG_VERSION = "1.0"
_MAX_CONFIG_BYTES = 64 * 1024
_MAX_CACHE_ENTRIES = 4
_MAX_STATE_NODES = 100_000
_MAX_STATE_DEPTH = 64
_MAX_STATE_ENTRIES_PER_DIRECTORY = 10_000
_MAX_STATE_BYTES = 32 * 1024 * 1024
_RUNTIME_TOKEN = object()


@dataclass(frozen=True, slots=True)
class RuntimeBuildResult:
    """Résultat maîtrisé d'une configuration de racines."""

    runtime: "SkillRuntime | None"
    codes: tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return self.runtime is not None and not self.codes


@dataclass(frozen=True, slots=True)
class RuntimeRegistryResult:
    """Résultat privé de résolution, sans chemin local."""

    registry: SkillRegistry | None
    codes: tuple[str, ...] = ()
    _discovery_json: str | None = field(default=None, repr=False)

    @property
    def ok(self) -> bool:
        return self.registry is not None and not self.codes

    def discovery_public(self) -> dict | None:
        """Rend une copie JSON fraîche du rapport public."""

        if self._discovery_json is None:
            return None
        return json.loads(self._discovery_json)


@dataclass(frozen=True, slots=True)
class _ConfiguredRoot:
    root_id: str
    canonical_id: str
    path: str = field(repr=False)
    path_key: str = field(repr=False)


@dataclass(frozen=True, slots=True)
class _CacheEntry:
    state_digest: str
    registry: SkillRegistry
    discovery_json: str
    watchers: tuple[int, ...] = field(repr=False)


@dataclass(slots=True)
class _RuntimeState:
    roots: tuple[_ConfiguredRoot, ...]
    config_digest: str
    cache: dict[tuple[str, tuple[str, ...], str], _CacheEntry]
    lock: threading.RLock


class SkillRuntime:
    """Handle opaque d'une configuration et de son cache borné."""

    __slots__ = ("__weakref__",)

    def __init__(self, token: object) -> None:
        if token is not _RUNTIME_TOKEN:
            raise TypeError("SkillRuntime doit provenir de configure_skill_runtime")

    def __setattr__(self, name: str, value: object) -> None:
        raise AttributeError("SkillRuntime est immuable")


def _runtime_capability():
    issued: dict[
        int,
        tuple[weakref.ReferenceType[SkillRuntime], _RuntimeState],
    ] = {}

    def create(state: _RuntimeState) -> SkillRuntime:
        runtime = SkillRuntime(_RUNTIME_TOKEN)
        identifier = id(runtime)

        def discard(_reference, key=identifier):
            entry = issued.pop(key, None)
            if entry is not None:
                _clear_cache(entry[1])

        reference = weakref.ref(
            runtime,
            discard,
        )
        issued[identifier] = (reference, state)
        return runtime

    def state(value: object) -> _RuntimeState | None:
        entry = issued.get(id(value))
        if (type(value) is not SkillRuntime or entry is None
                or entry[0]() is not value):
            return None
        return entry[1]

    return create, state


_new_runtime, _runtime_state = _runtime_capability()
del _runtime_capability


def canonical_root_id(value: object) -> str | None:
    """Normalise un identifiant MCP de racine, jamais un chemin."""

    if type(value) is not str or value != value.strip():
        return None
    normalized = unicodedata.normalize("NFKC", value)
    key = canonical_skill_id(normalized)
    if key is None or redact_sensitive_text(normalized) != normalized:
        return None
    return key


def _path_key(path: str) -> str | None:
    try:
        real = os.path.realpath(path)
        return unicodedata.normalize(
            "NFKC",
            os.path.normcase(real),
        ).casefold()
    except (OSError, ValueError):
        return None


def _configured_root(entry: object) -> tuple[_ConfiguredRoot | None, str]:
    if type(entry) is not dict or set(entry) != {"id", "path"}:
        return None, "SKILL_ROOT_CONFIG"
    root_id = entry.get("id")
    path = entry.get("path")
    if type(root_id) is not str or type(path) is not str:
        return None, "SKILL_ROOT_CONFIG"

    normalized_id = unicodedata.normalize("NFKC", root_id)
    canonical_id = canonical_root_id(root_id)
    normalized_path = _valid_root_path(path)
    if canonical_id is None or normalized_path is None:
        return None, "SKILL_ROOT_CONFIG"
    if (_path_has_reparse_component(normalized_path)
            or not os.path.isdir(normalized_path)):
        return None, "SKILL_ROOT_CONFIG"
    try:
        root_stat = os.stat(normalized_path, follow_symlinks=False)
    except (OSError, ValueError):
        return None, "SKILL_ROOT_CONFIG"
    if not stat.S_ISDIR(root_stat.st_mode):
        return None, "SKILL_ROOT_CONFIG"

    key = _path_key(normalized_path)
    if key is None:
        return None, "SKILL_ROOT_CONFIG"
    return (
        _ConfiguredRoot(
            normalized_id,
            canonical_id,
            normalized_path,
            key,
        ),
        "",
    )


def configure_skill_runtime(entries: object) -> RuntimeBuildResult:
    """Construit une configuration privée depuis des entrées de confiance."""

    if (type(entries) not in (list, tuple)
            or not entries
            or len(entries) > DEFAULT_SKILL_LIMITS.max_roots):
        return RuntimeBuildResult(None, ("SKILL_ROOT_CONFIG",))

    roots: list[_ConfiguredRoot] = []
    ids: set[str] = set()
    paths: set[str] = set()
    for entry in entries:
        root, code = _configured_root(entry)
        if root is None:
            return RuntimeBuildResult(None, (code,))
        if root.canonical_id in ids or root.path_key in paths:
            return RuntimeBuildResult(None, ("SKILL_ROOT_DUPLICATE",))
        ids.add(root.canonical_id)
        paths.add(root.path_key)
        roots.append(root)

    roots.sort(key=lambda item: (item.canonical_id, item.root_id))
    digest_payload = [
        {
            "id": root.canonical_id,
            "path": root.path_key,
        }
        for root in roots
    ]
    config_digest = hashlib.sha256(json.dumps(
        digest_payload,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    state = _RuntimeState(
        tuple(roots),
        config_digest,
        {},
        threading.RLock(),
    )
    return RuntimeBuildResult(_new_runtime(state))


def _reject_duplicate_keys(pairs):
    result = {}
    seen = set()
    for key, value in pairs:
        if type(key) is not str:
            raise ValueError("clé invalide")
        normalized = unicodedata.normalize("NFKC", key)
        if normalized in seen:
            raise ValueError("clé dupliquée")
        seen.add(normalized)
        result[key] = value
    return result


def _reject_constant(_value):
    raise ValueError("constante invalide")


def load_skill_runtime_config(path: object) -> RuntimeBuildResult:
    """Charge une configuration JSON bornée au démarrage du serveur."""

    if type(path) is not str and not isinstance(path, os.PathLike):
        return RuntimeBuildResult(None, ("SKILL_ROOT_CONFIG",))
    try:
        filename = os.fspath(path)
    except Exception:
        return RuntimeBuildResult(None, ("SKILL_ROOT_CONFIG",))
    if (type(filename) is not str or not filename or "\x00" in filename
            or len(filename) > 32_767 or not os.path.isabs(filename)):
        return RuntimeBuildResult(None, ("SKILL_ROOT_CONFIG",))
    try:
        with open(filename, "rb") as handle:
            raw = handle.read(_MAX_CONFIG_BYTES + 1)
    except (OSError, ValueError):
        return RuntimeBuildResult(None, ("SKILL_ROOT_CONFIG",))
    if len(raw) > _MAX_CONFIG_BYTES:
        return RuntimeBuildResult(None, ("SKILL_ROOT_CONFIG",))
    try:
        document = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_constant,
        )
    except (UnicodeDecodeError, json.JSONDecodeError, ValueError,
            RecursionError):
        return RuntimeBuildResult(None, ("SKILL_ROOT_CONFIG",))
    if (type(document) is not dict
            or set(document) != {"config_version", "roots"}
            or document.get("config_version") != ROOT_CONFIG_VERSION):
        return RuntimeBuildResult(None, ("SKILL_ROOT_CONFIG",))
    return configure_skill_runtime(document.get("roots"))


def _selected_roots(
        state: _RuntimeState,
        root_ids: object,
        ) -> tuple[tuple[_ConfiguredRoot, ...] | None, tuple[str, ...]]:
    if (type(root_ids) not in (list, tuple)
            or not root_ids
            or len(root_ids) > DEFAULT_SKILL_LIMITS.max_roots):
        return None, ("SKILL_ROOT_ID",)
    selected_keys: set[str] = set()
    for value in root_ids:
        key = canonical_root_id(value)
        if key is None:
            return None, ("SKILL_ROOT_ID",)
        if key in selected_keys:
            return None, ("SKILL_ROOT_DUPLICATE",)
        selected_keys.add(key)
    by_id = {root.canonical_id: root for root in state.roots}
    if not selected_keys.issubset(by_id):
        return None, ("SKILL_ROOT_UNKNOWN",)
    return (
        tuple(by_id[key] for key in sorted(selected_keys)),
        (),
    )


def _state_digest(
        roots: tuple[_ConfiguredRoot, ...],
        ) -> tuple[str | None, str | None]:
    """Empreinte bornée des métadonnées, sans lire le contenu."""

    digest = hashlib.sha256()
    hashed_bytes = 0
    nodes = 0
    for root in roots:
        if (_path_has_reparse_component(root.path)
                or not os.path.isdir(root.path)):
            return None, "SKILL_CACHE_STATE"
        stack: list[tuple[str, str, int]] = [(root.path, "", 0)]
        pending_bytes = 0
        while stack:
            path, relative, depth = stack.pop()
            pending_bytes -= len(relative.encode("utf-8", "surrogatepass"))
            nodes += 1
            if nodes > _MAX_STATE_NODES or depth > _MAX_STATE_DEPTH:
                return None, "SKILL_CACHE_LIMIT"
            try:
                info = os.lstat(path)
                if _is_reparse_point(path):
                    return None, "SKILL_CACHE_STATE"
            except (OSError, ValueError):
                return None, "SKILL_CACHE_STATE"

            if stat.S_ISDIR(info.st_mode):
                kind = "d"
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1:
                    return None, "SKILL_CACHE_STATE"
                kind = "f"
            else:
                return None, "SKILL_CACHE_STATE"
            record = (
                root.canonical_id,
                relative,
                kind,
                info.st_mode,
                info.st_size,
                info.st_mtime_ns,
                info.st_ctime_ns,
                info.st_dev,
                info.st_ino,
                info.st_nlink,
            )
            encoded = json.dumps(
                record,
                ensure_ascii=True,
                allow_nan=False,
                separators=(",", ":"),
            ).encode("utf-8") + b"\n"
            hashed_bytes += len(encoded)
            if hashed_bytes > _MAX_STATE_BYTES:
                return None, "SKILL_CACHE_LIMIT"
            digest.update(encoded)
            if kind != "d":
                continue
            try:
                with os.scandir(path) as iterator:
                    entries = []
                    for index, entry in enumerate(iterator, 1):
                        if index > _MAX_STATE_ENTRIES_PER_DIRECTORY:
                            return None, "SKILL_CACHE_LIMIT"
                        entries.append(entry.name)
            except (OSError, ValueError):
                return None, "SKILL_CACHE_STATE"
            entries.sort(key=lambda value: (
                unicodedata.normalize("NFKC", value).casefold(),
                value,
            ))
            if nodes + len(stack) + len(entries) > _MAX_STATE_NODES:
                return None, "SKILL_CACHE_LIMIT"
            for name in reversed(entries):
                child_relative = (
                    name if not relative else f"{relative}/{name}")
                pending_bytes += len(child_relative.encode(
                    "utf-8",
                    "surrogatepass",
                ))
                if pending_bytes > _MAX_STATE_BYTES:
                    return None, "SKILL_CACHE_LIMIT"
                stack.append((
                    os.path.join(path, name),
                    child_relative,
                    depth + 1,
                ))

    return digest.hexdigest(), None


def _close_watchers(watchers: tuple[int, ...]) -> None:
    if os.name != "nt":
        return
    for handle in watchers:
        try:
            _FIND_CLOSE_CHANGE(handle)
        except (OSError, ValueError):
            pass


def _create_watchers(
        roots: tuple[_ConfiguredRoot, ...],
        ) -> tuple[int, ...] | None:
    """Arme une notification récursive avant l'installation du cache."""

    if os.name != "nt":
        return ()
    # Noms, dossiers, attributs, taille, écriture, création et sécurité.
    notify_filter = 0x0000015F
    invalid_handle = ctypes.c_void_p(-1).value
    handles: list[int] = []
    for root in roots:
        try:
            handle = _FIND_FIRST_CHANGE(
                root.path,
                True,
                notify_filter,
            )
        except (OSError, ValueError):
            handle = None
        if handle in (None, invalid_handle):
            _close_watchers(tuple(handles))
            return None
        handles.append(handle)
    return tuple(handles)


def _watchers_changed(watchers: tuple[int, ...]) -> bool | None:
    """Vrai si Windows a observé un changement, None si le contrôle échoue."""

    if os.name != "nt":
        return False
    wait_object = 0
    wait_timeout = 258
    for handle in watchers:
        try:
            result = _WAIT_FOR_SINGLE_OBJECT(handle, 0)
        except (OSError, ValueError):
            return None
        if result == wait_object:
            return True
        if result != wait_timeout:
            return None
    return False


def _guarded_state_digest(
        roots: tuple[_ConfiguredRoot, ...],
        ) -> tuple[tuple[int, ...] | None, str | None, str | None]:
    """Arme puis stabilise une vue sans fenêtre avant le premier digest."""

    for _attempt in range(3):
        watchers = _create_watchers(roots)
        if watchers is None:
            return None, None, "SKILL_CACHE_STATE"
        digest, code = _state_digest(roots)
        if code is not None:
            _close_watchers(watchers)
            return None, None, code
        changed = _watchers_changed(watchers)
        if changed is None:
            _close_watchers(watchers)
            return None, None, "SKILL_CACHE_STATE"
        if changed:
            _close_watchers(watchers)
            continue
        return watchers, digest, None
    return None, None, "SKILL_CACHE_UNSTABLE"


def _remove_cache_entry(
        state: _RuntimeState,
        key: tuple[str, tuple[str, ...], str],
        ) -> None:
    entry = state.cache.pop(key, None)
    if entry is not None:
        _close_watchers(entry.watchers)


def _clear_cache(state: _RuntimeState) -> None:
    with state.lock:
        entries = tuple(state.cache.values())
        state.cache.clear()
    for entry in entries:
        _close_watchers(entry.watchers)


def _discovery_json(discovery) -> str:
    return json.dumps(
        discovery.to_public(),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )


def resolve_skill_registry(
        runtime: object,
        root_ids: object,
        today: datetime.date | None = None,
        *,
        refresh: bool = False,
        ) -> RuntimeRegistryResult:
    """Résout un registre validé et cache sa copie scellée.

    Une modification observable invalide l'entrée. La reconstruction remplace
    l'entrée seulement après validation complète.
    """

    state = _runtime_state(runtime)
    if state is None:
        return RuntimeRegistryResult(None, ("SKILL_ROOT_CONFIG",))
    if today is None:
        return RuntimeRegistryResult(None, ("TODAY_REQUIRED",))
    if type(today) is not datetime.date:
        return RuntimeRegistryResult(None, ("TODAY_INVALID",))
    if type(refresh) is not bool:
        return RuntimeRegistryResult(None, ("SKILL_CACHE",))
    roots, codes = _selected_roots(state, root_ids)
    if roots is None:
        return RuntimeRegistryResult(None, codes)
    key = (
        state.config_digest,
        tuple(root.canonical_id for root in roots),
        today.isoformat(),
    )

    with state.lock:
        if refresh:
            _remove_cache_entry(state, key)
        if key not in state.cache and len(state.cache) >= _MAX_CACHE_ENTRIES:
            oldest = next(iter(state.cache))
            _remove_cache_entry(state, oldest)

        guard_watchers, before, guard_code = _guarded_state_digest(roots)
        if guard_code is not None:
            _remove_cache_entry(state, key)
            return RuntimeRegistryResult(
                None,
                (guard_code,),
            )

        cached = state.cache.get(key)
        if cached is not None:
            changed = _watchers_changed(cached.watchers)
            if changed is None:
                _close_watchers(guard_watchers)
                _remove_cache_entry(state, key)
                return RuntimeRegistryResult(
                    None,
                    ("SKILL_CACHE_STATE",),
                )
            if changed:
                _remove_cache_entry(state, key)
                cached = None

        guard_changed = _watchers_changed(guard_watchers)
        if guard_changed is None:
            _close_watchers(guard_watchers)
            _remove_cache_entry(state, key)
            return RuntimeRegistryResult(
                None,
                ("SKILL_CACHE_STATE",),
            )
        if guard_changed:
            _close_watchers(guard_watchers)
            _remove_cache_entry(state, key)
            return RuntimeRegistryResult(
                None,
                ("SKILL_CACHE_UNSTABLE",),
            )

        if cached is not None:
            changed = _watchers_changed(cached.watchers)
            if changed is None:
                _close_watchers(guard_watchers)
                _remove_cache_entry(state, key)
                return RuntimeRegistryResult(
                    None,
                    ("SKILL_CACHE_STATE",),
                )
            if not changed and cached.state_digest == before:
                _close_watchers(guard_watchers)
                return RuntimeRegistryResult(
                    cached.registry,
                    _discovery_json=cached.discovery_json,
                )
            _remove_cache_entry(state, key)

        discovery = discover_skills(
            [root.path for root in roots],
            today,
        )
        public_json = _discovery_json(discovery)
        if not discovery.complete:
            _close_watchers(guard_watchers)
            return RuntimeRegistryResult(
                None,
                tuple(sorted(set(discovery.fatal_codes))),
                public_json,
            )
        built = build_registry(discovery)
        if not built.ok:
            _close_watchers(guard_watchers)
            return RuntimeRegistryResult(
                None,
                tuple(sorted({issue.code for issue in built.issues})),
                public_json,
            )
        after, state_code = _state_digest(roots)
        changed = _watchers_changed(guard_watchers)
        if (state_code is not None or after != before
                or changed is not False):
            _close_watchers(guard_watchers)
            return RuntimeRegistryResult(
                None,
                ("SKILL_CACHE_UNSTABLE",),
                public_json,
            )
        entry = _CacheEntry(
            after,
            built.registry,
            public_json,
            guard_watchers,
        )
        state.cache[key] = entry
        return RuntimeRegistryResult(
            entry.registry,
            _discovery_json=entry.discovery_json,
        )
