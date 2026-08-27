"""phases-agents — MCP local de selection de skills, en stdlib pure.

Le serveur decouvre, valide, selectionne et transporte des skills. Il
n'execute jamais leur contenu metier. Le LLM appelant conserve cette
responsabilite.
"""

from __future__ import annotations

import datetime
import json
import math
import os
import re
import sys
import traceback
import unicodedata
from copy import deepcopy
from typing import Any

from capabilities import (
    CLIENT_CAPABILITIES,
    MAX_CLIENT_CAPABILITIES,
    MAX_CLIENT_CAPABILITY_CHARS,
    normalize_client_capabilities,
)
from detector import detect_profile
from planner import build_b3_plan, build_plan
from registry import get_skill, list_skills
from skill_runtime import (
    SkillRuntime,
    canonical_root_id,
    load_skill_runtime_config,
    resolve_skill_registry,
)
from skill_types import canonical_skill_id
from validator import redact_sensitive_text

PROTOCOL_VERSION = "2024-11-05"
SUPPORTED_PROTOCOL_VERSIONS = (
    PROTOCOL_VERSION,
    "2025-06-18",
    "2025-11-25",
)
SERVER_NAME = "phases-agents"
SERVER_VERSION = "0.5.0"

USAGE = """\
phases-agents — serveur MCP local de sélection déterministe de skills.

Usage :
  python server.py --skills-config <chemin.json>   démarre le serveur stdio
  python server.py --help                          affiche cette aide
  python server.py --version                       affiche la version

Le serveur parle JSON-RPC 2.0 sur stdin/stdout, une requête par ligne.
Il découvre, valide et sélectionne des skills ; il n'en exécute aucun.

Le fichier de configuration déclare les racines de skills autorisées.
Un modèle est fourni dans skills-roots.template.json.

Une configuration illisible ou invalide arrête le serveur avec le code 2.
Sans argument, le serveur démarre mais aucune racine n'est disponible :
seul detect fonctionne, les autres outils rendent SKILL_ROOT_CONFIG.
"""
_MAX_REQUEST_BYTES = 1 * 1024 * 1024
_MAX_TOOL_RESULT_BYTES = 1 * 1024 * 1024
_MAX_RESPONSE_BYTES = 1 * 1024 * 1024
_MAX_REQUEST_DEPTH = 200
_MAX_REQUEST_NODES = 100_000
_MAX_TARGET_CHARS = 32_767
_MAX_INTEGER_DIGITS = 100
_MAX_ROOTS = 16
_MAX_CONSTRAINT_ITEMS = 100
_MAX_CONSTRAINT_CHARS = 128
_TECHNICAL_OUTPUT_FIELDS = {
    "action",
    "capability",
    "client_capabilities",
    "codes",
    "error_codes",
    "facts",
    "fatal_codes",
    "gap_id",
    "gate",
    "issues",
    "limitations",
    "missing_capabilities",
    "optional_capabilities",
    "plan_status",
    "plan_version",
    "position",
    "reason_codes",
    "reason_code",
    "required_capabilities",
    "required_facts",
    "severity",
    "skill_id",
    "state",
    "validation_level",
    "warnings",
}
_WINDOWS_ABSOLUTE_RE = re.compile(
    r"(?i)(?<![\w])(?:[a-z]:[\\/])[^<>\"'\r\n]*")
_UNC_ABSOLUTE_RE = re.compile(
    r"(?<![\\])\\\\[^<>\"'\r\n]*")
_SLASH_UNC_ABSOLUTE_RE = re.compile(
    r"(?<![/:])//[^<>\"'\r\n]*")
_FILE_URI_ABSOLUTE_RE = re.compile(
    r"(?i)\bfile:///(?:[^/\s<>\"']+(?:/[^/\s<>\"']*)*)")
_POSIX_ABSOLUTE_RE = re.compile(
    r"""(?:^|(?<=[\s(=,:;'"]))/(?:[^/\s<>"']+(?:/[^/\s<>"']*)*)""")

_ROOT_IDS_SCHEMA = {
    "type": "array",
    "items": {
        "type": "string",
        "maxLength": 64,
    },
    "minItems": 1,
    "maxItems": _MAX_ROOTS,
}
_TODAY_SCHEMA = {
    "type": "string",
    "minLength": 10,
    "maxLength": 10,
    "description": "Date ISO YYYY-MM-DD injectee.",
}
_CONSTRAINTS_SCHEMA = {
    "type": "object",
    "properties": {
        name: {
            "type": "array",
            "items": {
                "type": "string",
                "maxLength": _MAX_CONSTRAINT_CHARS,
            },
            "maxItems": _MAX_CONSTRAINT_ITEMS,
        }
        for name in ("platforms", "domains", "capabilities")
    },
    "additionalProperties": False,
}
_CLIENT_CAPABILITIES_SCHEMA = {
    "type": "array",
    "items": {
        "type": "string",
        "enum": list(CLIENT_CAPABILITIES),
        "maxLength": MAX_CLIENT_CAPABILITY_CHARS,
    },
    "maxItems": MAX_CLIENT_CAPABILITIES,
    "uniqueItems": True,
}

TOOL_DETECT = {
    "name": "phases_agents_detect",
    "description": (
        "Detecte localement le profil borne d'une cible. "
        "N'execute aucun fichier."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "target": {
                "type": "string",
                "maxLength": _MAX_TARGET_CHARS,
                "description": "Chemin absolu local du projet.",
            },
        },
        "required": ["target"],
        "additionalProperties": False,
    },
}
TOOL_LIST_SKILLS = {
    "name": "phases_agents_list_skills",
    "description": (
        "Decouvre et liste uniquement les packages de skills valides."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "root_ids": _ROOT_IDS_SCHEMA,
            "today": _TODAY_SCHEMA,
        },
        "required": ["root_ids", "today"],
        "additionalProperties": False,
    },
}
TOOL_GET_SKILL = {
    "name": "phases_agents_get_skill",
    "description": (
        "Retourne le contenu borne d'un skill valide par identifiant. "
        "Aucun chemin libre n'est accepte."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "root_ids": _ROOT_IDS_SCHEMA,
            "skill_id": {
                "type": "string",
                "maxLength": 64,
            },
            "today": _TODAY_SCHEMA,
        },
        "required": ["root_ids", "skill_id", "today"],
        "additionalProperties": False,
    },
}
TOOL_PLAN = {
    "name": "phases_agents_plan",
    "description": (
        "Detecte une cible, charge le registre valide et rend un plan "
        "deterministe. N'execute aucun skill."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "client_capabilities": _CLIENT_CAPABILITIES_SCHEMA,
            "constraints": _CONSTRAINTS_SCHEMA,
            "plan_version": {
                "type": "string",
                "enum": ["1.0", "B3"],
            },
            "root_ids": _ROOT_IDS_SCHEMA,
            "target": {
                "type": "string",
                "maxLength": _MAX_TARGET_CHARS,
                "description": "Chemin absolu local du projet.",
            },
            "today": _TODAY_SCHEMA,
        },
        "required": ["root_ids", "target", "today"],
        "additionalProperties": False,
    },
}
TOOL_REFRESH_SKILLS = {
    "name": "phases_agents_refresh_skills",
    "description": (
        "Reconstruit explicitement un registre depuis les racines autorisees."
    ),
    "inputSchema": {
        "type": "object",
        "properties": {
            "root_ids": _ROOT_IDS_SCHEMA,
            "today": _TODAY_SCHEMA,
        },
        "required": ["root_ids", "today"],
        "additionalProperties": False,
    },
}
_TOOLS = {
    tool["name"]: tool
    for tool in (
        TOOL_DETECT,
        TOOL_GET_SKILL,
        TOOL_LIST_SKILLS,
        TOOL_PLAN,
        TOOL_REFRESH_SKILLS,
    )
}


def _bounded_rpc_response(response: dict) -> dict:
    """Garantit qu'une réponse API est aussi transportable sur stdio."""

    try:
        encoded = json.dumps(
            response,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        encoded = b""
    if encoded and len(encoded) + 1 <= _MAX_RESPONSE_BYTES:
        return response
    return {
        "jsonrpc": "2.0",
        "id": response.get("id") if type(response) is dict else None,
        "error": {
            "code": -32603,
            "message": "Internal error: response too large",
        },
    }


def _result(request_id: Any, payload: dict) -> dict:
    return _bounded_rpc_response(
        {"jsonrpc": "2.0", "id": request_id, "result": payload})


def _error(request_id: Any, code: int, message: str) -> dict:
    return _bounded_rpc_response({
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    })


def _json_value_error(value) -> str | None:
    """Controle iteratif des appels directs.

    Le transport impose deja un Mio. Cette garde applique la meme enveloppe
    aux appels Python, detecte les cycles et refuse les types non JSON.
    """
    stack = [(value, 0, False)]
    active: set[int] = set()
    nodes = 0
    logical_bytes = 0
    while stack:
        item, depth, leaving = stack.pop()
        if leaving:
            active.discard(id(item))
            continue
        nodes += 1
        if nodes > _MAX_REQUEST_NODES:
            return "request too large"
        if depth > _MAX_REQUEST_DEPTH:
            return "request too deep"
        if type(item) is str:
            if any(unicodedata.category(ch) == "Cs" for ch in item):
                return "invalid Unicode"
            logical_bytes += len(item.encode("utf-8")) + 2
        elif item is None:
            logical_bytes += 4
        elif type(item) is bool:
            logical_bytes += 5
        elif type(item) is int:
            digits = (
                1 if item == 0
                else (abs(item).bit_length() * 30_103) // 100_000 + 1
            )
            if digits > _MAX_INTEGER_DIGITS:
                return "integer too large"
            logical_bytes += digits + (1 if item < 0 else 0)
        elif type(item) is float:
            if not math.isfinite(item):
                return "non-finite number"
            logical_bytes += len(repr(item))
        elif type(item) in (dict, list):
            identity = id(item)
            if identity in active:
                return "cyclic request"
            active.add(identity)
            stack.append((item, depth, True))
            logical_bytes += 2
            if len(item) > _MAX_REQUEST_NODES - nodes:
                return "request too large"
            if type(item) is dict:
                if any(type(key) is not str for key in item):
                    return "non-string object key"
                for key in item:
                    if any(unicodedata.category(ch) == "Cs" for ch in key):
                        return "invalid Unicode"
                    logical_bytes += len(key.encode("utf-8")) + 3
                    if logical_bytes > _MAX_REQUEST_BYTES:
                        return "request too large"
                for key in sorted(item, reverse=True):
                    stack.append((item[key], depth + 1, False))
            else:
                for child in reversed(item):
                    stack.append((child, depth + 1, False))
        else:
            return "non-JSON value"
        if logical_bytes > _MAX_REQUEST_BYTES:
            return "request too large"
    try:
        encoded = json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError, UnicodeError, RecursionError):
        return "non-JSON value"
    if len(encoded) > _MAX_REQUEST_BYTES:
        return "request too large"
    return None


def _valid_request_id(value) -> bool:
    if value is None:
        return True
    if type(value) is bool:
        return False
    if type(value) is int:
        return -(2 ** 53 - 1) <= value <= 2 ** 53 - 1
    if type(value) is str:
        return (
            len(value) <= 128
            and redact_sensitive_text(value) == value
        )
    return False


def _safe_response_id(message: dict) -> Any:
    """Rend uniquement un identifiant JSON-RPC renvoyable sans fuite.

    Toute branche de reponse, y compris une erreur de version, doit utiliser
    cette valeur deja neutralisee. Un identifiant absent, invalide ou sensible
    devient ``null`` dans la reponse.
    """
    if "id" not in message:
        return None
    candidate = message["id"]
    return candidate if _valid_request_id(candidate) else None


def _valid_local_target(target: str) -> bool:
    # Un chemin DESIGNE, il ne contient pas de preuve : la detection de
    # secrets ne s'applique pas ici. Un chemin legitime peut porter 16+
    # chiffres consecutifs (horodatage, identifiant) ; le refuser rendait le
    # projet inauditable sans proteger personne, puisque les sorties masquent
    # deja secrets et chemins absolus (detect_profile.public_target,
    # _sanitize_public_text). La validation STRUCTURELLE reste entiere.
    if (type(target) is not str or not target.strip()
            or len(target) > _MAX_TARGET_CHARS):
        return False
    if any(unicodedata.category(ch) in ("Cc", "Cf", "Cs") for ch in target):
        return False
    if target.startswith(("\\\\", "//", "\\\\?\\")):
        return False
    return os.path.isabs(target)


def _parse_today(value: object) -> datetime.date | None:
    if type(value) is not str or len(value) != 10:
        return None
    try:
        parsed = datetime.date.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.isoformat() == value else None


def _valid_root_ids(value: object) -> bool:
    return (
        type(value) is list
        and 1 <= len(value) <= _MAX_ROOTS
        and all(canonical_root_id(root) is not None for root in value)
        and len({
            canonical_root_id(root)
            for root in value
        }) == len(value)
    )


def _valid_string_list(value: object) -> bool:
    return (
        type(value) is list
        and len(value) <= _MAX_CONSTRAINT_ITEMS
        and all(
            type(item) is str
            and item
            and len(item) <= _MAX_CONSTRAINT_CHARS
            and item == item.strip()
            and redact_sensitive_text(item) == item
            and not any(
                unicodedata.category(char) in {"Cc", "Cf", "Cs"}
                for char in item
            )
            for item in value
        )
    )


def _valid_constraints(value: object) -> bool:
    if value is None:
        return True
    if type(value) is not dict:
        return False
    if set(value) - {"platforms", "domains", "capabilities"}:
        return False
    return all(_valid_string_list(item) for item in value.values())


def _valid_initialize_params(value: object) -> bool:
    """Valide l'initialisation MCP réellement supportée."""

    if type(value) is not dict or set(value) != {
            "protocolVersion", "capabilities", "clientInfo"}:
        return False
    if value.get("protocolVersion") not in SUPPORTED_PROTOCOL_VERSIONS:
        return False
    capabilities = value.get("capabilities")
    client = value.get("clientInfo")
    client_fields = {
        "description",
        "name",
        "title",
        "version",
        "websiteUrl",
    }
    return (
        type(capabilities) is dict
        and type(client) is dict
        and {"name", "version"} <= set(client) <= client_fields
        and all(
            type(client[field]) is str
            and 0 < len(client[field]) <= 256
            and client[field] == client[field].strip()
            for field in client
        )
    )


def _valid_request_meta(value: object) -> bool:
    """Valide les métadonnées MCP observées."""

    if (
        type(value) is not dict
        or len(value) > 16
        or any(
            type(key) is not str
            or re.fullmatch(r"[A-Za-z0-9_./:-]{1,128}", key) is None
            for key in value
        )
    ):
        return False
    if "progressToken" not in value:
        return True
    token = value["progressToken"]
    if type(token) is int:
        return 0 <= token <= 9_007_199_254_740_991
    return (
        type(token) is str
        and 0 < len(token) <= 128
        and token == token.strip()
        and redact_sensitive_text(token) == token
    )


def _valid_tools_list_params(value: object) -> bool:
    if value in (None, {}):
        return True
    return (
        type(value) is dict
        and set(value) == {"_meta"}
        and _valid_request_meta(value["_meta"])
    )


def _public_profile(profile: dict) -> dict:
    return {
        "blocked": profile.get("blocked") is True,
        "exists": profile.get("exists") is True,
        "issues": sorted(set(
            item for item in profile.get("issues", [])
            if isinstance(item, str)
        )),
        "languages": sorted(set(
            item for item in profile.get("languages", [])
            if isinstance(item, str)
        )),
        "facts": sorted(set(
            item for item in profile.get("facts", [])
            if isinstance(item, str)
        )),
        "markers": {
            key: sorted(set(values))
            for key, values in sorted(profile.get("markers", {}).items())
            if isinstance(key, str) and isinstance(values, list)
            and all(isinstance(value, str) for value in values)
        },
        "types": sorted(set(
            item for item in profile.get("types", [])
            if isinstance(item, str)
        )),
    }


def _sanitize_public_text(value: str) -> str:
    """Masque secrets et chemins absolus dans toute sortie de tool."""

    text = redact_sensitive_text(value)
    for pattern in (
            _FILE_URI_ABSOLUTE_RE,
            _WINDOWS_ABSOLUTE_RE,
            _UNC_ABSOLUTE_RE,
            _SLASH_UNC_ABSOLUTE_RE,
            _POSIX_ABSOLUTE_RE):
        text = pattern.sub("<chemin-local-masque>", text)
    return text


def _sanitize_public_value(value, technical: bool = False):
    if type(value) is str:
        if technical:
            return value
        return _sanitize_public_text(value)
    if type(value) is list:
        return [
            _sanitize_public_value(item, technical)
            for item in value
        ]
    if type(value) is dict:
        return {
            key: _sanitize_public_value(
                item,
                key in _TECHNICAL_OUTPUT_FIELDS,
            )
            for key, item in value.items()
        }
    return value


def _tool_envelope(payload: dict, is_error: bool = False) -> dict:
    payload = _sanitize_public_value(payload)
    text = json.dumps(
        payload,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    if len(text.encode("utf-8")) > _MAX_TOOL_RESULT_BYTES:
        text = json.dumps(
            {"code": "RESULT_TOO_LARGE"},
            sort_keys=True,
            separators=(",", ":"),
        )
        is_error = True
    return {
        "content": [{"type": "text", "text": text}],
        "isError": is_error,
    }


def _business_error(*codes: str, details: dict | None = None) -> dict:
    payload = {
        "codes": sorted(set(codes)),
    }
    if details:
        payload.update(details)
    return _tool_envelope(payload, True)


def _load_registry_for_tool(
        runtime: SkillRuntime | None,
        root_ids: list[str],
        today: datetime.date,
        *,
        refresh: bool = False,
        ):
    loaded = resolve_skill_registry(
        runtime,
        root_ids,
        today,
        refresh=refresh,
    )
    discovery = loaded.discovery_public()
    if not loaded.ok:
        details = (
            {"discovery": discovery}
            if discovery is not None else None
        )
        return None, discovery, _business_error(
            *loaded.codes,
            details=details,
        )
    return loaded.registry, discovery, None


def _dispatch_tool(
        name: str,
        arguments: dict,
        runtime: SkillRuntime | None = None,
        ) -> tuple[dict | None, str | None]:
    """Rend l'enveloppe MCP, ou une erreur de parametres."""

    definitions = {
        TOOL_DETECT["name"]: (
            {"target"},
            {"target"},
        ),
        TOOL_LIST_SKILLS["name"]: (
            {"root_ids", "today"},
            {"root_ids", "today"},
        ),
        TOOL_GET_SKILL["name"]: (
            {"root_ids", "skill_id", "today"},
            {"root_ids", "skill_id", "today"},
        ),
        TOOL_PLAN["name"]: (
            {
                "client_capabilities",
                "constraints",
                "plan_version",
                "root_ids",
                "target",
                "today",
            },
            {"root_ids", "target", "today"},
        ),
        TOOL_REFRESH_SKILLS["name"]: (
            {"root_ids", "today"},
            {"root_ids", "today"},
        ),
    }
    allowed, required = definitions[name]
    if set(arguments) - allowed:
        return None, "Invalid params: unknown argument"
    if not required.issubset(arguments):
        return None, "Invalid params: required argument missing"

    target = arguments.get("target")
    if "target" in allowed and not _valid_local_target(target):
        return None, "Invalid params: absolute local 'target' is required"
    root_ids = arguments.get("root_ids")
    if "root_ids" in allowed and not _valid_root_ids(root_ids):
        return None, "Invalid params: 'root_ids' must contain safe identifiers"
    today = (
        _parse_today(arguments.get("today"))
        if "today" in allowed else None
    )
    if "today" in allowed and today is None:
        return None, "Invalid params: valid ISO 'today' is required"
    constraints = arguments.get("constraints")
    if "constraints" in arguments and not _valid_constraints(constraints):
        return None, "Invalid params: invalid constraints"
    plan_version = arguments.get("plan_version", "1.0")
    if (type(plan_version) is not str
            or plan_version not in {"1.0", "B3"}):
        return None, "Invalid params: invalid plan_version"
    if (
            plan_version != "B3"
            and "client_capabilities" in arguments):
        return None, (
            "Invalid params: client_capabilities require plan_version B3"
        )
    if plan_version == "B3" and "constraints" in arguments:
        return None, (
            "Invalid params: B3 uses client_capabilities, not constraints"
        )
    client_capabilities = arguments.get("client_capabilities")
    if "client_capabilities" in arguments:
        normalized_capabilities, capability_error = (
            normalize_client_capabilities(client_capabilities)
        )
        if capability_error is not None:
            return None, "Invalid params: invalid client_capabilities"
        client_capabilities = list(normalized_capabilities)
    skill_id = arguments.get("skill_id")
    if ("skill_id" in allowed
            and canonical_skill_id(skill_id) is None):
        return None, "Invalid params: invalid skill_id"

    if name == TOOL_DETECT["name"]:
        profile = detect_profile(target)
        public = _public_profile(profile)
        is_error = not public["exists"] or public["blocked"]
        return _tool_envelope({"profile": public}, is_error), None

    registry, discovery, load_error = _load_registry_for_tool(
        runtime,
        root_ids,
        today,
        refresh=name == TOOL_REFRESH_SKILLS["name"],
    )
    if load_error is not None:
        return load_error, None

    if name == TOOL_REFRESH_SKILLS["name"]:
        return _tool_envelope({
            "discovery": discovery,
            "refreshed": True,
        }), None

    if name == TOOL_LIST_SKILLS["name"]:
        listed = list_skills(registry)
        if not listed.ok:
            return _business_error(
                *(issue.code for issue in listed.issues)), None
        return _tool_envelope({
            "discovery": discovery,
            "skills": [
                summary.to_public()
                for summary in listed.skills
            ],
        }), None

    if name == TOOL_GET_SKILL["name"]:
        found = get_skill(registry, skill_id)
        if not found.ok:
            return _business_error(
                *(issue.code for issue in found.issues),
                details={"discovery": discovery},
            ), None
        summary = found.skill.summary()
        summary.update({
            "content": found.skill.content,
            "validation_level": "STRUCTURALLY_VALIDATED",
        })
        return _tool_envelope({
            "discovery": discovery,
            "skill": summary,
        }), None

    profile = detect_profile(target)
    public_profile = _public_profile(profile)
    if not public_profile["exists"] or public_profile["blocked"]:
        codes = public_profile["issues"] or ["PROJECT_TARGET"]
        return _business_error(
            *codes,
            details={"profile": public_profile},
        ), None
    planned = (
        build_b3_plan(
            profile,
            registry,
            client_capabilities=(
                client_capabilities
                if "client_capabilities" in arguments
                else None
            ),
        )
        if plan_version == "B3"
        else build_plan(profile, registry, constraints)
    )
    if not planned.ok:
        return _business_error(
            *(issue.code for issue in planned.issues),
            details={"discovery": discovery},
        ), None
    return _tool_envelope({
        "discovery": discovery,
        "plan": planned.plan.to_public(),
    }), None


def handle_message(
        message: dict,
        runtime: SkillRuntime | None = None,
        ) -> dict | None:
    """Traite un message JSON-RPC. Rend la réponse, ou None pour une notification.

    Séparé du transport pour être testable sans stdio.
    """
    payload_error = _json_value_error(message)
    if payload_error is not None:
        suffix = (
            "request too large"
            if payload_error == "request too large"
            else "unsafe JSON payload"
        )
        return _error(None, -32600, f"Invalid Request: {suffix}")

    # Un message JSON-RPC DOIT être un objet. Un tableau/scalaire (ex: `[]`)
    # n'a pas de .get() : on refuse proprement au lieu de crasher.
    if type(message) is not dict:
        return _error(None, -32600, "Invalid Request: message must be a JSON object")

    request_id = _safe_response_id(message)
    if message.get("jsonrpc") != "2.0":
        return _error(request_id, -32600, "Invalid Request: jsonrpc must be '2.0'")

    allowed_message_keys = {"jsonrpc", "id", "method", "params"}
    if set(message) - allowed_message_keys:
        return _error(None, -32600, "Invalid Request: unknown member")

    method = message.get("method")
    if type(method) is not str or not method:
        return _error(None, -32600, "Invalid Request: method must be a string")
    if "id" in message and not _valid_request_id(message["id"]):
        return _error(None, -32600, "Invalid Request: invalid id")

    # JSON-RPC 2.0 : une notification (message sans "id") ne reçoit JAMAIS de
    # réponse, quelle que soit la méthode. On traite l'éventuel effet de bord
    # (aucun ici) puis on rend None avant tout dispatch qui répondrait.
    if "id" not in message:
        return None

    if method == "initialize":
        if not _valid_initialize_params(message.get("params")):
            return _error(
                request_id,
                -32602,
                "Invalid params: initialize fields are required",
            )
        return _result(
            request_id,
            {
                "protocolVersion": message["params"]["protocolVersion"],
                "capabilities": {"tools": {}},
                "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
            },
        )

    if method == "ping":
        if "params" in message and message["params"] not in ({}, None):
            return _error(request_id, -32602, "Invalid params: ping takes no arguments")
        # Spec MCP : ping répond toujours avec un résultat vide.
        return _result(request_id, {})

    if method == "tools/list":
        if not _valid_tools_list_params(message.get("params")):
            return _error(request_id, -32602, "Invalid params: tools/list takes no arguments")
        tools = [
            deepcopy(_TOOLS[name])
            for name in sorted(_TOOLS)
        ]
        return _result(request_id, {"tools": tools})

    if method == "tools/call":
        params = message.get("params", {})
        if type(params) is not dict:
            return _error(request_id, -32602, "Invalid params: expected an object")
        if set(params) - {"name", "arguments", "_meta"}:
            return _error(request_id, -32602, "Invalid params: unknown member")
        if "_meta" in params and not _valid_request_meta(params["_meta"]):
            return _error(request_id, -32602, "Invalid params: invalid _meta")
        name = params.get("name")
        if type(name) is not str or name not in _TOOLS:
            return _error(request_id, -32602, "Unknown tool")
        arguments = params.get("arguments", {})
        if type(arguments) is not dict:
            return _error(request_id, -32602, "Invalid params: arguments must be an object")
        payload, parameter_error = _dispatch_tool(name, arguments, runtime)
        if parameter_error is not None:
            return _error(request_id, -32602, parameter_error)
        return _result(request_id, payload)

    return _error(request_id, -32601, "Method not found")


def _reject_duplicate_keys(pairs):
    result = {}
    seen = set()
    for key, value in pairs:
        normalized = unicodedata.normalize("NFKC", key)
        if normalized in seen:
            raise ValueError("duplicate key")
        seen.add(normalized)
        result[key] = value
    return result


def _reject_constant(value):
    raise ValueError("non-standard JSON constant")


def _encode_response(response: dict) -> str:
    return json.dumps(
        response,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ) + "\n"


def _write_response(response: dict) -> bool:
    try:
        sys.stdout.write(_encode_response(response))
        sys.stdout.flush()
        return True
    except (BrokenPipeError, OSError, UnicodeError, ValueError):
        return False


def _startup_runtime(
        arguments: list[str],
        ) -> tuple[SkillRuntime | None, bool]:
    if not arguments:
        return None, True
    if len(arguments) != 2 or arguments[0] != "--skills-config":
        return None, False
    built = load_skill_runtime_config(arguments[1])
    return built.runtime, built.ok


def _write_startup_text(text: str) -> int:
    """Écrit une sortie de démarrage sur stdout sans jamais lever."""

    try:
        sys.stdout.write(text)
        sys.stdout.flush()
    except (BrokenPipeError, OSError, UnicodeError):
        return 2
    return 0


def main(arguments: list[str] | None = None) -> int:
    """Boucle stdio : une requête JSON par ligne, une réponse par ligne."""

    startup_arguments = (
        list(sys.argv[1:])
        if arguments is None else arguments
    )
    if startup_arguments and startup_arguments[0] in ("--help", "-h"):
        return _write_startup_text(USAGE)
    if startup_arguments and startup_arguments[0] == "--version":
        return _write_startup_text(f"{SERVER_NAME} {SERVER_VERSION}\n")
    runtime, configured = _startup_runtime(startup_arguments)
    if not configured:
        try:
            sys.stderr.write("Invalid skills configuration\n")
            sys.stderr.flush()
        except (BrokenPipeError, OSError, UnicodeError):
            pass
        return 2

    source = sys.stdin.buffer
    while True:
        raw = source.readline(_MAX_REQUEST_BYTES + 2)
        if not raw:
            return 0
        if len(raw) > _MAX_REQUEST_BYTES:
            while raw and not raw.endswith(b"\n"):
                raw = source.readline(_MAX_REQUEST_BYTES + 2)
            if not _write_response(_error(
                    None, -32600, "Invalid Request: request too large")):
                return 0
            continue
        try:
            line = raw.decode("utf-8").strip()
        except UnicodeDecodeError:
            if not _write_response(_error(None, -32700, "Parse error")):
                return 0
            continue
        if not line:
            continue
        try:
            message = json.loads(
                line,
                object_pairs_hook=_reject_duplicate_keys,
                parse_constant=_reject_constant,
            )
        except (json.JSONDecodeError, ValueError, RecursionError):
            if not _write_response(_error(None, -32700, "Parse error")):
                return 0
            continue
        try:
            response = handle_message(message, runtime)
        except Exception:  # noqa: BLE001 - dernier filet avant la mort du process
            # Un module qui leve tuait le processus stdio : le client perdait
            # la session ENTIERE, pas seulement l'appel fautif. La trace part
            # sur stderr pour qu'un bug reste visible, jamais silencieux.
            try:
                traceback.print_exc(file=sys.stderr)
                sys.stderr.flush()
            except (BrokenPipeError, OSError, UnicodeError):
                pass
            response = _error(
                _safe_response_id(message) if isinstance(message, dict) else None,
                -32603, "Internal error")
        if response is not None and not _write_response(response):
            return 0


if __name__ == "__main__":
    raise SystemExit(main())
