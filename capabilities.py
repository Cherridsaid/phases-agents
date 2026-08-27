"""Vocabulaire ferme des capacites du client B3."""

from __future__ import annotations

import re
import unicodedata


CLIENT_CAPABILITIES = (
    "browser",
    "dependency_installation",
    "filesystem_read",
    "filesystem_search",
    "filesystem_write",
    "human_question",
    "shell",
    "target_code_execution",
    "web",
)
# Capacites FOURNIES : vocabulaire OUVERT. Un catalogue nomme ce qu il apporte ;
# seule la forme est imposee (validator._CAPABILITY_NAME_RE). Les valeurs
# ci-dessous sont des EXEMPLES connus, pas une liste fermee : elles servent a
# eviter que ces identifiants soient pris pour des secrets dans un SKILL.md.
SKILL_PROVIDED_CAPABILITIES = (
    "example_domain_audit",
    "example_package_audit",
    "project_profile",
)
MAX_CLIENT_CAPABILITIES = 32
MAX_CLIENT_CAPABILITY_CHARS = 64
_CLIENT_CAPABILITY_SET = frozenset(CLIENT_CAPABILITIES)
_CAPABILITY_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")


def normalize_client_capabilities(
        value: object) -> tuple[tuple[str, ...] | None, str | None]:
    """Valide puis trie les capacites, sans supposer l'inconnu."""

    if type(value) is not list:
        return None, "CLIENT_CAPABILITIES_TYPE"
    if len(value) > MAX_CLIENT_CAPABILITIES:
        return None, "CLIENT_CAPABILITIES_LIMIT"

    seen: set[str] = set()
    normalized = []
    for item in value:
        if (type(item) is not str
                or not item
                or len(item) > MAX_CLIENT_CAPABILITY_CHARS
                or item != item.strip()
                or unicodedata.normalize("NFKC", item) != item
                or _CAPABILITY_RE.fullmatch(item) is None):
            return None, "CLIENT_CAPABILITY_INVALID"
        if item not in _CLIENT_CAPABILITY_SET:
            return None, "CLIENT_CAPABILITY_UNKNOWN"
        if item in seen:
            return None, "CLIENT_CAPABILITY_DUPLICATE"
        seen.add(item)
        normalized.append(item)
    return tuple(sorted(normalized)), None
