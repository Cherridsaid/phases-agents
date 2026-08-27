"""Détecteur de profil de projet — phases-agents.

Lit une cible en LECTURE SEULE et rend un profil structuré. N'exécute jamais
le code de la cible : il liste des fichiers et lit des extraits de texte pour
chercher des marqueurs. Un `.rs` seul ne suffit pas à conclure "solana" : il
faut un marqueur de contenu (anti-faux-positif).
"""

from __future__ import annotations

import json
import os
import re
import stat
import tomllib

from profile_facts import PROFILE_FACTS
from validator import (
    redact_sensitive_text,
    validate_project_facts_declaration,
)


def _strip_rust_noise(text: str) -> str:
    """Blanchit le "bruit" Rust avant de chercher un marqueur.

    Petit lexeur (pas une regex) qui gère correctement : commentaires de ligne,
    commentaires de bloc IMBRIQUÉS (`/* /* */ */`), chaînes normales avec
    échappement, et chaînes brutes `r#"..."#` à dièses équilibrés. Un marqueur
    dans un commentaire ou une chaîne ne prouve rien.
    """
    # BOM UTF-8 éventuel en tête : à retirer avant tout test positionnel.
    if text.startswith("﻿"):
        text = text[1:]

    # Shebang Rust : `#!...` en 1ère ligne est ignoré par le compilateur.
    # On le retire, MAIS on préserve un attribut interne `#![...]`.
    if text.startswith("#!") and not text.startswith("#!["):
        nl = text.find("\n")
        text = "" if nl == -1 else text[nl:]

    out: list[str] = []
    i, n = 0, len(text)
    while i < n:
        c = text[i]
        nxt = text[i + 1] if i + 1 < n else ""

        if c == "/" and nxt == "/":  # commentaire de ligne
            i += 2
            while i < n and text[i] != "\n":
                i += 1
            continue

        if c == "/" and nxt == "*":  # commentaire de bloc, imbriqué
            depth, i = 1, i + 2
            while i < n and depth > 0:
                if text[i] == "/" and i + 1 < n and text[i + 1] == "*":
                    depth, i = depth + 1, i + 2
                elif text[i] == "*" and i + 1 < n and text[i + 1] == "/":
                    depth, i = depth - 1, i + 2
                else:
                    i += 1
            out.append(" ")
            continue

        # Préfixe byte : b"..." b'..' br"..." br#"..."# -> on saute le `b`
        # et on retombe sur les branches raw/char/chaîne ci-dessous.
        if c == "b" and (
            nxt == '"'
            or nxt == "'"
            or (nxt == "r" and i + 2 < n and text[i + 2] in ('"', "#"))
        ):
            out.append(" ")
            i += 1
            c = text[i] if i < n else ""
            nxt = text[i + 1] if i + 1 < n else ""

        if c == "r" and (nxt == '"' or nxt == "#"):  # chaîne brute r#"..."#
            j, hashes = i + 1, 0
            while j < n and text[j] == "#":
                hashes, j = hashes + 1, j + 1
            if j < n and text[j] == '"':
                closing = '"' + "#" * hashes
                end = text.find(closing, j + 1)
                i = n if end == -1 else end + len(closing)
                out.append(" ")
                continue

        if c == "'":  # littéral caractère ('a', '\n', '\'') vs lifetime ('a)
            if nxt == "\\":
                j = i + 2  # après l'antislash : consommer le corps de l'échappement
                if j < n and text[j] == "x":
                    j += 3                      # \xHH
                elif j < n and text[j] == "u":
                    j += 1
                    while j < n and text[j] != "}":
                        j += 1
                    j += 1                      # \u{...}
                else:
                    j += 1                      # échappement simple : \n \' \\ ...
                if j < n and text[j] == "'":    # apostrophe fermante
                    i = j + 1
                    out.append(" ")
                    continue
                # littéral invalide -> apostrophe traitée comme char normal
            elif i + 2 < n and text[i + 2] == "'":
                i += 3                          # littéral simple 'a'
                out.append(" ")
                continue
            # sinon : lifetime/label ('a) -> apostrophe traitée comme un char normal

        if c == '"':  # chaîne normale
            i += 1
            while i < n:
                if text[i] == "\\":
                    i += 2
                    continue
                if text[i] == '"':
                    i += 1
                    break
                i += 1
            out.append(" ")
            continue

        out.append(c)
        i += 1
    return "".join(out)

# Dossiers ignorés à la marche (bruit / volumineux).
_SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv", ".pytest_cache",
    "dist", "build", "target", ".idea", ".vscode",
}

# Ne lire que des fichiers texte plausibles, et jamais plus que cette taille.
_MAX_MARKER_BYTES = 200_000
_MAX_FILES_SCANNED = 5_000
_MAX_ENTRIES_SCANNED = 10_000
_MAX_TARGET_CHARS = 32_767
_MAX_PROJECT_FACTS_BYTES = 32 * 1024
_PROJECT_FACTS_FILE = ".phases-profile.json"

# Marqueurs de contenu par type. Un type "fort" (blockchain) exige un marqueur ;
# un type "faible" (web/python) se contente d'indices de fichiers.

# Crates qui prouvent un projet Solana/Anchor quand ils sont une VRAIE
# dépendance Cargo (pas un commentaire ni une chaîne quelconque).
_SOLANA_CRATES = {
    "solana-program", "solana-sdk", "solana-client",
    "anchor-lang", "anchor-spl",
    "spl-token", "spl-associated-token-account",
}

# Usage Solana/Anchor SYNTAXIQUE dans du code .rs (après retrait des
# commentaires et chaînes). On exige un import `use X`, un chemin `X::` ou la
# macro `declare_id!` : un simple identifiant (variable, lifetime `'anchor_lang`,
# module homonyme) ne suffit pas. Les crates sont dérivés de _SOLANA_CRATES
# (forme underscore) -> une seule source de vérité, pas de crate oublié.
_SOLANA_RS_CRATE_NAMES = sorted(c.replace("-", "_") for c in _SOLANA_CRATES)


def _use_pattern(crate: str) -> "re.Pattern[str]":
    # `use anchor_lang` / `use ::anchor_lang` / `extern crate anchor_lang`.
    return re.compile(rf"\buse\s+(?:::\s*)?{crate}\b|\bextern\s+crate\s+{crate}\b")


def _abs_path_pattern(crate: str) -> "re.Pattern[str]":
    # Chemin ABSOLU `::anchor_lang::` (racine de crate) : réfère au crate externe,
    # jamais masqué par un module local homonyme.
    return re.compile(rf"(?<![\w:])::{crate}::")


def _rel_path_pattern(crate: str) -> "re.Pattern[str]":
    # Chemin RELATIF `anchor_lang::` en tête : peut désigner un module local
    # homonyme -> soumis à l'exclusion des `mod` locaux.
    return re.compile(rf"(?<![\w:]){crate}::")


_USE_PATTERNS = {c: _use_pattern(c) for c in _SOLANA_RS_CRATE_NAMES}
_ABS_PATH_PATTERNS = {c: _abs_path_pattern(c) for c in _SOLANA_RS_CRATE_NAMES}
_REL_PATH_PATTERNS = {c: _rel_path_pattern(c) for c in _SOLANA_RS_CRATE_NAMES}
_DECLARE_ID_RE = re.compile(r"\bdeclare_id\s*!")
_MOD_DECL_RE = re.compile(r"\bmod\s+(\w+)")


def _rust_uses_solana(code: str) -> bool:
    """Vrai si le code .rs utilise réellement un crate Solana.

    Signaux NON masquables (réfèrent sans ambiguïté au crate externe) :
    `declare_id!`, un import `use`/`extern crate`, un chemin ABSOLU `::crate::`.
    Signal masquable : un chemin RELATIF `crate::` est ignoré si un `mod <crate>`
    local existe (module maison homonyme). Les chemins `::` sont testés sur une
    copie où les espaces autour de `::` sont normalisés (Rust les autorise).
    """
    if _DECLARE_ID_RE.search(code):
        return True
    path_code = re.sub(r"\s*::\s*", "::", code)
    local_mods = set(_MOD_DECL_RE.findall(code))
    for crate in _SOLANA_RS_CRATE_NAMES:
        if _USE_PATTERNS[crate].search(code):
            return True
        if _ABS_PATH_PATTERNS[crate].search(path_code):
            return True
        if crate not in local_mods and _REL_PATH_PATTERNS[crate].search(path_code):
            return True
    return False

_WEB_EXTS = {".html", ".htm", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".vue", ".svelte"}
_WEB_FILES = {"package.json"}
_PY_EXTS = {".py"}
_PY_FILES = {"pyproject.toml", "requirements.txt", "setup.py", "setup.cfg", "pipfile"}
_SKILL_PACKAGE_FILES = {
    "phases.json",
    "skill.md",
    "skills_contract.md",
}


def _parse_project_facts(text: str) -> set[str] | None:
    """Parse une declaration explicite, fermee et sans doublon."""

    if len(text.encode("utf-8")) > _MAX_PROJECT_FACTS_BYTES:
        return None

    def reject_duplicate_object(pairs):
        value = {}
        for key, item in pairs:
            if key in value:
                raise ValueError("cle JSON dupliquee")
            value[key] = item
        return value

    def reject_constant(value):
        raise ValueError(f"constante JSON interdite: {value}")

    try:
        declaration = json.loads(
            text,
            object_pairs_hook=reject_duplicate_object,
            parse_constant=reject_constant,
        )
    except (json.JSONDecodeError, ValueError, RecursionError):
        return None
    if validate_project_facts_declaration(declaration):
        return None
    facts = declaration["facts"]
    if any(fact not in PROFILE_FACTS for fact in facts):
        return None
    return set(facts)


def _is_reparse_point(path: str) -> bool:
    """Un seul `os.lstat`, dont l'erreur remonte jusqu'au fail-closed.

    `os.path.islink` avalait l'erreur et rendait `False` : une permission
    refusee sur un composant devenait un feu vert hors Windows, alors que la
    branche Windows bloquait. Le meme appel sert desormais aux deux branches.
    """
    try:
        info = os.lstat(path)
        if os.name == "nt":
            attrs = info.st_file_attributes  # type: ignore[attr-defined]
            return bool(attrs & 0x400)
        return stat.S_ISLNK(info.st_mode)
    except (OSError, AttributeError, ValueError):
        return True


def _has_reparse_component(path: str) -> bool:
    """Refuse la cible et chacun de ses parents jusqu'a l'ancre.

    Pour une cible fichier, prendre son dossier parent comme racine rendait le
    confinement tautologique lorsqu'un parent etait une junction. Toute erreur
    de lecture d'un composant reste fail-closed.
    """
    try:
        current = os.path.abspath(os.fspath(path))
    except (OSError, TypeError, ValueError):
        return True
    while True:
        if _is_reparse_point(current):
            return True
        parent = os.path.dirname(current)
        if parent == current:
            return False
        current = parent


def _real_is_within(path: str, root: str) -> bool:
    try:
        real_path = os.path.normcase(os.path.realpath(path))
        real_root = os.path.normcase(os.path.realpath(root))
        return os.path.commonpath([real_path, real_root]) == real_root
    except (OSError, TypeError, ValueError):
        return False


def _safe_file_info(path: str, root: str):
    if _has_reparse_component(path):
        return None, "REPARSE_POINT"
    try:
        info = os.lstat(path)
    except (OSError, ValueError):
        return None, "READ_ERROR"
    if (_is_reparse_point(path) or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1):
        return None, "UNSAFE_FILE"
    if not _real_is_within(path, root):
        return None, "PATH_ESCAPE"
    if _has_reparse_component(path):
        return None, "REPARSE_POINT"
    return info, None


def _collect_files(root: str) -> tuple[list[str], list[str]]:
    """Marche bornee, triee, sans suivi de liens."""
    files: list[str] = []
    issues: list[str] = []
    pending = [os.path.abspath(root)]
    entries_seen = 0

    while pending:
        directory = pending.pop()
        if (_has_reparse_component(directory)
                or not _real_is_within(directory, root)):
            return [], ["REPARSE_POINT"]
        try:
            with os.scandir(directory) as iterator:
                entries = []
                for entry in iterator:
                    entries_seen += 1
                    if entries_seen > _MAX_ENTRIES_SCANNED:
                        return [], ["SCAN_LIMIT"]
                    entries.append(entry)
        except (OSError, ValueError):
            return [], ["DIRECTORY_UNREADABLE"]
        if (_has_reparse_component(directory)
                or not _real_is_within(directory, root)):
            return [], ["FILE_CHANGED"]

        entries.sort(key=lambda entry: (entry.name.casefold(), entry.name))
        child_directories: list[str] = []
        for entry in entries:
            try:
                if entry.name in _SKIP_DIRS and entry.is_dir(
                        follow_symlinks=False):
                    continue
            except OSError:
                return [], ["DIRECTORY_UNREADABLE"]
            if _is_reparse_point(entry.path):
                return [], ["REPARSE_POINT"]
            try:
                # Sous Windows, DirEntry.stat peut rendre st_ino/st_nlink a
                # zero depuis son cache. lstat donne l'identite reelle.
                info = os.lstat(entry.path)
            except OSError:
                return [], ["FILE_CHANGED"]
            if stat.S_ISDIR(info.st_mode):
                if not _real_is_within(entry.path, root):
                    return [], ["PATH_ESCAPE"]
                child_directories.append(entry.path)
            elif stat.S_ISREG(info.st_mode):
                if info.st_nlink != 1 or not _real_is_within(entry.path, root):
                    return [], ["UNSAFE_FILE"]
                files.append(entry.path)
                if len(files) > _MAX_FILES_SCANNED:
                    return [], ["SCAN_LIMIT"]
            else:
                return [], ["SPECIAL_FILE"]
        for child in reversed(child_directories):
            pending.append(child)
    return files, issues


def _read_text_head_secure(path: str, root: str) -> tuple[str, str | None]:
    before, error = _safe_file_info(path, root)
    if before is None:
        return "", error
    try:
        with open(path, "rb") as fh:
            opened = os.fstat(fh.fileno())
            if ((before.st_dev, before.st_ino)
                    != (opened.st_dev, opened.st_ino)
                    or opened.st_nlink != 1
                    or not stat.S_ISREG(opened.st_mode)):
                return "", "FILE_CHANGED"
            raw = fh.read(_MAX_MARKER_BYTES)
    except (OSError, ValueError):
        return "", "READ_ERROR"
    if not _real_is_within(path, root):
        return "", "FILE_CHANGED"
    if b"\x00" in raw:  # binaire : on n'y cherche pas de marqueur texte
        return "", None
    # `replace` (et non `ignore`) : un octet invalide devient U+FFFD au lieu de
    # DISPARAÎTRE — sinon `anchor_\xfflang` fusionnerait en `anchor_lang`.
    # Gère aussi une troncature au milieu d'un caractère multioctet.
    return raw.decode("utf-8", errors="replace"), None


def _read_text_head(path: str) -> str:
    """Compatibilite interne, confinee au dossier parent."""
    text, _ = _read_text_head_secure(path, os.path.dirname(path) or ".")
    return text


def _cargo_has_solana_dep(text: str) -> bool:
    """Vrai si Cargo.toml déclare une VRAIE dépendance Solana/Anchor.

    Parse le TOML : les commentaires (`# anchor-lang = ...`) et les chaînes
    quelconques sont ignorés, seuls les noms de crates des tables de
    dépendances comptent.
    """
    try:
        data = tomllib.loads(text)
    except (tomllib.TOMLDecodeError, ValueError, RecursionError):
        # Manifeste malformé ou pathologique (imbrication profonde) -> ignoré.
        return False

    workspace = data.get("workspace") if isinstance(data.get("workspace"), dict) else {}
    ws_deps = workspace.get("dependencies")
    ws_deps = ws_deps if isinstance(ws_deps, dict) else {}

    def real_crate_name(key: str, spec, _seen=None):
        # Rend le vrai nom du crate, ou None si non résolvable de façon fiable.
        # `alias = { package = "vrai-crate" }` -> le vrai nom est `package`.
        # `dep = { workspace = true }` -> hérite de [workspace.dependencies] du
        #   MÊME fichier ; si absent (héritage d'un manifeste racine non lu) ou
        #   cyclique -> None (on refuse d'inventer un nom, anti-faux-positif).
        if isinstance(spec, dict):
            if "package" in spec:
                # `package` présent : c'est le vrai nom, mais s'il n'est pas une
                # chaîne le manifeste est invalide -> None.
                pkg = spec["package"]
                return pkg if isinstance(pkg, str) else None
            if spec.get("workspace") is True:
                seen = _seen or set()
                if key in seen or key not in ws_deps:
                    return None
                seen.add(key)
                return real_crate_name(key, ws_deps.get(key), seen)
            return key  # table détaillée sans rename -> la clé est le crate
        if isinstance(spec, str):
            return key  # version simple `crate = "1.2"` -> la clé est le crate
        return None  # bool/int/liste... -> spec invalide, ignoré

    # Cargo accepte les alias underscore `dev_dependencies` / `build_dependencies`
    # (dépréciés, rejetés seulement en édition 2024).
    package = data.get("package") if isinstance(data.get("package"), dict) else {}
    edition_raw = package.get("edition", "")
    edition_known = True
    if isinstance(edition_raw, dict):
        ws_pkg = workspace.get("package") if isinstance(workspace.get("package"), dict) else {}
        if edition_raw.get("workspace") is True and isinstance(ws_pkg.get("edition"), str):
            edition = ws_pkg["edition"]  # hérité et résolu dans le MÊME fichier
        else:
            edition, edition_known = "", False  # hérité d'un parent non lu -> inconnu
    else:
        edition = str(edition_raw)  # absente -> défaut (2015), connue et != 2024

    # Les alias underscore (dépréciés) ne sont acceptés que si l'édition est
    # CONNUE et < 2024. Édition inconnue -> prudence, on les refuse.
    dep_keys = ["dependencies", "dev-dependencies", "build-dependencies"]
    if edition_known and edition != "2024":
        dep_keys += ["dev_dependencies", "build_dependencies"]

    tables: list[dict] = []

    def collect(node) -> None:
        if not isinstance(node, dict):
            return
        for key in dep_keys:
            table = node.get(key)
            if isinstance(table, dict):
                tables.append(table)

    collect(data)
    tables.append(ws_deps)  # une racine de workspace peut déclarer solana ici
    target_node = data.get("target")
    if isinstance(target_node, dict):
        for sub in target_node.values():
            collect(sub)

    for table in tables:
        for crate, spec in table.items():
            name = real_crate_name(crate, spec)
            # Comparaison EXACTE (casse + tirets) au nom canonique : `solana_program`
            # (underscore) ou `Solana-Program` (majuscules) sont d'AUTRES crates.
            if name in _SOLANA_CRATES:
                return True
    return False


def detect_profile(target: str) -> dict:
    """Rend un profil borne.

    Une incertitude de lecture produit ``blocked=true``. Aucun profil partiel
    n'est presente comme fiable.
    """
    public_target = (
        redact_sensitive_text(target)
        if isinstance(target, str)
        else "<cible-invalide>"
    )
    profile = {
        "target": public_target,
        "exists": False,
        "blocked": False,
        "issues": [],
        "types": [],
        "languages": [],
        "markers": {},
        "facts": [],
    }

    if (not isinstance(target, str) or not target.strip()
            or len(target) > _MAX_TARGET_CHARS
            or "\x00" in target
            or not os.path.isabs(target)):
        profile["types"] = ["inconnu"]
        profile["reason"] = "cible introuvable ou invalide"
        return profile
    try:
        exists = os.path.lexists(target)
    except (OSError, ValueError):
        exists = False
    if not exists:
        profile["types"] = ["inconnu"]
        profile["reason"] = "cible introuvable ou invalide"
        return profile
    if _has_reparse_component(target):
        profile["blocked"] = True
        profile["issues"] = ["REPARSE_POINT"]
        profile["types"] = ["inconnu"]
        profile["reason"] = "REPARSE_POINT"
        return profile

    profile["exists"] = True
    types: set[str] = set()
    languages: set[str] = set()
    markers: dict[str, list[str]] = {}
    declared_facts: set[str] = set()

    def add_marker(kind: str, evidence: str) -> None:
        markers.setdefault(kind, [])
        public_evidence = redact_sensitive_text(evidence)
        if public_evidence not in markers[kind]:
            markers[kind].append(public_evidence)

    # Une cible peut être un dossier, ou un fichier unique (ex: un .apk).
    # Fichier unique : on analyse EXACTEMENT ce chemin, jamais son voisinage
    # (un homonyme dans un sous-dossier ne doit pas contaminer le résultat).
    try:
        is_directory = os.path.isdir(target)
    except (OSError, ValueError):
        is_directory = False
    if is_directory:
        root = os.path.abspath(target)
        candidates, walk_issues = _collect_files(root)
        if walk_issues:
            profile["blocked"] = True
            profile["issues"] = sorted(set(walk_issues))
            profile["types"] = ["inconnu"]
            profile["reason"] = (
                "REPARSE_POINT"
                if profile["issues"] == ["REPARSE_POINT"]
                else "lecture sure impossible"
            )
            return profile
    else:
        root = os.path.abspath(os.path.dirname(target) or ".")
        info, file_error = _safe_file_info(target, root)
        if info is None:
            profile["blocked"] = True
            profile["issues"] = [file_error or "READ_ERROR"]
            profile["types"] = ["inconnu"]
            profile["reason"] = (
                "REPARSE_POINT"
                if file_error == "REPARSE_POINT"
                else "fichier cible non regulier"
            )
            return profile
        candidates = [os.path.abspath(target)]

    for full in candidates:
        # SEC-002 : la marche a pu voir un fichier regulier puis celui-ci peut
        # etre remplace avant la classification. Refaire le controle juste
        # avant tout usage, y compris pour les marqueurs fondes sur le nom
        # (.apk, package.json...) qui ne declenchent aucune lecture.
        current_info, current_error = _safe_file_info(full, root)
        if current_info is None:
            profile["blocked"] = True
            profile["issues"] = [current_error or "READ_ERROR"]
            profile["types"] = ["inconnu"]
            profile["languages"] = []
            profile["markers"] = {}
            profile["reason"] = (
                "REPARSE_POINT"
                if current_error == "REPARSE_POINT"
                else "fichier change ou non sur"
            )
            return profile
        name = os.path.basename(full)
        lower = name.lower()
        ext = os.path.splitext(lower)[1]

        if (lower == _PROJECT_FACTS_FILE
                and os.path.normcase(os.path.dirname(full))
                == os.path.normcase(root)):
            text, read_error = _read_text_head_secure(full, root)
            facts = (
                None
                if read_error
                else _parse_project_facts(text)
            )
            if facts is None:
                profile["blocked"] = True
                profile["issues"] = [
                    read_error or "PROJECT_FACTS_INVALID"
                ]
                profile["types"] = ["inconnu"]
                profile["languages"] = []
                profile["markers"] = {}
                profile["facts"] = []
                profile["reason"] = "declaration de faits invalide"
                return profile
            declared_facts.update(facts)
            add_marker("project_facts", name)
            continue

        if ext == ".apk":
            types.add("apk")
            add_marker("apk", name)
            continue

        if lower in _SKILL_PACKAGE_FILES:
            types.add("skill_package")
            add_marker("skill_package", name)

        if ext == ".rs":
            languages.add("rust")
            text, read_error = _read_text_head_secure(full, root)
            if read_error:
                profile["blocked"] = True
                profile["issues"] = [read_error]
                profile["types"] = ["inconnu"]
                profile["languages"] = []
                profile["markers"] = {}
                profile["reason"] = "fichier change ou illisible"
                return profile
            code = _strip_rust_noise(text)
            if _rust_uses_solana(code):
                types.add("solana")
                add_marker("solana", name)
            # sinon : rust générique, PAS solana (anti-faux-positif)

        if lower == "cargo.toml":
            languages.add("rust")
            head, read_error = _read_text_head_secure(full, root)
            if read_error:
                profile["blocked"] = True
                profile["issues"] = [read_error]
                profile["types"] = ["inconnu"]
                profile["languages"] = []
                profile["markers"] = {}
                profile["reason"] = "fichier change ou illisible"
                return profile
            # Un projet Anchor déclare souvent son marqueur en dépendance ici,
            # pas dans le .rs -> lire le manifeste évite un faux "inconnu".
            # Parse TOML : un marqueur commenté ne compte pas.
            if _cargo_has_solana_dep(head):
                types.add("solana")
                add_marker("solana", name)

        if ext in _PY_EXTS or lower in _PY_FILES:
            types.add("python")
            languages.add("python")
            add_marker("python", name)

        if ext in _WEB_EXTS or lower in _WEB_FILES:
            types.add("web")
            if ext in {".ts", ".tsx"}:
                languages.add("typescript")
            elif ext in {".js", ".mjs", ".cjs", ".jsx"}:
                languages.add("javascript")
            add_marker("web", name)

    profile["types"] = sorted(types) if types else ["inconnu"]
    profile["languages"] = sorted(languages)
    profile["markers"] = {
        kind: sorted(values, key=lambda value: (value.casefold(), value))
        for kind, values in sorted(markers.items())
    }
    facts = set(declared_facts)
    if "apk" in types:
        facts.add("has_apk")
    if "python" in types:
        facts.add("has_python")
    if "solana" in types:
        facts.add("has_solana")
    if "web" in types:
        facts.add("has_web")
    if "skill_package" in types:
        facts.add("has_skill_packages")
    if "javascript" in languages:
        facts.add("has_javascript")
    if "typescript" in languages:
        facts.add("has_typescript")
    if "rust" in languages:
        facts.add("has_rust")
    if (
            {"python", "solana", "web"} & types
            or {"javascript", "python", "rust", "typescript"} & languages):
        facts.add("has_source_code")
    profile["facts"] = sorted(facts)
    return profile
