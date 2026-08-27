"""P0 — invariants structurels du produit.

Le produit tient trois promesses qui sont toutes des gardes par ABSENCE :
aucune dépendance à l'exécution, aucun remote git, aucune capacité
d'exécution ou d'écriture sur le chemin d'audit. Une absence ne se casse
jamais par modification, seulement par ajout — aucune revue de diff ne la
protège durablement. Ces tests sont les tripwires : ils échouent le jour où
la chose apparaît.

Périmètre du troisième invariant : la fermeture transitive de ``server.py``,
le runtime MCP qui lit le dépôt audité. Seuls ces modules sont contraints :
un outil d'installation côté opérateur écrirait chez l'opérateur, jamais chez
la cible, et n'appartient donc pas au chemin d'audit.
"""

from __future__ import annotations

import ast
import subprocess
import tomllib
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent

def _local_imports(source: str, root: Path) -> set[str]:
    """Noms des modules locaux (fichiers ``<nom>.py`` de ``root``) importés."""
    found: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        names: list[str] = []
        if isinstance(node, ast.Import):
            names = [alias.name.split(".")[0] for alias in node.names]
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            names = [node.module.split(".")[0]]
        for name in names:
            if (root / f"{name}.py").is_file():
                found.add(name)
    return found


def _audit_path_closure(root: Path, entry: str = "server.py") -> tuple[str, ...]:
    """Fermeture transitive des imports locaux depuis ``entry``.

    Calculée à chaque exécution, jamais maintenue à la main : un module
    ajouté demain et importé depuis server.py entre dans le scan tout seul.
    """
    seen: set[str] = set()
    queue = [entry]
    while queue:
        current = queue.pop()
        if current in seen:
            continue
        seen.add(current)
        source = (root / current).read_text(encoding="utf-8")
        for name in sorted(_local_imports(source, root)):
            candidate = f"{name}.py"
            if candidate not in seen:
                queue.append(candidate)
    return tuple(sorted(seen))


AUDIT_PATH_MODULES = _audit_path_closure(REPO)

# Garde-fou de vacuité : si la fermeture s'effondrait (refactor cassant le
# calcul), le scan deviendrait vide et menteur. Ces modules connus doivent
# rester atteignables tant qu'ils existent à la racine.
EXPECTED_CORE_MODULES = frozenset(
    {"server.py", "detector.py", "planner.py", "validator.py", "registry.py"}
)

# Modules dont le seul import suffit à violer la promesse : exécution de
# processus, chargement dynamique de code, écriture, réseau.
FORBIDDEN_IMPORTS = frozenset(
    {
        "subprocess",
        "shutil",
        "tempfile",
        "importlib",
        "ctypes",
        "multiprocessing",
        "socket",
        "ssl",
        "http",
        "urllib",
        "ftplib",
        "smtplib",
        "poplib",
        "imaplib",
        "xmlrpc",
        "pickle",
        "marshal",
        "pty",
    }
)

# Attributs de ``os`` qui exécutent, suppriment ou écrivent.
FORBIDDEN_OS_ATTRIBUTES = frozenset(
    {
        "system",
        "popen",
        "open",
        "remove",
        "unlink",
        "rename",
        "renames",
        "replace",
        "rmdir",
        "removedirs",
        "mkdir",
        "makedirs",
        "chmod",
        "chown",
        "truncate",
        "link",
        "symlink",
        "kill",
        "fork",
        "startfile",
    }
)
FORBIDDEN_OS_PREFIXES = ("exec", "spawn")

# Méthodes d'écriture, quel que soit le receveur (tripwire volontairement
# conservateur : ces noms n'ont pas d'usage légitime sur le chemin d'audit).
# ``replace`` est absent à dessein : str.replace est omniprésent et légitime ;
# le cas Path(...).replace(...) est couvert par le contrôle sur receveur
# Path direct ci-dessous. Résidu assumé : un Path stocké dans une variable
# puis muté échappe au statique — borné par les interdits d'import et d'os.
FORBIDDEN_METHOD_NAMES = frozenset(
    {
        "write_text",
        "write_bytes",
        "touch",
        "symlink_to",
        "hardlink_to",
        "lchmod",
        "unlink",
        "mkdir",
        "rmdir",
        "chmod",
        "rename",
    }
)

PATH_CONSTRUCTORS = frozenset(
    {"Path", "PurePath", "PurePosixPath", "PureWindowsPath", "PosixPath", "WindowsPath"}
)

# "eval", "exec", "compile", "__import__" — construits par concaténation pour
# que le nom d'appel interdit n'apparaisse jamais littéralement dans ce fichier.
FORBIDDEN_BUILTIN_CALLS = frozenset(
    {"ev" + "al", "ex" + "ec", "comp" + "ile", "__imp" + "ort__"}
)

READ_ONLY_OPEN_MODES = frozenset({"r", "rb"})

# Modules dont la fonction ``open`` porte le mode en SECOND argument.
MODULE_OPEN_OWNERS = frozenset(
    {"io", "os", "codecs", "builtins", "gzip", "bz2", "lzma"}
)

# Exemption ciblée, jamais générale : skill_runtime.py lie trois fonctions
# kernel32 d'OBSERVATION de changements de répertoire (invalidation de cache).
# La surface exacte de cette exemption est épinglée par
# ``test_kernel32_bindings_are_observation_only`` ci-dessous.
EXEMPTED_IMPORTS: dict[str, frozenset[str]] = {
    "skill_runtime.py": frozenset({"ctypes"}),
}

KERNEL32_ALLOWED_BINDINGS = frozenset(
    {
        "FindFirstChangeNotificationW",
        "FindCloseChangeNotification",
        "WaitForSingleObject",
    }
)


def _binding_pairs(tree: ast.AST) -> list[tuple[list[ast.expr], ast.expr]]:
    """Toutes les liaisons de nom (affectation, annotée, walrus)."""
    pairs: list[tuple[list[ast.expr], ast.expr]] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            pairs.append((list(node.targets), node.value))
        elif isinstance(node, ast.AnnAssign) and node.value is not None:
            pairs.append(([node.target], node.value))
        elif isinstance(node, ast.NamedExpr):
            pairs.append(([node.target], node.value))
    return pairs


def _module_aliases(
    tree: ast.AST, module: str, *, invalidate_rebound: bool = False
) -> set[str]:
    """Noms qui désignent ``module``, alias compris.

    Amorcé par les importations, puis propagé par point fixe à travers les
    réaffectations (``ops = os``) : sinon un simple renommage local
    blanchirait tous les appels qualifiés.

    ``invalidate_rebound`` retire les noms réaffectés à autre chose. Les deux
    modes vont dans le sens strict, mais pas pour le même usage. Sans
    invalidation (défaut), on obtient l'UNION de tout ce qui a un jour
    désigné le module : c'est ce qu'il faut pour interdire, car l'analyse
    ignore l'ordre des instructions et ``os = None`` en fin de fichier ne
    doit pas blanchir un appel plus haut. Avec invalidation, on obtient les
    noms qui désignent SÛREMENT le module : c'est ce qu'il faut pour décider
    de la position d'un argument, où le doute doit retomber sur le cas
    général, plus sévère.
    """
    aliases = {
        alias.asname or alias.name.split(".")[0]
        for node in ast.walk(tree)
        if isinstance(node, ast.Import)
        for alias in node.names
        if alias.name.split(".")[0] == module
    }
    pairs = _binding_pairs(tree)
    changed = True
    while changed:
        changed = False
        for targets, value in pairs:
            if not (isinstance(value, ast.Name) and value.id in aliases):
                continue
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in aliases:
                    aliases.add(target.id)
                    changed = True
    if invalidate_rebound:
        for targets, value in pairs:
            if isinstance(value, ast.Name) and value.id in aliases:
                continue
            for target in targets:
                if isinstance(target, ast.Name):
                    aliases.discard(target.id)
    return aliases


def _scan_source(source: str, label: str) -> list[str]:
    """Retourne la liste des violations trouvées dans ``source``."""
    violations: list[str] = []
    exempted = EXEMPTED_IMPORTS.get(label, frozenset())
    tree = ast.parse(source, filename=label)
    # Première passe : tous les noms sous lesquels le module os est lié
    # (`import os`, `import os as ops`), pour que l'aliasing ne blanchisse
    # pas les appels qualifiés.
    # `import os.path` (sans asname) lie le nom `os`, pas `os.path` : le nom
    # effectivement lié est donc la racine du chemin pointé.
    os_aliases = _module_aliases(tree, "os")
    # Un appel qualifié par le module builtins rejoint l'appel nu :
    # mêmes primitives interdites, même traitement.
    builtins_aliases = _module_aliases(tree, "builtins")
    # Propriétaires d'un ``open`` dont le mode est le SECOND argument :
    # résolus depuis les imports réels, jamais depuis le nom seul.
    module_owners: set[str] = set()
    for owner in MODULE_OPEN_OWNERS:
        module_owners |= _module_aliases(tree, owner, invalidate_rebound=True)
    # `w = open` puis `w('f', 'w')` : l'alias du builtin reste contrôlé.
    open_aliases = {"open"} | {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        and (node.module or "").split(".")[0] in MODULE_OPEN_OWNERS
        for alias in node.names
        if alias.name == "open"
    }
    binding_pairs = _binding_pairs(tree)
    alias_changed = True
    while alias_changed:
        alias_changed = False
        for targets, value in binding_pairs:
            if not (isinstance(value, ast.Name) and value.id in open_aliases):
                continue
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in open_aliases:
                    open_aliases.add(target.id)
                    alias_changed = True
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                root = alias.name.split(".")[0]
                if root in FORBIDDEN_IMPORTS and root not in exempted:
                    violations.append(f"{label}:{node.lineno} import {alias.name}")
        elif isinstance(node, ast.ImportFrom):
            root = (node.module or "").split(".")[0]
            if root in FORBIDDEN_IMPORTS and root not in exempted:
                violations.append(f"{label}:{node.lineno} from {node.module} import ...")
            elif root == "os":
                # Importer directement un nom interdit depuis os
                # contournerait le contrôle des appels qualifiés os.<attr>.
                for alias in node.names:
                    if alias.name in FORBIDDEN_OS_ATTRIBUTES or alias.name.startswith(
                        FORBIDDEN_OS_PREFIXES
                    ):
                        violations.append(
                            f"{label}:{node.lineno} from os import {alias.name}"
                        )
            elif root == "builtins":
                for alias in node.names:
                    if alias.name in FORBIDDEN_BUILTIN_CALLS:
                        violations.append(
                            f"{label}:{node.lineno} from builtins import {alias.name}"
                        )
        elif isinstance(node, ast.Call):
            func = node.func
            if isinstance(func, ast.Name):
                # Les primitives interdites sont traitées à la lecture du
                # nom (branche ast.Name plus bas) : rien à faire ici.
                if func.id in open_aliases:
                    violations.extend(_check_open(node, label))
                elif func.id == "getattr" and node.args:
                    # L'accès dynamique contourne toute liste de noms :
                    # sur un module sensible, il est refusé en bloc.
                    owner = node.args[0]
                    if isinstance(owner, ast.Name) and (
                        owner.id in os_aliases or owner.id in builtins_aliases
                    ):
                        violations.append(
                            f"{label}:{node.lineno} getattr dynamique sur {owner.id}"
                        )
            elif isinstance(func, ast.Attribute):
                attr = func.attr
                receiver = func.value
                if attr == "open":
                    violations.extend(
                        _check_attribute_open(node, receiver, label, module_owners)
                    )
                elif attr == "replace" and (
                    isinstance(receiver, ast.Call)
                    and isinstance(receiver.func, ast.Name)
                    and receiver.func.id in PATH_CONSTRUCTORS
                ):
                    violations.append(
                        f"{label}:{node.lineno} appel Path(...).replace()"
                    )
        elif (
            isinstance(node, ast.Name)
            and isinstance(node.ctx, ast.Load)
            and node.id in FORBIDDEN_BUILTIN_CALLS
        ):
            # La primitive est capturée dès sa LECTURE : `run = exec` la
            # détient avant même le premier appel.
            violations.append(f"{label}:{node.lineno} lecture du builtin {node.id}")
        elif isinstance(node, ast.Attribute) and isinstance(node.ctx, ast.Load):
            # La capacité s'acquiert à la LECTURE de l'attribut, pas à
            # l'appel : `run = os.system` la capture avant tout appel.
            attr = node.attr
            receiver = node.value
            if (
                isinstance(receiver, ast.Name)
                and receiver.id in os_aliases
                and (
                    attr in FORBIDDEN_OS_ATTRIBUTES
                    or attr.startswith(FORBIDDEN_OS_PREFIXES)
                )
            ):
                violations.append(f"{label}:{node.lineno} accès os.{attr}")
            elif (
                isinstance(receiver, ast.Name)
                and receiver.id in builtins_aliases
                and attr in FORBIDDEN_BUILTIN_CALLS
            ):
                violations.append(f"{label}:{node.lineno} accès builtins.{attr}")
            elif attr in FORBIDDEN_METHOD_NAMES:
                violations.append(f"{label}:{node.lineno} accès .{attr}")
    return violations


def _check_open(node: ast.Call, label: str) -> list[str]:
    """``open`` builtin : le mode est le deuxième argument positionnel."""
    positional = node.args[1] if len(node.args) >= 2 else None
    return _check_open_mode(positional, node.keywords, label, node.lineno)


def _check_attribute_open(
    node: ast.Call, receiver: ast.expr, label: str, module_owners: set[str]
) -> list[str]:
    """``x.open(...)`` : la position du mode dépend du receveur.

    ``Path('f').open('w')`` porte le mode en PREMIER argument, tandis que
    ``io.open('f', 'w')`` le porte en SECOND. Les deux positions sont donc
    examinées : pour un chemin, le second argument est ``buffering`` (un
    entier), donc une chaîne de mode y est de toute façon suspecte.
    """
    module_owner = isinstance(receiver, ast.Name) and receiver.id in module_owners
    candidates: list[ast.expr] = []
    if not module_owner and node.args:
        candidates.append(node.args[0])
    if len(node.args) >= 2:
        candidates.append(node.args[1])

    violations: list[str] = []
    for candidate in candidates:
        for violation in _check_open_mode(
            candidate, node.keywords, label, node.lineno
        ):
            if violation not in violations:
                violations.append(violation)
    if not candidates:
        violations.extend(_check_open_mode(None, node.keywords, label, node.lineno))
    return violations


def _check_open_mode(
    positional: ast.expr | None,
    keywords: list[ast.keyword],
    label: str,
    lineno: int,
) -> list[str]:
    """Un mode d'ouverture n'est toléré qu'en lecture LITTÉRALE (r ou rb)."""
    mode_node = positional
    for keyword in keywords:
        if keyword.arg == "mode":
            mode_node = keyword.value
    if mode_node is None:
        return []  # défaut "r", lecture seule
    if isinstance(mode_node, ast.Constant):
        if not isinstance(mode_node.value, str):
            return []  # buffering, encoding=None... : ce n'est pas un mode
        if mode_node.value in READ_ONLY_OPEN_MODES:
            return []
        return [f"{label}:{lineno} open(mode={mode_node.value!r})"]
    return [f"{label}:{lineno} open() avec un mode non littéral"]


DLL_CONSTRUCTORS = frozenset({"WinDLL", "CDLL", "OleDLL", "PyDLL"})

# Seule bibliothèque native chargeable sur le chemin d'audit. Épinglée par
# nom littéral : charger une autre DLL rendrait la liste blanche de
# fonctions sans objet, puisque n'importe quel symbole pourrait s'y cacher.
ALLOWED_DLL_NAMES = frozenset({"kernel32"})

# Chargeurs paresseux de ctypes : `ctypes.windll.kernel32.X` lie un symbole
# sans jamais passer par un constructeur DLL. Aucun usage légitime ici.
LAZY_DLL_LOADERS = frozenset({"windll", "cdll", "oledll", "pydll", "pythonapi"})


def _dll_handle_violations(source: str, label: str) -> list[str]:
    """Contrôle exhaustif des poignées DLL ctypes.

    Toute poignée créée par WinDLL/CDLL (et tout alias transitif) ne peut
    être utilisée QUE pour lire un attribut de la liste blanche
    ``KERNEL32_ALLOWED_BINDINGS``. Alias, getattr, passage en argument ou
    tout autre usage constituent une violation : la capacité s'acquiert au
    moment où une nouvelle fonction est liée, c'est ce moment qu'on verrouille.
    """
    tree = ast.parse(source, filename=label)
    parents: dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parents[child] = node

    def _names_a_constructor(value: ast.expr) -> bool:
        """La valeur DÉSIGNE un constructeur DLL sans l'appeler."""
        if isinstance(value, ast.Name):
            return value.id in DLL_CONSTRUCTORS or value.id in constructor_aliases
        if isinstance(value, ast.Attribute):
            return value.attr in DLL_CONSTRUCTORS
        return False

    # Point fixe sur les alias de CONSTRUCTEUR (`Loader = ctypes.WinDLL`),
    # distincts des alias de poignée (`_K = _KERNEL32`). Amorcé par les
    # importations renommées (`from ctypes import WinDLL as Loader`).
    constructor_aliases: set[str] = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if alias.name in DLL_CONSTRUCTORS
    }
    # `from ctypes import pythonapi as api` importe une poignée déjà
    # construite : elle est traitée comme un chargeur, pas un constructeur.
    imported_lazy_loaders = {
        alias.asname or alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
        if alias.name in LAZY_DLL_LOADERS
    }
    alias_changed = True
    while alias_changed:
        alias_changed = False
        for node in ast.walk(tree):
            if isinstance(node, ast.Assign):
                alias_targets: list[ast.expr] = list(node.targets)
                alias_value = node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                alias_targets = [node.target]
                alias_value = node.value
            elif isinstance(node, ast.NamedExpr):
                alias_targets = [node.target]
                alias_value = node.value
            else:
                continue
            if not _names_a_constructor(alias_value):
                continue
            for target in alias_targets:
                if isinstance(target, ast.Name) and target.id not in constructor_aliases:
                    constructor_aliases.add(target.id)
                    alias_changed = True

    def _is_dll_constructor(value: ast.expr) -> bool:
        if not isinstance(value, ast.Call):
            return False
        func = value.func
        if isinstance(func, ast.Name):
            return func.id in DLL_CONSTRUCTORS or func.id in constructor_aliases
        if isinstance(func, ast.Attribute):
            return func.attr in DLL_CONSTRUCTORS
        return False

    def _loads_foreign_library(value: ast.expr) -> str | None:
        """La seule bibliothèque chargeable est kernel32, nom littéral."""
        if not _is_dll_constructor(value):
            return None
        assert isinstance(value, ast.Call)
        if not value.args:
            return "chargement DLL sans nom littéral"
        first = value.args[0]
        if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
            return "chargement DLL avec un nom non littéral"
        if first.value.lower() not in ALLOWED_DLL_NAMES:
            return f"chargement DLL non autorisé : {first.value!r}"
        return None

    handles: set[str] = set()
    changed = True
    while changed:
        changed = False
        for node in ast.walk(tree):
            # AnnAssign (`_K: object = ...`) et walrus lient aussi un nom.
            if isinstance(node, ast.Assign):
                targets: list[ast.expr] = list(node.targets)
                value = node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                targets = [node.target]
                value = node.value
            elif isinstance(node, ast.NamedExpr):
                targets = [node.target]
                value = node.value
            else:
                continue
            is_handle = _is_dll_constructor(value) or (
                isinstance(value, ast.Name) and value.id in handles
            )
            if not is_handle:
                continue
            for target in targets:
                if isinstance(target, ast.Name) and target.id not in handles:
                    handles.add(target.id)
                    changed = True

    violations: list[str] = []
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            problem = _loads_foreign_library(node)
            if problem:
                violations.append(f"{label}:{node.lineno} {problem}")
            if _is_dll_constructor(node):
                # Une poignée temporaire doit être soit liée à un nom, soit
                # immédiatement restreinte à un attribut de la liste blanche.
                # Tout autre usage (getattr, passage en argument, retour)
                # la fait échapper au contrôle statique.
                parent = parents.get(node)
                escapes = not (
                    (isinstance(parent, ast.Attribute) and parent.value is node)
                    or (
                        isinstance(
                            parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr)
                        )
                        and parent.value is node
                    )
                )
                if escapes:
                    violations.append(
                        f"{label}:{node.lineno} poignée DLL temporaire non contrôlée"
                    )
        if isinstance(node, ast.Name) and node.id in imported_lazy_loaders:
            if isinstance(node.ctx, ast.Load):
                violations.append(
                    f"{label}:{node.lineno} chargeur ctypes importé {node.id}"
                )
            continue
        if isinstance(node, ast.Attribute) and node.attr in LAZY_DLL_LOADERS:
            violations.append(
                f"{label}:{node.lineno} chargeur paresseux ctypes.{node.attr}"
            )
            continue
        if isinstance(node, ast.Attribute) and _is_dll_constructor(node.value):
            # Poignée jamais nommée : ctypes.WinDLL('kernel32').DeleteFileW
            if node.attr not in KERNEL32_ALLOWED_BINDINGS:
                violations.append(
                    f"{label}:{node.lineno} liaison non autorisée .{node.attr}"
                )
            continue
        if not (isinstance(node, ast.Name) and node.id in handles):
            continue
        if not isinstance(node.ctx, ast.Load):
            continue  # cible d'affectation : déjà suivie comme alias
        parent = parents.get(node)
        if isinstance(parent, ast.Attribute) and parent.value is node:
            if parent.attr not in KERNEL32_ALLOWED_BINDINGS:
                violations.append(
                    f"{label}:{node.lineno} liaison non autorisée .{parent.attr}"
                )
            continue
        if (
            isinstance(parent, (ast.Assign, ast.AnnAssign, ast.NamedExpr))
            and parent.value is node
        ):
            continue  # aliasing, suivi par le point fixe
        violations.append(
            f"{label}:{node.lineno} usage non contrôlé de la poignée {node.id}"
        )
    return violations


class TestNoRuntimeDependency:
    """Invariant 1 : le runtime reste bibliothèque standard seule."""

    def test_dependencies_empty(self):
        with (REPO / "pyproject.toml").open("rb") as handle:
            project = tomllib.load(handle)["project"]
        assert project["dependencies"] == []

    def test_no_optional_runtime_dependencies(self):
        with (REPO / "pyproject.toml").open("rb") as handle:
            project = tomllib.load(handle)["project"]
        assert project.get("optional-dependencies", {}) == {}


class TestNoImplicitNetwork:
    """Invariant 2 : le runtime ne joint jamais le réseau de lui-même.

    L'invariant porte sur le code, pas sur la configuration git du poste :
    un dépôt cloné a légitimement un remote, et le serveur ne le lit jamais.
    """

    def test_runtime_declares_no_network_module(self):
        forbidden = {"socket", "http", "urllib", "ftplib", "smtplib",
                     "telnetlib", "requests", "httpx"}
        offenders = {}
        for name in AUDIT_PATH_MODULES:
            tree = ast.parse((REPO / name).read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    found = {a.name.split(".")[0] for a in node.names}
                elif isinstance(node, ast.ImportFrom):
                    found = {(node.module or "").split(".")[0]}
                else:
                    continue
                hits = found & forbidden
                if hits:
                    offenders.setdefault(name, set()).update(hits)
        assert offenders == {}, f"imports réseau interdits : {offenders}"


class TestAuditPathNeverActs:
    """Invariant 3 : le chemin d'audit lit et dit, il n'agit pas."""

    def test_closure_reaches_known_core(self):
        """Un effondrement du calcul de fermeture rendrait le scan vide,
        donc menteur. Les modules cœur connus doivent y figurer."""
        missing = EXPECTED_CORE_MODULES - set(AUDIT_PATH_MODULES)
        assert missing == set(), f"fermeture incomplète, absents : {missing}"

    def test_closure_excludes_operator_tooling(self):
        """Un outil d'installation côté opérateur, qui écrirait chez
        l'opérateur, ne doit jamais entrer dans le chemin d'audit."""
        assert "installer.py" not in AUDIT_PATH_MODULES

    def test_closure_follows_indirect_imports(self, tmp_path):
        """Anti fail-open de la récursion : une violation atteinte via un
        import indirect doit être vue depuis le point d'entrée."""
        (tmp_path / "server.py").write_text("import a\n", encoding="utf-8")
        (tmp_path / "a.py").write_text("import b\n", encoding="utf-8")
        (tmp_path / "b.py").write_text("import subprocess\n", encoding="utf-8")
        closure = _audit_path_closure(tmp_path)
        assert set(closure) == {"server.py", "a.py", "b.py"}
        violations = [
            violation
            for name in closure
            for violation in _scan_source(
                (tmp_path / name).read_text(encoding="utf-8"), name
            )
        ]
        assert violations != []

    @pytest.mark.parametrize("name", AUDIT_PATH_MODULES)
    def test_module_has_no_forbidden_construct(self, name: str):
        source = (REPO / name).read_text(encoding="utf-8")
        violations = _scan_source(source, name)
        assert violations == []

    def test_kernel32_bindings_are_observation_only(self):
        """L'exemption ctypes de skill_runtime reste épinglée à trois
        fonctions d'observation. Toute nouvelle liaison kernel32 échoue ici."""
        source = (REPO / "skill_runtime.py").read_text(encoding="utf-8")
        assert _dll_handle_violations(source, "skill_runtime.py") == []

    def test_dll_check_flags_aliased_handle(self):
        """Anti fail-open : un alias de la poignée DLL ne blanchit rien."""
        snippet = (
            "import ctypes\n"
            "_KERNEL32 = ctypes.WinDLL('kernel32')\n"
            "_K = _KERNEL32\n"
            "_D = _K.DeleteFileW\n"
        )
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_flags_getattr_on_handle(self):
        snippet = (
            "import ctypes\n"
            "_KERNEL32 = ctypes.WinDLL('kernel32')\n"
            "fn = getattr(_KERNEL32, name)\n"
        )
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_flags_handle_escaping_as_argument(self):
        snippet = (
            "import ctypes\n"
            "_KERNEL32 = ctypes.WinDLL('kernel32')\n"
            "helper(_KERNEL32)\n"
        )
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_accepts_allowed_binding(self):
        snippet = (
            "import ctypes\n"
            "_KERNEL32 = ctypes.WinDLL('kernel32')\n"
            "_W = _KERNEL32.WaitForSingleObject\n"
        )
        assert _dll_handle_violations(snippet, "synthetic") == []

    def test_dll_check_flags_foreign_library(self):
        """Charger une autre DLL viderait la liste blanche de son sens."""
        snippet = (
            "import ctypes\n"
            "_K = ctypes.WinDLL('evil.dll')\n"
            "_W = _K.WaitForSingleObject\n"
        )
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_flags_non_literal_library_name(self):
        snippet = "import ctypes\n_K = ctypes.WinDLL(name)\n"
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_flags_cdll_loader(self):
        snippet = "import ctypes\n_K = ctypes.CDLL('libc.so.6')\n"
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_flags_getattr_on_temporary_handle(self):
        """La poignée passée à getattr échappe au contrôle statique."""
        snippet = (
            "import ctypes\n"
            "getattr(ctypes.WinDLL('kernel32'), 'DeleteFileW')\n"
        )
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_flags_temporary_handle_as_argument(self):
        snippet = "import ctypes\nhelper(ctypes.WinDLL('kernel32'))\n"
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_flags_unassigned_handle(self):
        """La poignée n'a pas besoin d'un nom pour lier une fonction."""
        snippet = "import ctypes\nctypes.WinDLL('kernel32').DeleteFileW('v')\n"
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_accepts_unassigned_allowed_binding(self):
        snippet = "import ctypes\nctypes.WinDLL('kernel32').WaitForSingleObject(h, 0)\n"
        assert _dll_handle_violations(snippet, "synthetic") == []

    def test_dll_check_flags_lazy_windll_loader(self):
        """ctypes.windll lie un symbole sans constructeur DLL."""
        snippet = "import ctypes\nctypes.windll.kernel32.DeleteFileW('x')\n"
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_flags_lazy_cdll_loader(self):
        snippet = "import ctypes\nctypes.cdll.LoadLibrary('x')\n"
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_flags_pythonapi(self):
        """ctypes.pythonapi donne accès à l'interpréteur lui-même."""
        snippet = "import ctypes\nctypes.pythonapi.PyRun_SimpleString(b'x')\n"
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_flags_imported_pythonapi_alias(self):
        snippet = "from ctypes import pythonapi as api\napi.PyRun_SimpleString(b'x')\n"
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_flags_imported_windll(self):
        snippet = "from ctypes import windll\nwindll.kernel32.DeleteFileW('x')\n"
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_flags_annotated_handle(self):
        """Une affectation annotée lie un nom comme une affectation nue."""
        snippet = (
            "import ctypes\n"
            "_K: object = ctypes.WinDLL('kernel32')\n"
            "_K.DeleteFileW('x')\n"
        )
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_flags_walrus_handle(self):
        snippet = (
            "import ctypes\n"
            "if (_K := ctypes.WinDLL('kernel32')):\n"
            "    _K.DeleteFileW('x')\n"
        )
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_follows_constructor_alias(self):
        """Aliaser le constructeur lui-même ne contourne pas le contrôle."""
        snippet = (
            "import ctypes\n"
            "Loader = ctypes.WinDLL\n"
            "k = Loader('evil.dll')\n"
            "k.DeleteFileW('x')\n"
        )
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_follows_renamed_import_constructor(self):
        """`from ctypes import WinDLL as Loader` amorce l'alias."""
        snippet = (
            "from ctypes import WinDLL as Loader\n"
            "k = Loader('evil.dll')\n"
            "k.DeleteFileW('x')\n"
        )
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_follows_plain_import_constructor(self):
        snippet = (
            "from ctypes import WinDLL\n"
            "k = WinDLL('kernel32')\n"
            "k.DeleteFileW('x')\n"
        )
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_follows_chained_constructor_alias(self):
        snippet = (
            "import ctypes\n"
            "L1 = ctypes.WinDLL\n"
            "L2 = L1\n"
            "k = L2('kernel32')\n"
            "k.DeleteFileW('x')\n"
        )
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_dll_check_follows_annotated_alias(self):
        snippet = (
            "import ctypes\n"
            "_KERNEL32 = ctypes.WinDLL('kernel32')\n"
            "_K: object = _KERNEL32\n"
            "_K.DeleteFileW('x')\n"
        )
        assert _dll_handle_violations(snippet, "synthetic") != []

    def test_exemption_does_not_leak_to_other_modules(self):
        """La même source avec un autre label doit être refusée : l'exemption
        est attachée au fichier, jamais au motif."""
        snippet = "import ctypes\n"
        assert _scan_source(snippet, "skill_runtime.py") == []
        assert _scan_source(snippet, "planner.py") != []

    # Anti fail-open : un scanner cassé qui ne détecte plus rien doit être
    # détecté ici, pas découvert le jour d'une vraie violation.

    def test_scanner_flags_forbidden_import(self):
        assert _scan_source("import subprocess\n", "synthetic") != []

    def test_scanner_flags_from_import(self):
        assert _scan_source("from shutil import rmtree\n", "synthetic") != []

    def test_scanner_flags_os_system(self):
        assert _scan_source("import os\nos.system('x')\n", "synthetic") != []

    def test_scanner_flags_os_exec_prefix(self):
        assert _scan_source("import os\nos.execv('x', [])\n", "synthetic") != []

    def test_scanner_flags_direct_os_import(self):
        snippet = "from os import system\nsystem('x')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_direct_os_import_with_prefix(self):
        snippet = "from os import execv\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_aliased_os(self):
        snippet = "import os as ops\nops.system('x')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_submodule_os_import(self):
        """`import os.path` lie le nom `os` : les appels restent contrôlés."""
        snippet = "import os.path\nos.system('x')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_aliased_submodule_os_import(self):
        snippet = "import os.path as osp\nosp.system('x')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_pathlib_mutators(self):
        snippet = (
            "from pathlib import Path\n"
            "Path('f').open('w')\n"
            "Path('f').unlink()\n"
        )
        found = _scan_source(snippet, "synthetic")
        assert len(found) == 2, found

    def test_scanner_flags_path_replace(self):
        snippet = "from pathlib import Path\nPath('a').replace('b')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_accepts_str_replace(self):
        """str.replace est légitime et omniprésent : jamais de faux positif."""
        snippet = "value = 'a-b'.replace('-', '_')\ntext.replace(x, y)\n"
        assert _scan_source(snippet, "synthetic") == []

    def test_scanner_accepts_path_open_read(self):
        snippet = "from pathlib import Path\nPath('f').open('rb').read()\n"
        assert _scan_source(snippet, "synthetic") == []

    def test_scanner_flags_module_open_write(self):
        """io.open porte le mode en second argument, pas en premier."""
        snippet = "import io\nio.open('r', 'w')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_codecs_open_write(self):
        snippet = "import codecs\ncodecs.open('f', 'a')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_accepts_module_open_read(self):
        snippet = "import io\nio.open('f', 'rb')\n"
        assert _scan_source(snippet, "synthetic") == []

    def test_scanner_accepts_path_open_with_buffering(self):
        """Le second argument de Path.open est buffering, pas un mode."""
        snippet = "from pathlib import Path\nPath('f').open('rb', 8192)\n"
        assert _scan_source(snippet, "synthetic") == []

    def test_scanner_flags_write_open(self):
        assert _scan_source("open('f', 'w')\n", "synthetic") != []

    def test_scanner_flags_dynamic_open_mode(self):
        assert _scan_source("open('f', m)\n", "synthetic") != []

    def test_scanner_flags_eval(self):
        snippet = "ev" + "al('1')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_write_method(self):
        assert _scan_source("p.write_text('x')\n", "synthetic") != []

    def test_scanner_flags_os_attribute_alias(self):
        """La capacité est capturée à la lecture, avant tout appel."""
        snippet = "import os\nrun = os.system\nrun('x')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_method_attribute_alias(self):
        snippet = "writer = p.write_text\nwriter('x')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_qualified_builtins_call(self):
        """builtins.<primitive> rejoint l'appel nu."""
        snippet = "import builtins\nbuiltins." + "ex" + "ec('x')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_aliased_builtins_module(self):
        snippet = "import builtins as b\nb." + "ev" + "al('1')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_builtin_read_without_call(self):
        """La primitive est détenue dès sa lecture."""
        snippet = "run = " + "ex" + "ec\nrun('x')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_open_alias_write(self):
        snippet = "w = open\nw('f', 'w')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_imported_open_alias(self):
        snippet = "from builtins import open as writer\nwriter('x', 'w')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_imported_io_open_alias(self):
        snippet = "from io import open as writer\nwriter('x', 'w')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_getattr_on_os(self):
        """L'accès dynamique contourne toute liste de noms."""
        snippet = "import os\ngetattr(os, 'sys' + 'tem')('x')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_getattr_on_builtins(self):
        snippet = "import builtins\ngetattr(builtins, 'ev' + 'al')('1')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_chained_open_alias(self):
        snippet = "a = open\nb = a\nb('f', 'a')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_accepts_open_alias_read(self):
        snippet = "reader = open\nreader('f', 'rb')\n"
        assert _scan_source(snippet, "synthetic") == []

    def test_scanner_flags_call_before_module_rebinding(self):
        """L'analyse ignore l'ordre : une réaffectation plus bas ne peut pas
        blanchir un appel plus haut."""
        snippet = "import os\nos.system('x')\nos = None\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_path_named_like_a_module(self):
        """Un nom qui ressemble à un module ne suffit pas : seul l'import
        réel décide de la position du mode."""
        snippet = (
            "from pathlib import Path\n"
            "io = Path('preuve.txt')\n"
            "io.open('w').write('x')\n"
        )
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_invalidates_rebound_module_name(self):
        """Un module réaffecté cesse d'être traité comme un module."""
        snippet = (
            "import io\n"
            "from pathlib import Path\n"
            "io = Path('preuve.txt')\n"
            "io.open('w')\n"
        )
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_reassigned_os_module(self):
        """Un simple renommage local ne blanchit pas les appels qualifiés."""
        snippet = "import os\nops = os\nops.system('x')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_chained_os_module_alias(self):
        snippet = "import os\na = os\nb = a\nb.system('x')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_reassigned_builtins_module(self):
        snippet = "import builtins\nb = builtins\nb." + "ex" + "ec('x')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_annotated_os_module_alias(self):
        snippet = "import os\nops: object = os\nops.system('x')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_renamed_builtins_import(self):
        """L'import renommé capture la primitive avant tout appel."""
        snippet = "from builtins import " + "ev" + "al as run\nrun('1')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_plain_builtins_import(self):
        snippet = "from builtins import " + "ex" + "ec\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_flags_builtins_import_primitive(self):
        snippet = "import builtins\nbuiltins.__imp" + "ort__('os')\n"
        assert _scan_source(snippet, "synthetic") != []

    def test_scanner_accepts_read_only(self):
        clean = "with open('f', 'rb') as fh:\n    fh.read()\n"
        assert _scan_source(clean, "synthetic") == []
