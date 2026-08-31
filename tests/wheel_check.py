"""Preuve que la wheel INSTALLÉE fonctionne, pas seulement qu'elle se construit.

Reproduit le refus de revue du 2026-08-27 : une wheel sans ``core/`` ni
``registry/`` s'installait mais ``validate_b3_plan({})`` rendait
``SCHEMA_MISSING`` — le paquet était mort à l'arrivée.

Ce script n'est PAS collecté par pytest (pas de préfixe ``test_``) : il crée
un venv jetable et installe la wheel, ce qui exige le réseau au premier venv
et n'a pas sa place dans la suite hermétique. Usage :

    python -m build --wheel
    python tests/wheel_check.py [chemin/vers/la.whl]

Sortie : ``WHEEL_CHECK_PASS`` et code 0, ou l'échec précis et code 1.
"""

from __future__ import annotations

import glob
import os
import subprocess
import sys
import tempfile
import venv

_REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Le repro s'exécute HORS du dépôt : depuis le dépôt, core/ serait résolu
# par le répertoire courant et masquerait une wheel incomplète.
_PROBE = r"""
from phases_agents import registry, validator, planner, detector, skill_gaps, server
for module in (registry, validator):
    assert "site-packages" in module.__file__, (
        "la sonde doit importer la wheel installee, pas le depot: "
        + module.__file__)
assert registry.__file__.endswith("registry.py"), (
    "import registry doit viser le module, pas le dossier de donnees: "
    + registry.__file__)
issues = validator.validate_b3_plan({})
codes = sorted({i.code for i in issues})
assert issues, "un plan vide doit produire des erreurs de schema"
assert "SCHEMA_MISSING" not in codes, (
    "core/ absent de la wheel installee: " + repr(codes))
rules = validator.validate_skill_gap_rules({"schema_id": "SKILL_GAP_RULES"})
assert all(i.code != "SCHEMA_MISSING" for i in rules), (
    "SKILL_GAP_RULES_SCHEMA.json absent de la wheel installee")
print("codes plan vide:", codes)
print("WHEEL_CHECK_PASS")
"""


_HARDLINK_PROBE = r"""
import os, sys
from phases_agents import validator

# uv/uvx materialise les fichiers du paquet en LIENS DURS vers son cache :
# st_nlink >= 2. On le reproduit ici en posant un second lien dur sur chaque
# donnee officielle installee, ce qui porte st_nlink de l'original a 2.
sidecar_dir = sys.argv[1]
os.makedirs(sidecar_dir, exist_ok=True)
linked = 0
for data_dir in (validator._DEFAULT_CORE_DIR, validator._DEFAULT_REGISTRY_DIR):
    for name in os.listdir(data_dir):
        src = os.path.join(data_dir, name)
        if not os.path.isfile(src):
            continue
        os.link(src, os.path.join(sidecar_dir, str(linked) + "_" + name))
        linked += 1
        assert os.stat(src).st_nlink >= 2, src

assert linked > 0, "aucune donnee officielle a lier"

# Avant le correctif, ces lectures de schemas a lien dur tombaient en
# PATH_UNSAFE puis SCHEMA_MISSING -> serveur inerte sous uvx.
issues = validator.validate_b3_plan({})
codes = sorted({i.code for i in issues})
assert "PATH_UNSAFE" not in codes, (
    "donnee du paquet a lien dur rejetee (regression uvx): " + repr(codes))
assert "SCHEMA_MISSING" not in codes, (
    "schema a lien dur introuvable (regression uvx): " + repr(codes))
assert "SCHEMA_INTEGRITY" not in codes, (
    "schema a lien dur juge non integre (regression uvx): " + repr(codes))
rules = validator.validate_skill_gap_rules({"schema_id": "SKILL_GAP_RULES"})
rules_codes = sorted({i.code for i in rules})
assert "PATH_UNSAFE" not in rules_codes, (
    "registre a lien dur rejete (regression uvx): " + repr(rules_codes))
print("codes plan vide (lien dur):", codes)
print("HARDLINK_PROBE_PASS")
"""


def main() -> int:
    if len(sys.argv) > 1:
        # Absolu AVANT le changement de cwd : pip tourne depuis le venv
        # jetable, un chemin relatif y deviendrait introuvable.
        wheel = os.path.abspath(sys.argv[1])
    else:
        wheels = sorted(glob.glob(os.path.join(_REPO, "dist", "*.whl")))
        if not wheels:
            print("aucune wheel dans dist/ — lancer: python -m build --wheel")
            return 1
        wheel = wheels[-1]
    print("wheel testee:", wheel)

    with tempfile.TemporaryDirectory(prefix="phases-wheel-") as workdir:
        env_dir = os.path.join(workdir, "venv")
        venv.EnvBuilder(with_pip=True).create(env_dir)
        python = os.path.join(
            env_dir,
            "Scripts" if os.name == "nt" else "bin",
            "python.exe" if os.name == "nt" else "python",
        )
        # -I (mode isolé) + purge : un PYTHONPATH herite pointant le depot
        # ferait importer le depot par la sonde -> faux PASS sur une wheel
        # incomplete. L'assert site-packages de _PROBE double cette garde.
        env = {
            key: value for key, value in os.environ.items()
            if key not in ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP")
        }
        sidecar = os.path.join(workdir, "hardlink-sidecar")
        steps = [
            [python, "-I", "-m", "pip", "install",
             "--no-deps", "--quiet", wheel],
            [python, "-I", "-c", _PROBE],
            # Reproduit l'install par liens durs (uv/uvx) et prouve que les
            # donnees du paquet restent lisibles : sans quoi le serveur est
            # inerte sous son runtime declare. Non couvert par pip, qui copie.
            [python, "-I", "-c", _HARDLINK_PROBE, sidecar],
        ]
        for step in steps:
            # cwd hors dépôt : voir le commentaire de _PROBE.
            result = subprocess.run(
                step, cwd=workdir, env=env, capture_output=True, text=True)
            if result.stdout:
                print(result.stdout, end="")
            if result.returncode != 0:
                print(result.stderr, end="", file=sys.stderr)
                print("ECHEC a l'etape:", step[1:3])
                return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
