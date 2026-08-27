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
import registry, validator, planner, detector, skill_gaps, server
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
        steps = [
            [python, "-I", "-m", "pip", "install",
             "--no-deps", "--quiet", wheel],
            [python, "-I", "-c", _PROBE],
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
