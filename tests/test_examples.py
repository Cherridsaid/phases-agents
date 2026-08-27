"""Le package d'exemple livré doit rester valide.

C'est le seul package que découvre un utilisateur qui clone le dépôt : s'il
cesse d'être valide, la démarche documentée dans le README ne marche plus.
"""

from __future__ import annotations

import datetime
import pathlib

from validator import redact_sensitive_text, validate_skill_package

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples" / "skills" / "hello-python"
TODAY = datetime.date(2026, 8, 27)


def test_shipped_example_package_is_valid():
    result = validate_skill_package(str(EXAMPLE), today=TODAY)
    assert result.valid, [
        f"{i.level} {i.code} {i.message}" for i in result.issues
    ]


def test_symbolic_schema_reference_is_not_a_secret():
    """`core:X.json` est la syntaxe imposée par output_schema : un SKILL.md
    doit pouvoir citer sa propre sortie sans être accusé de fuite."""
    line = "Sortie conforme à `core:FINDING_SCHEMA.json`."
    assert redact_sensitive_text(line) == line


def test_symbolic_prefix_does_not_whitewash_a_secret():
    """Anti fail-open : le préfixe `core:` ne blanchit pas ce qui le suit."""
    forged = "core:EVIL_AAAAAAAAAAAAAAAAAAAAAAAAAAAA"
    assert redact_sensitive_text(forged) != forged


def test_third_party_owner_is_accepted():
    """Un catalogue tiers doit pouvoir signer ses propres packages."""
    md = (EXAMPLE / "SKILL.md").read_text(encoding="utf-8")
    assert "owner: exemple" in md, "l'exemple doit démontrer un owner tiers"
    result = validate_skill_package(str(EXAMPLE), today=TODAY)
    assert [i for i in result.issues if i.code == "MANIFEST_MISMATCH"] == []
