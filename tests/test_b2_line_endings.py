"""Reproductibilité textuelle des contenus de skill."""

from __future__ import annotations

import pathlib

import pytest


def normalize_newlines(value: str) -> str:
    """Normalise uniquement les conventions de saut de ligne."""

    return value.replace("\r\n", "\n").replace("\r", "\n")


ROOT = pathlib.Path(__file__).resolve().parents[1]
ATTRIBUTES = ROOT / ".gitattributes"
REQUIRED_RULES = {
    "*": {"text=auto"},
    ".gitattributes": {"text", "eol=lf"},
    "*.py": {"text", "eol=lf"},
    "*.md": {"text", "eol=lf"},
    "*.json": {"text", "eol=lf"},
    "*.toml": {"text", "eol=lf"},
    "*.yaml": {"text", "eol=lf"},
    "*.yml": {"text", "eol=lf"},
}


def _parse_attributes(value: str) -> dict[str, list[set[str]]]:
    rules: dict[str, list[set[str]]] = {}
    for source_line in value.splitlines():
        line = source_line.split("#", 1)[0].strip()
        if not line:
            continue
        pattern, *attributes = line.split()
        rules.setdefault(pattern, []).append(set(attributes))
    return rules


def test_repository_declares_portable_lf_rules():
    rules = _parse_attributes(
        ATTRIBUTES.read_text(encoding="utf-8"))

    for pattern, required in REQUIRED_RULES.items():
        assert pattern in rules
        assert any(
            required <= attributes
            for attributes in rules[pattern]
        )


@pytest.mark.parametrize(
    "value",
    (
        "première\nseconde\n",
        "première\r\nseconde\r\n",
        "première\rseconde\r",
    ),
)
def test_logical_skill_content_accepts_portable_newlines(value):
    assert normalize_newlines(value) == "première\nseconde\n"


def test_logical_skill_content_detects_real_text_difference():
    expected = "première\nseconde\n"
    changed = "première\ncontenu modifié\n"

    assert normalize_newlines(changed) != normalize_newlines(expected)
