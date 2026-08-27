"""Fixtures deterministes partagees par les tests B1."""

from __future__ import annotations

import json
from pathlib import Path


TODAY_TEXT = "2026-07-27"

SECTIONS = (
    "Loi centrale",
    "Ce que ce skill fait",
    "Ce que ce skill ne fait pas",
    "Conditions d'activation",
    "Conditions d'exclusion",
    "Capacites necessaires",
    "Interdictions",
    "Methode d'audit",
    "Contrat de preuve",
    "Format de sortie",
    "Conditions de blocage",
    "Limites connues",
    "Exemples d'entree",
    "Exemple de sortie attendue",
)


def skill_markdown(skill_id: str, version: str = "0.1.0") -> str:
    body = "\n".join(
        f"## {section}\n\nContenu local.\n"
        for section in SECTIONS
    )
    return (
        "---\n"
        f"name: {skill_id}\n"
        "description: Skill local valide\n"
        f"version: {version}\n"
        "owner: phases-agents\n"
        "license: Apache-2.0\n"
        "---\n\n"
        f"# {skill_id}\n\n"
        f"{body}"
    )


def skill_manifest(skill_id: str,
                   project_types: tuple[str, ...] = ("python",),
                   platforms: tuple[str, ...] = ("generic",),
                   version: str = "0.1.0") -> dict:
    return {
        "schema_version": "1.0",
        "id": skill_id,
        "version": version,
        "title": f"Skill {skill_id}",
        "description": "Skill local en lecture seule.",
        "domain": "security",
        "project_types": list(project_types),
        "platforms": list(platforms),
        "activation": {"any": ["has_source_code"]},
        "exclusions": [],
        "requires_capabilities": ["filesystem_read"],
        "optional_capabilities": [],
        "forbidden_capabilities": [
            "web",
            "target_code_execution",
        ],
        "execution_mode": "read_only",
        "human_approval": "not_required_for_audit",
        "output_schema": "core:FINDING_SCHEMA.json",
        "rules_path": "rules",
        "references_path": "references",
        "scripts_path": "scripts",
        "tests_path": "tests",
        "files": ["scripts/helper.py"],
    }


def write_skill(root: Path, skill_id: str,
                directory_name: str | None = None,
                project_types: tuple[str, ...] = ("python",),
                platforms: tuple[str, ...] = ("generic",)) -> Path:
    package = root / (directory_name or skill_id)
    package.mkdir(parents=True)
    for name in ("rules", "references", "scripts", "tests"):
        (package / name).mkdir()
    (package / "rules" / "rule.json").write_text(
        json.dumps({"rule_id": "R1"}) + "\n",
        encoding="utf-8",
    )
    (package / "references" / "reference.txt").write_text(
        "Reference locale.\n", encoding="utf-8")
    (package / "scripts" / "helper.py").write_text(
        "# contenu non execute\n", encoding="utf-8")
    (package / "tests" / "test.txt").write_text(
        "Test local.\n", encoding="utf-8")
    (package / "phases.json").write_text(
        json.dumps(
            skill_manifest(skill_id, project_types, platforms),
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    (package / "SKILL.md").write_text(
        skill_markdown(skill_id),
        encoding="utf-8",
        newline="\n",
    )
    return package
