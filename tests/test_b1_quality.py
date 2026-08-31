"""Garde-fous transversaux B1 : matrice, fuzz, volume et determinisme."""

from __future__ import annotations

import datetime
import hashlib
import json
import pathlib
import subprocess
import sys
import tempfile

import pytest

from phases_agents import server
from phases_agents.planner import build_plan
from phases_agents.registry import build_registry, get_skill, list_skills
from phases_agents.skill_loader import discover_skills
from phases_agents.skill_runtime import configure_skill_runtime
from phases_agents.skill_types import DiscoveryReport
from tests.b1_helpers import write_skill


ROOT = pathlib.Path(__file__).resolve().parents[1]
TODAY = datetime.date(2026, 7, 27)
MATRIX = ROOT / "tests" / "b1_matrix.json"


def _matrix_errors(data, collected, executed=None):
    errors = []
    if data.get("schema") != "B1_MATRIX_V1":
        errors.append("schema")
    scenarios = data.get("scenarios")
    if not isinstance(scenarios, list):
        return errors + ["scenarios"]
    if data.get("total_contracts") != 12:
        errors.append("total_contracts")
    ids = [item.get("contract_id") for item in scenarios
           if isinstance(item, dict)]
    scenario_ids = [item.get("scenario_id") for item in scenarios
                    if isinstance(item, dict)]
    expected = {f"B1-{number:03d}" for number in range(1, 13)}
    if set(ids) != expected:
        errors.append("contract_ids")
    if (len(scenario_ids) != len(set(scenario_ids))
            or any(type(item) is not str for item in scenario_ids)):
        errors.append("scenario_ids")
    nodeids = [item.get("test_nodeid") for item in scenarios
               if isinstance(item, dict)]
    if len(nodeids) != len(set(nodeids)):
        errors.append("duplicate_nodeid")
    for item in scenarios:
        if not isinstance(item, dict):
            errors.append("scenario_type")
            continue
        nodeid = item.get("test_nodeid")
        if nodeid not in collected:
            errors.append(f"missing:{nodeid}")
        if not isinstance(item.get("description"), str):
            errors.append(f"description:{nodeid}")
        if item.get("expected_exit_code") != 0:
            errors.append(f"expected_exit_code:{nodeid}")
        if item.get("expected_result") != "PASS":
            errors.append(f"expected_result:{nodeid}")
        if executed is not None:
            result = executed.get(nodeid)
            if result is None:
                errors.append(f"not_executed:{nodeid}")
            elif result["exit_code"] != item["expected_exit_code"]:
                errors.append(f"exit_code:{nodeid}")
            elif not result["passed"] or result["skipped"]:
                errors.append(f"not_passed:{nodeid}")
    return sorted(errors)


def _collect_nodeids():
    result = subprocess.run(
        [sys.executable, "-m", "pytest", "--collect-only", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr
    return {
        line.strip()
        for line in result.stdout.splitlines()
        if line.startswith("tests/") and "::" in line
    }


def _execute_nodeids(scenarios):
    executed = {}
    for item in scenarios:
        nodeid = item["test_nodeid"]
        result = subprocess.run(
            [sys.executable, "-m", "pytest", nodeid, "-q"],
            cwd=ROOT,
            capture_output=True,
            text=True,
            timeout=60,
        )
        output = result.stdout + result.stderr
        executed[nodeid] = {
            "exit_code": result.returncode,
            "passed": "1 passed" in output,
            "skipped": "skipped" in output,
        }
    return executed


def _empty_registry(root):
    built = build_registry(discover_skills([root], TODAY))
    assert built.ok
    return built.registry


def _valid_profile():
    return {
        "exists": True,
        "blocked": False,
        "issues": [],
        "types": ["python"],
        "languages": ["python"],
        "markers": {"python": ["app.py"]},
    }


def _real_discovery(root, count):
    for index in range(count):
        skill_id = f"skill-{index:04d}"
        write_skill(root, skill_id)
    return discover_skills([root], TODAY)


class TestB1Matrix:
    def test_matrix_maps_all_contract_items(self):
        data = json.loads(MATRIX.read_text(encoding="utf-8"))
        executed = _execute_nodeids(data["scenarios"])
        assert _matrix_errors(
            data,
            _collect_nodeids(),
            executed,
        ) == []

    def test_fake_nodeid_mutation_is_caught(self):
        data = json.loads(MATRIX.read_text(encoding="utf-8"))
        data["scenarios"][0]["test_nodeid"] = "tests/nope.py::test_nope"
        assert any(error.startswith("missing:")
                   for error in _matrix_errors(data, _collect_nodeids()))

    def test_duplicate_scenario_mutation_is_caught(self):
        data = json.loads(MATRIX.read_text(encoding="utf-8"))
        data["scenarios"][1]["scenario_id"] = (
            data["scenarios"][0]["scenario_id"])
        assert "scenario_ids" in _matrix_errors(data, _collect_nodeids())

    def test_wrong_exit_and_skipped_mutations_are_caught(self):
        data = json.loads(MATRIX.read_text(encoding="utf-8"))
        nodeid = data["scenarios"][0]["test_nodeid"]
        executed = {
            item["test_nodeid"]: {
                "exit_code": 0,
                "passed": True,
                "skipped": False,
            }
            for item in data["scenarios"]
        }
        executed[nodeid]["exit_code"] = 1
        assert any(error.startswith("exit_code:")
                   for error in _matrix_errors(
                       data, _collect_nodeids(), executed))
        executed[nodeid] = {
            "exit_code": 0,
            "passed": False,
            "skipped": True,
        }
        assert any(error.startswith("not_passed:")
                   for error in _matrix_errors(
                       data, _collect_nodeids(), executed))


class TestB1DeterministicFuzz:
    def test_public_apis_never_raise_on_fixed_corpus(self, tmp_path):
        cycle = []
        cycle.append(cycle)
        corpus = [
            None,
            False,
            True,
            0,
            1,
            1.5,
            b"bytes",
            "",
            "x" * 10_000,
            [],
            (),
            {1},
            {},
            cycle,
            "\u200b",
            "../outside",
            "C:relative",
            "\\\\server\\share",
        ]
        registry = _empty_registry(tmp_path)
        for value in corpus:
            loader = discover_skills(value, TODAY)
            assert type(loader) is DiscoveryReport

            built = build_registry(value)
            assert built.registry is None
            assert built.issues

            planned = build_plan(value, registry)
            assert planned.plan is None
            assert planned.issues

            constrained = build_plan(_valid_profile(), registry, value)
            if value is not None and type(value) is not dict:
                assert constrained.plan is None
                assert constrained.issues

            lookup = get_skill(registry, value)
            assert lookup.skill is None
            assert lookup.issues

            for name in (
                    "phases_agents_detect",
                    "phases_agents_list_skills",
                    "phases_agents_get_skill",
                    "phases_agents_plan",
                    "phases_agents_refresh_skills"):
                response = server.handle_message({
                    "jsonrpc": "2.0",
                    "id": 1,
                    "method": "tools/call",
                    "params": {
                        "name": name,
                        "arguments": value,
                    },
                })
                assert response is not None
                assert "error" in response
                assert "Traceback" not in json.dumps(response)

    def test_cyclic_tool_arguments_are_rejected(self):
        arguments = {}
        arguments["cycle"] = arguments
        response = server.handle_message({
            "jsonrpc": "2.0",
            "id": 2,
            "method": "tools/call",
            "params": {
                "name": "phases_agents_plan",
                "arguments": arguments,
            },
        })
        assert response["error"]["code"] == -32600


class TestB1ScaleAndDeterminism:
    @pytest.mark.parametrize("count", [10, 100, 1_000])
    def test_registry_and_planner_scale_to_documented_limit(
            self, tmp_path, count):
        discovery = _real_discovery(tmp_path, count)
        assert discovery.complete
        built = build_registry(discovery)
        assert built.ok
        assert len(list_skills(built.registry).skills) == count
        planned = build_plan(_valid_profile(), built.registry)
        assert planned.ok
        assert len(planned.plan.selected_skills) == count
        assert [item.position for item in planned.plan.selected_skills] == (
            list(range(1, count + 1)))

    def test_plan_output_bytes_are_repeatable(self, tmp_path):
        built = build_registry(_real_discovery(tmp_path, 100))
        first = build_plan(_valid_profile(), built.registry).plan.to_public()
        second = build_plan(
            dict(reversed(tuple(_valid_profile().items()))),
            built.registry,
        ).plan.to_public()
        first_bytes = json.dumps(
            first,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        second_bytes = json.dumps(
            second,
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        assert first_bytes == second_bytes
        assert hashlib.sha256(first_bytes).digest() == hashlib.sha256(
            second_bytes).digest()

    def test_mcp_plan_bytes_are_repeatable(self):
        with tempfile.TemporaryDirectory(prefix="b1q_") as temporary:
            base = pathlib.Path(temporary)
            roots = base / "skills"
            target = base / "project"
            roots.mkdir()
            target.mkdir()
            (target / "app.py").write_text("x = 1\n", encoding="utf-8")
            configured = configure_skill_runtime([
                {"id": "main", "path": str(roots)},
            ])
            assert configured.ok
            request = {
                "jsonrpc": "2.0",
                "id": 7,
                "method": "tools/call",
                "params": {
                    "name": "phases_agents_plan",
                    "arguments": {
                        "root_ids": ["main"],
                        "target": str(target),
                        "today": "2026-07-27",
                    },
                },
            }
            first = server._encode_response(server.handle_message(
                request,
                configured.runtime,
            ))
            second = server._encode_response(server.handle_message(
                dict(reversed(tuple(request.items()))),
                configured.runtime,
            ))
            assert first == second
            assert hashlib.sha256(first.encode()).digest() == hashlib.sha256(
                second.encode()).digest()
