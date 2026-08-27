"""Transport JSON-RPC et tools B1 de phases-agents."""

import json
import os
import pathlib
import subprocess
import sys
import tempfile
from contextlib import contextmanager

import pytest

import server
from skill_runtime import load_skill_runtime_config
from tests.b1_helpers import write_skill


ROOT = pathlib.Path(__file__).resolve().parents[1]
_ACTIVE_RUNTIME = None
_ACTIVE_CONFIG = None


def _aws_synthetic():
    return "AK" + "IA" + "IOSFODNN7EXAMPLE"


def _stripe_synthetic():
    return "sk_" + "live_" + "51SyntheticOnly987654321"


def _bearer_synthetic():
    return "Bearer " + "eyJhbGciOiJub25lIn0.synthetic.signature"


def _run_server(payload: dict, server_path=None, config_path=None):
    target = pathlib.Path(server_path) if server_path else ROOT / "server.py"
    env = os.environ.copy()
    pythonpath = env.get("PYTHONPATH")
    env["PYTHONPATH"] = (
        str(ROOT)
        if not pythonpath
        else str(ROOT) + os.pathsep + pythonpath
    )
    command = [sys.executable, str(target)]
    selected_config = (
        _ACTIVE_CONFIG if config_path is None else config_path)
    if selected_config is not None:
        command.extend(["--skills-config", str(selected_config)])
    return subprocess.run(
        command,
        input=(json.dumps(payload) + "\n").encode("utf-8"),
        capture_output=True,
        cwd=ROOT,
        env=env,
        timeout=10,
    )


def _tool_call(name, arguments, request_id=101, runtime=None):
    return server.handle_message({
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
        },
    }, _ACTIVE_RUNTIME if runtime is None else runtime)


def _tool_payload(response):
    return json.loads(response["result"]["content"][0]["text"])


@contextmanager
def _b1_workspace(with_skill=True):
    global _ACTIVE_CONFIG, _ACTIVE_RUNTIME

    with tempfile.TemporaryDirectory(prefix="b1_") as temporary:
        base = pathlib.Path(temporary)
        roots = base / "skills"
        target = base / "project"
        roots.mkdir()
        target.mkdir()
        (target / "app.py").write_text("value = 1\n", encoding="utf-8")
        if with_skill:
            write_skill(roots, "audit-python")
        config = base / "skills-config.json"
        config.write_text(json.dumps({
            "config_version": "1.0",
            "roots": [{"id": "main", "path": str(roots)}],
        }), encoding="utf-8")
        built = load_skill_runtime_config(config)
        assert built.ok
        previous_runtime = _ACTIVE_RUNTIME
        previous_config = _ACTIVE_CONFIG
        _ACTIVE_RUNTIME = built.runtime
        _ACTIVE_CONFIG = config
        assert server._valid_local_target(str(roots))
        assert server._valid_local_target(str(target))
        try:
            yield roots, target
        finally:
            _ACTIVE_RUNTIME = previous_runtime
            _ACTIVE_CONFIG = previous_config


def _b1_arguments(roots, target=None):
    del roots
    arguments = {
        "root_ids": ["main"],
        "today": "2026-07-27",
    }
    if target is not None:
        arguments["target"] = str(target)
    return arguments


def _expected_error(code: int, message: str) -> dict:
    return {
        "jsonrpc": "2.0",
        "id": None,
        "error": {"code": code, "message": message},
    }


def _assert_safe_response(response: dict, secret: str,
                          code: int, message: str) -> None:
    assert response == _expected_error(code, message)
    rendered = json.dumps(response, sort_keys=True)
    assert secret not in rendered
    assert "Traceback" not in rendered


def _assert_safe_stdio(result, secret: str,
                       code: int, message: str) -> None:
    expected = json.dumps(
        _expected_error(code, message),
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + os.linesep.encode("ascii")
    assert result.returncode == 0
    assert result.stdout == expected
    assert result.stderr == b""
    assert secret.encode("utf-8") not in result.stdout + result.stderr
    assert b"Traceback" not in result.stdout + result.stderr


def _assert_exact_stdio_tool(request: dict, expected: dict) -> None:
    direct = server.handle_message(request, _ACTIVE_RUNTIME)
    assert direct == expected
    result = _run_server(request)
    assert result.returncode == 0
    assert result.stderr == b""
    expected_stdout = (
        server._encode_response(expected).removesuffix("\n").encode("utf-8")
        + os.linesep.encode("ascii")
    )
    assert result.stdout == expected_stdout
    assert b"Traceback" not in result.stdout


def test_initialize_returns_protocol_and_server_info():
    params = {
        "protocolVersion": server.PROTOCOL_VERSION,
        "capabilities": {},
        "clientInfo": {"name": "pytest", "version": "1.0"},
    }
    resp = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "method": "initialize",
            "params": params,
        }
    )
    assert resp["id"] == 1
    assert resp["result"]["protocolVersion"] == server.PROTOCOL_VERSION
    assert resp["result"]["serverInfo"]["name"] == "phases-agents"
    assert "tools" in resp["result"]["capabilities"]


def test_initialize_accepts_verified_claude_code_shape():
    params = {
        "protocolVersion": "2025-11-25",
        "capabilities": {
            "elicitation": {},
            "roots": {"listChanged": True},
        },
        "clientInfo": {
            "description": "Anthropic's agentic coding tool",
            "name": "claude-code",
            "title": "Claude Code",
            "version": "2.1.220",
            "websiteUrl": "https://claude.com/claude-code",
        },
    }

    response = server.handle_message({
        "jsonrpc": "2.0",
        "id": 102,
        "method": "initialize",
        "params": params,
    })

    assert response["result"]["protocolVersion"] == "2025-11-25"
    assert response["result"]["serverInfo"]["version"] == "0.5.0"


def test_initialize_accepts_verified_codex_shape():
    params = {
        "protocolVersion": "2025-06-18",
        "capabilities": {
            "elicitation": {
                "form": {},
                "url": {},
            },
        },
        "clientInfo": {
            "name": "codex-mcp-client",
            "title": "Codex",
            "version": "0.145.0",
        },
    }

    response = server.handle_message({
        "jsonrpc": "2.0",
        "id": 104,
        "method": "initialize",
        "params": params,
    })

    assert response["result"]["protocolVersion"] == "2025-06-18"
    assert response["result"]["serverInfo"]["name"] == "phases-agents"


def test_initialize_rejects_unknown_client_info_field():
    response = server.handle_message({
        "jsonrpc": "2.0",
        "id": 103,
        "method": "initialize",
        "params": {
            "protocolVersion": "2025-11-25",
            "capabilities": {},
            "clientInfo": {
                "name": "claude-code",
                "unexpected": "value",
                "version": "2.1.220",
            },
        },
    })

    assert response["error"]["code"] == -32602


@pytest.mark.parametrize(
    "params",
    [
        None,
        {},
        {
            "protocolVersion": server.PROTOCOL_VERSION,
            "capabilities": {},
        },
        {
            "protocolVersion": "wrong",
            "capabilities": {},
            "clientInfo": {"name": "pytest", "version": "1.0"},
        },
        {
            "protocolVersion": server.PROTOCOL_VERSION,
            "capabilities": [],
            "clientInfo": {"name": "pytest", "version": "1.0"},
        },
        {
            "protocolVersion": server.PROTOCOL_VERSION,
            "capabilities": {},
            "clientInfo": {},
        },
    ],
)
def test_initialize_rejects_incomplete_or_malformed_params(params):
    request = {
        "jsonrpc": "2.0",
        "id": 101,
        "method": "initialize",
    }
    if params is not None:
        request["params"] = params
    expected = {
        "jsonrpc": "2.0",
        "id": 101,
        "error": {
            "code": -32602,
            "message": "Invalid params: initialize fields are required",
        },
    }
    _assert_exact_stdio_tool(request, expected)


def test_tools_list_exposes_phases_agents_plan():
    resp = server.handle_message(
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
    )
    names = [t["name"] for t in resp["result"]["tools"]]
    assert names == [
        "phases_agents_detect",
        "phases_agents_get_skill",
        "phases_agents_list_skills",
        "phases_agents_plan",
        "phases_agents_refresh_skills",
    ]
    assert all(
        tool["inputSchema"]["additionalProperties"] is False
        for tool in resp["result"]["tools"]
    )
    plan = next(
        tool for tool in resp["result"]["tools"]
        if tool["name"] == "phases_agents_plan"
    )
    assert plan["inputSchema"]["required"] == [
        "root_ids", "target", "today",
    ]
    for tool in resp["result"]["tools"]:
        root_ids_schema = tool["inputSchema"]["properties"].get("root_ids")
        if root_ids_schema is not None:
            assert root_ids_schema["minItems"] == 1
        assert "roots" not in tool["inputSchema"]["properties"]


def test_tools_list_accepts_verified_codex_metadata():
    response = server.handle_message({
        "jsonrpc": "2.0",
        "id": 105,
        "method": "tools/list",
        "params": {
            "_meta": {
                "progressToken": 0,
            },
        },
    })

    assert "error" not in response
    assert len(response["result"]["tools"]) == 5


@pytest.mark.parametrize(
    "metadata",
    [
        {"progressToken": True},
        {"progressToken": -1},
        {"progressToken": ""},
        {"progressToken": " token "},
        {f"key{index}": index for index in range(17)},
    ],
)
def test_tools_list_rejects_invalid_metadata(metadata):
    response = server.handle_message({
        "jsonrpc": "2.0",
        "id": 106,
        "method": "tools/list",
        "params": {"_meta": metadata},
    })

    assert response["error"]["code"] == -32602


def test_tool_call_accepts_and_discards_verified_codex_metadata():
    workspace = r"C:\workspace\controlled"
    response = server.handle_message({
        "jsonrpc": "2.0",
        "id": 107,
        "method": "tools/call",
        "params": {
            "_meta": {
                "progressToken": 1,
                "threadId": "019fb3a6-12e7-7760-b77c-0fa3b8467be5",
                "x-codex-turn-metadata": {
                    "model": "gpt-5.6-sol",
                    "reasoning_effort": "max",
                    "sandbox": "windows_sandbox",
                    "session_id": "controlled-session",
                    "thread_id": "controlled-thread",
                    "thread_source": "user",
                    "turn_id": "controlled-turn",
                    "turn_started_at_unix_ms": 1_785_425_435_730,
                    "workspaces": {
                        workspace: {
                            "has_changes": False,
                            "latest_git_commit_hash": "0" * 40,
                        },
                    },
                },
            },
            "arguments": {"target": str(ROOT)},
            "name": "phases_agents_detect",
        },
    })

    assert "error" not in response
    assert response["result"]["isError"] is False
    assert workspace not in json.dumps(response)


def test_tool_call_accepts_and_discards_verified_claude_metadata():
    tool_use_id = "toolu_01PRtmaiRdDd6h2fcrUefMbd"
    response = server.handle_message({
        "jsonrpc": "2.0",
        "id": 108,
        "method": "tools/call",
        "params": {
            "_meta": {
                "claudecode/toolUseId": tool_use_id,
                "progressToken": 2,
            },
            "arguments": {"target": str(ROOT)},
            "name": "phases_agents_detect",
        },
    })

    assert "error" not in response
    assert response["result"]["isError"] is False
    assert tool_use_id not in json.dumps(response)


def test_initialized_notification_has_no_response():
    resp = server.handle_message(
        {"jsonrpc": "2.0", "method": "notifications/initialized"}
    )
    assert resp is None


def test_notification_without_id_gets_no_response():
    # JSON-RPC : tout message sans "id" est une notification -> aucune réponse,
    # même pour une méthode qui répondrait normalement (ex: tools/list).
    for method in ("tools/list", "initialize", "tools/call", "notifications/initialized"):
        resp = server.handle_message({"jsonrpc": "2.0", "method": method})
        assert resp is None, f"{method} sans id devrait rester silencieux"


def test_explicit_null_id_is_a_request_not_notification():
    # id présent mais null = requête (id dans le message) -> réponse attendue.
    resp = server.handle_message(
        {"jsonrpc": "2.0", "id": None, "method": "tools/list"}
    )
    assert resp is not None
    assert "result" in resp


def test_tools_call_known_tool_returns_content():
    with _b1_workspace(with_skill=False) as (roots, target):
        resp = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 3,
                "method": "tools/call",
                "params": {
                    "name": "phases_agents_plan",
                    "arguments": _b1_arguments(roots, target),
                },
            },
            _ACTIVE_RUNTIME,
        )
    assert resp["result"]["content"][0]["type"] == "text"
    assert resp["result"]["isError"] is False
    payload = json.loads(resp["result"]["content"][0]["text"])
    assert "planner non encore cable" not in json.dumps(payload)
    assert payload["plan"]["warnings"][-1] == "NO_COMPATIBLE_SKILL"


def test_tools_call_missing_or_bad_target_rejected():
    for arguments in ({}, {"target": ""}, {"target": "   "}, {"target": 3}, []):
        resp = server.handle_message(
            {
                "jsonrpc": "2.0",
                "id": 8,
                "method": "tools/call",
                "params": {"name": "phases_agents_plan", "arguments": arguments},
            }
        )
        assert "error" in resp, f"arguments={arguments!r} devrait etre rejete"
        assert resp["error"]["code"] == -32602


def test_tools_call_unknown_tool_errors():
    resp = server.handle_message(
        {
            "jsonrpc": "2.0",
            "id": 4,
            "method": "tools/call",
            "params": {"name": "nope"},
        }
    )
    assert "error" in resp


def test_tools_list_returns_fresh_schema_copies():
    first = server.handle_message(
        {"jsonrpc": "2.0", "id": 20, "method": "tools/list"})
    first["result"]["tools"][0]["name"] = "mutated"
    second = server.handle_message(
        {"jsonrpc": "2.0", "id": 21, "method": "tools/list"})
    assert second["result"]["tools"][0]["name"] == "phases_agents_detect"


class TestB1005McpSkills:
    def test_detect_direct(self):
        with _b1_workspace() as (_roots, target):
            response = _tool_call(
                "phases_agents_detect",
                {"target": str(target)},
            )
            assert response["result"]["isError"] is False
            assert _tool_payload(response) == {
                "profile": {
                    "blocked": False,
                    "exists": True,
                    "facts": ["has_python", "has_source_code"],
                    "issues": [],
                    "languages": ["python"],
                    "markers": {"python": ["app.py"]},
                    "types": ["python"],
                },
            }

    def test_list_direct(self):
        with _b1_workspace() as (roots, _target):
            response = _tool_call(
                "phases_agents_list_skills",
                _b1_arguments(roots),
            )
            payload = _tool_payload(response)
            assert response["result"]["isError"] is False
            assert [item["skill_id"] for item in payload["skills"]] == [
                "audit-python",
            ]
            assert payload["discovery"]["records"][0]["state"] == "VALID"
            assert payload["discovery"]["records"][0]["relative_path"] == (
                "root[0]/audit-python"
            )
            assert str(roots) not in json.dumps(payload)

    def test_absolute_paths_inside_metadata_and_content_are_masked(self):
        assert server._sanitize_public_text(
            "https://example.test/reference") == (
                "https://example.test/reference")
        local_paths = (
            "C:\\Users\\alice\\private\\notes.txt",
            "/home/user/private/notes.txt",
            "\\\\server\\share\\private\\notes.txt",
            "/etc",
            "file:///home/user/private.txt",
            "//server/share/private/notes.txt",
        )
        with _b1_workspace() as (roots, _target):
            package = roots / "audit-python"
            manifest_path = package / "phases.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            manifest["title"] = f"Consulter {local_paths[0]}"
            manifest["description"] = (
                f"Consulter {local_paths[1]}, {local_paths[3]} et "
                f"{local_paths[4]}, puis {local_paths[5]}"
            )
            manifest_path.write_text(
                json.dumps(manifest, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
            )
            markdown = (package / "SKILL.md").read_text(encoding="utf-8")
            (package / "SKILL.md").write_text(
                markdown.replace(
                    "Contenu local.",
                    f"Consulter {local_paths[2]}.",
                    1,
                ),
                encoding="utf-8",
            )

            listed = _tool_call(
                "phases_agents_list_skills",
                _b1_arguments(roots),
            )
            get_arguments = _b1_arguments(roots)
            get_arguments["skill_id"] = "audit-python"
            fetched = _tool_call(
                "phases_agents_get_skill",
                get_arguments,
            )
            for response in (listed, fetched):
                rendered = json.dumps(response, sort_keys=True)
                assert response["result"]["isError"] is False
                assert all(path not in rendered for path in local_paths)
                assert "<chemin-local-masque>" in rendered

    def test_get_direct_returns_validated_content(self):
        with _b1_workspace() as (roots, _target):
            arguments = _b1_arguments(roots)
            arguments["skill_id"] = "audit-python"
            response = _tool_call(
                "phases_agents_get_skill",
                arguments,
            )
            payload = _tool_payload(response)
            assert response["result"]["isError"] is False
            assert payload["skill"]["skill_id"] == "audit-python"
            assert payload["skill"]["validation_level"] == (
                "STRUCTURALLY_VALIDATED")
            assert "## Loi centrale" in payload["skill"]["content"]
            assert "path" not in payload["skill"]
            assert str(roots) not in json.dumps(payload)

    def test_get_unknown_is_structured(self):
        with _b1_workspace() as (roots, _target):
            arguments = _b1_arguments(roots)
            arguments["skill_id"] = "unknown"
            response = _tool_call(
                "phases_agents_get_skill",
                arguments,
            )
            assert response["result"]["isError"] is True
            assert _tool_payload(response)["codes"] == [
                "SKILL_NOT_FOUND",
            ]

    def test_get_never_accepts_a_path(self):
        with _b1_workspace() as (roots, _target):
            arguments = _b1_arguments(roots)
            arguments.update({
                "skill_id": "audit-python",
                "path": str(roots / "audit-python" / "SKILL.md"),
            })
            response = _tool_call(
                "phases_agents_get_skill",
                arguments,
            )
            assert response["error"] == {
                "code": -32602,
                "message": "Invalid params: unknown argument",
            }

    def test_plan_direct_selects_real_skill(self):
        with _b1_workspace() as (roots, target):
            response = _tool_call(
                "phases_agents_plan",
                _b1_arguments(roots, target),
            )
            payload = _tool_payload(response)
            assert response["result"]["isError"] is False
            assert payload["plan"]["selected_skills"][0]["skill_id"] == (
                "audit-python")
            assert payload["plan"]["steps"][0]["action"] == "PROVIDE_SKILL"
            assert str(roots) not in json.dumps(payload)
            assert str(target) not in json.dumps(payload)

    def test_plan_empty_registry_is_explicit(self):
        with _b1_workspace(with_skill=False) as (roots, target):
            response = _tool_call(
                "phases_agents_plan",
                _b1_arguments(roots, target),
            )
            payload = _tool_payload(response)
            assert response["result"]["isError"] is False
            assert payload["plan"]["selected_skills"] == []
            assert "NO_COMPATIBLE_SKILL" in payload["plan"]["warnings"]

    def test_invalid_skill_is_visible_and_not_listed(self):
        with _b1_workspace() as (roots, _target):
            (roots / "audit-python" / "SKILL.md").write_text(
                "invalide", encoding="utf-8")
            response = _tool_call(
                "phases_agents_list_skills",
                _b1_arguments(roots),
            )
            payload = _tool_payload(response)
            assert response["result"]["isError"] is True
            assert payload["codes"] == ["SKILL_INVALID"]
            assert payload["discovery"]["records"][0]["state"] == "INVALID"
            assert payload["discovery"]["records"][0]["error_codes"]

    def test_absent_root_is_fail_closed(self):
        with _b1_workspace(with_skill=False) as (roots, _target):
            roots.rmdir()
            arguments = {
                "root_ids": ["main"],
                "today": "2026-07-27",
            }
            response = _tool_call(
                "phases_agents_list_skills",
                arguments,
            )
            assert response["result"]["isError"] is True
            assert _tool_payload(response)["codes"] == [
                "SKILL_CACHE_STATE",
            ]

    @pytest.mark.parametrize(
        ("name", "arguments"),
        [
            ("phases_agents_detect", {}),
            ("phases_agents_detect", {"target": "relative"}),
            ("phases_agents_list_skills", {"root_ids": [], "today": "bad"}),
            ("phases_agents_list_skills", {"root_ids": "bad",
                                            "today": "2026-07-27"}),
            ("phases_agents_get_skill",
             {"root_ids": [], "today": "2026-07-27",
              "skill_id": "../x"}),
            ("phases_agents_plan",
             {"root_ids": [], "today": "2026-07-27",
              "target": str(ROOT),
              "constraints": {"unknown": []}}),
        ],
    )
    def test_bad_tool_arguments_are_protocol_errors(self, name, arguments):
        response = _tool_call(name, arguments)
        assert response["error"]["code"] == -32602
        assert "result" not in response

    def test_unhashable_tool_name_never_crashes(self):
        response = server.handle_message({
            "jsonrpc": "2.0",
            "id": 44,
            "method": "tools/call",
            "params": {"name": [], "arguments": {}},
        })
        assert response["error"]["code"] == -32602

    def test_root_ids_limit_is_enforced(self):
        response = _tool_call(
            "phases_agents_list_skills",
            {
                "root_ids": [f"root-{index}" for index in range(17)],
                "today": "2026-07-27",
            },
        )
        assert response["error"]["code"] == -32602

    def test_sensitive_skill_id_is_never_echoed(self):
        secret = _aws_synthetic()
        with _b1_workspace() as (roots, _target):
            arguments = _b1_arguments(roots)
            arguments["skill_id"] = secret
            response = _tool_call(
                "phases_agents_get_skill",
                arguments,
            )
            rendered = json.dumps(response, sort_keys=True)
            assert secret not in rendered
            assert "Traceback" not in rendered

    @pytest.mark.parametrize(
        "name",
        [
            "phases_agents_detect",
            "phases_agents_list_skills",
            "phases_agents_get_skill",
            "phases_agents_plan",
            "phases_agents_refresh_skills",
        ],
    )
    def test_each_tool_works_over_real_stdio(self, name):
        with _b1_workspace() as (roots, target):
            if name == "phases_agents_detect":
                arguments = {"target": str(target)}
            else:
                arguments = _b1_arguments(
                    roots,
                    target if name == "phases_agents_plan" else None,
                )
                if name == "phases_agents_get_skill":
                    arguments["skill_id"] = "audit-python"
            request = {
                "jsonrpc": "2.0",
                "id": 88,
                "method": "tools/call",
                "params": {"name": name, "arguments": arguments},
            }
            result = _run_server(request)
            assert result.returncode == 0
            assert result.stderr == b""
            response = json.loads(result.stdout)
            assert response["id"] == 88
            assert response["result"]["isError"] is False
            assert b"Traceback" not in result.stdout

    def test_negative_tools_are_exact_over_real_stdio(self):
        with _b1_workspace(with_skill=False) as (roots, target):
            cases = [
                (
                    "phases_agents_list_skills",
                    {
                        "root_ids": ["absent"],
                        "today": "2026-07-27",
                    },
                    {
                        "codes": ["SKILL_ROOT_UNKNOWN"],
                    },
                ),
                (
                    "phases_agents_get_skill",
                    {
                        **_b1_arguments(roots),
                        "skill_id": "unknown",
                    },
                    {
                        "codes": ["SKILL_NOT_FOUND"],
                        "discovery": {
                            "complete": True,
                            "fatal_codes": [],
                            "records": [],
                        },
                    },
                ),
            ]
            for index, (name, arguments, payload) in enumerate(cases, 700):
                request = {
                    "jsonrpc": "2.0",
                    "id": index,
                    "method": "tools/call",
                    "params": {"name": name, "arguments": arguments},
                }
                expected = {
                    "jsonrpc": "2.0",
                    "id": index,
                    "result": {
                        "content": [{
                            "type": "text",
                            "text": json.dumps(
                                payload,
                                sort_keys=True,
                                separators=(",", ":"),
                            ),
                        }],
                        "isError": True,
                    },
                }
                _assert_exact_stdio_tool(request, expected)

            empty_request = {
                "jsonrpc": "2.0",
                "id": 702,
                "method": "tools/call",
                "params": {
                    "name": "phases_agents_plan",
                    "arguments": _b1_arguments(roots, target),
                },
            }
            empty_direct = server.handle_message(
                empty_request,
                _ACTIVE_RUNTIME,
            )
            assert empty_direct["result"]["isError"] is False
            _assert_exact_stdio_tool(
                empty_request,
                empty_direct,
            )

    @pytest.mark.parametrize(
        ("name", "arguments", "message"),
        [
            (
                "phases_agents_list_skills",
                {"root_ids": [], "today": "2026-07-27"},
                "Invalid params: 'root_ids' must contain safe identifiers",
            ),
            (
                "phases_agents_get_skill",
                {
                    "root_ids": ["main"],
                    "today": "2026-07-27",
                    "skill_id": "audit-python",
                    "path": "C:\\secret\\SKILL.md",
                },
                "Invalid params: unknown argument",
            ),
        ],
    )
    def test_protocol_failures_are_exact_over_stdio(
            self, name, arguments, message):
        request = {
            "jsonrpc": "2.0",
            "id": 710,
            "method": "tools/call",
            "params": {"name": name, "arguments": arguments},
        }
        _assert_exact_stdio_tool(
            request,
            {
                "jsonrpc": "2.0",
                "id": 710,
                "error": {"code": -32602, "message": message},
            },
        )

    def test_secret_root_is_rejected_without_echo_over_stdio(self):
        secret = _aws_synthetic()
        request = {
            "jsonrpc": "2.0",
            "id": 711,
            "method": "tools/call",
            "params": {
                "name": "phases_agents_list_skills",
                "arguments": {
                    "root_ids": [secret],
                    "today": "2026-07-27",
                },
            },
        }
        expected = {
            "jsonrpc": "2.0",
            "id": 711,
            "error": {
                "code": -32602,
                "message": (
                    "Invalid params: 'root_ids' must contain "
                    "safe identifiers"
                ),
            },
        }
        _assert_exact_stdio_tool(request, expected)
        result = _run_server(request)
        assert secret.encode() not in result.stdout + result.stderr


def test_unknown_method_errors():
    resp = server.handle_message(
        {"jsonrpc": "2.0", "id": 5, "method": "does/not/exist"}
    )
    assert resp["error"]["code"] == -32601


def test_direct_and_stdio_apply_the_same_encoded_request_limit():
    request = {
        "jsonrpc": "2.0",
        "id": 505,
        "method": '"' * 600_000,
    }
    expected = {
        "jsonrpc": "2.0",
        "id": None,
        "error": {
            "code": -32600,
            "message": "Invalid Request: request too large",
        },
    }
    _assert_exact_stdio_tool(request, expected)


def test_full_jsonrpc_response_is_bounded_direct_and_over_stdio():
    with _b1_workspace() as (roots, _target):
        skill_md = roots / "audit-python" / "SKILL.md"
        original = skill_md.read_text(encoding="utf-8")
        skill_md.write_text(
            original.replace("Contenu local.", '"' * 18_650),
            encoding="utf-8",
        )
        manifest_path = roots / "audit-python" / "phases.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        manifest["project_types"] = [
            f"p{index}-" + ('"' * 400)
            for index in range(5)
        ]
        manifest_path.write_text(
            json.dumps(manifest, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        arguments = _b1_arguments(roots)
        arguments["skill_id"] = "audit-python"
        request = {
            "jsonrpc": "2.0",
            "id": 506,
            "method": "tools/call",
            "params": {
                "name": "phases_agents_get_skill",
                "arguments": arguments,
            },
        }
        expected = {
            "jsonrpc": "2.0",
            "id": 506,
            "error": {
                "code": -32603,
                "message": "Internal error: response too large",
            },
        }
        direct = server.handle_message(request, _ACTIVE_RUNTIME)
        assert direct == expected
        assert len(server._encode_response(direct).encode("utf-8")) <= (
            server._MAX_RESPONSE_BYTES
        )
        _assert_exact_stdio_tool(request, expected)


def test_bad_jsonrpc_version_rejected():
    resp = server.handle_message({"jsonrpc": "1.0", "id": 6, "method": "initialize"})
    assert "error" in resp


def test_ping_returns_empty_result():
    resp = server.handle_message({"jsonrpc": "2.0", "id": 12, "method": "ping"})
    assert resp["result"] == {}


def test_non_object_message_rejected_not_crash():
    # Une entrée JSON valide mais pas un objet (liste, scalaire) ne doit pas crasher.
    for bad in ([], "x", 3, None):
        resp = server.handle_message(bad)
        assert resp["error"]["code"] == -32600


def test_tools_call_non_object_params_rejected():
    resp = server.handle_message(
        {"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": []}
    )
    assert resp["error"]["code"] == -32602


_AWS_ID = _aws_synthetic()
_SECRET_ID_CASES = [
    pytest.param(_AWS_ID, id="aws"),
    pytest.param(_stripe_synthetic(), id="stripe"),
    pytest.param(_bearer_synthetic(), id="bearer-jwt"),
    pytest.param(_AWS_ID + " suffix", id="secret-at-start"),
    pytest.param("prefix " + _AWS_ID + " suffix", id="secret-in-middle"),
    pytest.param("prefix " + _AWS_ID, id="secret-at-end"),
    pytest.param(_AWS_ID + "," + _AWS_ID, id="secret-repeated"),
    pytest.param("(" + _AWS_ID + "):!", id="secret-punctuation"),
]


@pytest.mark.parametrize("secret", _SECRET_ID_CASES)
def test_sensitive_id_never_echoed_direct_or_stdio(secret, capsys):
    payload = {"jsonrpc": "1.0", "id": secret}
    code = -32600
    message = "Invalid Request: jsonrpc must be '2.0'"
    _assert_safe_response(server.handle_message(payload), secret, code, message)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    _assert_safe_stdio(_run_server(payload), secret, code, message)


_ID_ERROR_BRANCHES = [
    pytest.param(
        lambda secret: {"jsonrpc": "1.0", "id": secret},
        -32600,
        "Invalid Request: jsonrpc must be '2.0'",
        id="wrong-version",
    ),
    pytest.param(
        lambda secret: {"id": secret, "method": "ping"},
        -32600,
        "Invalid Request: jsonrpc must be '2.0'",
        id="missing-version",
    ),
    pytest.param(
        lambda secret: {"jsonrpc": 2, "id": secret, "method": "ping"},
        -32600,
        "Invalid Request: jsonrpc must be '2.0'",
        id="wrong-version-type",
    ),
    pytest.param(
        lambda secret: {
            "jsonrpc": "2.0", "id": secret, "method": "unknown/method",
        },
        -32600,
        "Invalid Request: invalid id",
        id="unknown-method",
    ),
    pytest.param(
        lambda secret: {
            "jsonrpc": "2.0", "id": secret, "method": "ping", "params": [],
        },
        -32600,
        "Invalid Request: invalid id",
        id="invalid-params",
    ),
    pytest.param(
        lambda secret: {
            "jsonrpc": "2.0",
            "id": secret,
            "method": "ping",
            "extra": "forbidden",
        },
        -32600,
        "Invalid Request: unknown member",
        id="unknown-member",
    ),
    pytest.param(
        lambda secret: {
            "jsonrpc": "2.0", "id": [secret], "method": "ping",
        },
        -32600,
        "Invalid Request: invalid id",
        id="wrong-id-type",
    ),
    pytest.param(
        lambda secret: {
            "jsonrpc": "2.0", "id": secret + "X" * 200, "method": "ping",
        },
        -32600,
        "Invalid Request: invalid id",
        id="overlong-id",
    ),
]


@pytest.mark.parametrize(
    ("payload_factory", "code", "message"),
    _ID_ERROR_BRANCHES,
)
def test_sensitive_id_error_branches_are_exact(
        payload_factory, code, message, capsys):
    secret = _AWS_ID
    payload = payload_factory(secret)
    _assert_safe_response(server.handle_message(payload), secret, code, message)
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""
    _assert_safe_stdio(_run_server(payload), secret, code, message)


@pytest.mark.parametrize(("payload", "code", "message"), [
    pytest.param(
        {"jsonrpc": "2.0", "id": 7, "method": "unknown/method"},
        -32601,
        "Method not found",
        id="unknown-method",
    ),
    pytest.param(
        {"jsonrpc": "2.0", "id": 7, "method": "ping", "params": []},
        -32602,
        "Invalid params: ping takes no arguments",
        id="invalid-params",
    ),
])
def test_downstream_error_branches_are_exact(
        payload, code, message, capsys):
    expected = {
        "jsonrpc": "2.0",
        "id": 7,
        "error": {"code": code, "message": message},
    }
    assert server.handle_message(payload) == expected
    captured = capsys.readouterr()
    assert captured.out == captured.err == ""

    result = _run_server(payload)
    expected_stdout = json.dumps(
        expected,
        ensure_ascii=True,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8") + os.linesep.encode("ascii")
    assert result.returncode == 0
    assert result.stdout == expected_stdout
    assert result.stderr == b""
    assert b"Traceback" not in result.stdout + result.stderr


def test_valid_non_sensitive_id_may_be_echoed():
    response = server.handle_message({
        "jsonrpc": "1.0",
        "id": "request-42",
    })
    assert response == {
        "jsonrpc": "2.0",
        "id": "request-42",
        "error": {
            "code": -32600,
            "message": "Invalid Request: jsonrpc must be '2.0'",
        },
    }


def test_mutation_raw_message_id_is_caught(tmp_path):
    source = (ROOT / "server.py").read_text(encoding="utf-8")
    safe = (
        "return _error(request_id, -32600, "
        "\"Invalid Request: jsonrpc must be '2.0'\")"
    )
    vulnerable = (
        "return _error(message.get(\"id\"), -32600, "
        "\"Invalid Request: jsonrpc must be '2.0'\")"
    )
    assert source.count(safe) == 1
    mutant = tmp_path / "server_mutant.py"
    mutant.write_text(source.replace(safe, vulnerable, 1), encoding="utf-8")

    secret = _AWS_ID
    payload = {"jsonrpc": "1.0", "id": secret}
    result = _run_server(payload, mutant)
    assert result.returncode == 0
    assert result.stderr == b""
    assert json.loads(result.stdout)["id"] == secret
    with pytest.raises(AssertionError):
        _assert_safe_stdio(
            result,
            secret,
            -32600,
            "Invalid Request: jsonrpc must be '2.0'",
        )


def test_target_with_long_digit_run_is_auditable(tmp_path):
    """Un chemin qui DESIGNE peut porter 16+ chiffres : il reste auditable.

    L'ancien gate appliquait la detection de secrets (seuil 16 chiffres,
    longueur d'un PAN) au chemin cible : tout projet dont le chemin contenait
    un long identifiant numerique etait inauditable, et le re-run de preuve du
    harnais /phases echouait dans ses worktrees horodates.
    """
    target = tmp_path / "2026073115471234567" / "projet"
    target.mkdir(parents=True)
    (target / "app.py").write_text("value = 1\n", encoding="utf-8")

    assert server._valid_local_target(str(target))

    response = server.handle_message({
        "jsonrpc": "2.0",
        "id": 601,
        "method": "tools/call",
        "params": {
            "arguments": {"target": str(target)},
            "name": "phases_agents_detect",
        },
    })
    assert "error" not in response
    assert response["result"]["isError"] is False


def test_target_digit_run_never_leaks_in_output(tmp_path):
    """Non-fuite : accepter la cible en entree n'expose rien en sortie.

    La suite de chiffres du chemin ne doit apparaitre dans aucune reponse de
    tool : le masquage de sortie (profil public + sanitisation) reste la
    couche qui protege, exactement comme avant l'elargissement d'entree.
    """
    digit_run = "2026073115471234567"
    target = tmp_path / digit_run / "projet"
    target.mkdir(parents=True)
    (target / "app.py").write_text("value = 1\n", encoding="utf-8")

    response = server.handle_message({
        "jsonrpc": "2.0",
        "id": 602,
        "method": "tools/call",
        "params": {
            "arguments": {"target": str(target)},
            "name": "phases_agents_detect",
        },
    })
    assert "error" not in response
    serialized = json.dumps(response)
    assert digit_run not in serialized
    assert str(target) not in serialized


def test_target_structural_rejections_remain():
    """L'elargissement ne retire QUE le gate de redaction, rien d'autre."""
    assert not server._valid_local_target("relative/path")
    assert not server._valid_local_target("")
    assert not server._valid_local_target("   ")
    assert not server._valid_local_target(None)
    assert not server._valid_local_target(12345)
    assert not server._valid_local_target("\\\\serveur\\partage")
    assert not server._valid_local_target("//serveur/partage")
    assert not server._valid_local_target("C:\\a\\controle" + chr(0) + "chr")
    assert not server._valid_local_target(
        "C:\\" + "a" * server._MAX_TARGET_CHARS)
