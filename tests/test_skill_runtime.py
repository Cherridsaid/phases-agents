"""Racines de confiance et cache déterministe du transport B1."""

from __future__ import annotations

import datetime
import io
import json
import os
import pathlib
import subprocess
import sys
from types import SimpleNamespace

import pytest

from phases_agents import server
from phases_agents import skill_runtime
from phases_agents.registry import get_skill, list_skills
from phases_agents.skill_runtime import (
    configure_skill_runtime,
    load_skill_runtime_config,
    resolve_skill_registry,
)
from tests.b1_helpers import write_skill


TODAY = datetime.date(2026, 7, 27)
ROOT = pathlib.Path(__file__).resolve().parents[1]


def _runtime(*entries):
    built = configure_skill_runtime(list(entries))
    assert built.ok, built.codes
    return built.runtime


def _request(name, arguments):
    return {
        "jsonrpc": "2.0",
        "id": 71,
        "method": "tools/call",
        "params": {
            "name": name,
            "arguments": arguments,
        },
    }


def _payload(response):
    return json.loads(response["result"]["content"][0]["text"])


def _stdio(request, config):
    env = os.environ.copy()
    pythonpath = env.get("PYTHONPATH")
    # Le paquet vit sous src/ : la racine du depot ne contient plus de module.
    source_root = str(ROOT / "src")
    env["PYTHONPATH"] = (
        source_root
        if not pythonpath
        else source_root + os.pathsep + pythonpath
    )
    return subprocess.run(
        [
            sys.executable,
            "-m",
            "phases_agents.server",
            "--skills-config",
            str(config),
        ],
        input=(json.dumps(request) + "\n").encode("utf-8"),
        capture_output=True,
        cwd=ROOT,
        env=env,
        timeout=10,
    )


class TestTrustedRoots:
    @pytest.mark.parametrize(
        "hostile",
        [
            "C:\\",
            "C:\\Users",
            "..",
            "\\\\server\\share",
            "\\\\?\\C:\\",
        ],
    )
    def test_mcp_never_accepts_a_root_path(self, tmp_path, hostile):
        roots = tmp_path / "skills"
        roots.mkdir()
        runtime = _runtime({"id": "main", "path": str(roots)})
        config = tmp_path / "roots.json"
        config.write_text(json.dumps({
            "config_version": "1.0",
            "roots": [{"id": "main", "path": str(roots)}],
        }), encoding="utf-8")
        request = _request(
            "phases_agents_list_skills",
            {"root_ids": [hostile], "today": "2026-07-27"},
        )

        response = server.handle_message(request, runtime)
        stdio = _stdio(request, config)

        assert response == {
            "jsonrpc": "2.0",
            "id": 71,
            "error": {
                "code": -32602,
                "message": (
                    "Invalid params: 'root_ids' must contain "
                    "safe identifiers"
                ),
            },
        }
        rendered = json.dumps(response, sort_keys=True)
        assert hostile not in rendered
        assert str(roots) not in rendered
        assert stdio.returncode == 0
        assert stdio.stderr == b""
        assert json.loads(stdio.stdout) == response
        assert hostile.encode() not in stdio.stdout + stdio.stderr

    def test_authorized_id_is_used_and_unknown_id_is_closed(self, tmp_path):
        roots = tmp_path / "skills"
        roots.mkdir()
        write_skill(roots, "audit-python")
        runtime = _runtime({"id": "main", "path": str(roots)})

        accepted = server.handle_message(_request(
            "phases_agents_list_skills",
            {"root_ids": ["MAIN"], "today": "2026-07-27"},
        ), runtime)
        rejected = server.handle_message(_request(
            "phases_agents_list_skills",
            {"root_ids": ["unknown"], "today": "2026-07-27"},
        ), runtime)

        assert accepted["result"]["isError"] is False
        assert [item["skill_id"] for item in _payload(accepted)["skills"]] == [
            "audit-python",
        ]
        assert rejected["result"]["isError"] is True
        assert _payload(rejected) == {"codes": ["SKILL_ROOT_UNKNOWN"]}
        assert str(roots) not in json.dumps((accepted, rejected))

    @pytest.mark.parametrize(
        "second_id",
        [
            "MAIN",
            "ｍａｉｎ",
        ],
    )
    def test_root_id_collisions_are_rejected(self, tmp_path, second_id):
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir()
        second.mkdir()

        built = configure_skill_runtime([
            {"id": "main", "path": str(first)},
            {"id": second_id, "path": str(second)},
        ])

        assert built.runtime is None
        assert built.codes == ("SKILL_ROOT_DUPLICATE",)

    def test_same_real_root_cannot_have_two_ids(self, tmp_path):
        roots = tmp_path / "skills"
        roots.mkdir()

        built = configure_skill_runtime([
            {"id": "first", "path": str(roots)},
            {"id": "second", "path": str(roots)},
        ])

        assert built.runtime is None
        assert built.codes == ("SKILL_ROOT_DUPLICATE",)

    def test_colliding_startup_config_stops_stdio_safely(self, tmp_path):
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir()
        second.mkdir()
        config = tmp_path / "roots.json"
        config.write_text(json.dumps({
            "config_version": "1.0",
            "roots": [
                {"id": "main", "path": str(first)},
                {"id": "MAIN", "path": str(second)},
            ],
        }), encoding="utf-8")

        result = _stdio(
            {"jsonrpc": "2.0", "id": 1, "method": "tools/list"},
            config,
        )

        assert result.returncode == 2
        assert result.stdout == b""
        assert result.stderr == (
            b"Invalid skills configuration"
            + os.linesep.encode("ascii")
        )
        assert str(first).encode() not in result.stderr
        assert str(second).encode() not in result.stderr

    def test_startup_config_is_strict_and_private(self, tmp_path):
        roots = tmp_path / "skills"
        roots.mkdir()
        config = tmp_path / "roots.json"
        config.write_text(json.dumps({
            "config_version": "1.0",
            "roots": [{"id": "main", "path": str(roots)}],
        }), encoding="utf-8")

        built = load_skill_runtime_config(config)
        relative = load_skill_runtime_config("roots.json")

        assert built.ok
        assert relative.runtime is None
        assert relative.codes == ("SKILL_ROOT_CONFIG",)
        assert not hasattr(built.runtime, "roots")
        assert str(roots) not in repr(built.runtime)
        with pytest.raises(AttributeError):
            built.runtime.cache = {}

    def test_configured_junction_or_symlink_is_rejected(self, tmp_path):
        target = tmp_path / "target"
        target.mkdir()
        linked = tmp_path / "linked"
        if os.name == "nt":
            created = subprocess.run(
                ["cmd", "/c", "mklink", "/J", str(linked), str(target)],
                capture_output=True,
                text=True,
            )
            assert created.returncode == 0, created.stderr
        else:
            os.symlink(target, linked, target_is_directory=True)
        try:
            built = configure_skill_runtime([
                {"id": "main", "path": str(linked)},
            ])
            assert built.runtime is None
            assert built.codes == ("SKILL_ROOT_CONFIG",)
        finally:
            if os.path.lexists(linked):
                if os.name == "nt":
                    os.rmdir(linked)
                else:
                    linked.unlink()


class TestRegistryCache:
    def test_list_get_and_plan_share_one_discovery(
            self, tmp_path, monkeypatch):
        roots = tmp_path / "skills"
        roots.mkdir()
        write_skill(roots, "audit-python")
        target = os.path.abspath(os.sep)
        runtime = _runtime({"id": "main", "path": str(roots)})
        calls = {"discover": 0, "build": 0}
        original_discover = skill_runtime.discover_skills
        original_build = skill_runtime.build_registry

        def counted_discover(*args, **kwargs):
            calls["discover"] += 1
            return original_discover(*args, **kwargs)

        def counted_build(*args, **kwargs):
            calls["build"] += 1
            return original_build(*args, **kwargs)

        monkeypatch.setattr(
            skill_runtime, "discover_skills", counted_discover)
        monkeypatch.setattr(
            skill_runtime, "build_registry", counted_build)
        monkeypatch.setattr(server, "detect_profile", lambda _target: {
            "blocked": False,
            "exists": True,
            "issues": [],
            "languages": ["python"],
            "markers": {},
            "types": ["python"],
        })
        common = {"root_ids": ["main"], "today": "2026-07-27"}
        calls_to_make = [
            ("phases_agents_list_skills", common),
            ("phases_agents_get_skill", {
                **common,
                "skill_id": "audit-python",
            }),
            ("phases_agents_plan", {
                **common,
                "target": str(target),
            }),
            ("phases_agents_list_skills", common),
        ]

        responses = [
            server.handle_message(_request(name, arguments), runtime)
            for name, arguments in calls_to_make
        ]

        assert all(response["result"]["isError"] is False
                   for response in responses)
        assert calls == {"discover": 1, "build": 1}

    def test_stdio_loop_reuses_one_validated_registry(
            self, tmp_path, monkeypatch):
        roots = tmp_path / "skills"
        roots.mkdir()
        write_skill(roots, "audit-python")
        config = tmp_path / "roots.json"
        config.write_text(json.dumps({
            "config_version": "1.0",
            "roots": [{"id": "main", "path": str(roots)}],
        }), encoding="utf-8")
        request = _request(
            "phases_agents_list_skills",
            {"root_ids": ["main"], "today": "2026-07-27"},
        )
        encoded = (json.dumps(request) + "\n").encode("utf-8")
        fake_input = SimpleNamespace(buffer=io.BytesIO(encoded + encoded))
        fake_output = io.StringIO()
        calls = 0
        original = skill_runtime.discover_skills

        def counted(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(skill_runtime, "discover_skills", counted)
        monkeypatch.setattr(server.sys, "stdin", fake_input)
        monkeypatch.setattr(server.sys, "stdout", fake_output)

        exit_code = server.main([
            "--skills-config",
            str(config),
        ])
        lines = fake_output.getvalue().splitlines()

        assert exit_code == 0
        assert calls == 1
        assert len(lines) == 2
        assert lines[0] == lines[1]

    def test_hot_lookup_never_reads_or_validates_content(
            self, tmp_path, monkeypatch):
        roots = tmp_path / "skills"
        roots.mkdir()
        write_skill(roots, "audit-python")
        runtime = _runtime({"id": "main", "path": str(roots)})
        first = resolve_skill_registry(runtime, ["main"], TODAY)
        assert first.ok

        def unexpected(*_args, **_kwargs):
            raise AssertionError("redécouverte chaude interdite")

        monkeypatch.setattr(skill_runtime, "discover_skills", unexpected)
        monkeypatch.setattr(skill_runtime, "build_registry", unexpected)

        second = resolve_skill_registry(runtime, ["main"], TODAY)

        assert second.ok
        assert list_skills(second.registry).ok

    def test_modification_is_detected_and_invalid_skill_is_not_stale(
            self, tmp_path):
        roots = tmp_path / "skills"
        roots.mkdir()
        package = write_skill(roots, "audit-python")
        runtime = _runtime({"id": "main", "path": str(roots)})
        first = resolve_skill_registry(runtime, ["main"], TODAY)
        assert first.ok
        (package / "SKILL.md").write_text("invalide", encoding="utf-8")

        changed = resolve_skill_registry(runtime, ["main"], TODAY)
        repeated = resolve_skill_registry(runtime, ["main"], TODAY)

        assert changed.registry is None
        assert changed.codes == ("SKILL_INVALID",)
        assert repeated.registry is None
        assert repeated.codes == ("SKILL_INVALID",)

    def test_valid_modification_is_visible_without_silent_staleness(
            self, tmp_path):
        roots = tmp_path / "skills"
        roots.mkdir()
        package = write_skill(roots, "audit-python")
        runtime = _runtime({"id": "main", "path": str(roots)})
        request = _request(
            "phases_agents_get_skill",
            {
                "root_ids": ["main"],
                "skill_id": "audit-python",
                "today": "2026-07-27",
            },
        )
        first = server.handle_message(request, runtime)
        markdown = (package / "SKILL.md").read_text(encoding="utf-8")
        (package / "SKILL.md").write_text(
            markdown.replace("Contenu local.", "Contenu modifie.", 1),
            encoding="utf-8",
        )

        second = server.handle_message(request, runtime)

        assert "Contenu modifie." not in _payload(first)["skill"]["content"]
        assert "Contenu modifie." in _payload(second)["skill"]["content"]

    def test_same_size_change_with_restored_mtime_is_not_stale(
            self, tmp_path, monkeypatch):
        roots = tmp_path / "skills"
        roots.mkdir()
        package = write_skill(roots, "audit-python")
        runtime = _runtime({"id": "main", "path": str(roots)})
        request = _request(
            "phases_agents_get_skill",
            {
                "root_ids": ["main"],
                "skill_id": "audit-python",
                "today": "2026-07-27",
            },
        )
        first = server.handle_message(request, runtime)
        calls = 0
        original_discover = skill_runtime.discover_skills

        def counted(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original_discover(*args, **kwargs)

        monkeypatch.setattr(
            skill_runtime,
            "discover_skills",
            counted,
        )
        skill_md = package / "SKILL.md"
        before = skill_md.stat()
        content = skill_md.read_bytes()
        changed = content.replace(
            b"Contenu local.",
            b"Contenu cache.",
            1,
        )
        assert len(changed) == len(content)
        skill_md.write_bytes(changed)
        os.utime(
            skill_md,
            ns=(before.st_atime_ns, before.st_mtime_ns),
        )
        restored = skill_md.stat()
        assert restored.st_size == before.st_size
        assert restored.st_mtime_ns == before.st_mtime_ns

        second = server.handle_message(request, runtime)

        assert calls == 1
        assert "Contenu cache." not in _payload(first)["skill"]["content"]
        assert "Contenu cache." in _payload(second)["skill"]["content"]

    def test_same_metadata_race_during_discovery_fails_closed(
            self, tmp_path, monkeypatch):
        roots = tmp_path / "skills"
        roots.mkdir()
        package = write_skill(roots, "audit-python")
        runtime = _runtime({"id": "main", "path": str(roots)})
        original_discover = skill_runtime.discover_skills
        raced = False

        def racing_discover(*args, **kwargs):
            nonlocal raced
            discovery = original_discover(*args, **kwargs)
            if not raced:
                raced = True
                skill_md = package / "SKILL.md"
                before = skill_md.stat()
                content = skill_md.read_bytes()
                changed = content.replace(
                    b"Contenu local.",
                    b"Contenu cache.",
                    1,
                )
                assert len(changed) == len(content)
                skill_md.write_bytes(changed)
                os.utime(
                    skill_md,
                    ns=(before.st_atime_ns, before.st_mtime_ns),
                )
            return discovery

        monkeypatch.setattr(
            skill_runtime,
            "discover_skills",
            racing_discover,
        )

        first = resolve_skill_registry(runtime, ["main"], TODAY)
        second = resolve_skill_registry(runtime, ["main"], TODAY)

        assert first.registry is None
        assert first.codes == ("SKILL_CACHE_UNSTABLE",)
        assert second.ok
        found = get_skill(second.registry, "audit-python")
        assert found.ok
        assert "Contenu cache." in found.skill.content

    def test_explicit_refresh_removes_invalidated_entry(self, tmp_path):
        roots = tmp_path / "skills"
        roots.mkdir()
        package = write_skill(roots, "audit-python")
        runtime = _runtime({"id": "main", "path": str(roots)})
        assert resolve_skill_registry(runtime, ["main"], TODAY).ok
        (package / "SKILL.md").write_text("invalide", encoding="utf-8")

        refreshed = server.handle_message(_request(
            "phases_agents_refresh_skills",
            {"root_ids": ["main"], "today": "2026-07-27"},
        ), runtime)
        after = server.handle_message(_request(
            "phases_agents_list_skills",
            {"root_ids": ["main"], "today": "2026-07-27"},
        ), runtime)

        assert refreshed["result"]["isError"] is True
        assert _payload(refreshed)["codes"] == ["SKILL_INVALID"]
        assert after["result"]["isError"] is True
        assert _payload(after)["codes"] == ["SKILL_INVALID"]

    def test_refresh_success_is_explicit(self, tmp_path):
        roots = tmp_path / "skills"
        roots.mkdir()
        write_skill(roots, "audit-python")
        runtime = _runtime({"id": "main", "path": str(roots)})

        refreshed = server.handle_message(_request(
            "phases_agents_refresh_skills",
            {"root_ids": ["main"], "today": "2026-07-27"},
        ), runtime)

        assert refreshed["result"]["isError"] is False
        assert _payload(refreshed)["refreshed"] is True
        assert _payload(refreshed)["discovery"]["complete"] is True

    def test_duplicate_appearing_on_refresh_blocks_everything(self, tmp_path):
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir()
        second.mkdir()
        write_skill(first, "audit-python")
        runtime = _runtime(
            {"id": "first", "path": str(first)},
            {"id": "second", "path": str(second)},
        )
        assert resolve_skill_registry(
            runtime, ["first", "second"], TODAY).ok
        write_skill(second, "audit-python")

        refreshed = server.handle_message(_request(
            "phases_agents_refresh_skills",
            {
                "root_ids": ["first", "second"],
                "today": "2026-07-27",
            },
        ), runtime)

        assert refreshed["result"]["isError"] is True
        assert _payload(refreshed)["codes"] == ["SKILL_DUPLICATE"]

    def test_caches_are_not_shared_between_configurations(
            self, tmp_path, monkeypatch):
        first = tmp_path / "first"
        second = tmp_path / "second"
        first.mkdir()
        second.mkdir()
        write_skill(first, "audit-python")
        write_skill(second, "audit-windows")
        one = _runtime({"id": "main", "path": str(first)})
        two = _runtime({"id": "main", "path": str(second)})
        calls = 0
        original = skill_runtime.discover_skills

        def counted(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(skill_runtime, "discover_skills", counted)

        first_result = resolve_skill_registry(one, ["main"], TODAY)
        second_result = resolve_skill_registry(two, ["main"], TODAY)

        assert first_result.ok and second_result.ok
        assert calls == 2
        assert [item.skill_id for item in
                list_skills(first_result.registry).skills] == [
                    "audit-python",
                ]
        assert [item.skill_id for item in
                list_skills(second_result.registry).skills] == [
                    "audit-windows",
                ]

    def test_public_mutation_cannot_change_cached_registry(self, tmp_path):
        roots = tmp_path / "skills"
        roots.mkdir()
        write_skill(roots, "audit-python")
        runtime = _runtime({"id": "main", "path": str(roots)})
        request = _request(
            "phases_agents_list_skills",
            {"root_ids": ["main"], "today": "2026-07-27"},
        )
        first = server.handle_message(request, runtime)
        first_payload = _payload(first)
        first_payload["skills"][0]["skill_id"] = "mutated"
        first_payload["discovery"]["records"].clear()

        second = server.handle_message(request, runtime)

        assert _payload(second)["skills"][0]["skill_id"] == "audit-python"
        assert len(_payload(second)["discovery"]["records"]) == 1

    def test_warm_result_is_byte_deterministic_and_private(self, tmp_path):
        roots = tmp_path / "skills"
        roots.mkdir()
        write_skill(roots, "audit-python")
        runtime = _runtime({"id": "main", "path": str(roots)})
        request = _request(
            "phases_agents_list_skills",
            {"root_ids": ["main"], "today": "2026-07-27"},
        )

        first = server._encode_response(
            server.handle_message(request, runtime))
        second = server._encode_response(
            server.handle_message(request, runtime))

        assert first == second
        assert str(roots) not in first
        assert "Traceback" not in first

    def test_root_selection_order_is_canonical(self, tmp_path):
        first_root = tmp_path / "first"
        second_root = tmp_path / "second"
        first_root.mkdir()
        second_root.mkdir()
        write_skill(first_root, "audit-python")
        write_skill(second_root, "audit-windows")
        runtime = _runtime(
            {"id": "zeta", "path": str(second_root)},
            {"id": "alpha", "path": str(first_root)},
        )
        first_request = _request(
            "phases_agents_list_skills",
            {
                "root_ids": ["zeta", "alpha"],
                "today": "2026-07-27",
            },
        )
        second_request = _request(
            "phases_agents_list_skills",
            {
                "root_ids": ["alpha", "zeta"],
                "today": "2026-07-27",
            },
        )

        first = server._encode_response(
            server.handle_message(first_request, runtime))
        second = server._encode_response(
            server.handle_message(second_request, runtime))

        assert first == second

    def test_cache_capacity_evicts_deterministically(
            self, tmp_path, monkeypatch):
        roots = tmp_path / "skills"
        roots.mkdir()
        write_skill(roots, "audit-python")
        runtime = _runtime({"id": "main", "path": str(roots)})
        calls = 0
        original = skill_runtime.discover_skills

        def counted(*args, **kwargs):
            nonlocal calls
            calls += 1
            return original(*args, **kwargs)

        monkeypatch.setattr(skill_runtime, "discover_skills", counted)

        for day in range(1, 6):
            result = resolve_skill_registry(
                runtime,
                ["main"],
                datetime.date(2026, 7, day),
            )
            assert result.ok
        first_again = resolve_skill_registry(
            runtime,
            ["main"],
            datetime.date(2026, 7, 1),
        )

        assert first_again.ok
        assert calls == 6

    def test_state_walk_limit_is_fail_closed(self, tmp_path, monkeypatch):
        roots = tmp_path / "skills"
        roots.mkdir()
        write_skill(roots, "audit-python")
        runtime = _runtime({"id": "main", "path": str(roots)})
        monkeypatch.setattr(skill_runtime, "_MAX_STATE_NODES", 2)

        result = resolve_skill_registry(runtime, ["main"], TODAY)

        assert result.registry is None
        assert result.codes == ("SKILL_CACHE_LIMIT",)
