# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.5.0] - 2026-08-28

First public release.

### Added

- Local MCP server over JSON-RPC/stdio with five tools: `phases_agents_detect`,
  `phases_agents_list_skills`, `phases_agents_get_skill`, `phases_agents_plan`
  and `phases_agents_refresh_skills`.
- Deterministic selection: same target, same catalogue, same parameters, same
  plan. Every valid skill lands in exactly one category with its reason.
- `B3` plan format with `skills_selected`, `skills_not_applicable`,
  `skills_blocked` and `skills_missing`, described by
  `PLAN_B3_SCHEMA.json`.
- Strict skill package contract: twenty one mandatory manifest fields,
  fourteen mandatory `SKILL.md` sections, closed vocabularies for client
  capabilities, and an open vocabulary for the capabilities a catalogue
  provides.
- Explicit threat model in `SECURITY.md`, including the `target` surface.
- Example package `examples/skills/hello-python` and bilingual README.

### Security

- Fail-closed reparse point detection on every platform: a permission error on
  any path component blocks the profile instead of allowing it. Before this,
  `os.path.islink` swallowed the error outside Windows and returned a green
  light where the Windows branch blocked.
- Registry, loader and runtime read only inside declared roots, with hard
  caps on package count, entry count, file sizes and public output size.

[Unreleased]: https://github.com/Cherridsaid/phases-agents/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/Cherridsaid/phases-agents/releases/tag/v0.5.0
