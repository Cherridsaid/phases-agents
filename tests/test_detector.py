"""Tests P2 — détecteur de profil de projet."""

import os
import subprocess

import pytest

import detector


def _write(base, rel, content=""):
    path = base / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")
    return path


def test_solana_repo_detected_by_content_marker(tmp_path):
    _write(tmp_path, "programs/lib.rs", "use anchor_lang::prelude::*;\ndeclare_id!(\"x\");")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]
    assert "rust" in prof["languages"]


def test_rust_without_solana_marker_is_not_solana(tmp_path):
    # Anti-faux-positif : .rs sans marqueur ne réveille PAS solana-scanner.
    _write(tmp_path, "src/main.rs", "fn main() { println!(\"hello\"); }")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]
    assert prof["types"] == ["inconnu"]
    assert "rust" in prof["languages"]


def test_solana_marker_only_in_rust_line_comment_is_not_solana(tmp_path):
    _write(tmp_path, "src/main.rs", "// anchor_lang was considered\nfn main() {}")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_solana_marker_in_rust_block_comment_is_not_solana(tmp_path):
    _write(tmp_path, "src/main.rs", "/* uses solana_program maybe */\nfn main() {}")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_solana_marker_in_rust_string_is_not_solana(tmp_path):
    _write(tmp_path, "src/main.rs", "fn main() { let s = \"solana_program\"; }")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_solana_marker_in_rust_raw_string_with_hashes_is_not_solana(tmp_path):
    # Chaîne brute r#"..."# contenant un guillemet interne : le marqueur à
    # l'intérieur ne doit pas compter (délimiteur à dièses équilibrés).
    _write(tmp_path, "src/lib.rs", "const S: &str = r#\"x \" anchor_lang\"#;")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_shebang_with_marker_is_not_solana(tmp_path):
    _write(tmp_path, "src/main.rs", "#!/usr/bin/anchor_lang::fake\nfn main() {}")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_inner_attribute_preserved_and_marker_after_it_detected(tmp_path):
    # `#![no_std]` n'est PAS un shebang : le fichier reste analysé normalement.
    _write(tmp_path, "src/lib.rs", "#![no_std]\nuse anchor_lang::prelude::*;")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_bom_before_shebang_still_stripped(tmp_path):
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "main.rs").write_text(
        "﻿#!/usr/bin/anchor_lang::fake\nfn main() {}", encoding="utf-8"
    )
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_escaped_quote_char_literals_do_not_expose_following_string(tmp_path):
    # '\'' puis '"' puis "anchor_lang::x" : le marqueur reste dans une chaîne.
    _write(tmp_path, "src/main.rs", "fn main(){let a='\\'';'\"';\"anchor_lang::x\";}")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_hex_and_unicode_char_escapes_consumed(tmp_path):
    _write(tmp_path, "src/main.rs", "fn f(){let _='\\x41';let _='\\u{1F600}';}\nuse anchor_lang::prelude::*;")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_char_literal_with_quote_does_not_break_marker_detection(tmp_path):
    # 'const Q: char = '"';' ne doit pas avaler le `use anchor_lang` qui suit.
    _write(tmp_path, "src/lib.rs", "const Q: char = '\"';\nuse anchor_lang::prelude::*;")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_byte_string_hiding_marker_is_not_solana(tmp_path):
    # b"solana_program" est une chaîne d'octets -> le marqueur ne compte pas.
    _write(tmp_path, "src/lib.rs", "fn main() { let _ = b\"solana_program\"; }")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_lifetime_named_like_marker_is_not_solana(tmp_path):
    # Un lifetime nommé 'anchor_lang n'est PAS un usage Solana.
    _write(tmp_path, "src/lib.rs", "struct S<'anchor_lang>(&'anchor_lang str);")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_absolute_import_wins_over_local_mod_shadow(tmp_path):
    # `mod anchor_lang {}` + `use ::anchor_lang` : l'import absolu réfère au
    # crate externe -> Solana, malgré le module local homonyme.
    _write(
        tmp_path,
        "src/lib.rs",
        "mod anchor_lang {}\nuse ::anchor_lang::prelude::*;",
    )
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_locally_declared_mod_shadows_crate_name(tmp_path):
    # `mod anchor_lang { ... }` : module maison homonyme -> pas le crate Solana.
    _write(
        tmp_path,
        "src/main.rs",
        "mod anchor_lang { pub fn ping() {} }\nfn main() { anchor_lang::ping(); }",
    )
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_absolute_path_type_alias_is_solana(tmp_path):
    # `::solana_program::pubkey::Pubkey` : chemin absolu vers le crate.
    _write(tmp_path, "src/lib.rs", "type Key = ::solana_program::pubkey::Pubkey;")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_local_path_with_spaces_around_colons_is_not_solana(tmp_path):
    # Espaces autour de `::` : `local :: anchor_lang :: ping()` reste local.
    _write(tmp_path, "src/main.rs", "fn f() { local :: anchor_lang :: ping(); }")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_local_module_named_like_crate_is_not_solana(tmp_path):
    # `local::anchor_lang::ping()` : anchor_lang est un module local, pas le crate.
    _write(tmp_path, "src/main.rs", "fn f() { local::anchor_lang::ping(); }")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_variable_named_like_marker_is_not_solana(tmp_path):
    # Une variable `solana_program` sans import/chemin/macro -> pas solana.
    _write(tmp_path, "src/lib.rs", "fn f() { let solana_program = 1; }")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_lifetime_annotation_not_confused_with_char(tmp_path):
    _write(tmp_path, "src/lib.rs", "struct S<'a> { x: &'a str }\nuse anchor_lang::prelude::*;")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_solana_client_import_is_solana(tmp_path):
    _write(tmp_path, "src/main.rs", "use solana_client::rpc_client::RpcClient;")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_absolute_path_use_is_solana(tmp_path):
    _write(tmp_path, "src/main.rs", "use ::anchor_lang as anchor;")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_extern_crate_form_is_solana(tmp_path):
    _write(tmp_path, "src/main.rs", "extern crate solana_program;")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_spl_associated_token_account_import_is_solana(tmp_path):
    _write(tmp_path, "src/main.rs", "use spl_associated_token_account::get_associated_token_address;")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_all_known_solana_crates_recognized_in_rs(tmp_path):
    # Chaque crate de la source de vérité doit être reconnu comme import .rs.
    for crate in detector._SOLANA_CRATES:
        underscore = crate.replace("-", "_")
        _write(tmp_path, f"src/{underscore}.rs", f"use {underscore}::something;")
        prof = detector.detect_profile(str(tmp_path / "src" / f"{underscore}.rs"))
        assert "solana" in prof["types"], crate


def test_real_declare_id_macro_is_solana(tmp_path):
    _write(tmp_path, "src/lib.rs", "declare_id!(\"Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS\");")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_nested_block_comment_marker_is_not_solana(tmp_path):
    # Commentaire de bloc IMBRIQUÉ : le marqueur reste dans le commentaire.
    _write(tmp_path, "src/lib.rs", "/* a /* b */ anchor_lang */\nfn main() {}")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_workspace_inherited_solana_dep_detected(tmp_path):
    _write(
        tmp_path,
        "Cargo.toml",
        "[workspace.dependencies]\nsolana-program = \"1.18\"\n"
        "[dependencies]\nsolana-program = { workspace = true }",
    )
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_workspace_inherited_renamed_away_is_not_solana(tmp_path):
    # Clé "solana-program" mais le workspace la fait pointer sur serde.
    _write(
        tmp_path,
        "Cargo.toml",
        "[workspace.dependencies]\nsolana-program = { package = \"serde\", version = \"1\" }\n"
        "[dependencies]\nsolana-program = { workspace = true }",
    )
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_workspace_self_cycle_no_crash(tmp_path):
    # [workspace.dependencies] avec workspace=true -> cycle non résolvable :
    # ne doit pas boucler, et par prudence ne compte pas comme solana.
    _write(
        tmp_path,
        "Cargo.toml",
        "[workspace.dependencies]\nsolana-program = { workspace = true }\n"
        "[dependencies]\nsolana-program = { workspace = true }",
    )
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_cross_file_workspace_rename_not_solana(tmp_path):
    # Racine renomme solana-program -> serde ; membre hérite via workspace=true.
    # L'héritage cross-fichier n'est pas résolu -> refusé, pas de faux positif.
    _write(
        tmp_path,
        "Cargo.toml",
        "[workspace]\nmembers = [\"member\"]\n"
        "[workspace.dependencies]\nsolana-program = { package = \"serde\", version = \"1\" }",
    )
    _write(
        tmp_path,
        "member/Cargo.toml",
        "[dependencies]\nsolana-program = { workspace = true }",
    )
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_apk_folder_detected(tmp_path):
    _write(tmp_path, "app-release.apk", "PK\x03\x04")
    prof = detector.detect_profile(str(tmp_path))
    assert prof["types"] == ["apk"]


def test_apk_single_file_target(tmp_path):
    apk = _write(tmp_path, "build/app.apk", "PK")
    prof = detector.detect_profile(str(apk))
    assert prof["types"] == ["apk"]


def test_web_detected_by_package_json(tmp_path):
    _write(tmp_path, "package.json", "{}")
    _write(tmp_path, "src/index.tsx", "export const A = 1;")
    prof = detector.detect_profile(str(tmp_path))
    assert "web" in prof["types"]
    assert "typescript" in prof["languages"]


def test_python_detected(tmp_path):
    _write(tmp_path, "pyproject.toml", "[project]")
    _write(tmp_path, "app.py", "print(1)")
    prof = detector.detect_profile(str(tmp_path))
    assert "python" in prof["types"]
    assert "python" in prof["languages"]


def test_hybrid_web_and_solana_both_activated(tmp_path):
    # Angle mort : un repo hybride doit activer les DEUX jeux.
    _write(tmp_path, "frontend/package.json", "{}")
    _write(tmp_path, "onchain/lib.rs", "use solana_program::pubkey::Pubkey;")
    prof = detector.detect_profile(str(tmp_path))
    assert "web" in prof["types"]
    assert "solana" in prof["types"]


def test_missing_path_returns_inconnu_no_crash():
    prof = detector.detect_profile("C:/chemin/qui/nexiste/pas/xyz")
    assert prof["exists"] is False
    assert prof["types"] == ["inconnu"]


def test_empty_dir_is_inconnu(tmp_path):
    prof = detector.detect_profile(str(tmp_path))
    assert prof["types"] == ["inconnu"]


def test_invalid_target_type_no_crash():
    for bad in ("", "   ", None):
        prof = detector.detect_profile(bad)
        assert prof["types"] == ["inconnu"]


def test_anchor_marker_in_cargo_toml_detected(tmp_path):
    # Marqueur Anchor en dépendance Cargo.toml, pas dans le .rs.
    _write(tmp_path, "Cargo.toml", "[dependencies]\nanchor-lang = \"0.30\"")
    _write(tmp_path, "src/lib.rs", "pub fn nothing() {}")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]
    assert "rust" in prof["languages"]


def test_commented_anchor_dep_is_not_solana(tmp_path):
    # Dépendance commentée -> ignorée (parse TOML, pas substring).
    _write(tmp_path, "Cargo.toml", "[dependencies]\nserde = \"1\"\n# anchor-lang = \"0.30\"")
    _write(tmp_path, "src/main.rs", "fn main() {}")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_anchor_mentioned_in_string_value_is_not_solana(tmp_path):
    # "anchor-lang" dans une valeur de chaîne, pas comme crate -> pas solana.
    _write(tmp_path, "Cargo.toml", "[package]\ndescription = \"built on anchor-lang\"\n[dependencies]\nserde = \"1\"")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_deeply_nested_cargo_toml_no_recursion_crash(tmp_path):
    # Imbrication pathologique -> tomllib peut lever RecursionError : pas de crash.
    _write(tmp_path, "Cargo.toml", "x = " + "[" * 500 + "0" + "]" * 500)
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_non_string_package_field_is_not_solana(tmp_path):
    # `package = false` (non-chaîne) -> manifeste invalide, pas de faux positif.
    _write(tmp_path, "Cargo.toml", "[dependencies]\nsolana-program = { package = false }")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_invalid_dep_spec_type_is_not_solana(tmp_path):
    # `solana-program = false` : spec de type invalide -> ignoré (pas de faux positif).
    _write(tmp_path, "Cargo.toml", "[dependencies]\nsolana-program = false")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_malformed_cargo_toml_no_crash_no_solana(tmp_path):
    _write(tmp_path, "Cargo.toml", "this is = = not valid toml [[[")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_capitalized_package_name_is_not_solana(tmp_path):
    # `Solana-Program` (majuscules) est un crate distinct du vrai `solana-program`.
    _write(
        tmp_path,
        "Cargo.toml",
        "[dependencies]\nfake = { package = \"Solana-Program\", path = \"fake\" }",
    )
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_fake_local_underscore_package_is_not_solana(tmp_path):
    # `package = "solana_program"` (underscore) + path local = un AUTRE crate.
    _write(
        tmp_path,
        "Cargo.toml",
        "[dependencies]\nsolana_program = { package = \"solana_program\", path = \"fake\" }",
    )
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_renamed_solana_crate_via_package_field_detected(tmp_path):
    # `chain = { package = "solana-program" }` : vrai crate = solana-program.
    _write(tmp_path, "Cargo.toml", "[dependencies]\nchain = { package = \"solana-program\", version = \"1.18\" }")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_alias_named_like_solana_but_pointing_elsewhere_is_not_solana(tmp_path):
    # Clé "solana-program" mais package réel = serde -> PAS solana.
    _write(tmp_path, "Cargo.toml", "[dependencies]\nsolana-program = { package = \"serde\", version = \"1\" }")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_underscore_dev_dependencies_alias_detected(tmp_path):
    _write(
        tmp_path,
        "Cargo.toml",
        "[package]\nname = \"p\"\nversion = \"0.1.0\"\nedition = \"2021\"\n"
        "[dev_dependencies]\nsolana-program = \"1.18\"",
    )
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_underscore_alias_ignored_in_edition_2024(tmp_path):
    # En édition 2024 l'alias underscore n'est plus valide -> non collecté.
    _write(
        tmp_path,
        "Cargo.toml",
        "[package]\nname = \"p\"\nversion = \"0.1.0\"\nedition = \"2024\"\n"
        "[dev_dependencies]\nsolana-program = \"1.18\"",
    )
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_workspace_inherited_edition_2024_excludes_underscore_alias(tmp_path):
    _write(
        tmp_path,
        "Cargo.toml",
        "[workspace]\n[workspace.package]\nedition = \"2024\"\n"
        "[package]\nname = \"p\"\nversion = \"0.1.0\"\nedition.workspace = true\n"
        "[dev_dependencies]\nsolana-program = \"1.18\"",
    )
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_unresolved_workspace_edition_refuses_underscore_alias(tmp_path):
    # Membre héritant l'édition d'un parent NON lu -> édition inconnue ->
    # l'alias underscore n'est pas accepté (pourrait être 2024).
    _write(
        tmp_path,
        "member/Cargo.toml",
        "[package]\nname = \"m\"\nversion = \"0.1.0\"\nedition.workspace = true\n"
        "[dev_dependencies]\nsolana-program = \"1.18\"",
    )
    prof = detector.detect_profile(str(tmp_path / "member" / "Cargo.toml"))
    assert "solana" not in prof["types"]


def test_solana_dep_in_target_specific_table(tmp_path):
    _write(
        tmp_path,
        "Cargo.toml",
        "[target.'cfg(unix)'.dependencies]\nsolana-program = \"1.18\"",
    )
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" in prof["types"]


def test_plain_rust_cargo_without_solana_stays_inconnu(tmp_path):
    _write(tmp_path, "Cargo.toml", "[dependencies]\nserde = \"1\"")
    _write(tmp_path, "src/main.rs", "fn main() {}")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]
    assert prof["types"] == ["inconnu"]
    assert "rust" in prof["languages"]


def test_single_file_target_ignores_homonym_in_subdir(tmp_path):
    # Cible = root/main.rs (sans marqueur). Un homonyme root/sub/main.rs
    # AVEC marqueur ne doit PAS contaminer le résultat.
    plain = _write(tmp_path, "main.rs", "fn main() {}")
    _write(tmp_path, "sub/main.rs", "use solana_program::pubkey::Pubkey;")
    prof = detector.detect_profile(str(plain))
    assert "solana" not in prof["types"]


def test_invalid_byte_does_not_fuse_marker(tmp_path):
    # Octet invalide entre `anchor_` et `lang` : ne doit pas fusionner en marqueur.
    p = tmp_path / "src"
    p.mkdir()
    (p / "main.rs").write_bytes(b"use anchor_\xfflang::prelude::*;")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def test_binary_rs_file_not_scanned_for_markers(tmp_path):
    # Un .rs binaire (octet nul) ne doit pas être lu comme texte marqueur.
    p = tmp_path / "weird.rs"
    p.write_bytes(b"\x00solana_program\x00")
    prof = detector.detect_profile(str(tmp_path))
    assert "solana" not in prof["types"]


def _make_windows_junction(link, target):
    made = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True,
        text=True,
    )
    assert made.returncode == 0, made.stderr


def _assert_reparse_blocked(profile):
    assert profile["blocked"] is True
    assert profile["issues"] == ["REPARSE_POINT"]
    assert profile["types"] == ["inconnu"]
    assert profile["languages"] == []
    assert profile["markers"] == {}
    assert profile["reason"] == "REPARSE_POINT"


@pytest.mark.skipif(os.name != "nt", reason="jonction Windows")
def test_directory_containing_windows_junction_is_blocked(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.py").write_text("print(1)\n", encoding="utf-8")
    junction = root / "escape"
    _make_windows_junction(junction, outside)
    try:
        _assert_reparse_blocked(detector.detect_profile(str(root)))
    finally:
        if os.path.lexists(junction):
            os.rmdir(junction)


@pytest.mark.skipif(os.name != "nt", reason="jonction Windows")
def test_single_file_through_parent_junction_is_blocked(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    (outside / "secret.py").write_text("print(1)\n", encoding="utf-8")
    junction = root / "escape"
    _make_windows_junction(junction, outside)
    try:
        target = junction / "secret.py"
        _assert_reparse_blocked(detector.detect_profile(str(target)))
    finally:
        if os.path.lexists(junction):
            os.rmdir(junction)


@pytest.mark.skipif(os.name != "nt", reason="jonction Windows")
def test_single_file_through_nested_parent_junction_is_blocked(tmp_path):
    root = tmp_path / "root" / "nested"
    outside = tmp_path / "outside"
    deep = outside / "deeper"
    root.mkdir(parents=True)
    deep.mkdir(parents=True)
    (deep / "secret.py").write_text("print(1)\n", encoding="utf-8")
    junction = root / "escape"
    _make_windows_junction(junction, outside)
    try:
        target = junction / "deeper" / "secret.py"
        _assert_reparse_blocked(detector.detect_profile(str(target)))
    finally:
        if os.path.lexists(junction):
            os.rmdir(junction)


@pytest.mark.skipif(os.name != "nt", reason="jonction Windows")
def test_final_windows_junction_is_blocked(tmp_path):
    root = tmp_path / "root"
    outside = tmp_path / "outside"
    root.mkdir()
    outside.mkdir()
    junction = root / "escape"
    _make_windows_junction(junction, outside)
    try:
        _assert_reparse_blocked(detector.detect_profile(str(junction)))
    finally:
        if os.path.lexists(junction):
            os.rmdir(junction)


def test_normal_single_file_has_no_reparse_block(tmp_path):
    target = _write(tmp_path, "normal.py", "print(1)\n")
    profile = detector.detect_profile(str(target))
    assert profile["blocked"] is False
    assert profile["issues"] == []
    assert profile["types"] == ["python"]


def test_parent_permission_error_is_fail_closed(
        tmp_path, monkeypatch):
    target = _write(tmp_path, "normal.py", "print(1)\n")
    denied_parent = os.path.normcase(os.path.abspath(tmp_path))
    real_lstat = detector.os.lstat

    def guarded_lstat(path, *args, **kwargs):
        current = os.path.normcase(os.path.abspath(os.fspath(path)))
        if current == denied_parent:
            raise PermissionError("parent denied")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(detector.os, "lstat", guarded_lstat)
    _assert_reparse_blocked(detector.detect_profile(str(target)))


def test_parent_permission_error_is_fail_closed_on_posix_branch(
        tmp_path, monkeypatch):
    """Meme garantie sur la branche POSIX, depuis n'importe quelle plateforme.

    Le test ci-dessus ne prouve que la branche de la machine qui l'execute :
    sous Windows il restait vert alors que la branche POSIX etait fail-open,
    parce que `os.path.islink` avale l'erreur de `lstat` et rend `False`.
    Forcer la branche ici rend la regression visible des deux cotes.
    """
    target = _write(tmp_path, "normal.py", "print(1)\n")
    denied_parent = os.path.normcase(os.path.abspath(tmp_path))
    real_lstat = detector.os.lstat

    def guarded_lstat(path, *args, **kwargs):
        current = os.path.normcase(os.path.abspath(os.fspath(path)))
        if current == denied_parent:
            raise PermissionError("parent denied")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(detector.os, "lstat", guarded_lstat)
    monkeypatch.setattr(detector.os, "name", "posix")
    _assert_reparse_blocked(detector.detect_profile(str(target)))
