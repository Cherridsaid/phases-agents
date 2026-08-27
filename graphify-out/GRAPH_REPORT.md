# Graph Report - MCP phase agent  (2026-08-27)

## Corpus Check
- 33 files · ~204,276 words
- Verdict: corpus is large enough that graph structure adds value.

## Summary
- 1189 nodes · 2627 edges · 50 communities (34 shown, 16 thin omitted)
- Extraction: 85% EXTRACTED · 15% INFERRED · 0% AMBIGUOUS · INFERRED: 396 edges (avg confidence: 0.73)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `76a00aa6`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- [[_COMMUNITY_Community 0|Community 0]]
- [[_COMMUNITY_Community 1|Community 1]]
- [[_COMMUNITY_Community 2|Community 2]]
- [[_COMMUNITY_Community 3|Community 3]]
- [[_COMMUNITY_Community 4|Community 4]]
- [[_COMMUNITY_Community 5|Community 5]]
- [[_COMMUNITY_Community 6|Community 6]]
- [[_COMMUNITY_Community 7|Community 7]]
- [[_COMMUNITY_Community 8|Community 8]]
- [[_COMMUNITY_Community 9|Community 9]]
- [[_COMMUNITY_Community 10|Community 10]]
- [[_COMMUNITY_Community 11|Community 11]]
- [[_COMMUNITY_Community 12|Community 12]]
- [[_COMMUNITY_Community 13|Community 13]]
- [[_COMMUNITY_Community 14|Community 14]]
- [[_COMMUNITY_Community 15|Community 15]]
- [[_COMMUNITY_Community 16|Community 16]]
- [[_COMMUNITY_Community 17|Community 17]]
- [[_COMMUNITY_Community 18|Community 18]]
- [[_COMMUNITY_Community 19|Community 19]]
- [[_COMMUNITY_Community 20|Community 20]]
- [[_COMMUNITY_Community 21|Community 21]]
- [[_COMMUNITY_Community 22|Community 22]]
- [[_COMMUNITY_Community 23|Community 23]]
- [[_COMMUNITY_Community 24|Community 24]]
- [[_COMMUNITY_Community 25|Community 25]]
- [[_COMMUNITY_Community 26|Community 26]]
- [[_COMMUNITY_Community 27|Community 27]]
- [[_COMMUNITY_Community 28|Community 28]]
- [[_COMMUNITY_Community 29|Community 29]]
- [[_COMMUNITY_Community 30|Community 30]]
- [[_COMMUNITY_Community 31|Community 31]]
- [[_COMMUNITY_Community 32|Community 32]]
- [[_COMMUNITY_Community 33|Community 33]]
- [[_COMMUNITY_Community 34|Community 34]]
- [[_COMMUNITY_Community 35|Community 35]]
- [[_COMMUNITY_Community 36|Community 36]]
- [[_COMMUNITY_Community 37|Community 37]]
- [[_COMMUNITY_Community 38|Community 38]]
- [[_COMMUNITY_Community 39|Community 39]]
- [[_COMMUNITY_Community 40|Community 40]]
- [[_COMMUNITY_Community 41|Community 41]]
- [[_COMMUNITY_Community 42|Community 42]]
- [[_COMMUNITY_Community 43|Community 43]]
- [[_COMMUNITY_Community 44|Community 44]]
- [[_COMMUNITY_Community 45|Community 45]]
- [[_COMMUNITY_Community 46|Community 46]]
- [[_COMMUNITY_Community 47|Community 47]]
- [[_COMMUNITY_Community 48|Community 48]]

## God Nodes (most connected - your core abstractions)
1. `_codes()` - 99 edges
2. `TestAuditPathNeverActs` - 74 edges
3. `_valid_finding()` - 70 edges
4. `Issue` - 68 edges
5. `discover_skills()` - 63 edges
6. `_vf()` - 63 edges
7. `_write()` - 57 edges
8. `write_skill()` - 53 edges
9. `_scan_source()` - 53 edges
10. `build_plan()` - 43 edges

## Surprising Connections (you probably didn't know these)
- `build_b3_plan()` --calls--> `normalize_client_capabilities()`  [INFERRED]
  planner.py → capabilities.py
- `_dispatch_tool()` --calls--> `normalize_client_capabilities()`  [INFERRED]
  server.py → capabilities.py
- `_parse_project_facts()` --calls--> `validate_project_facts_declaration()`  [INFERRED]
  detector.py → validator.py
- `detect_profile()` --calls--> `redact_sensitive_text()`  [INFERRED]
  detector.py → validator.py
- `_dispatch_tool()` --calls--> `detect_profile()`  [INFERRED]
  server.py → detector.py

## Communities (50 total, 16 thin omitted)

### Community 0 - "Community 0"
Cohesion: 0.07
Nodes (21): _parse_frontmatter(), Fabrique privee reservee aux tests unitaires internes.      Les interfaces pub, Valide un rapport V1 complet.      R6-001 + R6-004 : toutes les omissions sont, _trusted_rules_for_tests(), validate_report(), _codes(), _legal_basis(), Chaque contournement confirme par le jury devient un test permanent. (+13 more)

### Community 1 - "Community 1"
Cohesion: 0.06
Nodes (30): _bounded_codes(), _date_code(), discover_skills(), _outputs_fit(), Decouverte locale, bornee et deterministe des packages de skills., Decouvre et valide les enfants directs des racines autorisees.      Toute erreur, _real_within(), _record_state() (+22 more)

### Community 2 - "Community 2"
Cohesion: 0.05
Nodes (46): _path_has_reparse_component(), Controle tous les parents existants, sans suivre un lien volontairement., _valid_root_path(), _CacheEntry, canonical_root_id(), _clear_cache(), _close_watchers(), configure_skill_runtime() (+38 more)

### Community 3 - "Community 3"
Cohesion: 0.05
Nodes (21): _aws_synthetic(), _bearer_synthetic(), _codes(), Tests permanents de l'audit-security.  Corpus fixe. Aucun acces reseau. Aucune d, _run_server(), _stripe_synthetic(), test_hostile_evidence_paths_are_rejected(), test_issue_output_never_repeats_detected_secret() (+13 more)

### Community 4 - "Community 4"
Cohesion: 0.05
Nodes (64): _assert_reparse_blocked(), _make_windows_junction(), Tests P2 — détecteur de profil de projet., test_absolute_import_wins_over_local_mod_shadow(), test_absolute_path_type_alias_is_solana(), test_absolute_path_use_is_solana(), test_alias_named_like_solana_but_pointing_elsewhere_is_not_solana(), test_all_known_solana_crates_recognized_in_rs() (+56 more)

### Community 5 - "Community 5"
Cohesion: 0.06
Nodes (29): _assert_exact_stdio_tool(), _assert_safe_response(), _assert_safe_stdio(), _aws_synthetic(), _b1_arguments(), _b1_workspace(), _expected_error(), Transport JSON-RPC et tools B1 de phases-agents. (+21 more)

### Community 6 - "Community 6"
Cohesion: 0.06
Nodes (54): _bounded_rpc_response(), _business_error(), _dispatch_tool(), _encode_response(), _error(), handle_message(), _json_value_error(), _load_registry_for_tool() (+46 more)

### Community 7 - "Community 7"
Cohesion: 0.13
Nodes (12): _errors(), _make_skill(), Tests du validator — phases-agents.  Chaque test construit une fixture minimal, validate_skill avec `today` fourni par defaut (R6-001)., test_comparison_prose_preserves_all_required_sections(), TestAdversarialSkills, TestValidateSkill, _valid_manifest() (+4 more)

### Community 8 - "Community 8"
Cohesion: 0.08
Nodes (9): Retourne la liste des violations trouvées dans ``source``., Invariant 3 : le chemin d'audit lit et dit, il n'agit pas., `import os.path` lie le nom `os` : les appels restent contrôlés., str.replace est légitime et omniprésent : jamais de faux positif., Le second argument de Path.open est buffering, pas un mode., builtins.<primitive> rejoint l'appel nu., La primitive est détenue dès sa lecture., _scan_source() (+1 more)

### Community 9 - "Community 9"
Cohesion: 0.09
Nodes (26): _b3_error(), B3BlockedSkill, B3MissingSkill, B3NotApplicableSkill, B3PlanBuildResult, B3PlanStep, B3SelectedSkill, B3SkillPlan (+18 more)

### Community 10 - "Community 10"
Cohesion: 0.06
Nodes (34): _check_secret_masking(), _coherence_entry(), _fused_runs(), _html_hides_content(), _is_html_markup_candidate(), _is_legal_domain(), _is_markdown_email_autolink(), _is_prose_fragment() (+26 more)

### Community 11 - "Community 11"
Cohesion: 0.05
Nodes (38): Architecture, Brancher un client MCP, Champs de phases.json, code:text (identifiants de racines configurées), code:text (phases_agents_detect), code:text (detect(target)), code:json ({), code:text (python server.py --skills-config <chemin-absolu>/skills-root) (+30 more)

### Community 12 - "Community 12"
Cohesion: 0.09
Nodes (25): _has_invisible_or_mixed(), _host_allowed(), _known_rules_issue(), _legal_coherence_issue(), _legal_freshness_verdict(), _no_dup_object(), _norm_dedup_key(), _norm_unicode() (+17 more)

### Community 13 - "Community 13"
Cohesion: 0.06
Nodes (12): _dll_handle_violations(), Contrôle exhaustif des poignées DLL ctypes.      Toute poignée créée par WinDL, L'exemption ctypes de skill_runtime reste épinglée à trois         fonctions d', Anti fail-open : un alias de la poignée DLL ne blanchit rien., Charger une autre DLL viderait la liste blanche de son sens., La poignée passée à getattr échappe au contrôle statique., La poignée n'a pas besoin d'un nom pour lier une fonction., ctypes.windll lie un symbole sans constructeur DLL. (+4 more)

### Community 14 - "Community 14"
Cohesion: 0.19
Nodes (8): build_plan(), Selectionne sans executer, puis ordonne par identite canonique., _python_profile(), Planner B1 : selection explicite et ordre stable., _registry(), test_bad_constraints_never_raise(), test_bad_profile_types_never_raise(), TestB1004Planner

### Community 15 - "Community 15"
Cohesion: 0.15
Nodes (11): build_registry(), list_skills(), Construit tout le registre, ou rien.      Une decouverte incomplete, une entree, Rend des copies immuables des metadonnees publiques., _build(), _combined(), Registre B1 : confiance, collisions et immutabilite., test_bad_build_input_never_raises() (+3 more)

### Community 16 - "Community 16"
Cohesion: 0.09
Nodes (21): _audit_path_closure(), _binding_pairs(), _check_attribute_open(), _check_open(), _check_open_mode(), _local_imports(), _module_aliases(), P0 — invariants structurels du produit.  Le produit tient trois promesses qui (+13 more)

### Community 17 - "Community 17"
Cohesion: 0.14
Nodes (21): _cargo_has_solana_dep(), _collect_files(), detect_profile(), _has_reparse_component(), _is_reparse_point(), _parse_project_facts(), Détecteur de profil de projet — phases-agents.  Lit une cible en LECTURE SEULE, Vrai si le code .rs utilise réellement un crate Solana.      Signaux NON masqu (+13 more)

### Community 18 - "Community 18"
Cohesion: 0.13
Nodes (17): Etat prive profondement immuable d'un skill valide., RegistryBuildResult, RegistryListResult, _RegistryState, SkillSummary, _store_skill(), _StoredSkill, DiscoveryReport (+9 more)

### Community 19 - "Community 19"
Cohesion: 0.11
Nodes (23): _is_official_core_dir(), _is_reparse_point(), _listdir_bounded(), _load_official_schema(), _main(), Vrai si path est un reparse point Windows (jonction, symlink...).     Sous POSI, Confinement REEL : resout tous les liens intermediaires. Normalise la     casse, Vrai pour un fichier regulier, confine et sans lien. (+15 more)

### Community 20 - "Community 20"
Cohesion: 0.15
Nodes (20): normalize_client_capabilities(), Vocabulaire ferme des capacites du client B3., Valide puis trie les capacites, sans supposer l'inconnu., _payload_guard(), Valide `instance` contre un schema PHASES_SCHEMA_V1. Fail-closed : un     schem, R6-004 : rend uniquement le schema officiel versionne.      ``candidate=None``, Valide un plan B3 contre le schema officiel ferme., Valide la declaration fermee des capacites client. (+12 more)

### Community 21 - "Community 21"
Cohesion: 0.19
Nodes (11): _collect_nodeids(), _empty_registry(), _execute_nodeids(), _matrix_errors(), Garde-fous transversaux B1 : matrice, fuzz, volume et determinisme., _real_discovery(), test_registry_and_planner_scale_to_documented_limit(), TestB1DeterministicFuzz (+3 more)

### Community 22 - "Community 22"
Cohesion: 0.15
Nodes (5): Resout rel sous base. None si absolu, '..', invisible/melange, ADS,     trailin, _safe_relpath(), test_windows_junction_final_refused(), test_windows_junction_parent_refused(), TestSafeRelpath

### Community 23 - "Community 23"
Cohesion: 0.12
Nodes (12): Mapping, _check_json_depth(), _cross_check_severity_model(), _is_official_registry_dir(), _load_facts(), _load_json(), _load_known_rules(), Rejette un JSON trop profond (anti-DoS RecursionError). (+4 more)

### Community 24 - "Community 24"
Cohesion: 0.12
Nodes (16): 10. Codes B1, 11. Garanties et non-garanties, 12. Pack d'exemple, 13. Plan B3, 1. Portee, 2. Package, 3. Identite, 4. Racines et decouverte (+8 more)

### Community 25 - "Community 25"
Cohesion: 0.15
Nodes (10): _copy_skill(), from_skill(), get_skill(), _issue(), Registre immuable des snapshots de skills valides., Copies de lecture pour le planner, jamais l'etat du registre., Recherche par identite canonique, jamais par chemin., Rend une copie de donnees; elle ne constitue pas un sceau de validation. (+2 more)

### Community 26 - "Community 26"
Cohesion: 0.12
Nodes (15): Capacites necessaires, Ce que ce skill fait, Ce que ce skill ne fait pas, Conditions d'activation, Conditions d'exclusion, Conditions de blocage, Contrat de preuve, Exemple de sortie attendue (+7 more)

### Community 27 - "Community 27"
Cohesion: 0.18
Nodes (7): _safe_public_name(), canonical_skill_id(), _discovery_capability(), Types internes immuables de l'etape B1.  Ce module ne decouvre, ne valide et n'e, Lie les snapshots au rapport sans les exposer dans l'API publique., Rend la cle portable d'un identifiant, ou ``None``.      Les identifiants sont d, test_identity_is_portable()

### Community 28 - "Community 28"
Cohesion: 0.22
Nodes (8): 1. Le client MCP, via le paramètre `target`, 2. Un package de skill hostile déposé dans une racine autorisée, 3. Une configuration de racines malveillante, Ce que ce serveur ne fait jamais, Modèle de menace, Politique de sécurité, Signaler une vulnérabilité, Versions supportées

### Community 29 - "Community 29"
Cohesion: 0.25
Nodes (4): _check_schema_shape(), _load_schema(), Rejette tout schema hors PHASES_SCHEMA_V1 ou mal type. Jamais de crash :     pr, Charge un schema core. Fail-closed : absent, invalide, ou mal forme =     erreu

### Community 30 - "Community 30"
Cohesion: 0.36
Nodes (7): normalize_newlines(), _parse_attributes(), Reproductibilité textuelle des contenus de skill., Normalise uniquement les conventions de saut de ligne., test_logical_skill_content_accepts_portable_newlines(), test_logical_skill_content_detects_real_text_difference(), test_repository_declares_portable_lf_rules()

### Community 31 - "Community 31"
Cohesion: 0.33
Nodes (4): load_skill_gap_rules(), Chargement borne et memorise des regles de lacunes B3., Charge une fois le registre officiel, sinon échoue fermé., SkillGapRule

### Community 32 - "Community 32"
Cohesion: 0.5
Nodes (4): _portable_relpath_parts(), Valide la forme portable d'un chemin relatif.      Les antislashs seuls resten, Contrats specifiques par type de preuve., _validate_evidence_item()

## Knowledge Gaps
- **258 isolated node(s):** `Vocabulaire ferme des capacites du client B3.`, `Valide puis trie les capacites, sans supposer l'inconnu.`, `Détecteur de profil de projet — phases-agents.  Lit une cible en LECTURE SEULE`, `Blanchit le "bruit" Rust avant de chercher un marqueur.      Petit lexeur (pas`, `Vrai si le code .rs utilise réellement un crate Solana.      Signaux NON masqu` (+253 more)
  These have ≤1 connection - possible missing edges or undocumented components.
- **16 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Issue` connect `Community 9` to `Community 0`, `Community 32`, `Community 1`, `Community 6`, `Community 7`, `Community 10`, `Community 12`, `Community 18`, `Community 19`, `Community 20`, `Community 22`, `Community 23`, `Community 25`, `Community 29`?**
  _High betweenness centrality (0.186) - this node is a cross-community bridge._
- **Why does `write_skill()` connect `Community 1` to `Community 2`, `Community 5`, `Community 14`, `Community 15`, `Community 21`?**
  _High betweenness centrality (0.071) - this node is a cross-community bridge._
- **Why does `_b1_workspace()` connect `Community 5` to `Community 1`, `Community 2`?**
  _High betweenness centrality (0.069) - this node is a cross-community bridge._
- **Are the 34 inferred relationships involving `Issue` (e.g. with `SelectedSkill` and `RejectedSkill`) actually correct?**
  _`Issue` has 34 INFERRED edges - model-reasoned connections that need verification._
- **Are the 52 inferred relationships involving `discover_skills()` (e.g. with `limits_error()` and `SkillLoadRecord`) actually correct?**
  _`discover_skills()` has 52 INFERRED edges - model-reasoned connections that need verification._
- **What connects `Vocabulaire ferme des capacites du client B3.`, `Valide puis trie les capacites, sans supposer l'inconnu.`, `Détecteur de profil de projet — phases-agents.  Lit une cible en LECTURE SEULE` to the rest of the system?**
  _258 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `Community 0` be split into smaller, more focused modules?**
  _Cohesion score 0.07 - nodes in this community are weakly interconnected._