# phases-agents

![phases-agents : select, block, prove](docs/banner.png)

MCP local de découverte et sélection déterministe de skills validés.

Runtime Python standard library uniquement.

Un serveur. Cinq outils. Zéro exécution cachée.

## Principe

![Mêmes entrées, même plan](docs/determinism.png)

Même cible, même catalogue, mêmes paramètres : même plan. La sélection est
calculée, jamais improvisée.

```text
identifiants de racines configurées
→ découverte bornée
→ validation officielle
→ registre immuable
→ cache vérifié
→ profil detector
→ sélection déterministe
→ plan MCP
```

Le MCP transporte les skills sélectionnés.

Le LLM appelant les interprète ensuite.

Le MCP n’exécute aucun skill.

Le MCP sélectionne et expose.

Le LLM exécute la démarche.

Il utilise alors ses propres outils.

## Architecture

| Fichier | Rôle |
|---|---|
| `validator.py` | contrats officiels et snapshots validés |
| `skill_loader.py` | découverte locale bornée |
| `skill_runtime.py` | racines de confiance et cache vérifié |
| `skill_types.py` | types immuables et limites |
| `registry.py` | registre validé et immuable |
| `detector.py` | profil local de la cible |
| `planner.py` | sélection et ordre déterministes |
| `server.py` | transport JSON-RPC/MCP |
| `capabilities.py` | vocabulaire des capacités client |
| `profile_facts.py` | vocabulaire versionné des faits de profil |
| `skill_gaps.py` | règles de lacunes (`skills_missing`) |

Le contrat normatif est ici :

```text
core/SKILLS_CONTRACT.md
```

## Démarrage rapide

Un package d’exemple est livré dans `examples/skills/`. Trois commandes
suffisent pour voir un plan réel :

```bash
git clone https://github.com/Cherridsaid/phases-agents && cd phases-agents
```

Créez `skills-roots.json` en pointant la racine d’exemple :

```json
{
  "config_version": "1.0",
  "roots": [
    { "id": "demo", "path": "/chemin/absolu/vers/phases-agents/examples/skills" }
  ]
}
```

```bash
python server.py --skills-config /chemin/absolu/skills-roots.json
```

Le serveur lit du JSON-RPC ligne par ligne sur son entrée standard. Un
`phases_agents_plan` sur un projet Python sélectionne alors `hello-python` :

```json
{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"phases_agents_plan",
 "arguments":{"root_ids":["demo"],"target":"/chemin/absolu/vers/un/projet",
 "today":"2026-08-27","plan_version":"B3",
 "client_capabilities":["filesystem_read","filesystem_search"]}}}
```

Deux formats de plan coexistent. `"B3"` est le nom du format versionné, pas
un numéro de version du serveur : son schéma officiel est
`core/PLAN_B3_SCHEMA.json`. C’est le format à utiliser pour tout nouveau
travail ; le format historique reste servi pour ne pas casser les appelants
existants, et sera déprécié avant d’être retiré.

Sans `plan_version`, le plan historique rend une liste d’étapes. Avec `"plan_version": "B3"`, le plan versionné rend
`skills_selected`, `skills_not_applicable`, `skills_blocked` et
`skills_missing`. `client_capabilities` n’est accepté qu’en B3 : déclarer ce
que le client sait faire n’a de sens que dans ce format.

## Package de skill

Chaque package est un enfant direct d’une racine.

Il contient au minimum :

```text
<racine>/<skill-id>/SKILL.md
<racine>/<skill-id>/phases.json
```

Le plus simple pour démarrer le vôtre est de copier
`examples/skills/hello-python/`, puis de renommer l’identifiant.

### Frontmatter de SKILL.md

Cinq clés sont autorisées, toutes optionnelles, mais contrôlées si présentes :

| Clé | Contrainte |
|---|---|
| `name` | doit égaler `phases.json.id` |
| `description` | texte libre borné |
| `version` | doit égaler `phases.json.version` |
| `owner` | identité libre de l’auteur, sans caractère invisible |
| `license` | `Apache-2.0`, `MIT`, `BSD-2-Clause` ou `BSD-3-Clause` |

### Les quatorze sections obligatoires

Chacune est un titre Markdown (`##`), dans n’importe quel ordre :

`Loi centrale` · `Ce que ce skill fait` · `Ce que ce skill ne fait pas` ·
`Conditions d'activation` · `Conditions d'exclusion` ·
`Capacites necessaires` · `Interdictions` · `Methode d'audit` ·
`Contrat de preuve` · `Format de sortie` · `Conditions de blocage` ·
`Limites connues` · `Exemples d'entree` · `Exemple de sortie attendue`

### Champs de phases.json

Tous obligatoires : `schema_version`, `id`, `version`, `title`,
`description`, `domain`, `project_types`, `platforms`, `activation`,
`exclusions`, `requires_capabilities`, `optional_capabilities`,
`forbidden_capabilities`, `execution_mode`, `human_approval`,
`output_schema`, `rules_path`, `references_path`, `scripts_path`,
`tests_path`, `files`.

`output_schema` utilise la forme symbolique `core:NOM_SCHEMA.json`.

### Vocabulaires fermés

`project_types` doit croiser ce que le detector sait produire :
`apk`, `python`, `skill_package`, `solana`, `web`.

`activation.any` utilise les faits du profil : `collects_personal_data`,
`has_api`, `has_apk`, `has_authentication`, `has_database`, `has_ecommerce`,
`has_eu_context`, `has_file_upload`, `has_javascript`, `has_python`,
`has_rust`, `has_skill_packages`, `has_solana`, `has_source_code`,
`has_typescript`, `has_web`, `uses_ai`, `uses_payments`.

`requires_capabilities`, `optional_capabilities` et
`forbidden_capabilities` utilisent : `browser`,
`dependency_installation`, `filesystem_read`, `filesystem_search`,
`filesystem_write`, `human_question`, `shell`, `target_code_execution`,
`web`.

Un `domain` valant `legal`, `juridique`, `regulatory` ou `compliance`
déclenche un régime supplémentaire : chaque règle citée doit porter une
source officielle, une juridiction et une date de vérification.

Le validator contrôle aussi :

- frontmatter plat ;
- quatorze sections obligatoires ;
- routes déclarées ;
- fichiers déclarés ;
- schémas officiels ;
- registre local officiel ;
- chemins confinés ;
- date injectée.

La présence de `SKILL.md` seule échoue.

Un package invalide bloque le registre.

`SKILL_MANIFEST_SCHEMA.json` reste officiel.

Il décrit la **forme** de chaque `phases.json` : champs obligatoires, types et
vocabulaires fermés.

Le moteur de schéma est volontairement minimal. Il applique `enum`,
`minLength` et `minItems`, et rien d’autre : ni `pattern`, ni `if`/`then`, ni
`oneOf`. Un schéma qui utiliserait ces mots-clés serait lui-même rejeté.

Conséquence à connaître : les règles **conditionnelles** ne vivent pas dans le
schéma mais dans `validator.py`, qui reste la source de vérité. La règle de
version en est l’exemple :

- `requires_capabilities` fait partie des vingt et un champs obligatoires ;
- `provides_capabilities` est **interdit** en manifeste `1.0` et **exigé** en
  manifeste `1.1`.

Cette règle est appliquée et testée, mais elle n’est pas exprimable dans le
schéma. Ne lisez donc pas `required` comme la totalité du contrat.

Enfin, les capacités **fournies** forment un vocabulaire **ouvert** : chaque
catalogue nomme ce qu’il apporte, et seule la forme est imposée
(`^[a-z][a-z0-9_]{0,63}$`). Seules les capacités **client** sont fermées : ce
sont celles du protocole, pas celles de votre domaine.

## Identité

`phases.json.id` fournit l’identité.

`SKILL.md.name` doit correspondre.

Le dossier doit avoir la même clé.

La clé utilise NFKC puis `casefold`.

Les collisions bloquent toute construction.

## Sélection

![Chaque skill est classé et justifié](docs/classification.png)

Chaque skill valide du registre tombe dans exactement une catégorie, avec sa
raison. Rien n'est écarté en silence.

Le signal automatique prouvé reste :

```text
project_types ∩ profile.types
```

Plateforme, domaine et capacités filtrent seulement
si l’appelant fournit ces contraintes.

Une capacité interdite rejette le skill.

Aucun score sémantique n’est inventé.

Le plan est trié par identifiant.

Un plan vide reste explicitement valide.

Il contient `NO_COMPATIBLE_SKILL`.

Le plan `B3` classe chaque skill installé.

```text
skills_selected
skills_not_applicable
skills_blocked
```

Chaque skill apparaît exactement une fois.

`skills_missing` contient des capacités absentes.

Les lacunes utilisent des faits confirmés.

Une lacune ne prouve aucune non-conformité.

Le plan public complet reste limité à 1 Mio.

## Tools MCP

Surface publique :

```text
phases_agents_detect
phases_agents_list_skills
phases_agents_get_skill
phases_agents_plan
phases_agents_refresh_skills
```

Arguments principaux :

```text
detect(target)
list_skills(root_ids, today)
get_skill(root_ids, today, skill_id)
plan(root_ids, target, today, constraints?)
plan(root_ids, target, today, plan_version, client_capabilities?)
refresh_skills(root_ids, today)
```

## Démarrage

Les racines sont configurées au démarrage.

Copier `skills-roots.template.json`, puis :

```json
{
  "config_version": "1.0",
  "roots": [
    {
      "id": "product",
      "path": "<chemin-absolu-vers-vos-skills>"
    }
  ]
}
```

```text
python server.py --skills-config <chemin-absolu>/skills-roots.json
```

Le client MCP fournit uniquement des `root_ids`.

Aucun chemin de racine de skills n'est accepté par un appel MCP.

En revanche, `detect` et `plan` prennent un `target` : c'est le projet à
profiler. Ce chemin n'est pas confiné aux racines, par conception : le but
est d'analyser un projet quelconque. Il doit être absolu et local ; les
formes UNC sont refusées. Le serveur y lit des noms de fichiers et des
marqueurs, jamais leur contenu complet.

N'exposez donc ce serveur qu'à un client de confiance. Le modèle de menace
complet, `target` compris, est détaillé dans [SECURITY.md](SECURITY.md).

### Brancher un client MCP

Claude Code (`.mcp.json` à la racine de votre projet) :

```json
{
  "mcpServers": {
    "phases-agents": {
      "command": "python",
      "args": [
        "/chemin/absolu/vers/phases-agents/server.py",
        "--skills-config",
        "/chemin/absolu/vers/skills-roots.json"
      ]
    }
  }
}
```

Codex utilise la même paire commande/arguments dans son propre fichier de
configuration. Aucun jeton, aucune variable d’environnement n’est requis.

`get_skill` accepte uniquement un identifiant.

Le contenu vient du snapshot validé.

Les chemins absolus restent masqués.

Les chaînes sensibles détectées restent masquées.

Les schémas d’arguments sont fermés.

Toute réponse JSON-RPC encodée reste sous 1 Mio.

Le premier appel construit le registre validé.

Les appels chauds vérifient les métadonnées.

`refresh_skills` force la reconstruction.

## Limites

- 16 racines maximum ;
- profondeur directe uniquement ;
- 1 000 packages maximum ;
- 10 000 entrées par racine ;
- `SKILL.md` limité à 256 Kio ;
- référence limitée à 256 Kio ;
- références cumulées limitées à 1 Mio ;
- snapshots cumulés limités à 16 Mio ;
- résultat public limité à 1 Mio ;
- 100 issues maximum par package ;
- empreinte limitée à 100 000 noeuds.

Les appelants peuvent seulement réduire ces limites.

## Contraintes runtime

- Python `>=3.11` ;
- aucune dépendance runtime tierce ;
- aucun réseau implicite ;
- aucun shell runtime ;
- aucun code cible exécuté ;
- aucune horloge implicite ;
- aucune télémétrie ;
- aucun téléchargement de skill.

`pytest` reste une dépendance de développement.

## Tests

Commande :

```text
python -m pytest -q
```

Résultat attendu :

```text
729 réussis, 2 ignorés
0 échec
```

Les textes normatifs sont extraits en LF.

Cette règle vient de `.gitattributes`.

Quelques tests symlinks Windows peuvent être ignorés.

Ils dépendent d'un privilège Windows local.

Les junctions Windows sont réellement testées.

## Niveau de preuve

Le validator confirme uniquement :

```text
STRUCTURALLY_VALIDATED
```

Il ne vérifie pas la cible réelle.

`TARGET_VERIFIED` reste interdit en V1.

## Sécurité

Le loader refuse les reparse points.

Les lectures sont bornées et confinées.

Les sorties restent triées et déterministes.

## Non-garanties

- aucune pertinence sémantique universelle ;
- aucun skill externe automatiquement approuvé ;
- aucun audit du contenu des scripts ;
- aucune preuve cible réellement montée ;
- aucune atomicité Windows totale ;
- aucune reconnaissance HTML universelle ;
- aucune détection universelle des secrets ;
- aucune conformité juridique garantie ;
- aucune marketplace ou source distante.

## Licence

Apache-2.0. Voir `LICENSE` et `NOTICE`.
