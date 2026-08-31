# Contrat des skills : B1, B2 et B3

## 1. Portee

B1 decouvre, valide, enregistre, selectionne et transporte des skills locaux.
B3 versionne la planification complète et les capacités du client.
Il n'execute ni leur contenu metier, ni leurs scripts. Le LLM appelant lit les
skills selectionnes et reste responsable de leur execution.

Le depot Git est la seule source normative. Aucun skill externe, cache, memoire
ou registre distant n'est approuve implicitement.

## 2. Package

Un candidat est un enfant direct d'une racine explicitement autorisee. Il doit
contenir `SKILL.md` et `phases.json`. Le package complet respecte aussi
`SKILL_MANIFEST_SCHEMA.json`, les routes, fichiers, sections et frontmatter
controles par `validator.validate_skill`.

`SKILL_MANIFEST_SCHEMA.json` est le schéma officiel de `phases.json`.
Aucun autre schéma de manifeste B2 n'est créé.

`SKILL.md` porte les instructions du LLM. `phases.json` porte la sélection,
les capacités, les interdictions et les routes.

La presence de `SKILL.md` ne suffit jamais. Un package invalide n'entre jamais
dans le registre.

## 3. Identite

`phases.json.id` est l'identite. `SKILL.md.name` doit lui correspondre selon le
validator. Le nom du repertoire n'est pas une source d'identite, mais sa cle
portable doit correspondre a celle de l'identifiant.

Une identite :

- contient entre 1 et 64 caracteres ;
- est deja normalisee NFKC ;
- commence et finit par un caractère alphanumérique ;
- utilise seulement des lettres, chiffres, tirets ou traits bas en interne ;
- ne contient aucun separateur, point, controle ou invisible ;
- n'est pas un nom reserve Windows ;
- possede une cle canonique `casefold`.

Une collision de cles canoniques bloque le registre. Aucun premier ou dernier
package n'est choisi.

## 4. Racines et decouverte

Les chemins de racines appartiennent uniquement à une configuration de
confiance chargée au démarrage. Cette configuration associe un identifiant
portable à chaque chemin absolu local. Les identifiants sont normalisés NFKC
puis `casefold`. Une collision d'identifiants ou de chemins réels bloque toute
la configuration.

Un appel MCP sélectionne seulement des `root_ids`. Il ne fournit jamais un
chemin de racine. Un identifiant inconnu échoue avec `SKILL_ROOT_UNKNOWN`.
`discover_skills` conserve une API interne par chemins pour le loader, mais le
serveur lui transmet uniquement les chemins résolus depuis sa configuration.

Les racines ne dependent jamais du dossier courant. Les racines, leurs parents
et leurs packages refusent symlinks, junctions, reparse points et lectures non
sures selon les garanties du validator.

Le parcours B1 inspecte uniquement les enfants directs. Les entrees sont
triees. Une racine absente, illisible ou dangereuse rend la decouverte
incomplete. Cette erreur ne peut jamais devenir un registre vide valide.
Seuls les dossiers sont des candidats. Un fichier ordinaire est ignore. Tout
dossier candidat compte dans la limite avant validation de son nom, afin
qu'un nom hostile ne contourne pas la limite de packages.

Etats publics :

- `VALID` ;
- `INVALID` ;
- `BLOCKED` ;
- `DUPLICATE` ;
- `UNREADABLE` ;
- `TOO_LARGE`.

Les resultats publics contiennent un index de racine et un chemin relatif sur.
Ils ne contiennent aucun chemin absolu, traceback, secret ou contenu complet.
Une liste de racines vide est invalide. Un package invalide reste visible dans
les records et bloque la construction du registre.

## 5. Validation et snapshot

Le loader appelle le parcours officiel du validator. Ce parcours lit et valide
une seule fois `phases.json` et `SKILL.md`, puis fournit le snapshot exact de
ces lectures. Le loader ne relit pas librement les fichiers apres validation.

Un snapshot valide est scelle par le retour exact du validator officiel.
La fabrique interne de snapshot exige un `SkillPackageValidation` réellement
émis par cette API. Un objet construit ou modifié manuellement échoue. Cette
fabrique privée n'est pas une API publique. Le rapport public du loader ne
porte aucun snapshot ni contenu. Une association interne, liée à l'identité du
rapport, transmet les snapshots au registre.

Le registre refuse les objets construits manuellement, clones ou non scelles.

## 6. Limites

Limites maximales B1 :

- 16 racines ;
- profondeur de packages : 1 ;
- 1 000 packages ;
- 10 000 entrees par racine ;
- `SKILL.md` dans B1 : 256 Kio ;
- représentation JSON canonique de tous les champs des snapshots : 16 Mio ;
- 100 codes d'erreur uniques publies par skill ;
- resultat public global : 1 Mio.
- 100 valeurs par contrainte de plan ;
- 128 caractères par valeur de contrainte ;
- 1 000 éléments bornés dans le profil ;
- requête, plan public et réponse JSON-RPC encodée : 1 Mio.
- configuration de racines : 64 Kio ;
- cache MCP : 4 sélections validées ;
- empreinte de cache : 100 000 noeuds, profondeur 64, 10 000 entrées par
  dossier et 32 Mio de métadonnées canoniques.

Une configuration publique peut seulement reduire ces limites.
Le validator conserve sa limite generale de 2 Mio. B1 applique volontairement
une limite plus basse. Le transport contrôle ensuite l'enveloppe JSON-RPC
encodée complète. Une expansion JSON dépassant 1 Mio échoue explicitement.

Chaque référence déclarée reste limitée à 256 Kio. Leur total reste limité
à 1 Mio par package. Elles doivent être UTF-8. Un chemin absolu ou un secret
détecté dans une référence invalide le package.

## 7. Registre

Le registre est construit uniquement depuis une decouverte complete dont tous
les records sont `VALID`. Il est immuable, trie par cle canonique et
independant de l'ordre du systeme de fichiers. Les IDs sont uniques. Une
collision bloque toute construction.

`get_skill` recoit un identifiant, jamais un chemin. Le contenu retourne
provient du snapshot valide et reste borne. Le registre conserve une copie
profonde composée uniquement de chaînes et tuples immuables. Les objets rendus
au planner ou à l'appelant sont des copies fraîches : leur altération ne
modifie jamais le registre.

Le serveur conserve jusqu'à quatre registres scellés par configuration. La
clé comprend l'identité de la configuration, les `root_ids` triés et `today`.
Avant un appel chaud, une empreinte déterministe vérifie les métadonnées de
toute l'arborescence sélectionnée sans relire les contenus. Sous Windows, une
notification récursive native est armée avant le premier digest et avant la
validation. Elle détecte aussi une réécriture de même taille dont le `mtime`
est restauré, y compris pendant la découverte. Un changement ou une erreur
supprime l'ancienne entrée avant toute reconstruction. Un résultat invalide ou
dupliqué n'est jamais mis en cache.

À capacité, la plus ancienne insertion est retirée selon l'ordre logique des
appels. Cette éviction FIFO n'utilise ni horloge, ni ordre du système de
fichiers.

`phases_agents_refresh_skills` force une nouvelle validation. Il reste la
garantie portable lorsque le système ne fournit pas la notification Windows.
Aucune horloge ne commande la validité du cache.

## 8. Selection et plan historique

B1 utilise uniquement `detector.detect_profile`. Le signal de compatibilite
prouve est l'intersection entre `project_types` et `profile.types`.

Le detector ne produit encore ni plateforme, ni domaine, ni fait metier. B1
n'invente donc aucune pertinence semantique. `platforms`, `domain` et les
capacites filtrent uniquement quand l'appelant fournit une contrainte
explicite. Une capacite requise absente ou une capacite interdite presente
rejette le skill. Leur comparaison utilise la clé canonique `casefold`.
`activation.any` ne cree aucun score implicite.

Le schema actuel ne declare aucune dependance entre skills. B1 ne fabrique
donc ni prerequis, ni graphe, ni tri topologique.

Le plan est stable par identifiant. Un registre valide sans skill compatible
produit un plan vide avec `NO_COMPATIBLE_SKILL`. Sa représentation JSON
publique canonique ne dépasse jamais 1 Mio ; sinon `PLAN_LIMIT` est rendu.

## 9. MCP

La surface B1 comprend :

- `phases_agents_detect` ;
- `phases_agents_list_skills` ;
- `phases_agents_get_skill` ;
- `phases_agents_plan` ;
- `phases_agents_refresh_skills`.

Les schemas d'arguments sont fermes. `today` est injecte. Les `root_ids` sont
explicites et non vides. Les chemins correspondants sont chargés une fois par
`server.py --skills-config <chemin-absolu>`. `get_skill` n'accepte aucun
chemin. Les sorties ne publient ni racine, ni cible absolue, ni chemin absolu
present dans les metadonnees ou le contenu, ni secret, ni traceback.

L'initialisation MCP exige `protocolVersion`, `capabilities` et `clientInfo`.
Les limites de requête sont appliquées aux appels directs et au transport.
La taille finale concerne l'enveloppe JSON-RPC encodée, pas seulement le texte
interne du résultat d'un tool.

`phases_agents_plan` conserve le plan `1.0` par défaut. Le plan B3 exige
`plan_version="B3"`. Son paramètre `client_capabilities` est fermé, borné,
sans doublon et trié dans la sortie. Les contraintes B1 ne sont pas mélangées
silencieusement au contrat B3.

## 10. Codes B1

Codes de decouverte :

- `SKILL_ROOT`, `SKILL_ROOT_LIMIT`, `SKILL_ROOT_DUPLICATE` ;
- `SKILL_ROOT_CONFIG`, `SKILL_ROOT_ID`, `SKILL_ROOT_UNKNOWN` ;
- `SKILL_DISCOVERY`, `SKILL_PACKAGE_LIMIT` ;
- `SKILL_SNAPSHOT_LIMIT`, `SKILL_RESULT_LIMIT` ;
- `SKILL_CACHE`, `SKILL_CACHE_LIMIT`, `SKILL_CACHE_STATE`,
  `SKILL_CACHE_UNSTABLE` ;
- `PATH_UNSAFE`, `READ`, `TOO_LARGE` ;
- `SKILL_MISSING`, `MANIFEST_MISSING`, `SKILL_DUPLICATE`.

Codes de registre et plan :

- `REGISTRY_INVALID`, `REGISTRY_UNVALIDATED`, `REGISTRY_LIMIT` ;
- `SKILL_INVALID`, `SKILL_NOT_FOUND`, `SKILL_ID` ;
- `PROFILE_INVALID`, `PROFILE_BLOCKED`, `PLAN_INVALID`, `PLAN_LIMIT` ;
- `NO_COMPATIBLE_SKILL`, `CAPABILITY_MISSING`,
  `CAPABILITY_FORBIDDEN`.

## 11. Garanties et non-garanties

Garanties :

- runtime stdlib pur ;
- aucun reseau, shell ou code cible execute ;
- validation fail-closed ;
- decouverte, registre, selection et plan deterministes ;
- seuls les snapshots valides entrent au registre.

Non-garanties :

- aucune pertinence semantique universelle ;
- aucun telechargement ou approbation externe ;
- aucun audit du contenu des scripts ;
- aucune verification des preuves dans une cible ;
- symlinks Windows privilegies non demontres ;
- atomicite Windows totale non demontree ;
- hors Windows, l'empreinte chaude repose sur les métadonnées observables ;
  une réécriture qui restaure toutes ces métadonnées exige un
  rafraîchissement explicite.

## 12. Pack d'exemple

Une racine contient des packages enfants directs. Aucun package n'est
livré avec ce dépôt : les noms ci-dessous illustrent le contrat.

Exemple minimal à trois packages :

- `example-profiler` ;
- `example-qa` ;
- `example-review`.

`example-profiler` couvre les types detector analysables. Le type `inconnu`
reste exclu. Il organise les faits sans réimplémenter `detector.py`.

`example-qa` exige le type `skill_package`. Le detector produit ce type
seulement avec un marqueur fort. Un projet ordinaire ne le sélectionne pas.

`example-review` couvre des types applicatifs comme `python` et `web`. Il
guide seulement une lecture locale et bornée. Il ne lance aucun projet.

Le planner conserve son unique règle prouvée :

```text
project_types ∩ profile.types
```

Les `activation.any` restent documentaires en B2. Le planner les publie dans
le registre, mais ne les évalue pas.

Le plan historique B1 ne contient pas `skills_missing`. Le plan versionné B3
ajoute cette catégorie selon la section suivante.

La chaîne de responsabilité reste :

```text
Le catalogue de skills est distribué séparément du serveur.
Agent Skills rend SKILL.md portable.
Le MCP sélectionne et expose.
Le LLM exécute la démarche.
```

Le LLM utilise ses propres outils. Il corrige uniquement après autorisation.
Le MCP ne charge, importe ou exécute jamais un skill. Il ne lance aucun script.

Aucun client Claude ou Codex n'installe automatiquement ces packages. Leur
chargement natif éventuel dépend du client et sort du contrat MCP.

Limites B2 conservées :

- symlinks Windows privilégiés non démontrés ;
- atomicité Windows totale non démontrée ;
- preuves cibles non vérifiées ;
- contenu des scripts non audité ;
- reconnaissance HTML non universelle ;
- détection des secrets non universelle ;
- fraîcheur chaude proportionnelle aux packages ;
- aucun audit dynamique ;
- aucune conformité juridique garantie.

Aucun seuil de performance contractuel n'est créé en B2.

## 13. Plan B3

Le schéma officiel est `PLAN_B3_SCHEMA.json`, version `1.0.0`.

Le plan contient :

- `skills_selected` : installé, applicable et exécutable ;
- `skills_not_applicable` : installé, mais non pertinent ;
- `skills_blocked` : applicable, mais inexécutable ;
- `skills_missing` : capacité nécessaire sans fournisseur exécutable.

Chaque skill valide du registre apparaît exactement une fois dans les trois
premières catégories. `skills_missing` ne contient jamais un package installé.

Un skill sélectionné exige toutes ses capacités obligatoires. Une capacité
facultative absente ajoute `OPTIONAL_CLIENT_CAPABILITY_MISSING` et une limite.
Elle ne bloque pas le skill.

Une déclaration client absente ne signifie jamais « tout disponible ». Le plan
ajoute `CLIENT_CAPABILITIES_UNDECLARED`. Tout skill applicable exigeant une
capacité explicite devient bloqué. Une liste vide reste une déclaration vide.

Le vocabulaire officiel vit dans `CLIENT_CAPABILITIES_SCHEMA.json`. Il comprend
notamment `filesystem_read`, `filesystem_search`, `shell`, `web`,
`filesystem_write` et `browser`.

`SKILL_MANIFEST_SCHEMA.json` version `0.2.0` accepte les manifestes historiques
`1.0`. Un manifeste `1.1` exige `provides_capabilities`. Ce champ décrit ce que
le skill fournit. Il ne remplace jamais `requires_capabilities`, qui décrit les
outils nécessaires au client.

Exemple de déclarations de fournisseurs :

- `example-profiler` : `project_profile` ;
- `example-qa` : `example_package_audit` ;
- `example-review` : `example_domain_audit`.

Les lacunes viennent uniquement de `SKILL_GAP_RULES.json`, validé par
`SKILL_GAP_RULES_SCHEMA.json`. B3 contient une règle d'exemple :

- paiement confirmé : `example_domain_audit`.

Un fournisseur absent laisse la lacune ouverte.

Le detector dérive les faits techniques forts. Les faits métier sont déclarés
explicitement dans `.phases-profile.json`, validé par
`PROJECT_FACTS_SCHEMA.json`. Un mot libre du README ne devient jamais un fait.
Une déclaration invalide bloque le profil.

Une lacune disparaît seulement si un fournisseur :

- est installé et valide ;
- est applicable au profil ;
- possède toutes ses capacités obligatoires ;
- n'est pas bloqué.

Le statut global vaut :

- `READY` : au moins un skill exécutable, sans lacune ni blocage ;
- `PARTIAL` : exécution possible, avec lacune ou blocage ;
- `BLOCKED` : aucun skill exécutable.

Chaque étape B3 utilise `READ_AND_EXECUTE_SKILL` et `gate=0`. Cette action est
une instruction destinée au LLM. Le MCP ne lance aucun skill, script, shell,
projet cible, réseau, téléchargement ou LLM.

`skills_missing` n'est jamais une preuve de non-conformité. Il indique seulement
qu'un audit jugé nécessaire par une règle factuelle n'est pas couvert. Aucun
skill juridique et aucune remédiation autonome ne sont installés en B3.
