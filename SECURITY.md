# Politique de sécurité

## Signaler une vulnérabilité

Ouvrez un avis privé via l’onglet **Security** du dépôt
(*Report a vulnerability*). Merci de ne pas ouvrir d’issue publique pour une
faille non corrigée.

Décrivez l’entrée exacte, le comportement observé et le comportement attendu.
Une preuve reproductible locale accélère beaucoup le traitement.

## Modèle de menace

Ce serveur est **local** : il parle JSON-RPC sur stdin/stdout, n’ouvre aucun
port et ne joint aucun réseau. L’attaquant considéré n’est donc pas un
attaquant distant, mais l’une de ces trois sources.

### 1. Le client MCP, via le paramètre `target`

**C’est la principale surface d’attaque, et elle est assumée par conception.**

`phases_agents_detect` et `phases_agents_plan` acceptent un chemin `target`
absolu et local. Ce chemin n’est **pas** confiné aux racines configurées : le
but de l’outil est justement de profiler un projet quelconque. Un client MCP
compromis, ou un modèle soumis à une injection de prompt, peut donc faire
énumérer n’importe quel répertoire lisible par le processus.

Ce qui borne l’exposition :

- **le contenu de certains fichiers est lu**, jusqu’à 200 000 octets par
  fichier (`_MAX_MARKER_BYTES`), pour y chercher des marqueurs techniques :
  dépendances, imports, motifs de framework. Un fichier de faits déclarés
  (`.phases-profile.json`) est lu jusqu’à 32 768 octets, la lecture elle-même
  est bornée à un octet de plus, juste assez pour détecter le dépassement ;
- **aucun contenu brut n’est renvoyé** : la sortie ne porte que des faits, des
  types, des langages et des noms de marqueurs. Le texte lu sert à décider,
  il n’est jamais republié ;
- l’exploration s’arrête à 5 000 fichiers et 10 000 entrées ;
- les chemins absolus sont masqués dans les champs publics ;
- les formes UNC sont refusées ;
- les reparse points et jonctions suspects sont refusés.

Ce que cela implique concrètement : un fichier de la cible peut être lu sans
que son contenu ressorte. La donnée qui remonte est une conclusion
(« ce projet est en Python », « il utilise une base de données »), pas un
extrait. Traitez néanmoins la lecture comme réelle quand vous choisissez le
compte sous lequel tourne le serveur.

Ce qui reste vrai malgré tout : **une arborescence de noms est de
l’information**. Un nom de fichier peut révéler un client, un projet ou une
pathologie.

Conséquence pratique : lancez ce serveur sous un compte qui n’a accès qu’à ce
que vous acceptez de voir profilé, et ne le branchez qu’à un client de
confiance. Si vous avez besoin d’un confinement strict de `target` aux racines
configurées, ouvrez une issue : c’est une option défendable, ce n’est pas le
comportement actuel.

### 2. Un package de skill hostile déposé dans une racine autorisée

Le serveur **n’exécute jamais** un skill : ni `SKILL.md`, ni les scripts
déclarés. Il valide, puis transporte le contenu vers le modèle appelant.

Un package invalide **bloque le registre** au lieu de le dégrader en silence.
Les identités sont normalisées NFKC + `casefold`, et une collision bloque la
construction plutôt que d’élire un gagnant arbitraire.

Limite connue : le corps de `SKILL.md` n’est pas filtré des caractères de
contrôle. Un package hostile peut y placer des séquences ANSI qui perturbent
l’affichage d’un terminal. L’impact est l’usurpation d’affichage, pas
l’exécution de code.

Limite connue : le contenu d’un skill est du texte destiné à un modèle. Il
peut contenir des instructions hostiles. Le serveur ne peut pas juger de
l’intention d’un texte ; c’est au client de décider ce qu’il approuve.

### 3. Une configuration de racines malveillante

Les chemins de racines viennent **uniquement** du fichier de configuration
chargé au démarrage. Un appel MCP ne transmet que des `root_ids` : il ne peut
pas injecter un chemin. Protégez ce fichier comme vous protégeriez un fichier
de configuration de service.

## Ce que ce serveur ne fait jamais

- exécuter un skill, un script ou un shell ;
- écrire dans le projet analysé ;
- installer une dépendance ;
- ouvrir une connexion réseau ;
- lire une horloge pour décider (les dates sont injectées).

Ces absences sont vérifiées par des tests permanents, pas seulement par
convention : voir `tests/test_invariants.py`.

## Versions supportées

La version publiée la plus récente. Ce projet n’a pas encore de branche de
maintenance à long terme.
