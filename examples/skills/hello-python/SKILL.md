---
name: hello-python
description: Skill d'exemple, lecture seule, sans dépendance
version: 0.1.0
owner: exemple
license: Apache-2.0
---

# hello-python

Skill minimal complet : copiez ce dossier pour démarrer le vôtre.

## Loi centrale

Ne conclure que sur un fichier réellement lu. Aucune supposition.

## Ce que ce skill fait

Inventorie les fichiers Python du projet et signale les modules sans test associé.

## Ce que ce skill ne fait pas

Il n'exécute aucun code, n'installe rien et ne modifie aucun fichier.

## Conditions d'activation

Le profil du projet contient le fait `has_python`.

## Conditions d'exclusion

Aucun fichier `.py` lisible dans la cible.

## Capacites necessaires

`filesystem_read` est obligatoire. `filesystem_search` accélère l'inventaire.

## Interdictions

Ne jamais ouvrir une URL, lancer un interpréteur ou écrire dans la cible.

## Methode d'audit

1. Lister les fichiers `.py`.
2. Repérer les fichiers `test_*.py`.
3. Associer chaque module à son test.
4. Émettre un finding par module non couvert.

## Contrat de preuve

Chaque finding cite un chemin relatif existant. Sans chemin lu, le finding est invalide.

## Format de sortie

Un tableau de findings conformes à `core:FINDING_SCHEMA.json`.

## Conditions de blocage

Cible illisible ou profil bloqué : rendre BLOCKED, ne rien deviner.

## Limites connues

L'association module/test est nominale : un test placé ailleurs n'est pas vu.

## Exemples d'entree

Un projet contenant `app.py`, `utils.py` et `tests/test_app.py`.

## Exemple de sortie attendue

Un finding `EX-001` : `utils.py` n'a pas de test associé, sévérité `P3_LOW`, preuve = chemin du module.
