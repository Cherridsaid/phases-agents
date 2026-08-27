"""validator.py — phases-agents.

Juge mecanique des skills, des findings et des rapports. Il ne raisonne pas :
il verifie que ce qui est DECLARE est reellement IMPLEMENTE et COHERENT.
Zero dependance tierce (stdlib pure). Deterministe : la date est TOUJOURS
injectee (parametre `today`), jamais lue depuis l'horloge. Fail-closed :
tout schema ou registre absent/invalide est une ERREUR, jamais un laisser-passer.

Sous-ensemble JSON Schema : PHASES_SCHEMA_V1 (PAS Draft-07). Supporte :
  - type: object, array, string, integer, boolean
  - required (objets), properties (objets), additionalProperties: false
  - items (tableaux, schema unique)
  - enum (chaines), minLength (chaines)
Toute autre cle de schema est rejetee au chargement. Les schemas eux-memes
sont valides avant usage : un schema malforme est une erreur, jamais un crash.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import stat
import sys
import unicodedata
import weakref
from collections.abc import Mapping

from capabilities import (
    CLIENT_CAPABILITIES,
    SKILL_PROVIDED_CAPABILITIES,
    normalize_client_capabilities,
)
from profile_facts import PROFILE_FACTS, PROFILE_FACTS_VERSION

_DEFAULT_CORE_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "core")
_DEFAULT_REGISTRY_DIR = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "registry")
_OFFICIAL_SCHEMA_META = {
    "CLIENT_CAPABILITIES_SCHEMA.json": (
        "CLIENT_CAPABILITIES_SCHEMA",
        "1.0.0",
    ),
    "FINDING_SCHEMA.json": ("FINDING_SCHEMA", "0.2.0"),
    "PROJECT_PROFILE_SCHEMA.json": ("PROJECT_PROFILE_SCHEMA", "0.1.0"),
    "PLAN_B3_SCHEMA.json": ("PLAN_B3_SCHEMA", "1.0.0"),
    "PROJECT_FACTS_SCHEMA.json": ("PROJECT_FACTS_SCHEMA", "1.0.0"),
    "REPORT_SCHEMA.json": ("REPORT_SCHEMA", "0.1.0"),
    "SKILL_GAP_RULES_SCHEMA.json": (
        "SKILL_GAP_RULES_SCHEMA",
        "1.0.0",
    ),
    "SKILL_MANIFEST_SCHEMA.json": ("SKILL_MANIFEST_SCHEMA", "0.2.0"),
    "SKILLS_QA_SCHEMA.json": ("SKILLS_QA_SCHEMA", "0.1.0"),
}

# Anti-DoS : plafonds durs avant toute recursion ou parsing profond.
_MAX_JSON_DEPTH = 200
_MAX_SCHEMA_DEPTH = 50
_MAX_FRONTMATTER_VALUE = 500
_MAX_SECTION_BODY = 500
_MAX_API_NODES = 100_000
_MAX_INTEGER_DIGITS = 100

# ---------------------------------------------------------------------------
# Constantes du contrat (miroir de core/). Le validator refuse l'inconnu.
# ---------------------------------------------------------------------------

FINDING_STATES = {
    "OBSERVED", "SUSPECTED", "CONFIRMED", "NOT_APPLICABLE", "BLOCKED",
    "REMEDIATION_PROPOSED", "REMEDIATED", "HUMAN_REVIEW_REQUIRED",
}
SEVERITIES = {"P0_CRITICAL", "P1_HIGH", "P2_MEDIUM", "P3_LOW", "P4_CONTEXTUAL"}
CONFIDENCES = {"HIGH", "MEDIUM", "LOW", "UNKNOWN"}
EVIDENCE_TYPES = {"file", "absence", "config", "log", "observation"}
IMPACT_LEVELS = {"HIGH", "MEDIUM", "LOW", "NONE", "UNKNOWN"}
REMEDIATION_MODES = {"PROPOSE_ONLY", "NONE"}
GATES = {"HUMAN_APPROVAL", "LEGAL_REVIEW", "NONE"}
LEGAL_RULE_STATUSES = {"en_vigueur", "modifie", "abroge"}
LEGAL_BASIS_STATUSES = {
    "VERIFIED_CURRENT", "UNVERIFIED_CURRENT", "STALE", "REPEALED", "NOT_LEGAL",
    "CONFLICTING_SOURCES",
}
DECISIONS = {"CONFIRMED", "SUSPECTED", "HUMAN_REVIEW_REQUIRED", "BLOCKED", "NOT_APPLICABLE"}
PROFILE_FACT_STATES = {
    "CONFIRMED",
    "LIKELY",
    "UNKNOWN",
    "HUMAN_INPUT_REQUIRED",
}
LIVE_CHECK_RESULTS = {"en_vigueur", "modifie", "abroge", "introuvable"}
LIVE_CHECK_METHODS = {"web_search", "official_api", "manual", "cache"}
REPORT_VERSIONS = {"0.1.0"}
# Autorites legales connues (liste blanche, extensible).
LEGAL_AUTHORITIES = {
    "Parlement europeen", "Conseil de l'Union europeenne", "Commission europeenne",
    "CNIL", "APD", "GBA", "EDPB", "EDPS", "Moniteur belge", "Legifrance",
    "Gouvernement francais", "Gouvernement belge", "UE", "Union europeenne",
    # R6-003 : autorites nationales des juridictions desormais cartographiees.
    "BfDI", "Bundesanzeiger",                      # DE
    "Autoriteit Persoonsgegevens", "Overheid.nl",  # NL
    "Garante", "Normattiva",                       # IT
    "AEPD", "BOE",                                 # ES
}
# Jurisdictions reconnues. R6-003 : chaque entree DOIT etre cartographiee dans
# LEGAL_COHERENCE, sans quoi elle serait acceptee sans controle de relation.
# L'invariant est verifie par un test permanent (pas seulement par convention).
LEGAL_JURISDICTIONS = {
    "EU", "EEA", "BE", "FR", "DE", "NL", "IT", "ES", "EUROPE", "BELGIQUE",
    "FRANCE", "UNION EUROPEENNE",
}

# R5-005 / R6-003 : registre de coherence juridiction -> autorites autorisees ->
# domaines officiels autorises. La RELATION est verifiee, pas seulement la
# presence de chaque valeur dans une liste. Un triplet incoherent (ex:
# authority=CNIL + jurisdiction=EU + source=eur-lex.europa.eu) est rejete.
#
# R6-003 - MODELE DE DOMAINES EXPLICITE. `hosts` est un dict :
#     {domaine_exact: (sous-domaines explicitement autorises, ...)}
# Le domaine exact est toujours accepte. Un sous-domaine n'est accepte QUE s'il
# figure nommement dans le tuple. Il n'y a plus de `endswith` permissif :
# `evil.cnil.fr` est rejete alors que `www.cnil.fr` est accepte.
_EU_AUTHORITY_HOSTS = {
    "Parlement europeen": {"eur-lex.europa.eu": ()},
    "Conseil de l'Union europeenne": {"eur-lex.europa.eu": ()},
    "Commission europeenne": {"eur-lex.europa.eu": ()},
    "EDPB": {"edpb.europa.eu": ()},
    "EDPS": {"edps.europa.eu": ()},
    "UE": {"eur-lex.europa.eu": ()},
    "Union europeenne": {"eur-lex.europa.eu": ()},
}
_FR_AUTHORITY_HOSTS = {
    "CNIL": {"cnil.fr": ("www",)},
    "Legifrance": {"legifrance.gouv.fr": ("www",)},
    "Gouvernement francais": {"legifrance.gouv.fr": ("www",)},
}
_BE_AUTHORITY_HOSTS = {
    "APD": {"autoriteprotectiondonnees.be": ("www",)},
    "GBA": {"gegevensbeschermingsautoriteit.be": ("www",)},
    "Moniteur belge": {"moniteur.be": ("www",), "etaamb.be": ("www",)},
    "Gouvernement belge": {"just.fgov.be": ("www",)},
}


def _coherence_entry(authority_hosts: dict[str, dict[str, tuple[str, ...]]]) -> dict:
    """Construit une entree relationnelle.

    `authority_hosts` est la source de verite. `authorities` et `hosts` sont
    des vues derivees, conservees pour l'inspection et les invariants publics.
    """
    hosts: dict[str, tuple[str, ...]] = {}
    for allowed in authority_hosts.values():
        hosts.update(allowed)
    return {
        "authority_hosts": authority_hosts,
        "authorities": set(authority_hosts),
        "hosts": hosts,
    }


LEGAL_COHERENCE = {
    "EU": _coherence_entry(_EU_AUTHORITY_HOSTS),
    "EEA": _coherence_entry(_EU_AUTHORITY_HOSTS),
    "EUROPE": _coherence_entry(_EU_AUTHORITY_HOSTS),
    "UNION EUROPEENNE": _coherence_entry(_EU_AUTHORITY_HOSTS),
    "FR": _coherence_entry(_FR_AUTHORITY_HOSTS),
    "FRANCE": _coherence_entry(_FR_AUTHORITY_HOSTS),
    "BE": _coherence_entry(_BE_AUTHORITY_HOSTS),
    "BELGIQUE": _coherence_entry(_BE_AUTHORITY_HOSTS),
    # R6-003 : juridictions nationales auparavant reconnues mais NON
    # cartographiees. Elles acceptaient silencieusement n'importe quel
    # couple autorite/domaine (ex: DE + CNIL + cnil.fr).
    "DE": _coherence_entry({
        "BfDI": {"bfdi.bund.de": ("www",)},
        "Bundesanzeiger": {"gesetze-im-internet.de": ("www",)},
    }),
    "NL": _coherence_entry({
        "Autoriteit Persoonsgegevens": {
            "autoriteitpersoonsgegevens.nl": ("www",),
        },
        "Overheid.nl": {"wetten.overheid.nl": ()},
    }),
    "IT": _coherence_entry({
        "Garante": {"garanteprivacy.it": ("www",)},
        "Normattiva": {"normattiva.it": ("www",)},
    }),
    "ES": _coherence_entry({
        "AEPD": {"aepd.es": ("www",)},
        "BOE": {"boe.es": ("www",)},
    }),
}


def _host_allowed(host: str, hosts: dict) -> bool:
    """R6-003 : un hote est autorise s'il est le domaine EXACT, ou un
    sous-domaine EXPLICITEMENT liste. Aucun `endswith` permissif : un domaine
    trompeur (`evil.cnil.fr`) ou un suffixe pirate (`notcnil.fr`) est rejete."""
    if not host:
        return False
    for domain, subdomains in hosts.items():
        if host == domain:
            return True
        if host.endswith("." + domain):
            label = host[: -(len(domain) + 1)]
            if label in subdomains:
                return True
    return False


def _legal_coherence_issue(jurisdiction, authority, source_url, path, issues) -> None:
    """R5-005 / R6-003 : verifie la RELATION juridiction -> authority -> host.

    Un triplet incoherent est rejete meme si chaque valeur est connue
    separement. Une juridiction reconnue mais NON cartographiee ne peut plus
    passer silencieusement : elle produit LEGAL_JURISDICTION_UNSUPPORTED.
    """
    if not isinstance(jurisdiction, str):
        issues.append(Issue("error", "LEGAL_JURISDICTION",
                            "juridiction absente ou non-chaine", path))
        return
    if _has_invisible_or_mixed(jurisdiction):
        issues.append(Issue("error", "LEGAL_JURISDICTION",
                            "juridiction avec caractere invisible", path))
        return
    if not _norm_unicode(jurisdiction):
        issues.append(Issue("error", "LEGAL_JURISDICTION",
                            "juridiction vide apres normalisation", path))
        return
    jur = _norm_unicode(jurisdiction).upper()
    entry = LEGAL_COHERENCE.get(jur)
    if entry is None:
        if jur in {_norm_unicode(j).upper() for j in LEGAL_JURISDICTIONS}:
            issues.append(Issue("error", "LEGAL_JURISDICTION_UNSUPPORTED",
                                f"juridiction {jur} reconnue mais non cartographiee "
                                "(autorites et domaines officiels non definis)",
                                path))
        else:
            issues.append(Issue("error", "LEGAL_JURISDICTION",
                                f"juridiction inconnue: {jur!r}", path))
        return
    if not isinstance(authority, str):
        issues.append(Issue("error", "LEGAL_AUTHORITY",
                            "authority absente ou non-chaine", path))
    elif _has_invisible_or_mixed(authority):
        issues.append(Issue("error", "LEGAL_AUTHORITY",
                            "authority avec caractere invisible", path))
    elif not _norm_unicode(authority):
        issues.append(Issue("error", "LEGAL_AUTHORITY",
                            "authority vide apres normalisation", path))
    authority_hosts = None
    authority_can_relate = (
        isinstance(authority, str)
        and not _has_invisible_or_mixed(authority)
        and bool(_norm_unicode(authority))
    )
    if authority_can_relate:
        auth_norm = _norm_dedup_key(authority)
        authority_name = next(
            (name for name in entry["authority_hosts"]
             if _norm_dedup_key(name) == auth_norm),
            None,
        )
        if authority_name is None:
            issues.append(Issue("error", "LEGAL_COHERENCE",
                                f"authority {authority!r} non autorisee pour {jur}",
                                path))
        else:
            authority_hosts = entry["authority_hosts"][authority_name]
    if not isinstance(source_url, str):
        issues.append(Issue("error", "LEGAL_SOURCE",
                            "source absente ou non-chaine", path))
    elif _has_invisible_or_mixed(source_url):
        issues.append(Issue("error", "LEGAL_SOURCE",
                            "source avec caractere invisible", path))
    elif not _norm_unicode(source_url):
        issues.append(Issue("error", "LEGAL_SOURCE",
                            "source vide apres normalisation", path))
    else:
        host = _url_host(source_url)
        allowed_hosts = (
            authority_hosts
            if authority_hosts is not None
            else entry["hosts"] if authority_can_relate
            else None
        )
        if allowed_hosts is not None and (
                not host or not _host_allowed(host, allowed_hosts)):
            issues.append(Issue("error", "LEGAL_COHERENCE",
                                f"source {host!r} non autorisee pour "
                                f"{authority!r} dans {jur}",
                                path))

# Domaines a composante juridique (canoniques + alias). La normalisation
# Unicode (tirets, casse) est faite avant comparaison : un tiret cadratin ou
# une majuscule ne contourne pas les controles.
LEGAL_DOMAINS = {
    "legal", "juridique", "regulatory", "compliance",
}

# Sources juridiques officielles autorisees. R6-003 : meme modele explicite que
# LEGAL_COHERENCE — {domaine_exact: (sous-domaines autorises,)}. Un sous-domaine
# non liste est refuse (`evil.cnil.fr` n'est pas une source officielle).
# Construit depuis LEGAL_COHERENCE : une source officielle est, par definition,
# le domaine d'une juridiction cartographiee. Impossible d'ajouter un domaine
# ici sans le rattacher a une juridiction.
OFFICIAL_LEGAL_HOSTS = {
    domain: subs
    for entry in LEGAL_COHERENCE.values()
    for domain, subs in entry["hosts"].items()
}

SYMBOLIC_SCHEMA_RE = re.compile(r"^core:([A-Z0-9_]+\.json)$")
_FRONTMATTER_KEY_RE = re.compile(r"^[a-z][a-z0-9_-]*$")

# Forme d'un nom de capacite (fournie par un skill, ou citee par une regle de
# lacune). Meme grammaire que les capacites client, mais vocabulaire OUVERT :
# le protocole fixe ce que le client sait faire, pas ce qu'un catalogue apporte.
_CAPABILITY_NAME_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
# Identifiant de lacune : majuscules, chiffres et tirets, borne comme le reste.
_GAP_ID_RE = re.compile(r"^[A-Z][A-Z0-9-]{0,63}$")
# Identifiant LISIBLE : au moins trois segments separes, chacun de DOUZE
# caracteres au plus (lookahead), soit un mot commencant par une lettre et
# portant AU PLUS UN bloc numerique, final ou interne (`oauth2`, `sha256`,
# `iso27001`, `log4j`), soit un nombre pur (version, norme). Un secret
# structure ALTERNE plusieurs blocs dans un segment (`2f8h3k9d`,
# `a1b2c3d4e5f6`), le commence par un chiffre, ou etire un segment au-dela
# de douze caracteres (`abcdefghijkl123`).
_READABLE_IDENTIFIER_RE = re.compile(
    r"(?=[a-z0-9]{1,12}(?![a-z0-9]))[a-z]+(?:[0-9]+[a-z]*)?"
    r"(?:[_-](?:(?=[a-z0-9]{1,12}(?![a-z0-9]))[a-z]+(?:[0-9]+[a-z]*)?"
    r"|[0-9]{1,5})){2,}")

_SCHEMA_KEYS = {
    "$schema", "schema_id", "version", "type", "required", "properties",
    "additionalProperties", "items", "enum", "minLength", "minItems",
}
_SCHEMA_TYPES = {"object", "array", "string", "integer", "boolean"}

SKILL_REQUIRED_SECTIONS = [
    "Loi centrale", "Ce que ce skill fait", "Ce que ce skill ne fait pas",
    "Conditions d'activation", "Conditions d'exclusion", "Capacites necessaires",
    "Interdictions", "Methode d'audit", "Contrat de preuve", "Format de sortie",
    "Conditions de blocage", "Limites connues", "Exemples d'entree",
    "Exemple de sortie attendue",
]
_SECTION_RES = {s: re.compile(rf"^##+\s+{re.escape(s)}\s*$", re.MULTILINE)
                for s in SKILL_REQUIRED_SECTIONS}

# Plafonds durs (anti-bombe).
_MAX_SKILL_MD_BYTES = 2 * 1024 * 1024
_MAX_JSON_BYTES = 1 * 1024 * 1024
_MAX_EXCERPT_CHARS = 2000
_MAX_REFERENCE_BYTES = 256 * 1024
_MAX_REFERENCE_TOTAL_BYTES = 1 * 1024 * 1024
_REFERENCE_ABSOLUTE_PATTERNS = (
    re.compile(r"(?i)(?<![\w])(?:[a-z]:[\\/])[^<>\"'\r\n]*"),
    re.compile(r"(?<![\\])\\\\[^<>\"'\r\n]*"),
    re.compile(r"(?i)\bfile:///(?:[^/\s<>\"']+(?:/[^/\s<>\"']*)*)"),
    re.compile(
        r"""(?:^|(?<=[\s(=,:;'"]))/(?:[^/\s<>"']+(?:/[^/\s<>"']*)*)"""),
)
_MAX_DIRECTORY_ENTRIES = 10_000
_WINDOWS_RESERVED_BASENAMES = {
    "con", "prn", "aux", "nul",
    *(f"com{i}" for i in range(1, 10)),
    *(f"lpt{i}" for i in range(1, 10)),
}

_ISO_DATE_RE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
_SEMVER_RE = _VERSION_RE

_STRONG_EVIDENCE_TYPES = {"file", "config", "absence"}

# R6-006 : deux niveaux EXPLICITES de preuve.
#
# STRUCTURALLY_VALIDATED : le validator confirme la FORME de la preuve
#   (champs obligatoires, types, chemin syntaxiquement sur, ligne valide,
#   extrait non vide, coherence du format). Il ne consulte PAS la cible.
#
# TARGET_VERIFIED : exige qu'un composant ait recu la RACINE de la cible et
#   verifie mecaniquement l'existence du fichier, le confinement du chemin,
#   l'existence de la ligne et la correspondance de l'extrait.
#
# L'etape A ne monte pas la cible : aucun composant ne peut produire cette
# preuve mecanique. TARGET_VERIFIED est donc INTERDIT dans la V1 actuelle.
# Un rapport qui le revendique est rejete (il affirmerait une verification
# qui n'a pas eu lieu).
VALIDATION_LEVELS = {"STRUCTURALLY_VALIDATED", "TARGET_VERIFIED"}
V1_ALLOWED_VALIDATION_LEVELS = {"STRUCTURALLY_VALIDATED"}
# Niveau implicite quand le champ est absent : le validator n'ayant jamais
# consulte la cible, l'omission equivaut a la validation structurelle. Elle ne
# peut donc jamais surestimer ce qui a ete reellement verifie.
DEFAULT_VALIDATION_LEVEL = "STRUCTURALLY_VALIDATED"


class Issue:
    """Un probleme releve. level in {"error", "warning"}. Tri stable explicite."""

    __slots__ = ("level", "code", "message", "path")

    def __init__(self, level: str, code: str, message: str, path: str = "") -> None:
        self.level = level
        self.code = code
        # SEC-006 : une erreur secondaire ne doit jamais recopier un secret
        # deja detecte. Le filtrage central couvre aussi les erreurs de schema,
        # de chemin, d'URL et du parseur.
        self.message = redact_sensitive_text(message)
        self.path = redact_sensitive_text(path)

    def __repr__(self) -> str:
        loc = f" [{self.path}]" if self.path else ""
        return f"{self.level.upper()} {self.code}{loc}: {self.message}"

    def sort_key(self) -> tuple:
        return (self.path, self.code, self.message)


class SkillPackageValidation:
    """Resultat immuable d'une lecture-validation unique d'un package."""

    __slots__ = ("_issues", "_manifest_json", "_skill_md", "__weakref__")

    def __init__(self, issues: list[Issue], manifest_json: str | None,
                 skill_md: str | None) -> None:
        self._issues = tuple(issues)
        self._manifest_json = manifest_json
        self._skill_md = skill_md

    def __setattr__(self, name: str, value: object) -> None:
        if hasattr(self, name):
            raise AttributeError("SkillPackageValidation est immuable")
        object.__setattr__(self, name, value)

    @property
    def issues(self) -> tuple[Issue, ...]:
        return self._issues

    @property
    def valid(self) -> bool:
        return (
            self._manifest_json is not None
            and self._skill_md is not None
            and not any(issue.level == "error" for issue in self._issues)
        )

    @property
    def manifest_json(self) -> str | None:
        return self._manifest_json if self.valid else None

    @property
    def skill_md(self) -> str | None:
        return self._skill_md if self.valid else None


def _skill_validation_capability():
    issued: dict[int, weakref.ReferenceType[SkillPackageValidation]] = {}

    def seal(result: SkillPackageValidation) -> SkillPackageValidation:
        if type(result) is not SkillPackageValidation:
            raise TypeError("SkillPackageValidation attendu")
        identifier = id(result)
        issued[identifier] = weakref.ref(
            result,
            lambda _reference, key=identifier: issued.pop(key, None),
        )
        return result

    def trusted(value: object) -> bool:
        reference = issued.get(id(value))
        return type(value) is SkillPackageValidation and (
            reference is not None and reference() is value
        )

    return seal, trusted


(_seal_skill_package_validation,
 _is_trusted_skill_package_validation) = _skill_validation_capability()
del _skill_validation_capability


def _sorted(issues: list[Issue]) -> list[Issue]:
    return sorted(issues, key=lambda i: i.sort_key())


def _payload_guard(payload, path: str,
                   max_bytes: int = _MAX_JSON_BYTES) -> list[Issue]:
    """Valide l'enveloppe JSON d'une entree API directe.

    Le transport fichier est borne a un Mio et 200 niveaux. L'API Python
    applique la meme enveloppe logique. La marche est iterative : cycles,
    objets non JSON et profondeurs hostiles deviennent des issues.
    """
    issues: list[Issue] = []
    stack = [(payload, path, 0, False)]
    active: set[int] = set()
    approximate_bytes = 0
    nodes = 0

    while stack:
        value, current, depth, leaving = stack.pop()
        if leaving:
            active.discard(id(value))
            continue

        nodes += 1
        if nodes > _MAX_API_NODES:
            issues.append(Issue(
                "error", "TOO_LARGE",
                f"entree API depasse {_MAX_API_NODES} noeuds", path))
            return issues
        if depth > _MAX_JSON_DEPTH:
            issues.append(Issue(
                "error", "TOO_DEEP",
                f"entree API trop profonde (>{_MAX_JSON_DEPTH})", current))
            return issues

        if isinstance(value, str):
            if any(unicodedata.category(ch) == "Cs" for ch in value):
                issues.append(Issue(
                    "error", "ENCODING",
                    "chaine contenant un surrogate Unicode isole", current))
                return issues
            approximate_bytes += len(value.encode("utf-8")) + 2
        elif value is None:
            approximate_bytes += 4
        elif isinstance(value, bool):
            approximate_bytes += 5
        elif isinstance(value, int):
            digits = (
                1 if value == 0
                else (abs(value).bit_length() * 30_103) // 100_000 + 1
            )
            if digits > _MAX_INTEGER_DIGITS:
                issues.append(Issue(
                    "error", "TOO_LARGE",
                    f"entier depasse {_MAX_INTEGER_DIGITS} chiffres",
                    current))
                return issues
            approximate_bytes += digits + (1 if value < 0 else 0)
        elif isinstance(value, float):
            if value != value or value in (float("inf"), float("-inf")):
                issues.append(Issue(
                    "error", "PAYLOAD_TYPE",
                    "nombre non fini interdit en JSON", current))
                return issues
            approximate_bytes += len(repr(value))
        elif isinstance(value, (dict, list)):
            container_id = id(value)
            if container_id in active:
                issues.append(Issue(
                    "error", "PAYLOAD_CYCLE",
                    "structure cyclique interdite", current))
                return issues
            active.add(container_id)
            stack.append((value, current, depth, True))
            approximate_bytes += 2
            if len(value) > _MAX_API_NODES - nodes:
                issues.append(Issue(
                    "error", "TOO_LARGE",
                    f"entree API depasse {_MAX_API_NODES} noeuds", path))
                return issues
            if isinstance(value, dict):
                bad_key = next((key for key in value if not isinstance(key, str)), None)
                if bad_key is not None:
                    issues.append(Issue(
                        "error", "PAYLOAD_TYPE",
                        "objet JSON avec cle non-chaine", current))
                    return issues
                for key in value:
                    if any(unicodedata.category(ch) == "Cs" for ch in key):
                        issues.append(Issue(
                            "error", "ENCODING",
                            "cle contenant un surrogate Unicode isole",
                            current))
                        return issues
                    approximate_bytes += len(key.encode("utf-8")) + 3
                    if approximate_bytes > max_bytes:
                        issues.append(Issue(
                            "error", "TOO_LARGE",
                            f"entree API depasse {max_bytes} octets logiques",
                            path))
                        return issues
                ordered = sorted(value.items(), key=lambda item: item[0])
                for key, child in reversed(ordered):
                    stack.append((
                        child, f"{current}.{key}", depth + 1, False))
            else:
                for index in range(len(value) - 1, -1, -1):
                    stack.append((
                        value[index], f"{current}[{index}]",
                        depth + 1, False))
        else:
            issues.append(Issue(
                "error", "PAYLOAD_TYPE",
                f"type non JSON interdit: {type(value).__name__}", current))
            return issues

        if approximate_bytes > max_bytes:
            issues.append(Issue(
                "error", "TOO_LARGE",
                f"entree API depasse {max_bytes} octets logiques", path))
            return issues
    return issues


# ---------------------------------------------------------------------------
# Normalisation (Unicode, casse, domaines)
# ---------------------------------------------------------------------------

def _norm_unicode(text: str) -> str:
    """NFKC + retrait des invisibles + espaces/points finaux (canonique Windows).
    Utilise pour noms de fichiers et comparaisons (doublons Unicode/casse/NTFS
    detectes). NFKC (pas NFC) pour replier les formes de compatibilite."""
    if not isinstance(text, str):
        return ""
    nfkc = unicodedata.normalize("NFKC", text)
    cleaned = "".join(c for c in nfkc if unicodedata.category(c) not in ("Cf", "Cc"))
    return cleaned.strip().rstrip(" .")


def _norm_dedup_key(text: str) -> str:
    """Cle de deduplication : canonique + casse pliee."""
    return _norm_unicode(text).lower()


# Confondables latins -> ASCII (homoglyphes cyrilliques/grecs/full-width).
_CONFUSABLES = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M", "Н": "H", "О": "O",
    "Р": "P", "С": "C", "Т": "T", "Х": "X",
    "α": "a", "ο": "o", "ρ": "p", "ν": "v",
}


def _norm_domain(text) -> str:
    """Normalise un domaine legal : NFKC + casse + tirets Unicode + trim +
    confondables -> ASCII. 'compliance ' (espace) ou NBSP ou full-width ne
    contourne pas."""
    if not isinstance(text, str):
        return ""
    s = _norm_unicode(text).lower().strip()
    for dash in ("‐", "‑", "‒", "–", "—", "−"):
        s = s.replace(dash, "-")
    s = "".join(_CONFUSABLES.get(c, c) for c in s)
    return s


def _is_legal_domain(domain) -> bool:
    return _norm_domain(domain) in LEGAL_DOMAINS


_HTML_CONTENT_TAGS = {
    "address", "article", "aside", "audio", "blockquote", "body", "canvas",
    "caption", "center", "code", "colgroup", "dd", "details", "dialog", "dir",
    "div", "dl", "dt", "fieldset", "figcaption", "figure", "footer", "form",
    "frameset", "h1", "h2", "h3", "h4", "h5", "h6", "head", "header",
    "html", "iframe", "legend", "li", "listing", "main", "math", "menu",
    "nav", "noembed", "noframes", "noscript", "object", "ol", "optgroup",
    "option", "p", "plaintext", "pre", "script", "search", "section",
    "select", "style", "summary", "svg", "table", "tbody", "td", "template",
    "textarea", "tfoot", "th", "thead", "title", "tr", "ul", "video", "xmp",
}
_HTML_PASSTHROUGH_TAGS = {
    "a", "abbr", "acronym", "b", "bdi", "bdo", "big", "cite", "data", "del",
    "dfn", "em", "font", "i", "ins", "kbd", "label", "mark", "nobr", "q",
    "rp", "rt", "ruby", "s", "samp", "small", "span", "strike", "strong",
    "sub", "sup", "time", "tt", "u", "var",
}
_HTML_VOID_TAGS = {
    "area", "base", "basefont", "bgsound", "br", "col", "command", "embed",
    "hr", "img", "input", "keygen", "link", "meta", "param", "source",
    "track", "wbr",
}
_HTML_KNOWN_TAGS = (
    _HTML_CONTENT_TAGS | _HTML_PASSTHROUGH_TAGS | _HTML_VOID_TAGS)
_HTML_AMBIGUOUS_BLOCK = "\0ambiguous-html"
_AUTOLINK_URI_RE = re.compile(
    r"^[A-Za-z][A-Za-z0-9+.-]{1,31}:[^\s<>]*$")
_AUTOLINK_EMAIL_LOCAL_CHARS = frozenset(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    "0123456789.!#$%&'*+/=?^_`{|}~-")


def _is_markdown_email_autolink(candidate: str) -> bool:
    """Valide un autolink email strict, sans ambiguite avec une balise HTML."""
    if len(candidate) > 254 or candidate.count("@") != 1:
        return False
    local, domain = candidate.split("@", 1)
    if (not local or len(local) > 64
            or local[0] == "." or local[-1] == "." or ".." in local
            or any(char not in _AUTOLINK_EMAIL_LOCAL_CHARS
                   for char in local)):
        return False
    if not domain or len(domain) > 253 or "." not in domain:
        return False
    labels = domain.split(".")
    for label in labels:
        if (not label or len(label) > 63
                or not label[0].isascii() or not label[0].isalnum()
                or not label[-1].isascii() or not label[-1].isalnum()
                or any(not char.isascii()
                       or (not char.isalnum() and char != "-")
                       for char in label)):
            return False
    return True


def _html_hides_content(tag: str) -> bool:
    """Politique fail-closed des conteneurs HTML.

    Les elements inline explicitement autorises conservent leur texte. Les
    elements void n'ont aucun contenu. Tout autre nom, standard ou inconnu,
    est traite comme conteneur : une balise nouvelle ne peut donc pas exposer
    artificiellement un titre Markdown.
    """
    return (
        tag in _HTML_CONTENT_TAGS
        or (tag not in _HTML_PASSTHROUGH_TAGS
            and tag not in _HTML_VOID_TAGS)
    )


def _is_html_markup_candidate(tag: str, closing: bool,
                              at_block_start: bool,
                              preceded_by_identifier: bool,
                              html_active: bool) -> bool:
    """Distingue le balisage HTML de la prose technique en temps constant.

    Un element de contenu reconnu reste prioritaire meme colle a du texte :
    ``x<script>`` ne doit pas devenir un contournement. Les elements void ne
    portent aucun contenu et restent reconnus partout. Un element inline
    ouvrant au milieu d'un identifiant, ou un nom inconnu hors debut de bloc,
    reste du texte (``a<b`` et ``List<String>``).
    """
    if html_active:
        return True
    if tag in _HTML_CONTENT_TAGS or tag in _HTML_VOID_TAGS:
        return True
    if closing:
        return tag in _HTML_KNOWN_TAGS or at_block_start
    if preceded_by_identifier:
        return False
    if tag in _HTML_PASSTHROUGH_TAGS:
        return True
    return at_block_start


def _should_arm_ambiguous_html(tag: str, closing: bool,
                               markup_candidate: bool) -> bool:
    """Arme le fail-closed uniquement pour un conteneur HTML reconnu."""
    return (
        markup_candidate
        and not closing
        and tag in _HTML_CONTENT_TAGS
    )


def _scan_markdown_autolink(content: str, start: int):
    """Retourne la fin d'un autolink Markdown, sans scan non borne repete."""
    index = start + 1
    length = len(content)
    while index < length:
        char = content[index]
        if char == ">":
            candidate = content[start + 1:index]
            if (_AUTOLINK_URI_RE.fullmatch(candidate)
                    or _is_markdown_email_autolink(candidate)):
                return index + 1
            return None
        if char == "<" or char.isspace() or unicodedata.category(char) == "Cc":
            return None
        index += 1
    return None


def _scan_html_tag(content: str, start: int):
    """Analyse une balise sur une seule tranche, sans rescanner le suffixe.

    Les guillemets simples et doubles delimitent les valeurs d'attribut :
    ``<`` et ``>`` y sont consommes comme du texte. Hors citation, un second
    ``<`` termine le candidat ambigu et rend l'index atteint a l'appelant.
    Cette progression preserve la croissance lineaire des corpus ``"<a" * N``.
    Les formes ambigues mais fermees comme ``<div"x">`` ou ``<div=1>`` sont
    traitees comme balises afin qu'un titre masque ne devienne jamais une
    section Markdown. Les noms Unicode et les caracteres tels que ``_`` sont
    consommes ; les autolinks Markdown sont reconnus avant cet analyseur.

    Le dernier booleen du resultat indique si le ``>`` final a ete trouve.
    L'appelant peut ainsi traiter une balise de bloc incomplete en fail-closed
    sans rescanner son suffixe.
    """
    length = len(content)
    index = start + 1
    closing = False
    if index < length and content[index] == "/":
        closing = True
        index += 1
    if index >= length or not content[index].isalpha():
        return None

    name_start = index
    index += 1
    while index < length:
        char = content[index]
        if char not in " \t\f\r\n/>\"'=<":
            index += 1
            continue
        break
    tag = content[name_start:index].lower()

    quote = ""
    while index < length:
        char = content[index]
        if quote:
            if char == quote:
                quote = ""
            index += 1
            continue
        if char in ("\"", "'"):
            quote = char
            index += 1
            continue
        if char == "<":
            return tag, closing, False, index, False
        if char == ">":
            self_closing = content[start:index].rstrip().endswith("/")
            return tag, closing, self_closing, index + 1, True
        index += 1
    return tag, closing, False, length, False


def _strip_markdown_code(text: str) -> str:
    """Retire le contenu non Markdown en temps lineaire.

    SEC-005 / SEC-REV-002 / SEC-A2-REV-001 / SEC-A3-REV-001 : le parseur de
    balise s'arrete au prochain ``<`` hors citation. Les ``<`` et ``>`` situes
    dans une valeur d'attribut citee sont consommes sans exposer le contenu
    HTML. Une suite hostile ``"<a" * N`` ne peut donc pas faire rescanner tout
    le suffixe. La prose ``x<y`` ou ``List<String>`` reste textuelle. Le
    balisage et le code retires deviennent des espaces : aucun titre ne peut
    etre promu artificiellement vers la colonne zero.
    """
    if not isinstance(text, str):
        return ""

    output: list[str] = []
    fence_char = ""
    fence_length = 0
    html_stack: list[str] = []
    in_comment = False
    raw_html_terminator = ""

    for line in text.splitlines(keepends=True):
        newline = "\n" if line.endswith(("\n", "\r")) else ""
        content = line.rstrip("\r\n")
        leading = len(content) - len(content.lstrip(" "))
        candidate = content[leading:] if leading <= 3 else ""

        if fence_char:
            close = re.match(
                rf"^{re.escape(fence_char)}{{{fence_length},}}\s*$",
                candidate)
            if close:
                fence_char = ""
                fence_length = 0
            output.append(newline)
            continue

        opening = re.match(r"^(`{3,}|~{3,})", candidate)
        if opening:
            marker = opening.group(1)
            fence_char = marker[0]
            fence_length = len(marker)
            output.append(newline)
            continue

        i = 0
        visible: list[str] = []
        line_passthrough: list[str] = []
        while i < len(content):
            if in_comment:
                end = content.find("-->", i)
                if end < 0:
                    visible.extend(" " * (len(content) - i))
                    i = len(content)
                    continue
                visible.extend(" " * (end + 3 - i))
                in_comment = False
                i = end + 3
                continue

            if raw_html_terminator:
                end = content.find(raw_html_terminator, i)
                if end < 0:
                    visible.extend(" " * (len(content) - i))
                    i = len(content)
                    continue
                raw_end = end + len(raw_html_terminator)
                visible.extend(" " * (raw_end - i))
                raw_html_terminator = ""
                i = raw_end
                continue

            if content.startswith("<!--", i):
                visible.extend(" " * 4)
                in_comment = True
                i += 4
                continue

            if content.startswith("<![CDATA[", i):
                visible.extend(" " * len("<![CDATA["))
                raw_html_terminator = "]]>"
                i += len("<![CDATA[")
                continue

            if content.startswith("<?", i):
                visible.extend("  ")
                raw_html_terminator = "?>"
                i += 2
                continue

            if content.startswith("<!", i):
                visible.extend("  ")
                raw_html_terminator = ">"
                i += 2
                continue

            if content[i] == "<":
                autolink_end = _scan_markdown_autolink(content, i)
                if autolink_end is not None:
                    visible.extend(content[i:autolink_end])
                    i = autolink_end
                    continue
                tag_match = _scan_html_tag(content, i)
                if tag_match is not None:
                    tag, closing, _self_closing, tag_end, complete = tag_match
                    at_block_start = leading <= 3 and i == leading
                    preceded_by_identifier = (
                        i > 0
                        and (content[i - 1].isalnum()
                             or content[i - 1] == "_")
                    )
                    markup_candidate = _is_html_markup_candidate(
                        tag,
                        closing,
                        at_block_start,
                        preceded_by_identifier,
                        bool(html_stack),
                    )
                    if not complete:
                        if not html_stack:
                            visible.extend(content[i:tag_end])
                        else:
                            visible.extend(" " * (tag_end - i))
                        if (_should_arm_ambiguous_html(
                                tag, closing, markup_candidate)
                                and _HTML_AMBIGUOUS_BLOCK not in html_stack):
                            html_stack.append(_HTML_AMBIGUOUS_BLOCK)
                        i = tag_end
                        continue
                    if not markup_candidate:
                        visible.extend(content[i:tag_end])
                        i = tag_end
                        continue
                    visible.extend(" " * (tag_end - i))
                    if tag in _HTML_PASSTHROUGH_TAGS:
                        if closing:
                            if (line_passthrough
                                    and line_passthrough[-1] == tag):
                                line_passthrough.pop()
                            elif html_stack and html_stack[-1] == tag:
                                html_stack.pop()
                        elif at_block_start:
                            line_passthrough.append(tag)
                        i = tag_end
                        continue
                    if _html_hides_content(tag):
                        if line_passthrough:
                            html_stack.extend(line_passthrough)
                            line_passthrough.clear()
                        if closing:
                            if html_stack and html_stack[-1] == tag:
                                html_stack.pop()
                        else:
                            # En HTML, le slash d'auto-fermeture est ignore
                            # pour ces elements non-void. Fail-closed : leur
                            # contenu reste masque jusqu'a une vraie fermeture.
                            html_stack.append(tag)
                    i = tag_end
                    continue

            if html_stack:
                visible.append(" ")
                i += 1
                continue

            if content[i] == "`":
                run_end = i + 1
                while run_end < len(content) and content[run_end] == "`":
                    run_end += 1
                marker = content[i:run_end]
                closing = content.find(marker, run_end)
                if closing < 0:
                    visible.extend(" " * (len(content) - i))
                    i = len(content)
                else:
                    code_end = closing + len(marker)
                    visible.extend(" " * (code_end - i))
                    i = code_end
                continue

            visible.append(content[i])
            i += 1

        if line_passthrough:
            html_stack.extend(line_passthrough)
        output.append("".join(visible) + newline)
    return "".join(output)


# ---------------------------------------------------------------------------
# Moteur de schema PHASES_SCHEMA_V1
# ---------------------------------------------------------------------------

def _check_schema_shape(schema, issues: list[Issue], path: str,
                        _depth: int = 0, _seen: set | None = None) -> None:
    """Rejette tout schema hors PHASES_SCHEMA_V1 ou mal type. Jamais de crash :
    profondeur bornee et cycles detectes (schema auto-referent)."""
    if _depth > _MAX_SCHEMA_DEPTH:
        issues.append(Issue("error", "TOO_DEEP",
                            f"schema trop profond (>{_MAX_SCHEMA_DEPTH})", path))
        return
    if not isinstance(schema, dict):
        issues.append(Issue("error", "SCHEMA_SHAPE", "schema non-objet", path))
        return
    if _seen is None:
        _seen = set()
    sid = id(schema)
    if sid in _seen:
        issues.append(Issue("error", "SCHEMA_CYCLE", "schema auto-referent", path))
        return
    _seen.add(sid)
    for key in schema:
        if not isinstance(key, str):
            issues.append(Issue("error", "SCHEMA_KW_TYPE", "cle non-chaine", path))
            continue
        if key not in _SCHEMA_KEYS:
            issues.append(Issue("error", "SCHEMA_UNKNOWN_KEY",
                                f"cle de schema inconnue: {key}", path))
    t = schema.get("type")
    # R5-003 : `type` est OBLIGATOIRE dans TOUT schema PHASES_SCHEMA_V1, y
    # compris a la racine. Les metadonnees ($schema/schema_id/version) n'exemptent
    # jamais la racine. Un schema sans type = validation inactive = rejet.
    if t is None:
        issues.append(Issue("error", "SCHEMA_TYPE", "schema sans type", path))
    elif not isinstance(t, str):
        issues.append(Issue("error", "SCHEMA_KW_TYPE",
                            f"type non-chaine: {type(t).__name__}", path))
    elif t not in _SCHEMA_TYPES:
        issues.append(Issue("error", "SCHEMA_TYPE", f"type inconnu: {t}", path))
    if "required" in schema:
        req = schema["required"]
        if not isinstance(req, list):
            issues.append(Issue("error", "SCHEMA_KW_TYPE", "required non-liste", path))
        elif not all(isinstance(r, str) for r in req):
            issues.append(Issue("error", "SCHEMA_KW_TYPE",
                                "required avec element non-chaine", path))
    if "enum" in schema:
        enum = schema["enum"]
        if not isinstance(enum, list):
            issues.append(Issue("error", "SCHEMA_KW_TYPE", "enum non-liste", path))
        elif not all(isinstance(e, str) for e in enum):
            issues.append(Issue("error", "SCHEMA_KW_TYPE",
                                "enum avec element non-chaine", path))
    if "properties" in schema and not isinstance(schema["properties"], dict):
        issues.append(Issue("error", "SCHEMA_KW_TYPE", "properties non-objet", path))
    if "additionalProperties" in schema and not isinstance(schema["additionalProperties"], bool):
        issues.append(Issue("error", "SCHEMA_KW_TYPE", "additionalProperties non-booleen", path))
    if "minLength" in schema:
        ml = schema["minLength"]
        if not isinstance(ml, int) or isinstance(ml, bool):
            issues.append(Issue("error", "SCHEMA_KW_TYPE", "minLength non-entier", path))
        elif ml < 0:
            issues.append(Issue("error", "SCHEMA_KW_TYPE", "minLength negatif", path))
    if "minItems" in schema:
        mi = schema["minItems"]
        if not isinstance(mi, int) or isinstance(mi, bool):
            issues.append(Issue("error", "SCHEMA_KW_TYPE", "minItems non-entier", path))
        elif mi < 0:
            issues.append(Issue("error", "SCHEMA_KW_TYPE", "minItems negatif", path))
    if "items" in schema:
        items = schema["items"]
        if not isinstance(items, dict):
            issues.append(Issue("error", "SCHEMA_KW_TYPE", "items non-objet", path))
        elif not items:
            # J4-002 : items:{} vide = accepte tout, inoperant.
            issues.append(Issue("error", "SCHEMA_KW_TYPE", "items vide (accepte tout)", path))
    if isinstance(schema.get("properties"), dict):
        for name, sub in schema["properties"].items():
            _check_schema_shape(sub, issues, f"{path}.{name}" if path else name,
                                _depth + 1, _seen)
    if isinstance(schema.get("items"), dict):
        _check_schema_shape(schema["items"], issues, f"{path}[]" if path else "[]",
                            _depth + 1, _seen)
    _seen.discard(sid)


def _validate(instance, schema: dict, issues: list[Issue], path: str) -> None:
    """Valide `instance` contre un schema PHASES_SCHEMA_V1. Fail-closed : un
    schema invalide est signale (et l'instance rejetee), jamais ignore."""
    if not isinstance(schema, dict):
        issues.append(Issue("error", "SCHEMA_INVALID", "schema non-objet", path))
        return
    # Le schema doit avoir un type valide pour valider. Sinon : rejet.
    t = schema.get("type")
    if not isinstance(t, str) or t not in _SCHEMA_TYPES:
        issues.append(Issue("error", "SCHEMA_INVALID",
                            f"schema avec type invalide ou absent: {t!r}", path))
        return
    here = path or "$"

    if t == "object":
        if not isinstance(instance, dict):
            issues.append(Issue("error", "TYPE", "attendu object", here))
            return
        req = schema.get("required", [])
        if isinstance(req, list):
            for r in req:
                if isinstance(r, str) and r not in instance:
                    issues.append(Issue("error", "REQUIRED",
                                        f"propriete requise absente: {r}", here))
        props = schema.get("properties", {})
        if not isinstance(props, dict):
            props = {}
        if schema.get("additionalProperties") is False:
            for key in instance:
                if isinstance(key, str) and key not in props:
                    issues.append(Issue("error", "UNKNOWN_PROPERTY",
                                        f"propriete inconnue: {key}", here))
        for key, sub in props.items():
            if isinstance(key, str) and key in instance:
                _validate(instance[key], sub, issues, f"{here}.{key}")
        return

    if t == "array":
        if not isinstance(instance, list):
            issues.append(Issue("error", "TYPE", "attendu array", here))
            return
        min_items = schema.get("minItems", 0)
        if (isinstance(min_items, int) and not isinstance(min_items, bool)
                and len(instance) < min_items):
            issues.append(Issue("error", "EMPTY_ARRAY", "tableau vide", here))
        item_schema = schema.get("items")
        if isinstance(item_schema, dict):
            for i, item in enumerate(instance):
                _validate(item, item_schema, issues, f"{here}[{i}]")
        return

    if t == "string":
        if not isinstance(instance, str):
            issues.append(Issue("error", "TYPE", "attendu string", here))
            return
        min_len = schema.get("minLength", 0)
        if isinstance(min_len, int) and not isinstance(min_len, bool) and min_len > 0:
            if len(instance) < min_len:
                issues.append(Issue("error", "EMPTY_STRING", "chaine vide", here))
        enum = schema.get("enum")
        if isinstance(enum, list) and instance not in enum:
            issues.append(Issue("error", "ENUM", f"valeur hors enum: {instance!r}", here))
        return

    if t == "integer":
        if not isinstance(instance, int) or isinstance(instance, bool):
            issues.append(Issue("error", "TYPE", "attendu integer", here))
        return

    if t == "boolean":
        if not isinstance(instance, bool):
            issues.append(Issue("error", "TYPE", "attendu boolean", here))
        return


# ---------------------------------------------------------------------------
# Chemins : confinement strict, liens reels, jonctions Windows, Unicode
# ---------------------------------------------------------------------------

def _is_reparse_point(path: str) -> bool:
    """Vrai si path est un reparse point Windows (jonction, symlink...).
    Sous POSIX, retombe sur os.path.islink. Ne leve jamais."""
    try:
        if os.name == "nt":
            attrs = os.lstat(path).st_file_attributes  # type: ignore[attr-defined]
            return bool(attrs & 0x400)  # FILE_ATTRIBUTE_REPARSE_POINT
        return os.path.islink(path)
    except (OSError, AttributeError, ValueError):
        return os.path.islink(path)


def _has_invisible_or_mixed(text: str) -> bool:
    """Detecte caracteres invisibles / separateurs melanges (signaux hostiles).
    Les backslashes seuls sont acceptes (chemins Windows legitimes), mais les
    MELANGES '/' + '\' sont suspects."""
    if "\\" in text and "/" in text:
        return True
    for ch in text:
        cat = unicodedata.category(ch)
        if cat in ("Cf", "Cc", "Zs") and ch != " ":
            return True
        if ch in ("​", "﻿", "⁠", "　"):
            return True
    return False


def _real_is_within(path: str, base: str) -> bool:
    """Confinement REEL : resout tous les liens intermediaires. Normalise la
    casse (Windows) et les separateurs."""
    try:
        real_path = os.path.normcase(os.path.realpath(path))
        real_base = os.path.normcase(os.path.realpath(base))
        return os.path.commonpath([real_path, real_base]) == real_base
    except (OSError, ValueError):
        return False


def _portable_relpath_parts(rel: str) -> list[str] | None:
    """Valide la forme portable d'un chemin relatif.

    Les antislashs seuls restent acceptes. Toute forme ambigue, non canonique
    ou interpretable differemment sous Windows est refusee.
    """
    if not isinstance(rel, str) or not rel.strip():
        return None
    if unicodedata.normalize("NFKC", rel) != rel:
        return None
    if _has_invisible_or_mixed(rel):
        return None
    if any(mark in rel for mark in (
            "%", "․", "．", "。", "／", "⁄", "∕", "＼")):
        return None
    if (os.path.isabs(rel) or re.match(r"^[A-Za-z]:", rel)
            or rel.startswith(("\\\\", "//"))):
        return None
    # Le tilde designe le repertoire personnel : « ~/secret » et « ~alice/x »
    # sortent du projet audite au meme titre qu'un chemin absolu, mais
    # os.path.isabs ne les voit pas.
    if rel.startswith("~"):
        return None
    parts = rel.replace("\\", "/").split("/")
    if any(part in ("", ".", "..") for part in parts):
        return None
    if any(part != part.rstrip(" .") or ":" in part for part in parts):
        return None
    if any(
            part.split(".", 1)[0].casefold() in _WINDOWS_RESERVED_BASENAMES
            for part in parts):
        return None
    return parts


def _safe_relpath(base: str, rel: str) -> str | None:
    """Resout rel sous base. None si absolu, '..', invisible/melange, ADS,
    trailing dot/space, UNC, URL-encode, homographe, reparse point (final OU
    parent), ou si le chemin REEL sort de base."""
    parts = _portable_relpath_parts(rel)
    if parts is None:
        return None
    full = os.path.normpath(os.path.join(base, *parts))
    node = full
    while True:
        if os.path.lexists(node) and _is_reparse_point(node):
            return None
        parent = os.path.dirname(node)
        if parent == node or os.path.normcase(parent) == os.path.normcase(os.path.realpath(base)):
            break
        node = parent
    if not _real_is_within(full, base):
        return None
    return full


def _safe_regular_file(path: str, root: str) -> bool:
    """Vrai pour un fichier regulier, confine et sans lien."""
    try:
        info = os.lstat(path)
        return (
            stat.S_ISREG(info.st_mode)
            and info.st_nlink == 1
            and not _is_reparse_point(path)
            and _real_is_within(path, root)
        )
    except (OSError, ValueError):
        return False


def _listdir_bounded(path: str, issues: list[Issue], label: str,
                     root: str) -> list[str]:
    """Liste au plus un nombre documente d'entrees."""
    entries: list[str] = []
    if (_is_reparse_point(path) or not _real_is_within(path, root)):
        issues.append(Issue(
            "error", "PATH_UNSAFE",
            f"{label} lie ou hors confinement", "phases.json"))
        return []
    try:
        with os.scandir(path) as iterator:
            for entry in iterator:
                entries.append(entry.name)
                if len(entries) > _MAX_DIRECTORY_ENTRIES:
                    issues.append(Issue(
                        "error", "TOO_LARGE",
                        f"{label} depasse {_MAX_DIRECTORY_ENTRIES} entrees",
                        "phases.json"))
                    return []
    except (OSError, ValueError):
        issues.append(Issue(
            "error", "PATH_UNSAFE",
            f"{label} illisible au listing", "phases.json"))
        return []
    if (_is_reparse_point(path) or not _real_is_within(path, root)):
        issues.append(Issue(
            "error", "FILE_CHANGED",
            f"{label} change pendant le listing", "phases.json"))
        return []
    return sorted(entries, key=lambda value: (value.casefold(), value))


# ---------------------------------------------------------------------------
# Chargement sur (UTF-8 strict, BOM interdite, plafond, doublons JSON)
# ---------------------------------------------------------------------------

def _no_dup_object(pairs):
    """object_pairs_hook : rejette les cles JSON dupliquees, y compris apres
    normalisation Unicode/casse (fail-closed)."""
    seen = {}
    seen_norm = set()
    for k, v in pairs:
        if k in seen:
            raise ValueError(f"cle JSON dupliquee: {k!r}")
        norm = _norm_dedup_key(k) if isinstance(k, str) else k
        if norm in seen_norm:
            raise ValueError(f"cle JSON dupliquee (normalisee): {k!r}")
        seen[k] = v
        seen_norm.add(norm)
    return seen


def _check_json_depth(node, depth: int = 0) -> None:
    """Rejette un JSON trop profond (anti-DoS RecursionError)."""
    if depth > _MAX_JSON_DEPTH:
        raise ValueError(f"JSON trop profond (>{_MAX_JSON_DEPTH})")
    if isinstance(node, dict):
        for key, v in node.items():
            if (not isinstance(key, str)
                    or any(unicodedata.category(ch) == "Cs" for ch in key)):
                raise ValueError("cle JSON Unicode invalide")
            _check_json_depth(v, depth + 1)
    elif isinstance(node, list):
        for v in node:
            _check_json_depth(v, depth + 1)
    elif isinstance(node, str) and any(
            unicodedata.category(ch) == "Cs" for ch in node):
        raise ValueError("chaine JSON Unicode invalide")


def _read_bytes(path: str, issues: list[Issue], what: str, max_bytes: int,
                root: str | None = None) -> bytes | None:
    """Lit un fichier regulier borne.

    SEC-001/SEC-002 : refuse reparse points, liens durs, changements entre
    ``lstat`` et ``open``, lectures hors racine et croissance apres le stat.
    """
    try:
        before = os.lstat(path)
    except (OSError, ValueError):
        issues.append(Issue("error", "READ", f"{what} illisible", what))
        return None
    if (not stat.S_ISREG(before.st_mode) or _is_reparse_point(path)
            or before.st_nlink != 1):
        issues.append(Issue(
            "error", "PATH_UNSAFE",
            f"{what} doit etre un fichier regulier sans lien", what))
        return None
    if root is not None and not _real_is_within(path, root):
        issues.append(Issue(
            "error", "PATH_UNSAFE", f"{what} hors confinement", what))
        return None
    if before.st_size > max_bytes:
        issues.append(Issue("error", "TOO_LARGE",
                            f"{what} depasse {max_bytes} octets", what))
        return None
    try:
        with open(path, "rb") as fh:
            opened = os.fstat(fh.fileno())
            identity_before = (before.st_dev, before.st_ino)
            identity_opened = (opened.st_dev, opened.st_ino)
            if (identity_before != identity_opened
                    or not stat.S_ISREG(opened.st_mode)
                    or opened.st_nlink != 1):
                issues.append(Issue(
                    "error", "FILE_CHANGED",
                    f"{what} remplace entre controle et lecture", what))
                return None
            raw = fh.read(max_bytes + 1)
    except (OSError, ValueError):
        issues.append(Issue("error", "READ", f"{what} illisible", what))
        return None
    if len(raw) > max_bytes:
        issues.append(Issue(
            "error", "TOO_LARGE",
            f"{what} depasse {max_bytes} octets pendant la lecture", what))
        return None
    if root is not None and not _real_is_within(path, root):
        issues.append(Issue(
            "error", "FILE_CHANGED",
            f"{what} sort du confinement pendant la lecture", what))
        return None
    return raw


def _reference_contains_absolute_path(text: str) -> bool:
    """Détecte un chemin local absolu publié."""

    return any(pattern.search(text) for pattern in (
        _REFERENCE_ABSOLUTE_PATTERNS))


def _load_json(path: str, issues: list[Issue], what: str,
               max_bytes: int = _MAX_JSON_BYTES, root: str | None = None):
    raw = _read_bytes(path, issues, what, max_bytes, root=root)
    if raw is None:
        return None
    if raw.startswith(b"\xef\xbb\xbf"):
        issues.append(Issue("error", "BOM", f"{what} en UTF-8 avec BOM", what))
        return None
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        issues.append(Issue("error", "ENCODING", f"{what} non UTF-8: {exc}", what))
        return None

    def reject_constant(value):
        raise ValueError(f"constante JSON non standard: {value}")

    try:
        data = json.loads(
            text,
            object_pairs_hook=_no_dup_object,
            parse_constant=reject_constant,
        )
        _check_json_depth(data)
        return data
    except RecursionError:
        issues.append(Issue("error", "TOO_DEEP",
                            f"{what}: JSON trop profond (RecursionError)", what))
        return None
    except ValueError as exc:
        msg = str(exc)
        if "dupliquee" in msg:
            code = "DUPLICATE_KEY"
        elif "profond" in msg:
            code = "TOO_DEEP"
        else:
            code = "JSON"
        issues.append(Issue("error", code, f"{what}: {exc}", what))
        return None


def _load_schema(core_dir: str, name: str, issues: list[Issue]):
    """Charge un schema core. Fail-closed : absent, invalide, ou mal forme =
    erreur (le schema n'est pas utilise ensuite)."""
    schema = _load_json(os.path.join(core_dir, name), issues, name)
    if not isinstance(schema, dict):
        issues.append(Issue("error", "SCHEMA_MISSING", f"{name} absent ou non-objet", name))
        return None
    if schema.get("$schema") != "PHASES_SCHEMA_V1":
        issues.append(Issue("error", "SCHEMA_ID", f"{name}: $schema != PHASES_SCHEMA_V1", name))
        _check_schema_shape(schema, issues, name)
        return None
    before = len(issues)
    _check_schema_shape(schema, issues, name)
    if len(issues) > before:
        return None  # schema mal forme -> inutilisable
    return schema


def _resolve_official_schema(candidate, name: str, issues: list[Issue],
                             path: str = ""):
    """R6-004 : rend uniquement le schema officiel versionne.

    ``candidate=None`` signifie que l'API charge elle-meme le schema officiel.
    Un schema fourni reste accepte pour compatibilite, mais seulement s'il est
    strictement identique au schema versionne dans ``core/``. Un objet permissif
    ne peut donc jamais desactiver un controle public.
    """
    if name not in _OFFICIAL_SCHEMA_META:
        issues.append(Issue("error", "SCHEMA_ID",
                            f"schema officiel inconnu: {name}", path or name))
        return None

    official_issues: list[Issue] = []
    official = _load_schema(_DEFAULT_CORE_DIR, name, official_issues)
    if official is None or official_issues:
        issues.extend(official_issues)
        issues.append(Issue("error", "SCHEMA_INTEGRITY",
                            f"schema officiel inutilisable: {name}", path or name))
        return None

    if candidate is None:
        return official
    if not isinstance(candidate, dict):
        issues.append(Issue("error", "SCHEMA_INTEGRITY",
                            f"{name} fourni non-objet", path or name))
        return None

    payload_issues = _payload_guard(candidate, path or name)
    if payload_issues:
        issues.extend(payload_issues)
        return None

    shape_issues: list[Issue] = []
    _check_schema_shape(candidate, shape_issues, path or name)
    if shape_issues:
        issues.extend(shape_issues)
        return None

    expected_id, expected_version = _OFFICIAL_SCHEMA_META[name]
    if candidate.get("$schema") != "PHASES_SCHEMA_V1":
        issues.append(Issue("error", "SCHEMA_ID",
                            f"{name}: $schema officiel requis", path or name))
    if candidate.get("schema_id") != expected_id:
        issues.append(Issue("error", "SCHEMA_ID",
                            f"{name}: schema_id attendu {expected_id}",
                            path or name))
    if candidate.get("version") != expected_version:
        issues.append(Issue("error", "SCHEMA_VERSION",
                            f"{name}: version attendue {expected_version}",
                            path or name))
    if issues and any(i.path == (path or name) and
                      i.code in {"SCHEMA_ID", "SCHEMA_VERSION"}
                      for i in issues):
        return None
    if candidate != official:
        issues.append(Issue("error", "SCHEMA_INTEGRITY",
                            f"{name} differe du schema officiel versionne",
                            path or name))
        return None
    return official


def _load_official_schema(core_dir: str, name: str, issues: list[Issue]):
    """Charge un schema depuis ``core_dir``, puis prouve son identite officielle."""
    candidate = _load_schema(core_dir, name, issues)
    if candidate is None:
        return None
    return _resolve_official_schema(candidate, name, issues, name)


# ---------------------------------------------------------------------------
# Dates : parsing strict, futur interdit, fraicheur bloquante
# ---------------------------------------------------------------------------

def _parse_iso_date(text: str) -> datetime.date | None:
    if not isinstance(text, str) or not _ISO_DATE_RE.match(text):
        return None
    try:
        return datetime.date.fromisoformat(text)
    except ValueError:
        return None


def _today_issue(today, path: str) -> Issue | None:
    """R6-001 : validation CENTRALE et UNIQUE de `today`.

    Toute fonction publique qui effectue un controle date-dependant passe par
    ici. Rend une Issue (erreur deterministe) ou None si `today` est utilisable.

    Contrat strict :
      - absent / None                  -> TODAY_REQUIRED
      - "" / "bad" / int / autre type  -> TODAY_INVALID
      - datetime.datetime              -> TODAY_INVALID

    `datetime.datetime` est REJETE bien qu'il herite de `datetime.date` :
    `datetime - date` leve TypeError dans les calculs de fraicheur. L'accepter
    reintroduirait exactement le TypeError non maitrise que R6-001 interdit.

    Aucune horloge implicite n'est jamais consultee : `datetime.date.today()`
    n'est appele nulle part dans ce module.
    """
    if today is None:
        return Issue("error", "TODAY_REQUIRED",
                     "today requis (aucune horloge implicite)", path)
    if isinstance(today, datetime.datetime) or not isinstance(today, datetime.date):
        return Issue("error", "TODAY_INVALID",
                     f"today doit etre un datetime.date, recu {type(today).__name__}",
                     path)
    return None


def _legal_freshness_verdict(verified_on: str, window_days: int,
                             today: datetime.date) -> str:
    """Rend 'ok' | 'invalid_date' | 'future' | 'stale'. `today` est injecte."""
    von = _parse_iso_date(verified_on)
    if von is None:
        return "invalid_date"
    if von > today:
        return "future"
    if (today - von).days > window_days:
        return "stale"
    return "ok"


# ---------------------------------------------------------------------------
# Registres (facts + regles)
# ---------------------------------------------------------------------------

class _TrustedRules(Mapping):
    """Instantane immuable cree uniquement par un chargeur de confiance."""

    __slots__ = ("_data",)

    def __init__(self, data: dict[str, str]) -> None:
        self._data = dict(data)

    def __getitem__(self, key):
        return self._data[key]

    def __iter__(self):
        return iter(self._data)

    def __len__(self):
        return len(self._data)


def _is_official_registry_dir(registry_dir: str) -> bool:
    try:
        return (
            os.path.normcase(os.path.realpath(registry_dir))
            == os.path.normcase(os.path.realpath(_DEFAULT_REGISTRY_DIR))
        )
    except (OSError, TypeError, ValueError):
        return False


def _is_official_core_dir(core_dir: str) -> bool:
    try:
        return (
            os.path.normcase(os.path.realpath(core_dir))
            == os.path.normcase(os.path.realpath(_DEFAULT_CORE_DIR))
        )
    except (OSError, TypeError, ValueError):
        return False


def _load_facts(registry_dir: str, issues: list[Issue]) -> set[str]:
    if not _is_official_registry_dir(registry_dir):
        issues.append(Issue(
            "error", "FACTS_REGISTRY",
            "seul le registre officiel versionne est autorise",
            "profile-facts.json"))
        return set()
    path = os.path.join(registry_dir, "profile-facts.json")
    data = _load_json(path, issues, "profile-facts.json")
    if isinstance(data, dict) and isinstance(data.get("facts"), list):
        expected_keys = {"schema_id", "version", "description", "facts"}
        if set(data) != expected_keys:
            issues.append(Issue(
                "error", "FACTS_REGISTRY",
                "cles inattendues dans profile-facts.json",
                "profile-facts.json"))
        if data.get("schema_id") != "PROFILE_FACTS":
            issues.append(Issue(
                "error", "FACTS_REGISTRY",
                "schema_id PROFILE_FACTS requis", "profile-facts.json"))
        if data.get("version") != PROFILE_FACTS_VERSION:
            issues.append(Issue(
                "error", "FACTS_REGISTRY",
                "version de registre facts inconnue", "profile-facts.json"))
        facts: set[str] = set()
        normalized: set[str] = set()
        for fact in data["facts"]:
            if not isinstance(fact, str) or not _norm_unicode(fact):
                issues.append(Issue(
                    "error", "FACTS_REGISTRY",
                    "fact absent ou non-chaine", "profile-facts.json"))
                continue
            key = _norm_dedup_key(fact)
            if key in normalized:
                issues.append(Issue(
                    "error", "FACTS_REGISTRY",
                    "fact duplique apres normalisation",
                    "profile-facts.json"))
                continue
            normalized.add(key)
            facts.add(fact)
        if facts != set(PROFILE_FACTS):
            issues.append(Issue(
                "error",
                "FACTS_REGISTRY",
                "vocabulaire de faits officiel incomplet ou divergent",
                "profile-facts.json",
            ))
        return facts
    issues.append(Issue("error", "FACTS_REGISTRY",
                        "profile-facts.json absent ou sans 'facts' liste", path))
    return set()


def _load_known_rules(registry_dir: str, issues: list[Issue]) -> _TrustedRules:
    """Charge registry/rules.json. Rend {rule_id: status}.

    R6-004 : chaque entree porte explicitement ``rule_id`` et ``status``.
    Les formes abregees et statuts inconnus sont rejetes. Les statuts sont
    normalises par NFKC, trim et casse avant comparaison.
    """
    if not _is_official_registry_dir(registry_dir):
        issues.append(Issue(
            "error", "RULES_REGISTRY",
            "seul le registre officiel versionne est autorise",
            "rules.json"))
        return _TrustedRules({})
    path = os.path.join(registry_dir, "rules.json")
    data = _load_json(path, issues, "rules.json")
    out: dict[str, str] = {}
    if not isinstance(data, dict) or not isinstance(data.get("rules"), list):
        issues.append(Issue("error", "RULES_REGISTRY",
                            "rules.json absent ou sans 'rules' liste", path))
        return _TrustedRules(out)
    expected_keys = {"schema_id", "version", "description", "rules"}
    if set(data) != expected_keys:
        issues.append(Issue(
            "error", "RULES_REGISTRY",
            "cles inattendues dans rules.json", "rules.json"))
    if data.get("schema_id") != "RULES_REGISTRY":
        issues.append(Issue(
            "error", "RULES_REGISTRY",
            "schema_id RULES_REGISTRY requis", "rules.json"))
    if data.get("version") != "0.1.0":
        issues.append(Issue(
            "error", "RULES_REGISTRY",
            "version de registre inconnue", "rules.json"))
    for item in data["rules"]:
        if not isinstance(item, dict):
            issues.append(Issue("error", "RULES_REGISTRY",
                                "entree de regle non-objet", path))
            continue
        if set(item) != {"rule_id", "status"}:
            issues.append(Issue(
                "error", "RULES_REGISTRY",
                "proprietes de regle inattendues", "rules.json"))
            continue
        rid = item.get("rule_id")
        status = item.get("status")
        if not isinstance(rid, str) or not _norm_unicode(rid):
            issues.append(Issue("error", "RULES_REGISTRY",
                                "entree de regle sans rule_id lisible", path))
            continue
        if not isinstance(status, str):
            issues.append(Issue("error", "RULES_REGISTRY",
                                f"statut de regle non-chaine: {status!r}", path))
            continue
        status = _norm_unicode(status).lower()
        if status not in LEGAL_RULE_STATUSES:
            issues.append(Issue("error", "RULES_REGISTRY",
                                f"statut de regle non normalise: {status!r}", path))
            continue
        # Doublon apres normalisation Unicode/casse.
        norm = _norm_dedup_key(rid)
        existing = {_norm_dedup_key(k): k for k in out}
        if norm in existing:
            issues.append(Issue("error", "DUPLICATE_RULE",
                                f"rule_id duplique dans le registre: {rid}", path))
            continue
        out[rid] = status
    return _TrustedRules(out)


# ---------------------------------------------------------------------------
# Cross-checks core/
# ---------------------------------------------------------------------------

def _cross_check_severity_model(core_dir: str, issues: list[Issue]) -> None:
    """N-002 : SEVERITY_MODEL + enum FINDING_SCHEMA + constantes = meme ensemble."""
    model = _load_json(os.path.join(core_dir, "SEVERITY_MODEL.json"), issues,
                       "SEVERITY_MODEL.json")
    if isinstance(model, dict):
        levels = model.get("levels")
        if not isinstance(levels, list):
            issues.append(Issue("error", "SEVERITY_MODEL", "levels absent ou non-liste",
                                "SEVERITY_MODEL.json"))
        else:
            declared = {lv.get("id") for lv in levels if isinstance(lv, dict)}
            declared.discard(None)
            if declared != SEVERITIES:
                issues.append(Issue("error", "SEVERITY_MODEL",
                                    f"niveaux SEVERITY_MODEL {sorted(declared)} != "
                                    f"validator {sorted(SEVERITIES)}", "SEVERITY_MODEL.json"))
    finding_schema = _load_json(os.path.join(core_dir, "FINDING_SCHEMA.json"),
                                issues, "FINDING_SCHEMA.json")
    if isinstance(finding_schema, dict):
        sev = (finding_schema.get("properties", {}).get("severity", {}) or {}).get("enum")
        if isinstance(sev, list) and set(sev) != SEVERITIES:
            issues.append(Issue("error", "SEVERITY_MODEL",
                                f"enum severity FINDING_SCHEMA {sorted(sev)} != "
                                f"validator {sorted(SEVERITIES)}", "FINDING_SCHEMA.json"))


# ---------------------------------------------------------------------------
# Frontmatter plat
# ---------------------------------------------------------------------------

# Cles de frontmatter autorisees (les 5 obligatoires + description).
_FRONTMATTER_ALLOWED_KEYS = {"name", "description", "version", "owner", "license"}


def _parse_frontmatter(text: str, issues: list[Issue], path: str) -> dict:
    # Normalise les fins de ligne (CR-only / CRLF -> LF) AVANT splitlines.
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        issues.append(Issue("error", "FRONTMATTER", "pas de frontmatter ---", path))
        return {}
    data: dict[str, str] = {}
    closed = False
    for line in lines[1:]:
        if line.strip() == "---":
            closed = True
            break
        if not line.strip():
            continue
        if line.startswith((" ", "\t")):
            issues.append(Issue("error", "FRONTMATTER_NESTED",
                                "imbrication interdite (indentation)", path))
            continue
        if ":" not in line:
            issues.append(Issue("error", "FRONTMATTER",
                                f"ligne sans 'cle: valeur': {line!r}", path))
            continue
        key, _, value = line.partition(":")
        key = key.strip()
        value = value.strip()
        if not _FRONTMATTER_KEY_RE.match(key):
            issues.append(Issue("error", "FRONTMATTER_KEY", f"cle invalide: {key!r}", path))
            continue
        if value.startswith(("{", "[", "-")):
            issues.append(Issue("error", "FRONTMATTER_NESTED",
                                f"valeur structuree interdite pour {key!r}", path))
            continue
        if key in data:
            issues.append(Issue("error", "FRONTMATTER_DUP", f"cle dupliquee: {key!r}", path))
            continue
        # Retire guillemets et commentaire inline AVANT comparaison (evite les
        # faux MANIFEST_MISMATCH). La valeur est normalisee (espaces plies).
        v = value.split("#", 1)[0].strip().strip('"').strip("'")
        v = " ".join(v.split())
        if not v:
            issues.append(Issue("error", "FRONTMATTER_VALUE",
                                f"valeur vide pour {key!r}", path))
            continue
        if len(v) > _MAX_FRONTMATTER_VALUE:
            issues.append(Issue("error", "FRONTMATTER_VALUE",
                                f"valeur trop longue pour {key!r}", path))
            continue
        data[key] = v
    if not closed:
        issues.append(Issue("error", "FRONTMATTER", "frontmatter non ferme ---", path))
    # Cles inconnues rejetees (frontmatter minimal strict).
    for key in data:
        if key not in _FRONTMATTER_ALLOWED_KEYS:
            issues.append(Issue("error", "FRONTMATTER_UNKNOWN_KEY",
                                f"cle frontmatter inconnue: {key!r}", path))
    return data


# ---------------------------------------------------------------------------
# Resolution des references symboliques
# ---------------------------------------------------------------------------

def _resolve_symbolic_schema(ref: str, core_dir: str, issues: list[Issue], path: str):
    m = SYMBOLIC_SCHEMA_RE.match(ref) if isinstance(ref, str) else None
    if not m:
        issues.append(Issue("error", "OUTPUT_SCHEMA_REF",
                            f"reference symbolique invalide: {ref!r}", path))
        return None
    name = m.group(1)
    full = os.path.join(core_dir, name)
    if not os.path.isfile(full):
        issues.append(Issue("error", "OUTPUT_SCHEMA_UNKNOWN",
                            f"schema symbolique inconnu: core:{name}", path))
        return None
    return _load_official_schema(core_dir, name, issues)


# ---------------------------------------------------------------------------
# Validation d'un skill
# ---------------------------------------------------------------------------

def _validate_skill_package(skill_dir: str, core_dir: str | None = None,
                            today: datetime.date | None = None,
                            registry_dir: str | None = None
                            ) -> SkillPackageValidation:
    """Valide un dossier de skill. `today` injecte = deterministe. `registry_dir`
    alimente facts et regles ; par defaut `registry/` a cote du validator.

    R6-001 : `today` DOIT etre un `datetime.date`. Absent, None ou mal type =
    erreur deterministe et arret immediat : aucune regle juridique n'est
    validee en mode degrade (une regle future ne peut plus passer faute de
    date de reference)."""
    t_issue = _today_issue(today, "skill")
    if t_issue is not None:
        return SkillPackageValidation([t_issue], None, None)
    issues: list[Issue] = []
    if not isinstance(skill_dir, (str, os.PathLike)):
        return SkillPackageValidation(
            [Issue("error", "SKILL_DIR",
                   "skill_dir attendu chemin", "skill")],
            None, None)
    skill_dir = os.fspath(skill_dir)
    if core_dir is None:
        core_dir = _DEFAULT_CORE_DIR
    elif not isinstance(core_dir, (str, os.PathLike)):
        return SkillPackageValidation(
            [Issue("error", "SCHEMA_INTEGRITY",
                   "core_dir attendu chemin", "skill")],
            None, None)
    else:
        core_dir = os.fspath(core_dir)
    if not _is_official_core_dir(core_dir):
        return SkillPackageValidation(
            [Issue(
                "error", "SCHEMA_INTEGRITY",
                "seul le dossier core officiel versionne est autorise",
                "skill")],
            None, None)
    if registry_dir is None:
        registry_dir = _DEFAULT_REGISTRY_DIR
    elif not isinstance(registry_dir, (str, os.PathLike)):
        return SkillPackageValidation(
            [Issue("error", "RULES_REGISTRY",
                   "registry_dir attendu chemin", "skill")],
            None, None)
    else:
        registry_dir = os.fspath(registry_dir)

    manifest_schema = _load_official_schema(
        core_dir, "SKILL_MANIFEST_SCHEMA.json", issues)
    _load_official_schema(core_dir, "FINDING_SCHEMA.json", issues)
    _cross_check_severity_model(core_dir, issues)
    known_facts = _load_facts(registry_dir, issues)
    _load_known_rules(registry_dir, issues)

    if _is_reparse_point(skill_dir) or not os.path.isdir(skill_dir):
        issues.append(Issue("error", "SKILL_DIR",
                            "dossier de skill absent ou reparse point", skill_dir))
        return SkillPackageValidation(_sorted(issues), None, None)

    # --- phases.json (confinement uniforme : via _safe_relpath, J4-010) ---
    manifest_path = _safe_relpath(skill_dir, "phases.json")
    if manifest_path is None:
        issues.append(Issue("error", "PATH_UNSAFE",
                            "phases.json hors confinement", "phases.json"))
        manifest = None
    else:
        manifest = _load_json(
            manifest_path, issues, "phases.json", root=skill_dir)
    if isinstance(manifest, dict) and isinstance(manifest_schema, dict):
        _validate(manifest, manifest_schema, issues, "phases.json")
        schema_version = manifest.get("schema_version")
        provides_present = "provides_capabilities" in manifest
        if schema_version == "1.0" and provides_present:
            issues.append(Issue(
                "error",
                "MANIFEST_SCHEMA_VERSION",
                "provides_capabilities exige schema_version 1.1",
                "phases.json",
            ))
        elif schema_version == "1.1" and not provides_present:
            issues.append(Issue(
                "error",
                "MANIFEST_SCHEMA_VERSION",
                "provides_capabilities requis en schema_version 1.1",
                "phases.json",
            ))
        # Les capacites FOURNIES sont ouvertes : chaque catalogue nomme ce
        # qu'il apporte. Seule la FORME est imposee, comme pour les capacites
        # client. Une liste fermee ici bloquerait tout auteur tiers.
        provided = manifest.get("provides_capabilities")
        if isinstance(provided, list):
            for value in provided:
                if (not isinstance(value, str)
                        or _CAPABILITY_NAME_RE.fullmatch(value) is None):
                    issues.append(Issue(
                        "error",
                        "MANIFEST_CAPABILITY_FORM",
                        f"capacite fournie invalide: {value!r}",
                        "phases.json",
                    ))
        for field in (
                "requires_capabilities",
                "optional_capabilities",
                "forbidden_capabilities",
                "provides_capabilities"):
            values = manifest.get(field)
            if isinstance(values, list):
                strings = [
                    value for value in values
                    if isinstance(value, str)
                ]
                if len(strings) != len(set(strings)):
                    issues.append(Issue(
                        "error",
                        "SKILL_CAPABILITY_DUPLICATE",
                        f"{field} contient un doublon",
                        "phases.json",
                    ))
        required_capabilities = manifest.get("requires_capabilities")
        optional_capabilities = manifest.get("optional_capabilities")
        forbidden_capabilities = manifest.get("forbidden_capabilities")
        if all(isinstance(value, list) for value in (
                required_capabilities,
                optional_capabilities,
                forbidden_capabilities)):
            # Un item non-chaine est deja signale par le schema : on ne garde
            # que les chaines, car un item non hachable planterait set() et
            # tuerait la session stdio entiere.
            required_set = {
                value for value in required_capabilities
                if isinstance(value, str)}
            optional_set = {
                value for value in optional_capabilities
                if isinstance(value, str)}
            forbidden_set = {
                value for value in forbidden_capabilities
                if isinstance(value, str)}
            if (
                    required_set & optional_set
                    or required_set & forbidden_set
                    or optional_set & forbidden_set):
                issues.append(Issue(
                    "error",
                    "SKILL_CAPABILITY_CONFLICT",
                    "capacite presente dans plusieurs politiques",
                    "phases.json",
                ))
    if isinstance(manifest, dict):
        _scan_secrets_globally(manifest, issues, "phases.json")

    # --- SKILL.md (plafond 2 Mio, confinement uniforme) ---
    skill_md_path = _safe_relpath(skill_dir, "SKILL.md")
    if skill_md_path is None:
        issues.append(Issue("error", "PATH_UNSAFE",
                            "SKILL.md hors confinement", "SKILL.md"))
        raw_md = None
    else:
        raw_md = _read_bytes(
            skill_md_path, issues, "SKILL.md", _MAX_SKILL_MD_BYTES,
            root=skill_dir)
    frontmatter: dict = {}
    body = ""
    body_readable = False
    md_text = None
    if raw_md is not None:
        if raw_md.startswith(b"\xef\xbb\xbf"):
            issues.append(Issue("error", "BOM", "SKILL.md en UTF-8 avec BOM", "SKILL.md"))
        else:
            try:
                md_text = raw_md.decode("utf-8")
            except UnicodeDecodeError as exc:
                issues.append(Issue("error", "ENCODING", f"SKILL.md non UTF-8: {exc}", "SKILL.md"))
                md_text = None
            if md_text is not None:
                frontmatter = _parse_frontmatter(md_text, issues, "SKILL.md")
                parts = md_text.split("---", 2)
                body = parts[2] if len(parts) >= 3 else ""
                body_readable = True
                _scan_secrets_globally(frontmatter, issues,
                                       "SKILL.md.frontmatter")
                for line_no, line in enumerate(body.splitlines(), 1):
                    _scan_secrets_globally(
                        line, issues, f"SKILL.md.body[{line_no}]")

    if body_readable:
        # Les titres dans du code/commentaire/HTML ne comptent pas comme sections.
        body_no_code = _strip_markdown_code(body)
        for section, rx in _SECTION_RES.items():
            matches = list(rx.finditer(body_no_code))
            if not matches:
                issues.append(Issue("error", "SKILL_SECTION",
                                    f"titre de section absent: {section}", "SKILL.md"))
                continue
            if len(matches) > 1:
                issues.append(Issue("error", "SKILL_SECTION",
                                    f"section dupliquee: {section} ({len(matches)}x)", "SKILL.md"))
            m = matches[0]
            # La section doit avoir un contenu minimal (pas un titre nu).
            after = body_no_code[m.end():]
            nxt = re.search(r"^##+\s", after, re.MULTILINE)
            content = after[:nxt.start()] if nxt else after
            content = content.strip()
            # J4-009 : un contenu fait d'invisibles (Cf) n'est pas un contenu.
            visible = "".join(c for c in content if unicodedata.category(c) not in ("Cf", "Cc"))
            if len(visible) < 3:
                issues.append(Issue("error", "SKILL_SECTION",
                                    f"section vide ou invisible: {section}", "SKILL.md"))
            elif len(content) > _MAX_SECTION_BODY * 100:
                issues.append(Issue("error", "SKILL_SECTION",
                                    f"section surdimensionnee: {section}", "SKILL.md"))

    # --- Coherence frontmatter <-> phases.json ---
    if isinstance(manifest, dict) and frontmatter:
        for fm_key in ("name", "version", "owner", "license"):
            if fm_key not in frontmatter:
                issues.append(Issue("error", "FRONTMATTER_REQUIRED",
                                    f"champ frontmatter absent: {fm_key}", "SKILL.md"))
        if "name" in frontmatter and manifest.get("id") != frontmatter["name"]:
            issues.append(Issue("error", "MANIFEST_MISMATCH",
                                f"SKILL.md name={frontmatter['name']!r} != "
                                f"phases.json id={manifest.get('id')!r}", "SKILL.md"))
        if "version" in frontmatter and manifest.get("version") != frontmatter["version"]:
            issues.append(Issue("error", "MANIFEST_MISMATCH",
                                "version SKILL.md != phases.json", "SKILL.md"))
        # owner : identite libre de l'auteur du skill, mais bornee et sans
        # invisible. Un catalogue tiers doit pouvoir signer ses propres
        # packages : verrouiller cette valeur rendrait le format inutilisable
        # hors de ce depot.
        owner = frontmatter.get("owner")
        if owner is not None:
            if (not isinstance(owner, str)
                    or not owner.strip()
                    or len(owner) > _MAX_FRONTMATTER_VALUE
                    or owner != owner.strip()
                    or _norm_unicode(owner) != owner
                    # Redondant avec la ligne precedente pour Cc et Cf, que
                    # _norm_unicode retire deja : garde en defense en
                    # profondeur, et seul filet pour les surrogates (Cs).
                    # Une mutation de cette ligne seule ne rougit donc pas.
                    or any(unicodedata.category(c) in {"Cc", "Cf", "Cs"}
                           for c in owner)):
                issues.append(Issue("error", "MANIFEST_MISMATCH",
                                    f"owner invalide: {owner!r}", "SKILL.md"))
        # license : liste blanche (pas de valeur arbitraire).
        if "license" in frontmatter and frontmatter["license"] not in (
                "Apache-2.0", "MIT", "BSD-2-Clause", "BSD-3-Clause"):
            issues.append(Issue("error", "MANIFEST_MISMATCH",
                                f"license non reconnue: {frontmatter['license']!r}", "SKILL.md"))

    # --- Version semver ---
    if isinstance(manifest, dict):
        domain = manifest.get("domain")
        if isinstance(domain, str) and (
                not _norm_unicode(domain) or _has_invisible_or_mixed(domain)):
            issues.append(Issue("error", "DOMAIN_INVALID",
                                "domain vide ou invisible apres normalisation",
                                "phases.json"))
        ver = manifest.get("version")
        if isinstance(ver, str) and not _SEMVER_RE.match(ver):
            issues.append(Issue("error", "VERSION_FORMAT",
                                f"version non semver: {ver!r}", "phases.json"))

    # --- Facts d'activation connus ---
    if isinstance(manifest, dict):
        activation = manifest.get("activation")
        if isinstance(activation, dict):
            facts = activation.get("any", [])
            if isinstance(facts, list):
                if not facts:
                    issues.append(Issue("error", "EMPTY_ACTIVATION",
                                        "activation.any vide (aucun declencheur)",
                                        "phases.json"))
                for fact in facts:
                    if isinstance(fact, str) and fact not in known_facts:
                        issues.append(Issue("error", "UNKNOWN_FACT",
                                            f"fact d'activation inconnu: {fact}", "phases.json"))

    # --- J4-007 : project_types/platforms/files non vides ---
    if isinstance(manifest, dict):
        for field in ("project_types", "platforms"):
            v = manifest.get(field)
            if isinstance(v, list) and not v:
                issues.append(Issue("error", "EMPTY_FIELD",
                                    f"{field} vide (aucune cible declaree)", "phases.json"))
        files = manifest.get("files")
        if isinstance(files, list) and not files:
            issues.append(Issue("error", "EMPTY_FIELD",
                                "files vide (aucun fichier declare)", "phases.json"))

    # --- output_schema : symbolique resolu ---
    if isinstance(manifest, dict):
        out = manifest.get("output_schema")
        if isinstance(out, str):
            if ".." in out or os.path.isabs(out) or re.match(r"^[A-Za-z]:", out):
                issues.append(Issue("error", "OUTPUT_SCHEMA_PATH",
                                    "output_schema doit etre symbolique (core:NOM.json)",
                                    "phases.json"))
            else:
                _resolve_symbolic_schema(out, core_dir, issues, "phases.json")

    # --- Routes obligatoires : dossiers distincts + contenu reel ---
    if isinstance(manifest, dict):
        seen_routes: dict[str, str] = {}
        for key in ("rules_path", "references_path", "scripts_path", "tests_path"):
            rel = manifest.get(key)
            if not isinstance(rel, str):
                issues.append(Issue("error", "REQUIRED", f"route manquante: {key}", "phases.json"))
                continue
            norm = _norm_unicode(rel).lower().replace("\\", "/").strip("/")
            if norm in seen_routes:
                issues.append(Issue("error", "DUPLICATE_ROUTE",
                                    f"{key} et {seen_routes[norm]} pointent vers {rel!r}",
                                    "phases.json"))
            else:
                seen_routes[norm] = key
            full = _safe_relpath(skill_dir, rel)
            if full is None:
                issues.append(Issue("error", "PATH_UNSAFE",
                                    f"{key} invalide ou hors skill: {rel!r}", "phases.json"))
            elif not os.path.isdir(full):
                issues.append(Issue("error", "GHOST_PATH",
                                    f"{key} annonce mais dossier absent: {rel}", "phases.json"))
            else:
                # Un dossier ne contenant que des placeholders (.keep) = vide.
                entries = _listdir_bounded(full, issues, key, skill_dir)
                real_files = []
                for entry_name in entries:
                    if entry_name.startswith("."):
                        continue
                    entry_path = _safe_relpath(
                        skill_dir, f"{rel}/{entry_name}")
                    if entry_path is not None and _safe_regular_file(
                            entry_path, skill_dir):
                        real_files.append(entry_name)
                    elif entry_path is not None and os.path.lexists(entry_path):
                        issues.append(Issue(
                            "error", "PATH_UNSAFE",
                            f"{key} contient un fichier lie ou non regulier",
                            "phases.json"))
                # Vide (aucun fichier) OU que des placeholders = EMPTY_PATH.
                if not entries or not real_files:
                    issues.append(Issue("error", "EMPTY_PATH",
                                        f"{key} annonce mais aucun fichier reel: {rel}",
                                        "phases.json"))

        # Fichiers individuels declares : existent, sont de vrais fichiers,
        # restent confines, et ne sont pas des doublons (casse/Unicode).
        files = manifest.get("files")
        if isinstance(files, list):
            seen_files: set[str] = set()
            for rel in files:
                if not isinstance(rel, str):
                    continue
                normf = _norm_unicode(rel).lower().replace("\\", "/")
                if normf in seen_files:
                    issues.append(Issue("error", "DUPLICATE_FILE",
                                        f"fichier declare en doublon: {rel!r}", "phases.json"))
                    continue
                seen_files.add(normf)
                full = _safe_relpath(skill_dir, rel)
                if full is None:
                    issues.append(Issue("error", "PATH_UNSAFE",
                                        f"fichier declare invalide: {rel!r}", "phases.json"))
                elif not os.path.lexists(full):
                    issues.append(Issue("error", "GHOST_FILE",
                                        f"fichier declare absent: {rel}", "phases.json"))
                elif not _safe_regular_file(full, skill_dir):
                    issues.append(Issue(
                        "error", "PATH_UNSAFE",
                        f"fichier declare lie, non regulier ou hors racine: {rel}",
                        "phases.json"))

            # Les références sont fournies au LLM.
            # Elles restent UTF-8, bornées et portables.
            references_rel = manifest.get("references_path")
            references_norm = (
                _norm_unicode(references_rel).lower()
                .replace("\\", "/").strip("/")
                if isinstance(references_rel, str) else None
            )
            reference_bytes = 0
            for rel in files:
                if not isinstance(rel, str) or references_norm is None:
                    continue
                normalized = (
                    _norm_unicode(rel).lower()
                    .replace("\\", "/").strip("/")
                )
                if not normalized.startswith(references_norm + "/"):
                    continue
                full = _safe_relpath(skill_dir, rel)
                if full is None or not _safe_regular_file(full, skill_dir):
                    continue
                raw_reference = _read_bytes(
                    full,
                    issues,
                    rel,
                    _MAX_REFERENCE_BYTES,
                    root=skill_dir,
                )
                if raw_reference is None:
                    continue
                reference_bytes += len(raw_reference)
                if reference_bytes > _MAX_REFERENCE_TOTAL_BYTES:
                    issues.append(Issue(
                        "error",
                        "REFERENCE_LIMIT",
                        "references cumulées trop volumineuses",
                        references_rel,
                    ))
                    break
                if raw_reference.startswith(b"\xef\xbb\xbf"):
                    issues.append(Issue(
                        "error",
                        "BOM",
                        f"{rel} en UTF-8 avec BOM",
                        rel,
                    ))
                    continue
                try:
                    reference_text = raw_reference.decode("utf-8")
                except UnicodeDecodeError:
                    issues.append(Issue(
                        "error",
                        "ENCODING",
                        f"{rel} non UTF-8",
                        rel,
                    ))
                    continue
                if _reference_contains_absolute_path(reference_text):
                    issues.append(Issue(
                        "error",
                        "REFERENCE_ABSOLUTE_PATH",
                        "chemin absolu publié dans une référence",
                        rel,
                    ))
                for line_no, line in enumerate(
                        reference_text.splitlines(), 1):
                    _scan_secrets_globally(
                        line,
                        issues,
                        f"{rel}[{line_no}]",
                    )

    # --- Regles : chargees, uniques, strictes si juridique ---
    if isinstance(manifest, dict):
        rules_rel = manifest.get("rules_path")
        rules_full = _safe_relpath(skill_dir, rules_rel) if isinstance(rules_rel, str) else None
        rule_ids: set[str] = set()
        rule_norms: set[str] = set()
        if rules_full and os.path.isdir(rules_full):
            rule_entries = _listdir_bounded(
                rules_full, issues, "rules", skill_dir)
            for name in rule_entries:
                if not name.endswith(".json"):
                    continue
                # J4-010 : confinement uniforme aussi pour rules/*.json.
                rule_full = _safe_relpath(skill_dir, f"{rules_rel}/{name}")
                if rule_full is None:
                    issues.append(Issue("error", "PATH_UNSAFE",
                                        f"regle hors confinement: {name}", f"rules/{name}"))
                    continue
                rule = _load_json(
                    rule_full, issues, f"rules/{name}", root=skill_dir)
                if not isinstance(rule, dict):
                    continue
                _scan_secrets_globally(rule, issues, f"rules/{name}")
                rid = rule.get("rule_id")
                if isinstance(rid, str) and rid:
                    # J4-007 : doublons apres normalisation casse/Unicode (pas juste exacts).
                    norm = _norm_dedup_key(rid)
                    if norm in rule_norms:
                        issues.append(Issue("error", "DUPLICATE_RULE",
                                            f"rule_id duplique (normalise): {rid}", f"rules/{name}"))
                    rule_norms.add(norm)
                    rule_ids.add(rid)
                if _is_legal_domain(manifest.get("domain")):
                    _validate_legal_rule(rule, name, issues, today)
        if _is_legal_domain(manifest.get("domain")) and not rule_ids:
            issues.append(Issue("error", "LEGAL_NO_RULES",
                                "skill juridique sans aucune regle exploitable", "rules"))

    ordered = _sorted(issues)
    if (any(issue.level == "error" for issue in ordered)
            or not isinstance(manifest, dict)
            or not isinstance(md_text, str)):
        return SkillPackageValidation(ordered, None, None)
    manifest_json = json.dumps(
        manifest,
        ensure_ascii=False,
        allow_nan=False,
        sort_keys=True,
        separators=(",", ":"),
    )
    return SkillPackageValidation(ordered, manifest_json, md_text)


def _public_skill_package_api(seal):
    def validate_skill_package(
            skill_dir: str,
            core_dir: str | None = None,
            today: datetime.date | None = None,
            registry_dir: str | None = None,
            ) -> SkillPackageValidation:
        """Valide, scelle et rend le snapshot exact deja lu.

        Le contenu n'est disponible que si aucune erreur n'existe. Cette API
        est le parcours officiel du loader B1. L'emetteur du sceau reste
        enferme dans cette fonction et ne peut pas sceller des champs fournis
        directement par un appelant.
        """

        result = _validate_skill_package(
            skill_dir, core_dir, today, registry_dir)
        return seal(result)

    return validate_skill_package


validate_skill_package = _public_skill_package_api(
    _seal_skill_package_validation)
del _public_skill_package_api
del _seal_skill_package_validation


def validate_skill(skill_dir: str, core_dir: str | None = None,
                   today: datetime.date | None = None,
                   registry_dir: str | None = None) -> list[Issue]:
    """Compatibilite R6 : rend uniquement les issues triees."""

    return list(
        _validate_skill_package(
            skill_dir, core_dir, today, registry_dir).issues)


def _validate_legal_rule(rule: dict, name: str, issues: list[Issue],
                         today: datetime.date) -> None:
    """Controles stricts d'une regle juridique. Types d'abord (anti-crash).

    R6-001 : `today` est garanti valide par `validate_skill` (contrat verifie
    en entree). La fraicheur est donc TOUJOURS evaluee : plus aucune branche
    ne saute le controle faute de date de reference."""
    path = f"rules/{name}"
    # J4-005 : title + authority requis (comme legal_basis), en plus des champs
    # deja exiges.
    for field in ("rule_id", "jurisdiction", "authority", "title", "source_url",
                  "verified_on", "freshness_window_days", "applicability",
                  "confidence", "status"):
        if field not in rule:
            issues.append(Issue("error", "LEGAL_RULE_FIELD",
                                f"regle juridique sans {field}", path))

    # Types stricts AVANT toute comparaison (un dict n'est pas hashable).
    # J4-005 : title et authority inclus dans le controle de type.
    for field in ("rule_id", "jurisdiction", "authority", "title", "source_url",
                  "verified_on", "applicability"):
        v = rule.get(field)
        if v is not None and not isinstance(v, str):
            issues.append(Issue("error", "LEGAL_TYPE",
                                f"{field} attendu string", path))
    status = rule.get("status")
    if status is not None and not isinstance(status, str):
        issues.append(Issue("error", "LEGAL_TYPE", "status attendu string", path))
        status = None
    conf = rule.get("confidence")
    if conf is not None and (not isinstance(conf, str) or conf not in CONFIDENCES):
        issues.append(Issue("error", "LEGAL_TYPE", f"confidence hors enum: {conf!r}", path))
    fwd = rule.get("freshness_window_days")
    if fwd is not None and (not isinstance(fwd, int) or isinstance(fwd, bool)):
        issues.append(Issue("error", "LEGAL_TYPE",
                            "freshness_window_days attendu integer", path))
        fwd = None

    if isinstance(status, str):
        if status not in LEGAL_RULE_STATUSES:
            issues.append(Issue("error", "LEGAL_RULE_STATUS",
                                f"statut juridique non normalise: {status!r}", path))
        elif status == "abroge":
            issues.append(Issue("error", "LEGAL_RULE_REPEALED",
                                "regle abrogee utilisee comme droit actuel", path))

    # J4-005 : authority + jurisdiction en whitelist (comme legal_basis).
    authority = rule.get("authority")
    if isinstance(authority, str):
        if (_has_invisible_or_mixed(authority) or not _norm_unicode(authority)
                or _norm_dedup_key(authority) not in
                {_norm_dedup_key(a) for a in LEGAL_AUTHORITIES}):
            issues.append(Issue("error", "LEGAL_AUTHORITY",
                                f"authority non reconnue: {authority!r}", path))
    jurisdiction = rule.get("jurisdiction")
    if isinstance(jurisdiction, str):
        if (_has_invisible_or_mixed(jurisdiction) or not _norm_unicode(jurisdiction)
                or _norm_unicode(jurisdiction).upper() not in
                {_norm_unicode(j).upper() for j in LEGAL_JURISDICTIONS}):
            issues.append(Issue("error", "LEGAL_JURISDICTION",
                                f"jurisdiction non reconnue: {jurisdiction!r}", path))

    url = rule.get("source_url")
    if isinstance(url, str):
        host = _url_host(url)
        if not _host_allowed(host, OFFICIAL_LEGAL_HOSTS):
            issues.append(Issue("error", "LEGAL_SOURCE",
                                f"source non officielle: {url!r}", path))
        # HTTPS + pas userinfo + port standard (comme legal_basis).
        if not url.lower().startswith("https://"):
            issues.append(Issue("error", "LEGAL_SOURCE", "source non HTTPS", path))
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            issues.append(Issue("error", "LEGAL_SOURCE", "source avec userinfo", path))
        hostport = url.split("//", 1)[-1].split("/", 1)[0]
        if ":" in hostport:
            port = hostport.rsplit(":", 1)[-1]
            if port not in ("443",):
                issues.append(Issue("error", "LEGAL_SOURCE", f"port non standard: {port}", path))

    if isinstance(fwd, int):
        if fwd > 365:
            issues.append(Issue("error", "LEGAL_FRESHNESS",
                                "freshness_window_days > 365", path))
        if fwd <= 0:
            issues.append(Issue("error", "LEGAL_FRESHNESS",
                                "freshness_window_days <= 0", path))

    # Dates : validite TOUJOURS bloquante ; fraicheur relative si today fourni.
    von = rule.get("verified_on")
    if isinstance(von, str):
        if _parse_iso_date(von) is None:
            issues.append(Issue("error", "LEGAL_DATE", f"verified_on invalide: {von!r}", path))
        else:
            # R6-001 : une date FUTURE est rejetee meme sans fenetre de
            # fraicheur declaree (fwd absent/mal type ne doit pas ouvrir de
            # passe-droit a une regle datee du futur).
            if _parse_iso_date(von) > today:
                issues.append(Issue("error", "LEGAL_DATE",
                                    f"verified_on dans le futur: {von!r}", path))
            elif isinstance(fwd, int) and _legal_freshness_verdict(von, fwd, today) == "stale":
                issues.append(Issue("error", "LEGAL_STALE",
                                    f"regle perimee (verified_on={von})", path))

    # R5-005 : relation juridiction -> authority -> host.
    _legal_coherence_issue(rule.get("jurisdiction"), rule.get("authority"),
                           rule.get("source_url"), path, issues)


def _url_host(url: str) -> str:
    if not isinstance(url, str):
        return ""
    m = re.match(r"^https?://([^/?#]+)", url.strip(), re.IGNORECASE)
    if not m:
        return ""
    return m.group(1).split("@")[-1].split(":")[0].lower()


# ---------------------------------------------------------------------------
# Validation d'un finding
# ---------------------------------------------------------------------------

def _validate_evidence_item(e, idx: int, issues: list[Issue]) -> None:
    """Contrats specifiques par type de preuve."""
    path = f"finding.evidence[{idx}]"
    if not isinstance(e, dict):
        issues.append(Issue("error", "EVIDENCE", "preuve non-objet", path))
        return
    etype = e.get("type")

    # R6-006 : niveau de validation revendique. Le schema controle type + enum.
    # Ce controle ajoute uniquement la limite semantique propre a la V1.
    if "validation_level" in e:
        level = e.get("validation_level")
        # Le schema officiel gere type + enum. Le controle semantique gere
        # uniquement l'interdiction V1 de TARGET_VERIFIED.
        if isinstance(level, str) and level in VALIDATION_LEVELS and (
                level not in V1_ALLOWED_VALIDATION_LEVELS):
            issues.append(Issue("error", "EVIDENCE_VALIDATION_LEVEL",
                                f"validation_level {level} interdit en V1 : la "
                                "racine de la cible n'est pas montee, aucune "
                                "verification mecanique de la cible n'est possible",
                                path))

    p = e.get("path")
    if isinstance(p, str):
        if _portable_relpath_parts(p) is None:
            issues.append(Issue(
                "error", "EVIDENCE_PATH",
                "chemin de preuve non portable ou ambigu", path))

    line = e.get("line")
    if line is not None:
        if not isinstance(line, int) or isinstance(line, bool) or line < 1:
            issues.append(Issue("error", "EVIDENCE_LINE", f"ligne invalide: {line!r}", path))
        elif line > 10_000_000:
            issues.append(Issue("error", "EVIDENCE_LINE",
                                f"ligne incoherente (trop elevee): {line}", path))

    excerpt = e.get("excerpt")
    if excerpt is not None and not isinstance(excerpt, str):
        issues.append(Issue("error", "EVIDENCE_EXCERPT", "extrait non-chaine", path))
    elif isinstance(excerpt, str):
        if len(excerpt) > _MAX_EXCERPT_CHARS:
            issues.append(Issue("error", "EVIDENCE_EXCERPT", "extrait trop long", path))
        if not excerpt.strip():
            issues.append(Issue("error", "EVIDENCE_EXCERPT", "extrait vide", path))

    # Contrats par type : le CONTRAT exige ligne ET extrait pour file/config.
    if etype == "file":
        if not p or not isinstance(p, str) or p.strip() in ("", ".", "decorative"):
            issues.append(Issue("error", "EVIDENCE_WEAK", "preuve file sans chemin exploitable", path))
        if line is None:
            issues.append(Issue("error", "EVIDENCE_WEAK", "preuve file sans ligne", path))
        if not isinstance(excerpt, str):
            issues.append(Issue("error", "EVIDENCE_WEAK", "preuve file sans extrait", path))
    elif etype == "config":
        if not p or not isinstance(p, str) or p.strip() in ("", ".", "decorative"):
            issues.append(Issue("error", "EVIDENCE_WEAK", "preuve config sans chemin", path))
        if line is None and not isinstance(excerpt, str):
            issues.append(Issue("error", "EVIDENCE_WEAK",
                                "preuve config sans ligne ni extrait", path))
        # J4-008 : une preuve config documente la CLE et la VALEUR incriminee.
        # excerpt doit contenir la configuration (pas juste le chemin).
        if isinstance(excerpt, str) and excerpt.strip() and "=" not in excerpt and ":" not in excerpt:
            issues.append(Issue("error", "EVIDENCE_WEAK",
                                "preuve config sans cle/valeur dans l'extrait", path))
    elif etype == "absence":
        # `searched_in` designe des FICHIERS : c'est une liste, jamais une
        # phrase. Une chaine libre obligeait a deviner ou commence un chemin
        # dans de la prose, ce qui ne converge pas. La forme structuree fait
        # disparaitre l'ambiguite au lieu de tenter de la resoudre.
        si = e.get("searched_in")
        if not isinstance(si, list) or not si:
            issues.append(Issue("error", "EVIDENCE_WEAK", "absence sans searched_in", path))
        elif any(_portable_relpath_parts(item) is None for item in si):
            issues.append(Issue("error", "EVIDENCE_PATH",
                                "searched_in non portable ou ambigu", path))
        result = e.get("result")
        # "absent" EXACT (casse et espaces normalises, mais le mot doit etre seul).
        if not isinstance(result, str) or _norm_unicode(result).strip().lower() != "absent":
            issues.append(Issue("error", "EVIDENCE_WEAK",
                                "absence sans resultat 'absent' exact", path))
    elif etype == "log":
        if not isinstance(excerpt, str) or not excerpt.strip():
            issues.append(Issue("error", "EVIDENCE_WEAK", "log sans extrait", path))


def _normalize_known_rules(known_rules, path: str) -> tuple[_TrustedRules | None,
                                                            list[Issue]]:
    """R6-004 : valide et normalise le registre public.

    Rend le registre canonique et toutes les erreurs deterministes :
      - absent / None       -> pas de registre, une regle inconnue passerait
      - mauvais type        -> liste, chaine, entier...
      - entree mal typee    -> cle non-chaine ou statut non-chaine
      - statut inconnu      -> jamais accepte par l'API directe

    Un registre VIDE ({}) est structurellement valide : il rejette alors tout
    finding qui reference une regle (via UNKNOWN_RULE), ce qui est la decision
    correcte et non un contournement.
    """
    issues: list[Issue] = []
    if known_rules is None:
        issues.append(Issue("error", "RULES_REGISTRY",
                            "known_rules requis (registre de regles obligatoire)",
                            path))
        return None, issues
    if not isinstance(known_rules, _TrustedRules):
        issues.append(Issue(
            "error", "RULES_REGISTRY",
            "known_rules doit provenir du chargeur officiel",
            path))
        return None, issues
    payload_issues = _payload_guard(dict(known_rules), path)
    if payload_issues:
        return None, payload_issues
    normalized: dict[str, str] = {}
    seen: set[str] = set()
    for rid, status in known_rules.items():
        if not isinstance(rid, str) or not _norm_unicode(rid):
            issues.append(Issue(
                "error", "RULES_REGISTRY",
                f"entree de registre mal typee (rule_id): {rid!r}", path))
            continue
        norm_rid = _norm_dedup_key(rid)
        if norm_rid in seen:
            issues.append(Issue("error", "RULES_REGISTRY",
                                f"rule_id duplique apres normalisation: {rid!r}",
                                path))
            continue
        seen.add(norm_rid)
        if not isinstance(status, str):
            issues.append(Issue(
                "error", "RULES_REGISTRY",
                f"entree de registre mal typee (status de {rid}): {status!r}",
                path))
            continue
        norm_status = _norm_unicode(status).lower()
        if norm_status not in LEGAL_RULE_STATUSES:
            issues.append(Issue(
                "error", "RULES_REGISTRY",
                f"statut de regle non normalise pour {rid}: {status!r}", path))
            continue
        normalized[rid] = norm_status
    if issues:
        return None, _sorted(issues)
    return _TrustedRules(normalized), []


def _trusted_rules_for_tests(mapping: dict[str, str]) -> _TrustedRules:
    """Fabrique privee reservee aux tests unitaires internes.

    Les interfaces publiques n'acceptent jamais un ``dict`` arbitraire.
    """
    candidate = _TrustedRules(mapping)
    normalized, issues = _normalize_known_rules(candidate, "tests")
    if issues or normalized is None:
        raise ValueError("registre de test invalide")
    return normalized


def _known_rules_issue(known_rules, path: str) -> Issue | None:
    """Compatibilite interne : premiere erreur du validateur central."""
    _, issues = _normalize_known_rules(known_rules, path)
    return issues[0] if issues else None


def validate_b3_plan(plan: object,
                     plan_schema: dict | None = None) -> list[Issue]:
    """Valide un plan B3 contre le schema officiel ferme."""

    issues = _payload_guard(plan, "plan")
    if issues:
        return _sorted(issues)
    schema = _resolve_official_schema(
        plan_schema,
        "PLAN_B3_SCHEMA.json",
        issues,
        "plan",
    )
    if schema is None:
        return _sorted(issues)
    _validate(plan, schema, issues, "plan")
    if not isinstance(plan, dict):
        return _sorted(issues)

    def canonical_list(value, path):
        if not isinstance(value, list) or not all(
                isinstance(item, str) for item in value):
            return
        if len(value) != len(set(value)):
            issues.append(Issue(
                "error",
                "PLAN_DUPLICATE",
                "liste B3 dupliquee",
                path,
            ))
        if value != sorted(value):
            issues.append(Issue(
                "error",
                "PLAN_ORDER",
                "liste B3 non canonique",
                path,
            ))

    client_capabilities = plan.get("client_capabilities")
    normalized, capability_error = normalize_client_capabilities(
        client_capabilities)
    if (capability_error is None
            and normalized is not None
            and list(normalized) != client_capabilities):
        issues.append(Issue(
            "error",
            "CLIENT_CAPABILITIES_ORDER",
            "capacites client non canoniques",
            "plan.client_capabilities",
        ))

    profile = plan.get("project_profile")
    if isinstance(profile, dict):
        for field in ("facts", "languages", "types"):
            canonical_list(
                profile.get(field),
                f"plan.project_profile.{field}",
            )

    categories = (
        "skills_selected",
        "skills_not_applicable",
        "skills_blocked",
    )
    category_values = [
        plan.get(category) for category in categories
    ]
    if all(isinstance(value, list) for value in category_values):
        identifiers = [
            item.get("skill_id")
            for value in category_values
            for item in value
            if isinstance(item, dict)
            and isinstance(item.get("skill_id"), str)
        ]
        canonical_identifiers = [
            identifier.casefold() for identifier in identifiers
        ]
        if len(canonical_identifiers) != len(
                set(canonical_identifiers)):
            issues.append(Issue(
                "error",
                "PLAN_SKILL_PARTITION",
                "skill present dans plusieurs categories",
                "plan",
            ))

    selected = plan.get("skills_selected")
    if isinstance(selected, list):
        selected_ids = [
            item.get("skill_id")
            for item in selected
            if isinstance(item, dict)
        ]
        if (
                all(isinstance(value, str) for value in selected_ids)
                and selected_ids != sorted(
                    selected_ids,
                    key=lambda value: (value.casefold(), value))):
            issues.append(Issue(
                "error", "PLAN_ORDER",
                "skills_selected non canonique",
                "plan.skills_selected"))
        positions = [
            item.get("position")
            for item in selected
            if isinstance(item, dict)
        ]
        if positions != list(range(1, len(selected) + 1)):
            issues.append(Issue(
                "error", "PLAN_ORDER",
                "positions selectionnees non consecutives",
                "plan.skills_selected"))
        for index, item in enumerate(selected):
            if not isinstance(item, dict):
                continue
            for field in (
                    "limitations",
                    "optional_capabilities",
                    "required_capabilities"):
                canonical_list(
                    item.get(field),
                    f"plan.skills_selected[{index}].{field}",
                )
            reasons = item.get("reason_codes")
            if isinstance(reasons, list) and len(reasons) != len(
                    set(reason for reason in reasons
                        if isinstance(reason, str))):
                issues.append(Issue(
                    "error", "PLAN_DUPLICATE",
                    "reason code duplique",
                    f"plan.skills_selected[{index}].reason_codes"))

    for category in ("skills_not_applicable", "skills_blocked"):
        values = plan.get(category)
        if not isinstance(values, list):
            continue
        identifiers = [
            item.get("skill_id")
            for item in values
            if isinstance(item, dict)
        ]
        if (
                all(isinstance(value, str) for value in identifiers)
                and identifiers != sorted(
                    identifiers,
                    key=lambda value: (value.casefold(), value))):
            issues.append(Issue(
                "error", "PLAN_ORDER",
                f"{category} non canonique",
                f"plan.{category}"))
        for index, item in enumerate(values):
            if not isinstance(item, dict):
                continue
            reasons = item.get("reason_codes")
            if isinstance(reasons, list) and len(reasons) != len(
                    set(reason for reason in reasons
                        if isinstance(reason, str))):
                issues.append(Issue(
                    "error", "PLAN_DUPLICATE",
                    "reason code duplique",
                    f"plan.{category}[{index}].reason_codes"))
            if category == "skills_blocked":
                canonical_list(
                    item.get("missing_capabilities"),
                    f"plan.{category}[{index}].missing_capabilities",
                )

    missing = plan.get("skills_missing")
    if isinstance(missing, list):
        missing_keys = [
            (item.get("capability"), item.get("gap_id"))
            for item in missing
            if isinstance(item, dict)
        ]
        string_keys = [
            key for key in missing_keys
            if all(isinstance(part, str) for part in key)
        ]
        if (len(string_keys) == len(missing_keys)
                and missing_keys != sorted(missing_keys)):
            issues.append(Issue(
                "error", "PLAN_ORDER",
                "skills_missing non canonique",
                "plan.skills_missing"))
        # Une cle non-chaine est deja signalee par le schema : un tuple non
        # hachable planterait set() et tuerait la session stdio entiere.
        if len(string_keys) != len(set(string_keys)):
            issues.append(Issue(
                "error", "PLAN_DUPLICATE",
                "lacune dupliquee",
                "plan.skills_missing"))
        for index, item in enumerate(missing):
            if not isinstance(item, dict):
                continue
            # Meme grammaire que le registre (GAP_RULE_ID_INVALID /
            # GAP_CAPABILITY_UNKNOWN) : le plan public ne doit pas accepter
            # une lacune que le registre refuse.
            gap_id = item.get("gap_id")
            if (isinstance(gap_id, str)
                    and _GAP_ID_RE.fullmatch(gap_id) is None):
                issues.append(Issue(
                    "error", "PLAN_GAP_ID_INVALID",
                    f"gap_id invalide: {gap_id!r}",
                    f"plan.skills_missing[{index}].gap_id"))
            capability = item.get("capability")
            if (isinstance(capability, str)
                    and _CAPABILITY_NAME_RE.fullmatch(capability) is None):
                issues.append(Issue(
                    "error", "PLAN_GAP_CAPABILITY_INVALID",
                    "capacite de lacune invalide",
                    f"plan.skills_missing[{index}].capability"))
            canonical_list(
                item.get("required_facts"),
                f"plan.skills_missing[{index}].required_facts",
            )

    warnings = plan.get("warnings")
    canonical_list(warnings, "plan.warnings")

    steps = plan.get("steps")
    if isinstance(selected, list) and isinstance(steps, list):
        expected_steps = [
            {
                "action": "READ_AND_EXECUTE_SKILL",
                "gate": 0,
                "position": item.get("position"),
                "reason_codes": item.get("reason_codes"),
                "required_capabilities": item.get(
                    "required_capabilities"),
                "skill_id": item.get("skill_id"),
            }
            for item in selected
            if isinstance(item, dict)
        ]
        if steps != expected_steps:
            issues.append(Issue(
                "error",
                "PLAN_STEP",
                "etapes incoherentes avec la selection",
                "plan.steps",
            ))

    if (
            isinstance(selected, list)
            and isinstance(plan.get("skills_blocked"), list)
            and isinstance(missing, list)):
        expected_status = (
            "BLOCKED"
            if not selected
            else "PARTIAL"
            if plan["skills_blocked"] or missing
            else "READY"
        )
        if plan.get("plan_status") != expected_status:
            issues.append(Issue(
                "error",
                "PLAN_STATUS",
                "statut global incoherent",
                "plan.plan_status",
            ))
    return _sorted(issues)


def validate_client_capabilities(
        capabilities: object,
        capabilities_schema: dict | None = None) -> list[Issue]:
    """Valide la declaration fermee des capacites client."""

    issues = _payload_guard(capabilities, "client_capabilities")
    if issues:
        return _sorted(issues)
    schema = _resolve_official_schema(
        capabilities_schema,
        "CLIENT_CAPABILITIES_SCHEMA.json",
        issues,
        "client_capabilities",
    )
    if schema is None:
        return _sorted(issues)
    _validate(capabilities, schema, issues, "client_capabilities")
    normalized, code = normalize_client_capabilities(capabilities)
    if code is not None or normalized is None:
        issues.append(Issue(
            "error",
            code or "CLIENT_CAPABILITIES_INVALID",
            "declaration de capacites client invalide",
            "client_capabilities",
        ))
    return _sorted(issues)


def validate_project_facts_declaration(
        declaration: object,
        declaration_schema: dict | None = None) -> list[Issue]:
    """Valide les faits explicitement confirmes par le projet."""

    issues = _payload_guard(declaration, "project_facts")
    if issues:
        return _sorted(issues)
    schema = _resolve_official_schema(
        declaration_schema,
        "PROJECT_FACTS_SCHEMA.json",
        issues,
        "project_facts",
    )
    if schema is None:
        return _sorted(issues)
    _validate(declaration, schema, issues, "project_facts")
    if isinstance(declaration, dict):
        facts = declaration.get("facts")
        if isinstance(facts, list):
            normalized = [
                fact for fact in facts if isinstance(fact, str)
            ]
            if len(normalized) != len(set(normalized)):
                issues.append(Issue(
                    "error",
                    "PROFILE_FACT_DUPLICATE",
                    "fait projet duplique",
                    "project_facts.facts",
                ))
    return _sorted(issues)


def validate_skill_gap_rules(
        rules: object,
        rules_schema: dict | None = None) -> list[Issue]:
    """Valide le registre deterministe des lacunes B3."""

    issues = _payload_guard(rules, "skill_gap_rules")
    if issues:
        return _sorted(issues)
    schema = _resolve_official_schema(
        rules_schema,
        "SKILL_GAP_RULES_SCHEMA.json",
        issues,
        "skill_gap_rules",
    )
    if schema is None:
        return _sorted(issues)
    _validate(rules, schema, issues, "skill_gap_rules")
    if not isinstance(rules, dict) or not isinstance(
            rules.get("rules"), list):
        return _sorted(issues)

    seen_gaps: set[str] = set()
    seen_capabilities: set[str] = set()
    for index, item in enumerate(rules["rules"]):
        if not isinstance(item, dict):
            continue
        path = f"skill_gap_rules.rules[{index}]"
        gap_id = item.get("gap_id")
        capability = item.get("capability")
        required_facts = item.get("required_facts")
        if isinstance(gap_id, str):
            if gap_id in seen_gaps:
                issues.append(Issue(
                    "error", "GAP_RULE_DUPLICATE",
                    "gap_id duplique", path))
            seen_gaps.add(gap_id)
            # Le schema ne porte plus d'enum fige : un catalogue tiers nomme
            # ses propres lacunes. La forme reste imposee ici.
            if _GAP_ID_RE.fullmatch(gap_id) is None:
                issues.append(Issue(
                    "error", "GAP_RULE_ID_INVALID",
                    f"gap_id invalide: {gap_id!r}", path))
        if isinstance(capability, str):
            if capability in seen_capabilities:
                issues.append(Issue(
                    "error", "GAP_CAPABILITY_DUPLICATE",
                    "capacite de lacune dupliquee", path))
            seen_capabilities.add(capability)
            if _CAPABILITY_NAME_RE.fullmatch(capability) is None:
                issues.append(Issue(
                    "error", "GAP_CAPABILITY_UNKNOWN",
                    "capacite de lacune invalide", path))
        if isinstance(required_facts, list):
            string_facts = [
                fact for fact in required_facts
                if isinstance(fact, str)
            ]
            if len(string_facts) != len(set(string_facts)):
                issues.append(Issue(
                    "error", "GAP_FACT_DUPLICATE",
                    "fait de lacune duplique", path))
            if any(fact not in PROFILE_FACTS for fact in string_facts):
                issues.append(Issue(
                    "error", "GAP_FACT_UNKNOWN",
                    "fait de lacune inconnu", path))
            if not required_facts:
                issues.append(Issue(
                    "error", "GAP_FACTS_EMPTY",
                    "lacune sans fait requis", path))
    return _sorted(issues)


def validate_finding(finding: dict, finding_schema: dict | None = None,
                     today: datetime.date | None = None,
                     legal: bool | None = None,
                     known_rules: dict[str, str] | None = None) -> list[Issue]:
    """Valide un finding. `today` et `known_rules` injectes = deterministe.

    `known_rules` = {rule_id: status}. Un rule_id inconnu est rejete, et une
    regle abrogee est interdite comme droit actuel.

    R6-001 : `today` DOIT etre un `datetime.date` (TODAY_REQUIRED /
    TODAY_INVALID). Aucun controle n'est execute en mode degrade.

    R6-004 : `known_rules` DOIT etre un registre valide (RULES_REGISTRY).
    L'API publique et la CLI rendent desormais la MEME decision : une regle
    inconnue ne peut plus passer par l'API directe. Aucune validation partielle
    sans registre n'est exposee (pas de porte derobee interne).
    """
    issues: list[Issue] = []
    # R6-001 / R6-004 : contrat d'appel verifie AVANT tout controle. Toutes
    # les omissions deviennent des issues, jamais un TypeError Python.
    contract: list[Issue] = []
    t_issue = _today_issue(today, "finding")
    if t_issue is not None:
        contract.append(t_issue)
    normalized_rules, rule_issues = _normalize_known_rules(known_rules, "finding")
    contract.extend(rule_issues)
    resolved_schema = _resolve_official_schema(
        finding_schema, "FINDING_SCHEMA.json", contract, "finding_schema")
    if contract:
        return _sorted(contract)
    if not isinstance(finding, dict):
        return [Issue("error", "FINDING", "finding non-objet")]
    payload_issues = _payload_guard(finding, "finding")
    if payload_issues:
        return _sorted(payload_issues)

    _validate(finding, resolved_schema, issues, "finding")

    status = finding.get("status")
    severity = finding.get("severity")
    confidence = finding.get("confidence")
    domain = finding.get("domain")

    if isinstance(domain, str):
        if not _norm_unicode(domain) or _has_invisible_or_mixed(domain):
            issues.append(Issue("error", "DOMAIN_INVALID",
                                "domain vide ou invisible apres normalisation",
                                "finding.domain"))

    # Regle connue + non abrogee (registre garanti valide par R6-004).
    rid = finding.get("rule_id")
    if isinstance(rid, str):
        if rid not in normalized_rules:
            issues.append(Issue("error", "UNKNOWN_RULE", f"rule_id inconnu: {rid}",
                                "finding.rule_id"))
        elif normalized_rules.get(rid) == "abroge":
            issues.append(Issue("error", "RULE_REPEALED",
                                f"regle abrogee citee comme droit actuel: {rid}",
                                "finding.rule_id"))

    # --- Relations interchamps ---
    if status == "REMEDIATED":
        issues.append(Issue("error", "V1_REMEDIATED",
                            "REMEDIATED interdit en V1 (audit seul)", "finding.status"))
    if status in ("BLOCKED", "NOT_APPLICABLE"):
        reason = finding.get("status_reason")
        # status_reason non vide ET sans caractere invisible (ZWSP/BOM/...).
        if not isinstance(reason, str) or not _norm_unicode(reason).strip():
            issues.append(Issue("error", "STATUS_REASON",
                                f"{status} sans status_reason lisible", "finding.status_reason"))

    rem = finding.get("remediation")
    if isinstance(rem, dict) and status == "REMEDIATION_PROPOSED":
        if rem.get("mode") != "PROPOSE_ONLY" or rem.get("required_gate") not in ("HUMAN_APPROVAL", "LEGAL_REVIEW"):
            issues.append(Issue("error", "REMEDIATION_GATE",
                                "REMEDIATION_PROPOSED exige mode=PROPOSE_ONLY "
                                "et gate HUMAN_APPROVAL/LEGAL_REVIEW", "finding.remediation"))

    # P4_CONTEXTUAL : ni preuve technique directe, ni log direct.
    evidence = finding.get("evidence")
    if severity == "P4_CONTEXTUAL" and isinstance(evidence, list):
        if any(isinstance(e, dict) and e.get("type") in ("file", "config", "absence", "log")
               for e in evidence):
            issues.append(Issue("error", "P4_WITH_PROOF",
                                "P4_CONTEXTUAL avec preuve directe", "finding.severity"))

    # --- Preuves ---
    if isinstance(evidence, list):
        if not evidence:
            issues.append(Issue("error", "EMPTY_EVIDENCE", "evidence vide", "finding.evidence"))
        for i, e in enumerate(evidence):
            _validate_evidence_item(e, i, issues)

    # --- CONFIRMED exige une preuve FORTE (tout niveau) ---
    if status == "CONFIRMED":
        if not isinstance(evidence, list) or not evidence:
            issues.append(Issue("error", "CONFIRMED_NO_EVIDENCE",
                                "CONFIRMED sans evidence", "finding.evidence"))
        else:
            has_strong = any(
                isinstance(e, dict) and e.get("type") in _STRONG_EVIDENCE_TYPES
                and isinstance(e.get("path"), str) and e.get("path").strip() not in ("", ".", "decorative")
                for e in evidence
            )
            if not has_strong:
                issues.append(Issue("error", "WEAK_EVIDENCE",
                                    "CONFIRMED sans preuve forte exploitable",
                                    "finding.evidence"))
            # J4-008 : un P0/P1 CONFIRMED ne peut reposer QUE sur une absence
            # (l'absence prouve un manque, pas une compromission active).
            if severity in ("P0_CRITICAL", "P1_HIGH"):
                has_active = any(
                    isinstance(e, dict) and e.get("type") in ("file", "config")
                    for e in evidence
                )
                if not has_active:
                    issues.append(Issue("error", "WEAK_EVIDENCE",
                                        f"{severity} CONFIRMED sans preuve active "
                                        "(file/config), absence seule insuffisante",
                                        "finding.evidence"))
            # HIGH exige une preuve forte ; une observation seule ne suffit pas.
            if confidence == "HIGH" and not has_strong:
                issues.append(Issue("error", "CONFIDENCE_MISMATCH",
                                    "confidence HIGH sans preuve forte", "finding.confidence"))
            # CONFIRMED avec confidence faible = incoherence (surtout P0).
            if confidence in ("LOW", "UNKNOWN"):
                issues.append(Issue("error", "CONFIDENCE_MISMATCH",
                                    f"CONFIRMED {severity} avec confidence {confidence}",
                                    "finding.confidence"))
    else:
        # Hors CONFIRMED, HIGH exige quand meme une preuve forte (pas de credit gratuit).
        if confidence == "HIGH":
            has_strong = isinstance(evidence, list) and any(
                isinstance(e, dict) and e.get("type") in _STRONG_EVIDENCE_TYPES
                for e in evidence
            )
            if not has_strong:
                issues.append(Issue("error", "CONFIDENCE_MISMATCH",
                                    "confidence HIGH sans preuve forte", "finding.confidence"))

    # --- Trois axes juridiques : si l'un est present, tous requis ---
    three_axes = ("observation_status", "legal_basis_status", "decision")
    present_axes = [a for a in three_axes if a in finding]
    if present_axes and len(present_axes) != 3:
        issues.append(Issue("error", "AXES_INCOMPLETE",
                            "trois axes juridiques incomplets (observation/legal/decision)",
                            "finding"))
    lbs = finding.get("legal_basis_status")
    dec = finding.get("decision")
    if lbs in ("UNVERIFIED_CURRENT", "STALE", "REPEALED", "NOT_LEGAL") and dec == "CONFIRMED":
        issues.append(Issue("error", "AXES_CONTRADICTION",
                            f"decision CONFIRMED avec legal_basis_status={lbs}",
                            "finding.decision"))

    # --- Coherence status <-> decision <-> observation_status ---
    obs = finding.get("observation_status")
    if dec is not None and status is not None:
        # decision CONFIRMED exige status CONFIRMED (pas de raccourci).
        if dec == "CONFIRMED" and status != "CONFIRMED":
            issues.append(Issue("error", "STATE_INCOHERENT",
                                f"decision CONFIRMED avec status {status}",
                                "finding.decision"))
        # status CONFIRMED exige une decision coherente si elle existe.
        if status == "CONFIRMED" and dec in ("BLOCKED", "NOT_APPLICABLE",
                                             "SUSPECTED", "HUMAN_REVIEW_REQUIRED"):
            issues.append(Issue("error", "STATE_INCOHERENT",
                                f"status CONFIRMED avec decision {dec}",
                                "finding.decision"))
    if status == "CONFIRMED" and obs is not None and obs != "CONFIRMED":
        issues.append(Issue("error", "STATE_INCOHERENT",
                            f"status CONFIRMED avec observation_status {obs}",
                            "finding.observation_status"))
    if status == "CONFIRMED" and lbs == "NOT_LEGAL":
        issues.append(Issue("error", "STATE_INCOHERENT",
                            "status CONFIRMED avec legal_basis_status NOT_LEGAL",
                            "finding.legal_basis_status"))
    # CONFLICTING_SOURCES : sources en desaccord -> jamais CONFIRMED, toujours
    # HUMAN_REVIEW_REQUIRED (J4-006).
    if lbs == "CONFLICTING_SOURCES":
        if status == "CONFIRMED" or dec == "CONFIRMED":
            issues.append(Issue("error", "STATE_INCOHERENT",
                                "CONFLICTING_SOURCES avec CONFIRMED",
                                "finding.legal_basis_status"))
        if dec is not None and dec != "HUMAN_REVIEW_REQUIRED":
            issues.append(Issue("error", "STATE_INCOHERENT",
                                "CONFLICTING_SOURCES exige decision HUMAN_REVIEW_REQUIRED",
                                "finding.decision"))

    # --- Juridique ---
    # Le DOMAINE decide, jamais l'appelant : legal=False ne desactive rien
    # si le domaine est juridique (pas de bypass par parametre).
    is_legal = _is_legal_domain(domain) or legal is True
    if is_legal:
        for ax in three_axes:
            if ax not in finding:
                issues.append(Issue("error", "AXES_INCOMPLETE",
                                    f"finding juridique sans {ax}", f"finding.{ax}"))
        if "legal_basis" not in finding:
            issues.append(Issue("error", "LEGAL_BASIS",
                                "finding juridique sans legal_basis", "finding"))
        else:
            _validate_legal_basis(finding["legal_basis"], status, today, issues,
                                  decision=dec, legal_basis_status=lbs)
        if status == "CONFIRMED" and confidence in ("LOW", "UNKNOWN"):
            issues.append(Issue("error", "LEGAL_LOW_CONFIDENCE",
                                "finding juridique CONFIRMED avec confidence LOW/UNKNOWN",
                                "finding.confidence"))

    # --- Secrets : politique GLOBALE recursive (R5-004). TOUTES les chaines
    # utilisateur du finding sont scannees, avec une liste tres limitee de
    # champs techniques exclus. Deterministe, sans pretendre tout reconnaitre.
    _scan_secrets_globally(finding, issues)

    return _sorted(issues)


# R6-002 : liste d'exclusion TRES LIMITEE et DOCUMENTEE. Chaque cle exclue l'est
# parce qu'un autre controle la valide de maniere exhaustive (enum ferme, date
# ISO, entier). `status_reason` et les champs `legal_basis` (authority,
# jurisdiction, source_url) ont ete RETIRES de cette liste : ce sont des chaines
# libres ou semi-libres, et un secret y passait sans detection.
_SECRET_SCAN_SKIP_KEYS = {
    # enums fermes, valides par le schema (aucune chaine libre possible)
    "status", "severity", "confidence", "type", "mode",
    "required_gate", "observation_status", "legal_basis_status", "decision",
    "done", "validation_level", "execution_mode", "human_approval",
    # dates ISO et entiers, valides par des controles dedies
    "verified_on", "checked_at", "freshness_window_days", "line",
}


def _secret_scan_value_is_exempt(key, value) -> bool:
    """Exempte seulement une valeur technique DEJA fermee par son contrat.

    Le nom de cle seul ne suffit jamais. Ainsi, une valeur hostile placee dans
    ``status`` ou ``validation_level`` reste scannee si elle n'appartient pas
    a l'enum attendu. Cette verification rend la liste d'exclusion utilisable
    dans plusieurs contextes sans creer de passe-droit par nom de champ.
    """
    enums = {
        "status": FINDING_STATES | LEGAL_RULE_STATUSES,
        "severity": SEVERITIES,
        "confidence": CONFIDENCES,
        "type": EVIDENCE_TYPES,
        "mode": REMEDIATION_MODES,
        "required_gate": GATES,
        "observation_status": FINDING_STATES,
        "legal_basis_status": LEGAL_BASIS_STATUSES,
        "decision": DECISIONS,
        "validation_level": VALIDATION_LEVELS,
        "execution_mode": {"read_only"},
        "human_approval": {
            "not_required_for_audit", "required_before_apply",
        },
    }
    if key in enums:
        return isinstance(value, str) and value in enums[key]
    if key == "done":
        return isinstance(value, bool)
    if key in {"verified_on", "checked_at"}:
        return isinstance(value, str) and _parse_iso_date(value) is not None
    if key in {"freshness_window_days", "line"}:
        return isinstance(value, int) and not isinstance(value, bool)
    return False


def _scan_secrets_globally(payload, issues: list[Issue],
                           root_path: str = "finding") -> None:
    """R5-004 / R6-002 : traversee recursive de toutes les chaines utilisateur.

    Le meme mecanisme couvre findings, rapports, manifestes, frontmatter,
    contenu SKILL.md et regles. Les seules exclusions sont des enums fermes
    ou des valeurs techniques validees exhaustivement ailleurs.

    Seule exclusion : _SECRET_SCAN_SKIP_KEYS (enums fermes, dates ISO, entiers),
    dont la validite est deja garantie exhaustivement ailleurs.

    Politique de PREVENTION deterministe, pas une detection universelle de tous
    les secrets possibles : signale les identifiants continus plausibles non
    masques, avec exceptions sur format entier (canari exact, UUID, hash
    labellise, cle publique SSH, nom de fichier)."""
    stack = [(payload, root_path)]
    seen_containers: set[int] = set()
    while stack:
        value, field_path = stack.pop()
        if isinstance(value, str):
            if _secret_violation(value) is not None:
                issues.append(Issue(
                    "error", "SECRET_UNMASKED",
                    f"secret probable non masque dans {field_path}",
                    field_path))
        elif isinstance(value, dict):
            container_id = id(value)
            if container_id in seen_containers:
                continue
            seen_containers.add(container_id)
            items = sorted(value.items(), key=lambda item: str(item[0]))
            for key, child in reversed(items):
                if key in _SECRET_SCAN_SKIP_KEYS and (
                        _secret_scan_value_is_exempt(key, child)):
                    continue
                stack.append((child, f"{field_path}.{key}"))
        elif isinstance(value, list):
            container_id = id(value)
            if container_id in seen_containers:
                continue
            seen_containers.add(container_id)
            for index in range(len(value) - 1, -1, -1):
                stack.append((value[index], f"{field_path}[{index}]"))


def _validate_legal_basis(lb, status, today, issues: list[Issue],
                          decision=None, legal_basis_status=None) -> None:
    """legal_basis complet : source officielle, autorite, dates, live_check integral.

    `legal_basis_status` impose la coherence : VERIFIED_CURRENT exige un
    live_check done=true et result=en_vigueur (sinon le statut ment)."""
    path = "finding.legal_basis"
    if not isinstance(lb, dict):
        issues.append(Issue("error", "LEGAL_BASIS", "legal_basis non-objet", path))
        return

    # Autorite + jurisdiction : listes blanches (pas de valeur fictive).
    authority = lb.get("authority")
    if not isinstance(authority, str) or not authority.strip():
        issues.append(Issue("error", "LEGAL_AUTHORITY",
                            "legal_basis sans authority", path))
    elif (_has_invisible_or_mixed(authority)
          or _norm_dedup_key(authority) not in
          {_norm_dedup_key(a) for a in LEGAL_AUTHORITIES}):
        issues.append(Issue("error", "LEGAL_AUTHORITY",
                            f"authority non reconnue: {authority!r}", path))
    jurisdiction = lb.get("jurisdiction")
    if not isinstance(jurisdiction, str) or not _norm_unicode(jurisdiction):
        issues.append(Issue("error", "LEGAL_JURISDICTION",
                            "legal_basis sans jurisdiction lisible", path))
    elif _has_invisible_or_mixed(jurisdiction):
        issues.append(Issue("error", "LEGAL_JURISDICTION",
                            "jurisdiction avec caractere invisible", path))
    else:
        if _norm_unicode(jurisdiction).upper() not in {
                _norm_unicode(j).upper() for j in LEGAL_JURISDICTIONS}:
            issues.append(Issue("error", "LEGAL_JURISDICTION",
                                f"jurisdiction non reconnue: {jurisdiction!r}", path))

    url = lb.get("source_url")
    if isinstance(url, str):
        host = _url_host(url)
        if not _host_allowed(host, OFFICIAL_LEGAL_HOSTS):
            issues.append(Issue("error", "LEGAL_SOURCE", f"source non officielle: {url!r}", path))
        # HTTPS exige, pas de userinfo, pas de port non standard.
        if not url.lower().startswith("https://"):
            issues.append(Issue("error", "LEGAL_SOURCE", "source non HTTPS", path))
        if "@" in url.split("//", 1)[-1].split("/", 1)[0]:
            issues.append(Issue("error", "LEGAL_SOURCE", "source avec userinfo", path))
        hostport = url.split("//", 1)[-1].split("/", 1)[0]
        if ":" in hostport:
            port = hostport.rsplit(":", 1)[-1]
            if port not in ("443",):
                issues.append(Issue("error", "LEGAL_SOURCE", f"port non standard: {port}", path))

    for field in ("source_url", "verified_on", "jurisdiction", "rule_id"):
        v = lb.get(field)
        if v is not None and not isinstance(v, str):
            issues.append(Issue("error", "LEGAL_TYPE", f"{field} attendu string", path))
    fwd = lb.get("freshness_window_days")
    if fwd is not None and (not isinstance(fwd, int) or isinstance(fwd, bool)):
        issues.append(Issue("error", "LEGAL_TYPE",
                            "freshness_window_days attendu integer", path))
        fwd = None

    von = lb.get("verified_on")
    if isinstance(von, str):
        von_parsed = _parse_iso_date(von)
        if von_parsed is None:
            issues.append(Issue("error", "LEGAL_DATE", f"verified_on invalide: {von!r}", path))
        elif von_parsed > today:
            # R6-001 : date future rejetee meme sans freshness_window_days.
            issues.append(Issue("error", "LEGAL_DATE", f"verified_on futur: {von!r}", path))
        elif isinstance(fwd, int) and _legal_freshness_verdict(von, fwd, today) == "stale":
            issues.append(Issue("error", "LEGAL_STALE", f"legal_basis perime (verified_on={von})", path))

    live = lb.get("live_check")
    if isinstance(live, dict) and live.get("done") is True:
        method = live.get("method")
        if not isinstance(method, str) or not method.strip():
            issues.append(Issue("error", "LIVE_CHECK", "live_check sans method", path))
        elif method not in LIVE_CHECK_METHODS:
            issues.append(Issue("error", "LIVE_CHECK",
                                f"live_check method non reconnue: {method!r}", path))
        checked = live.get("checked_at")
        checked_date = _parse_iso_date(checked) if isinstance(checked, str) else None
        if checked_date is None:
            issues.append(Issue("error", "LIVE_CHECK", f"live_check checked_at invalide: {checked!r}", path))
        else:
            # R6-001 : `today` garanti valide -> controle toujours actif.
            if checked_date > today:
                issues.append(Issue("error", "LIVE_CHECK", f"live_check checked_at futur: {checked!r}", path))
            # checked_at ne peut preceder verified_on (incoherent).
            von_date = _parse_iso_date(von) if isinstance(von, str) else None
            if von_date is not None and checked_date < von_date:
                issues.append(Issue("error", "LIVE_CHECK",
                                    "live_check checked_at avant verified_on", path))
            # Un live_check trop ancien ne prouve rien de recent.
            if isinstance(fwd, int) and (today - checked_date).days > fwd:
                issues.append(Issue("error", "LIVE_CHECK",
                                    "live_check checked_at trop ancien (perime)", path))
        if live.get("result") not in LIVE_CHECK_RESULTS:
            issues.append(Issue("error", "LIVE_CHECK",
                                f"live_check result non normalise: {live.get('result')!r}", path))
    if status == "CONFIRMED" or decision == "CONFIRMED":
        done = isinstance(live, dict) and live.get("done") is True
        if not done:
            issues.append(Issue("error", "LEGAL_NO_LIVE_CHECK",
                                "conclusion juridique CONFIRMED sans live_check", path))
        elif isinstance(live, dict) and live.get("result") != "en_vigueur":
            issues.append(Issue("error", "LEGAL_NO_LIVE_CHECK",
                                f"CONFIRMED avec live_check result={live.get('result')!r}", path))

    # J4-006 : VERIFIED_CURRENT exige un live_check done=true et result
    # en_vigueur. Sinon le statut legal_basis_status ment (dit "verifie" sans
    # verification effective).
    if legal_basis_status == "VERIFIED_CURRENT":
        done = isinstance(live, dict) and live.get("done") is True
        if not done:
            issues.append(Issue("error", "LEGAL_BASIS_STATUS",
                                "VERIFIED_CURRENT sans live_check effectif", path))
        elif isinstance(live, dict) and live.get("result") != "en_vigueur":
            issues.append(Issue("error", "LEGAL_BASIS_STATUS",
                                f"VERIFIED_CURRENT avec live_check result={live.get('result')!r}",
                                path))

    # R5-005 : relation juridiction -> authority -> host.
    _legal_coherence_issue(lb.get("jurisdiction"), lb.get("authority"),
                           lb.get("source_url"), path, issues)


# Seuil a partir duquel un identifiant continu est suspect (couvre les secrets
# de 19-20 chars signales par le jury).
_SECRET_MIN_LEN = 16

# R6-002 - EXCEPTIONS SUR FORMAT ENTIER, JAMAIS SUR SOUS-CHAINE.
#
# L'ancienne politique tolerait tout token CONTENANT "TEST" (ou EXAMPLE, FAKE...)
# et tout extrait CONTENANT un nom de fichier. Deux contournements triviaux :
#   "TEST<identifiant-long>"     -> passait grace a la sous-chaine TEST
#   "<credential-long> app.py"   -> passait grace au suffixe .py
# Desormais chaque exception exige une correspondance de FORMAT COMPLET.

# Canari : la valeur EXACTE du contrat de preuve. Rien d'autre.
_CANARY_EXACT = "TEST-CANARY-NOT-A-REAL-KEY-0000"
# UUID : format entier (fullmatch), pas une sous-chaine noyee dans un secret.
_UUID_RE = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                      re.IGNORECASE)
# Label de hash : doit accompagner un hash de longueur exacte.
_HASH_LABEL_RE = re.compile(r"sha|md5|hash|commit|checksum|digest|fingerprint|empreinte",
                            re.IGNORECASE)
_HASH_EXACT_RE = re.compile(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", re.IGNORECASE)


# Reference symbolique officielle d'un schema core (syntaxe de output_schema).
_SYMBOLIC_REF_FIND_RE = re.compile(r"core:[A-Za-z0-9_]+\.json\b")

_WEAK_SEP_RE = re.compile(r"[\s.,;:!?()\[\]{}'\"/\\]+")
_FILENAME_FIND_RE = re.compile(
    r"[A-Za-z0-9_-]+\.(?:py|js|ts|md|json|toml|yaml|yml|txt|sql|html|css|cfg|ini|env|sh|lock|xml|csv|pdf|log)\b",
    re.IGNORECASE)
_SAFE_TECHNICAL_TOKENS = (
    FINDING_STATES
    | SEVERITIES
    | CONFIDENCES
    | EVIDENCE_TYPES
    | IMPACT_LEVELS
    | REMEDIATION_MODES
    | GATES
    | LEGAL_BASIS_STATUSES
    | DECISIONS
    | PROFILE_FACT_STATES
    | VALIDATION_LEVELS
    # Vocabulaires fermes du contrat, definis dans le code et non extensibles
    # par un package : un SKILL.md doit pouvoir nommer les capacites qu'il
    # exige, alors que la section « Capacites necessaires » est obligatoire.
    # La comparaison porte sur le TOKEN ENTIER : aucun secret reel ne peut
    # etre egal a `filesystem_search`.
    | set(CLIENT_CAPABILITIES)
    | set(SKILL_PROVIDED_CAPABILITIES)
    | {
        "PROJECT_PROFILE_SCHEMA",
        "SKILLS_QA_SCHEMA",
        "has_authentication",
        "has_file_upload",
        "has_skill_packages",
    }
    # Vocabulaire FERME du plan B3 (enums de PLAN_B3_SCHEMA.json). Sans ces
    # tokens, un code de raison legitime depasse le seuil de secret et le plan
    # rendu au client contient `<contenu-sensible-masque>` a la place de la
    # valeur : le plan echoue alors son propre validateur (ENUM).
    | {
        "ACTIVATION_FACT_MISMATCH",
        "CLIENT_CAPABILITIES_UNDECLARED",
        "FORBIDDEN_CLIENT_CAPABILITY_PRESENT",
        "NO_COMPATIBLE_SKILL",
        "NO_EXECUTABLE_SKILL",
        "NO_INSTALLED_SKILL_FOR_CAPABILITY",
        "OPTIONAL_CAPABILITY_UNAVAILABLE",
        "OPTIONAL_CLIENT_CAPABILITY_MISSING",
        "PROJECT_TYPE_MATCH",
        "PROJECT_TYPE_MISMATCH",
        "READ_AND_EXECUTE_SKILL",
        "REQUIRED_CLIENT_CAPABILITIES_AVAILABLE",
        "REQUIRED_CLIENT_CAPABILITY_MISSING",
    }
)


def _is_prose_fragment(frag: str) -> bool:
    """R6-002 : un fragment de PROSE (mot en lettres minuscules) n'est jamais
    recolle a ses voisins pour reconstituer un pseudo-secret.

    Sans cette regle, la defragmentation transforme du texte naturel en
    identifiant continu : "fichier illisible" -> "fichierillisible" (16
    caracteres) serait signale comme secret. Un vrai secret fragmente comporte
    des majuscules, des chiffres ou des caracteres base64.

    LIMITE ASSUMEE ET DOCUMENTEE : un secret compose exclusivement de lettres
    minuscules n'est pas reconstitue par defragmentation. C'est le prix d'une
    politique deterministe sans faux positifs sur le texte redactionnel.
    """
    return (
        frag.isalpha() and (frag.islower() or frag.istitle())
    ) or bool(re.fullmatch(r"[a-z]{4,}(?:[_-][a-z]{4,})+", frag))


def _fused_runs(text: str) -> list[str]:
    """Recolle les suites de fragments TECHNIQUES separes par de la ponctuation
    faible. Les mots de prose coupent la sequence."""
    runs: list[str] = []
    current: list[str] = []
    for frag in _WEAK_SEP_RE.split(text):
        if not frag:
            continue
        if _is_prose_fragment(frag):
            if current:
                runs.append("".join(current))
                current = []
        else:
            current.append(frag)
    if current:
        runs.append("".join(current))
    return runs


def _secret_probe(token: str) -> str:
    """Isole la VALEUR d'un token colle a son etiquette ("id=550e...", "key=x").

    Les exceptions de R6-002 portent sur un format ENTIER : il faut donc
    comparer la valeur seule, pas la valeur prefixee de son libelle. Le padding
    base64 ('=' final) n'est jamais en tete, `lstrip` est donc sans risque.
    """
    probe = token.lstrip("=")
    head, sep, tail = probe.partition("=")
    if sep and tail and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_-]*", head):
        return tail
    return probe


def _secret_violation(excerpt) -> str | None:
    """Rend le motif d'un secret non masque.

    Ce controle est une politique de prevention structurelle, PAS une detection
    universelle de tous les secrets possibles : il signale les identifiants
    continus plausibles non masques, avec des exceptions sur FORMAT ENTIER.

    Detection : identifiants continus >= _SECRET_MIN_LEN, y compris FRAGMENTES
    (espaces, ponctuation faible, slashs et backslashes). Les fragments de prose
    minuscules interrompent la fusion. Un chemin normal reste donc lisible,
    tandis qu'un identifiant technique fragmente reste controle.

    Masquage valide : >= 4 etoiles consecutives, et le core restant (sans *)
    doit etre < _SECRET_MIN_LEN (le secret est reellement detruit).

    Exceptions R6-002 (format complet exige, jamais une sous-chaine) :
      - canari : la valeur EXACTE `TEST-CANARY-NOT-A-REAL-KEY-0000` ; un token
        contenant simplement "TEST" est un secret comme un autre ;
      - UUID : le token entier est un UUID (fullmatch) ;
      - cle publique SSH : l'extrait entier est une ligne de cle publique ;
      - hash hex : longueur exacte 32/40/64 AVEC label de hash dans l'extrait ;
      - nom de fichier : le token ENTIER est un nom de fichier (un secret suivi
        de `app.py` dans le meme extrait reste signale).
    Choix strict : un JWT (eyJ...) est un credential -> toujours masque.
    """
    if not isinstance(excerpt, str):
        return None
    # Ligne de cle publique SSH complete : publique par nature, format entier.
    stripped = excerpt.strip()
    if re.fullmatch(r"(ssh-rsa|ssh-ed25519|ecdsa-sha2-\S+)\s+[A-Za-z0-9+/=]+(\s+\S+)?",
                    stripped):
        return None
    # Noms de fichiers presents dans l'extrait, sous leur forme defragmentee :
    # sert l'exception "le TOKEN ENTIER est un nom de fichier".
    filenames = {m.group(0) for m in _FILENAME_FIND_RE.finditer(excerpt)}
    filenames_fused = {f.replace(".", "") for f in filenames}
    # Reference symbolique du produit (`core:NOM_SCHEMA.json`) : c'est la
    # syntaxe imposee par output_schema, donc elle apparait legitimement dans
    # tout SKILL.md. Fusionnee, elle depasse le seuil de secret : sans cette
    # exception, aucun skill ne peut documenter sa propre sortie.
    for match in _SYMBOLIC_REF_FIND_RE.finditer(excerpt):
        filenames_fused.add(_WEAK_SEP_RE.sub("", match.group(0)))

    for run in _fused_runs(excerpt):
        for token in re.findall(r"[A-Za-z0-9+/=_*-]{%d,}" % _SECRET_MIN_LEN, run):
            core = token.replace("*", "")
            if "****" in token:
                if len(core) < _SECRET_MIN_LEN:
                    continue  # masquage reel (secret detruit)
                # 4 etoiles mais core trop long = masquage insuffisant.
                return "masquage insuffisant (core restant trop long)"
            if len(core) < _SECRET_MIN_LEN:
                continue  # core trop court pour etre un secret exploitable
            probe = _secret_probe(token)
            if probe in _SAFE_TECHNICAL_TOKENS:
                continue
            if probe == _CANARY_EXACT:
                continue  # canari documente : correspondance EXACTE uniquement
            if _UUID_RE.fullmatch(probe):
                continue  # la valeur ENTIERE est un UUID (identifiant, pas secret)
            if _HASH_EXACT_RE.fullmatch(probe) and _HASH_LABEL_RE.search(excerpt):
                continue  # hash hex de longueur exacte avec label explicite
            if re.fullmatch(r"[a-z]{4,}(?:[_-][a-z]{4,}){2,}", probe):
                # Identifiant redactionnel snake_case/kebab-case entier.
                # Aucun chiffre, aucun segment court, au moins trois mots :
                # un jeton de fournisseur et les tokens techniques restent controles.
                continue
            if _READABLE_IDENTIFIER_RE.fullmatch(probe):
                # Variante chiffree : un nom de version ou de norme
                # (`pci_dss_4_0_compliance`) reste lisible parce que ses
                # segments sont COURTS et SEPARES. Un secret, lui, contient un
                # bloc continu long : `zzqaiosfodnn7example` est refuse ici,
                # alors qu'une liste blanche par champ l'aurait laisse passer.
                continue
            if probe in filenames or probe in filenames_fused:
                continue  # la valeur EST un nom de fichier (pas: suivi d'un fichier)
            return "secret probable non masque (ou masquage insuffisant)"
    return None


def redact_sensitive_text(value) -> str:
    """Masque integralement une chaine reconnue sensible.

    Le masquage est central. Les erreurs secondaires, chemins, exceptions,
    sorties CLI et profils du detecteur peuvent donc reutiliser la meme
    politique que le rejet des rapports.
    """
    text = value if isinstance(value, str) else str(value)
    if _secret_violation(text) is not None:
        return "<contenu-sensible-masque>"
    return text


def _check_secret_masking(excerpt, idx: int, issues: list[Issue]) -> None:
    """Compatibilite : transforme la detection pure en Issue."""
    violation = _secret_violation(excerpt)
    if violation is not None:
        issues.append(Issue(
            "error", "SECRET_UNMASKED", violation,
            f"finding.evidence[{idx}]"))


# ---------------------------------------------------------------------------
# Validation d'un rapport complet
# ---------------------------------------------------------------------------

def validate_report(report, finding_schema: dict | None = None,
                    today: datetime.date | None = None,
                    known_rules: dict[str, str] | None = None,
                    report_schema: dict | None = None) -> list[Issue]:
    """Valide un rapport V1 complet.

    R6-001 + R6-004 : toutes les omissions sont syntaxiquement acceptees,
    puis transformees en issues deterministes. Les schemas absents sont charges
    depuis ``core/``. Un schema fourni doit etre strictement officiel.

    R6-001 : `today` doit etre un `datetime.date` (TODAY_REQUIRED si absent,
    TODAY_INVALID si mal type). R6-004 : `known_rules` doit etre un registre
    structurellement valide (RULES_REGISTRY).
    """
    issues: list[Issue] = []
    contract: list[Issue] = []
    t_issue = _today_issue(today, "report")
    if t_issue is not None:
        contract.append(t_issue)
    normalized_rules, rule_issues = _normalize_known_rules(known_rules, "report")
    contract.extend(rule_issues)
    resolved_finding_schema = _resolve_official_schema(
        finding_schema, "FINDING_SCHEMA.json", contract, "finding_schema")
    resolved_report_schema = _resolve_official_schema(
        report_schema, "REPORT_SCHEMA.json", contract, "report_schema")
    if contract:
        return _sorted(contract)
    if not isinstance(report, dict):
        return [Issue("error", "REPORT", "rapport non-objet")]
    payload_issues = _payload_guard(report, "report")
    if payload_issues:
        return _sorted(payload_issues)

    _validate(report, resolved_report_schema, issues, "report")
    _scan_secrets_globally(
        {k: v for k, v in report.items() if k != "findings"},
        issues, "report")

    # Version contrôlee (type inclus : un entier n'est pas une version).
    ver = report.get("version")
    if ver is not None and (not isinstance(ver, str) or ver not in REPORT_VERSIONS):
        issues.append(Issue("error", "REPORT_VERSION",
                            f"version de rapport non supportee: {ver!r}", "report.version"))

    findings = report.get("findings")
    if not isinstance(findings, list):
        issues.append(Issue("error", "TYPE", "report.findings attendu array", "report.findings"))
        return _sorted(issues)
    if not findings:
        issues.append(Issue("error", "EMPTY_REPORT",
                            "rapport sans aucun finding (silence != absence de risque)",
                            "report.findings"))

    seen_ids: set[str] = set()
    seen_norm: set[str] = set()
    for i, f in enumerate(findings):
        if not isinstance(f, dict):
            issues.append(Issue("error", "FINDING",
                                "finding non-objet dans le rapport", f"report.findings[{i}]"))
            continue
        sub = validate_finding(
            f, resolved_finding_schema, today=today,
            known_rules=normalized_rules)
        for issue in sub:
            issue.path = f"report.findings[{i}].{issue.path}" if issue.path else f"report.findings[{i}]"
            issues.append(issue)
        fid = f.get("finding_id")
        if isinstance(fid, str):
            if fid in seen_ids:
                issues.append(Issue("error", "DUP_FINDING",
                                    f"finding_id duplique: {fid}", f"report.findings[{i}]"))
            norm = _norm_dedup_key(fid)
            if norm in seen_norm:
                issues.append(Issue("error", "DUP_FINDING",
                                    f"finding_id duplique (normalise): {fid}", f"report.findings[{i}]"))
            seen_ids.add(fid)
            seen_norm.add(norm)
        if f.get("skill_id") != report.get("skill_id"):
            issues.append(Issue("error", "REPORT_SKILL_MISMATCH",
                                "finding.skill_id != report.skill_id", f"report.findings[{i}]"))
        lb = f.get("legal_basis")
        if isinstance(lb, dict):
            lrid = lb.get("rule_id")
            if isinstance(lrid, str) and lrid != f.get("rule_id"):
                issues.append(Issue("error", "RULE_ID_MISMATCH",
                                    f"finding.rule_id={f.get('rule_id')!r} != "
                                    f"legal_basis.rule_id={lrid!r}",
                                    f"report.findings[{i}]"))
    return _sorted(issues)


# ---------------------------------------------------------------------------
# CLI (fail-closed : toute erreur de chargement = exit 1)
# ---------------------------------------------------------------------------

def _main(argv: list[str]) -> int:
    import argparse
    import sys

    class SafeArgumentParser(argparse.ArgumentParser):
        def error(self, message):
            self.print_usage(sys.stderr)
            self.exit(2, "validator.py: arguments invalides\n")

    parser = SafeArgumentParser(prog="validator.py")
    parser.add_argument("target", help="dossier de skill OU fichier de rapport JSON")
    parser.add_argument("core_dir", nargs="?", default=os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "core"))
    parser.add_argument("--mode", default=None,
                        help="force le mode ; sinon deduit du type de cible")
    parser.add_argument("--today", required=True,
                        help="date ISO YYYY-MM-DD injectee (obligatoire, deterministe)")
    parser.add_argument("--registry", default=_DEFAULT_REGISTRY_DIR,
        help="registre officiel local (un autre chemin est refuse)")
    args = parser.parse_args(argv[1:])

    today = _parse_iso_date(args.today)
    if today is None:
        sys.stderr.write("--today invalide\n")
        return 2

    mode = args.mode
    if mode is not None and mode not in ("skill", "report"):
        sys.stderr.write("--mode invalide\n")
        return 2
    if mode is None:
        mode = "report" if os.path.isfile(args.target) else "skill"

    if mode == "skill":
        issues = validate_skill(args.target, args.core_dir, today=today,
                                registry_dir=args.registry)
    else:
        issues = []
        schema = _load_official_schema(
            args.core_dir, "FINDING_SCHEMA.json", issues)
        report_schema = _load_official_schema(
            args.core_dir, "REPORT_SCHEMA.json", issues)
        known_rules = _load_known_rules(args.registry, issues)
        report = _load_json(args.target, issues, "rapport")
        # Fail-closed : si un schema, le registre ou le rapport est absent/
        # invalide, on NE valide PAS (les erreurs de chargement suffisent).
        load_failed = bool(issues)
        if not load_failed:
            if not isinstance(report, dict):
                # Un rapport JSON valide mais non-objet (liste, scalaire, null)
                # est refuse, jamais accepte silencieusement.
                issues.append(Issue("error", "REPORT",
                                    "rapport non-objet (liste/scalaire/null)", "report"))
            else:
                issues = validate_report(report, schema, today=today,
                                         known_rules=known_rules,
                                         report_schema=report_schema)

    for issue in issues:
        print(repr(issue))
    errors = sum(1 for i in issues if i.level == "error")
    warnings = sum(1 for i in issues if i.level == "warning")
    print(f"{errors} erreur(s), {warnings} avertissement(s)")
    return 1 if errors else 0


if __name__ == "__main__":
    import sys
    raise SystemExit(_main(sys.argv))
