"""phases-agents : serveur MCP local de selection deterministe de skills.

Le paquet expose les modules historiques sous un espace de noms unique. Ils
etaient auparavant installes a plat dans site-packages, ou des noms aussi
generiques que ``server``, ``registry`` ou ``validator`` entraient en
collision avec n'importe quel autre paquet du meme environnement.

Point d'entree console : ``phases-agents`` -> ``phases_agents.server:main``.
"""

from __future__ import annotations

__all__ = ["__version__"]

__version__ = "0.5.0"
