"""Compila regras de rede verificáveis para o complemento Qproxy.

Regras ABP que exigem scriptlets, inspeção TLS, cosméticos e recursos de
imagem/vídeo são ignoradas. O escopo é a página do YouTube, e a decisão
é aplicada no navegador por declarativeNetRequest.
"""
from __future__ import annotations

import json
from pathlib import Path

SAFE_RESOURCES = ("script", "xmlhttprequest", "sub_frame", "ping")
RESOURCE_MAPPING = {
    "script": "script",
    "xmlhttprequest": "xmlhttprequest",
    "subdocument": "sub_frame",
    "ping": "ping",
}
PROTECTED_DOMAINS = (
    "youtube.com",
    "youtu.be",
    "ytimg.com",
    "googlevideo.com",
    "youtubei.googleapis.com",
    "youtube.googleapis.com",
    "youtube-nocookie.com",
)
# First-party advertising endpoints, not the player/video delivery endpoints.
SAFE_FIRST_PARTY_PATHS = ("/pagead/", "/api/stats/ads")
LIMIT = 800


def _valid_host(value: str) -> bool:
    parts = value.split(".")
    return (
        2 <= len(parts) <= 30
        and len(value) <= 253
        and all(
            label and len(label) <= 63 and not label.startswith("-")
            and not label.endswith("-")
            and all(c.isascii() and (c.isalnum() or c == "-") for c in label)
            for label in parts
        )
    )


def _protected(host: str) -> bool:
    return any(host == item or host.endswith("." + item) for item in PROTECTED_DOMAINS)


def _parse_rule(raw: str) -> tuple[dict, bool, bool] | None:
    """Return DNR condition, allow-rule flag and YouTube-specific priority."""
    raw = raw.strip()
    if not raw or raw.startswith(("!", "#", "[")) or "##" in raw or "#@#" in raw:
        return None
    is_exception = raw.startswith("@@")
    if is_exception:
        raw = raw[2:]
    if not raw.startswith("||"):
        return None

    pattern, separator, options_text = raw.partition("$")
    # '|' em $domain=youtube.com|music.youtube.com é legítimo.
    # Conferir metacaracteres somente no padrão da URL, não nas opções.
    if "*" in pattern or "?" in pattern or "|" in pattern[2:]:
        return None
    # Hosts with cosmetic/resource constraints must not be broadened.
    options = [p.strip().lower() for p in options_text.split(",")] if separator else []
    if any(not option for option in options):
        return None

    targeted = False
    domain_type = None
    resource_types: list[str] = []
    for option in options:
        if option.startswith("domain="):
            values = option[7:].split("|")
            allowed_scopes = {"youtube.com", "www.youtube.com", "m.youtube.com", "music.youtube.com"}
            if not any(v in allowed_scopes for v in values) or any(
                v and not v.startswith("~") and v not in allowed_scopes for v in values
            ):
                return None
            targeted = True
        elif option == "third-party":
            domain_type = "thirdParty"
        elif option == "~third-party":
            domain_type = "firstParty"
        elif option in RESOURCE_MAPPING:
            resource_types.append(RESOURCE_MAPPING[option])
        else:
            return None

    tail = pattern[2:]
    # ||example.com^ or ||example.com (domain); ||example.com/pagead/... (URL).
    host_and_path = tail.split("/", 1)
    host = host_and_path[0].removesuffix("^").lower().rstrip(".")
    if not _valid_host(host):
        return None
    path = "/" + host_and_path[1] if len(host_and_path) > 1 else ""
    if "^" in path or "#" in path:
        return None

    if _protected(host):
        # A regra first-party precisa identificar um caminho publicitário
        # específico. Nunca bloquear o domínio que entrega vídeos.
        if not path or not any(path.startswith(p) for p in SAFE_FIRST_PARTY_PATHS):
            return None
        if is_exception:
            return None
        condition = {
            "urlFilter": f"||{host}{path}",
            "initiatorDomains": ["youtube.com"],
            "resourceTypes": list(SAFE_RESOURCES),
        }
        return condition, is_exception, True

    if path:
        # Selecionar URL completa sem ampliar para o domínio.
        if not targeted:
            return None
        condition = {
            "urlFilter": f"||{host}{path}",
            "initiatorDomains": ["youtube.com"],
            "resourceTypes": resource_types or list(SAFE_RESOURCES),
        }
    else:
        condition = {
            "requestDomains": [host],
            "initiatorDomains": ["youtube.com"],
            "resourceTypes": resource_types or list(SAFE_RESOURCES),
        }

    if domain_type:
        condition["domainType"] = domain_type
    elif not targeted:
        condition["domainType"] = "thirdParty"

    return condition, is_exception, targeted


def compile_youtube_rules(sources: list[Path], limit: int = LIMIT) -> list[dict]:
    """Prioritize YouTube-scoped rules and exceptions over generic ad hosts."""
    if not 1 <= limit <= 5000:
        raise ValueError("invalid rule limit")
    targeted: list[tuple[dict, bool, bool]] = []
    generic: list[tuple[dict, bool, bool]] = []
    visited: set[str] = set()
    for source in sources:
        if not source.is_file():
            continue
        for raw in source.read_text(encoding="utf-8", errors="ignore").splitlines():
            parsed = _parse_rule(raw)
            if parsed is None:
                continue
            condition, is_exception, is_targeted = parsed
            key = json.dumps([condition, is_exception], sort_keys=True)
            if key in visited:
                continue
            visited.add(key)
            (targeted if is_targeted or is_exception else generic).append(parsed)
    result = []
    for condition, is_exception, _ in [*targeted, *generic]:
        if len(result) >= limit:
            break
        result.append({
            "id": 10001 + len(result),
            "priority": 3 if is_exception else 1,
            "action": {"type": "allow" if is_exception else "block"},
            "condition": condition,
        })
    return result
