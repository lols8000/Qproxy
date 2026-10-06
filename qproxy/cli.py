from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from .blocklist import DomainMatcher
from .config import Config
from .proxy import ProxyServer


def _resolve_paths(config_path: str | None, paths: list[str]) -> list[Path]:
    base = Path(config_path).resolve().parent if config_path else Path.cwd()
    return [(base / p).resolve() if not Path(p).is_absolute() else Path(p) for p in paths]


def build_matcher(config: Config, config_path: str | None) -> DomainMatcher:
    matcher = DomainMatcher()
    blocked = 0
    allowed = 0
    for path in _resolve_paths(config_path, config.blocklists):
        blocked += matcher.load_file(path, default_allow=False)
    for path in _resolve_paths(config_path, config.whitelists):
        allowed += matcher.load_file(path, default_allow=True)
    logging.getLogger("qproxy").info(
        "Listas carregadas: %d regras de bloqueio, %d regras de liberação",
        blocked,
        allowed,
    )
    return matcher


def main() -> None:
    parser = argparse.ArgumentParser(description="Qproxy - proxy local com bloqueio de anúncios por domínio")
    parser.add_argument("--config", default="config.example.json", help="Arquivo JSON de configuração")
    parser.add_argument("--host", help="Sobrescreve listen_host")
    parser.add_argument("--port", type=int, help="Sobrescreve listen_port")
    parser.add_argument("--verbose", action="store_true", help="Mostra também tráfego permitido")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        datefmt="%H:%M:%S",
    )

    config_path = args.config if Path(args.config).exists() else None
    config = Config.load(config_path)
    if args.host:
        config.listen_host = args.host
    if args.port:
        config.listen_port = args.port
    if args.verbose:
        config.log_allowed = True

    matcher = build_matcher(config, config_path)
    server = ProxyServer(config, matcher)

    try:
        asyncio.run(server.serve())
    except KeyboardInterrupt:
        print("\nQproxy encerrado.")
