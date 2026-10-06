from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path

from .blocklist import RuleManager
from .config import Config
from .dashboard import DashboardServer
from .proxy import ProxyServer
from .stats import StatsStore
from .updater import BlocklistUpdater


def _resolve(base: Path, value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else (base / p).resolve()


def build_runtime(config: Config, config_path: str | None):
    base = Path(config_path).resolve().parent if config_path else Path.cwd()
    cache_dir = _resolve(base, config.remote_cache_dir)
    updater = BlocklistUpdater(config.remote_blocklists, cache_dir, config.remote_download_timeout_seconds)

    block_sources: list[tuple[Path, str]] = [(_resolve(base, p), "ad") for p in config.blocklists]
    for source in config.remote_blocklists:
        block_sources.append((updater.source_path(cache_dir, source), source.category))
    whitelist_paths = [_resolve(base, p) for p in config.whitelists]
    rules = RuleManager(block_sources, whitelist_paths)
    stats = StatsStore(_resolve(base, config.stats_file))
    return rules, stats, updater


async def _scheduled_updates(config: Config, updater: BlocklistUpdater, rules: RuleManager) -> None:
    delay = 0.2 if config.update_on_start else max(config.update_interval_hours * 3600, 60)
    while True:
        await asyncio.sleep(delay)
        await asyncio.to_thread(updater.refresh)
        rules.reload()
        delay = max(config.update_interval_hours * 3600, 60)


async def _run(config: Config, rules: RuleManager, stats: StatsStore, updater: BlocklistUpdater) -> None:
    server = ProxyServer(config, rules, stats)
    updater_task = asyncio.create_task(_scheduled_updates(config, updater, rules))
    try:
        await server.serve()
    finally:
        updater_task.cancel()
        await asyncio.gather(updater_task, return_exceptions=True)
        stats.save()


def main() -> None:
    parser = argparse.ArgumentParser(description="Qproxy V2 - proxy local com bloqueio de anúncios e trackers por domínio")
    parser.add_argument("--config", default="config.example.json", help="Arquivo JSON de configuração")
    parser.add_argument("--host", help="Sobrescreve listen_host")
    parser.add_argument("--port", type=int, help="Sobrescreve listen_port")
    parser.add_argument("--verbose", action="store_true", help="Mostra também tráfego permitido")
    parser.add_argument("--update-lists", action="store_true", help="Atualiza listas e encerra")
    args = parser.parse_args()

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S")
    config_path = args.config if Path(args.config).exists() else None
    config = Config.load(config_path)
    if args.host:
        config.listen_host = args.host
    if args.port:
        config.listen_port = args.port
    if args.verbose:
        config.log_allowed = True

    rules, stats, updater = build_runtime(config, config_path)
    if args.update_lists:
        updater.refresh()
        counts = rules.reload()
        print(f"Listas atualizadas. Domínios bloqueados: {counts.get('blocked_domains', 0)}")
        return

    dashboard = None
    if config.dashboard_enabled:
        dashboard = DashboardServer(config.dashboard_host, config.dashboard_port, stats, rules, updater, config.dashboard_token)
        dashboard.start()

    try:
        asyncio.run(_run(config, rules, stats, updater))
    except KeyboardInterrupt:
        print("\nQproxy encerrado.")
    finally:
        stats.save()
        if dashboard:
            dashboard.stop()
