from __future__ import annotations

import argparse
import asyncio
import logging
from pathlib import Path
import sys

from .blocklist import RuleManager
from .config import Config
from .dashboard import DashboardServer
from .dns_cache import DnsPacketCache, HostAddressCache
from .dns_server import LocalDnsServer
from .packet_filter import PacketProcessor, WindowsPacketFilter
from .proxy import ProxyServer
from .stats import StatsStore
from .updater import BlocklistUpdater
from .windivert_setup import (
    download_and_install_windivert,
    find_windivert_dll,
    is_windows_admin,
)
from .windows_net import flush_windows_dns_cache

LOG = logging.getLogger("qproxy")


def _resolve(base: Path, value: str) -> Path:
    p = Path(value)
    return p if p.is_absolute() else (base / p).resolve()


def build_runtime(config: Config, config_path: str | None):
    base = Path(config_path).resolve().parent if config_path else Path.cwd()
    cache_dir = _resolve(base, config.remote_cache_dir)
    updater = BlocklistUpdater(
        config.remote_blocklists, cache_dir, config.remote_download_timeout_seconds
    )

    block_sources: list[tuple[Path, str]] = [(_resolve(base, p), "ad") for p in config.blocklists]
    for source in config.remote_blocklists:
        block_sources.append((updater.source_path(cache_dir, source), source.category))
    whitelist_paths = [_resolve(base, p) for p in config.whitelists]
    rules = RuleManager(
        block_sources,
        whitelist_paths,
        config.compatibility_allowlist,
        _resolve(base, config.manual_blocklist_file),
    )
    stats = StatsStore(_resolve(base, config.stats_file))
    return rules, stats, updater


async def _scheduled_updates(
    config: Config, updater: BlocklistUpdater, rules: RuleManager
) -> None:
    delay = 0.2 if config.update_on_start else max(config.update_interval_hours * 3600, 60)
    while True:
        await asyncio.sleep(delay)
        await asyncio.to_thread(updater.refresh)
        # O parsing de listas grandes não pode bloquear o loop de rede.
        await asyncio.to_thread(rules.reload)
        if config.packet_filter.flush_windows_dns_on_start:
            await asyncio.to_thread(flush_windows_dns_cache)
        delay = max(config.update_interval_hours * 3600, 60)


def _resolve_effective_mode(config: Config, base: Path) -> tuple[str, Path | None, str]:
    """Determina o melhor motor disponível (packet > dns > proxy) sem travar a inicialização."""
    requested = (config.mode or "auto").strip().lower()
    windivert_dir = _resolve(base, config.packet_filter.windivert_dir)
    dll = find_windivert_dll(windivert_dir, base)
    admin = is_windows_admin()
    on_windows = sys.platform == "win32"

    if requested == "packet":
        if not on_windows:
            return "proxy", None, "Modo pacotes requer Windows; usando proxy HTTP/HTTPS."
        if not admin:
            return (
                "proxy",
                None,
                "Execute como Administrador (scripts\\iniciar_qproxy_admin.bat) para ativar o modo pacotes.",
            )
        if dll is None:
            if config.packet_filter.auto_download_windivert:
                try:
                    dll = download_and_install_windivert(windivert_dir)
                except Exception as exc:
                    return (
                        "dns",
                        None,
                        f"Falha ao baixar WinDivert ({exc}); usando servidor DNS local.",
                    )
            else:
                return (
                    "dns",
                    None,
                    "Driver WinDivert ausente; execute `python main.py --install-windivert` para ativar inspeção TLS/QUIC em pacotes.",
                )
        return "packet", dll, ""

    if requested == "hybrid":
        if on_windows and admin and dll is not None:
            return "hybrid", dll, ""
        return (
            "proxy",
            None,
            "Modo híbrido requer Windows + Administrador + WinDivert; operando em modo proxy.",
        )

    if requested == "dns":
        return "dns", None, ""

    if requested == "proxy":
        return (
            "proxy",
            None,
            "Modo proxy selecionado. Use --mode packet (como Admin) para bloqueio direto nos pacotes do Windows.",
        )

    # Modo 'auto': prioriza bloqueio nos pacotes do Windows > DNS local (admin) > proxy otimizado.
    if on_windows and admin and config.packet_filter.enabled:
        if dll is None and config.packet_filter.auto_download_windivert:
            try:
                dll = download_and_install_windivert(windivert_dir)
            except Exception as exc:
                LOG.warning("Download automático do WinDivert falhou: %s", exc)
        if dll is not None:
            return "packet", dll, ""
        return (
            "dns",
            None,
            "Rodando como Administrador sem WinDivert: usando servidor DNS local. Instale WinDivert (`python main.py --install-windivert`) para adicionar TLS SNI e QUIC/HTTP3.",
        )

    hint = (
        "Execute scripts\\iniciar_qproxy_admin.bat (ou `python main.py --elevate`) para ativar bloqueio nos pacotes do Windows sem lentidão de proxy."
        if on_windows
        else "Modo proxy otimizado ativo."
    )
    return "proxy", None, hint


async def _run(
    config: Config,
    base: Path,
    rules: RuleManager,
    stats: StatsStore,
    updater: BlocklistUpdater,
    dns_cache: DnsPacketCache,
    host_cache: HostAddressCache,
    engine_state: dict,
) -> None:
    mode, dll_path, hint = _resolve_effective_mode(config, base)
    engine_state["mode"] = mode
    engine_state["hint"] = hint
    engine_state["is_admin"] = is_windows_admin()
    engine_state["windivert_ready"] = dll_path is not None

    packet_filter: WindowsPacketFilter | None = None
    dns_server: LocalDnsServer | None = None
    proxy_server: ProxyServer | None = None

    if mode in ("packet", "hybrid") and dll_path is not None:
        processor = PacketProcessor(
            rules, stats, config.packet_filter, dns_cache=dns_cache, log_allowed=config.log_allowed
        )
        packet_filter = WindowsPacketFilter(dll_path, processor, config.packet_filter)
        try:
            packet_filter.start()
            engine_state["windivert_active"] = True
            engine_state["active_layers"] = packet_filter.active_layers()
            if config.packet_filter.flush_windows_dns_on_start:
                flush_windows_dns_cache()
        except Exception as exc:
            LOG.error("Não foi possível iniciar WinDivert (%s); alternando para proxy/DNS.", exc)
            engine_state["error"] = str(exc)
            engine_state["hint"] = f"WinDivert indisponível ({exc}). Usando modo alternativo."
            packet_filter = None
            mode = "proxy"
            engine_state["mode"] = mode

    if mode == "dns" or (config.dns_server.enabled and packet_filter is None):
        dns_server = LocalDnsServer(
            config.dns_server,
            rules,
            stats,
            dns_cache,
            block_mode=config.packet_filter.dns_block_mode,
            filter_cname_cloaking=config.packet_filter.filter_cname_cloaking,
            signal_local_dns_filter=config.packet_filter.signal_local_dns_filter,
        )
        try:
            await dns_server.start()
            engine_state["dns_server_active"] = True
            engine_state["dns_port"] = dns_server.bound_port
            engine_state["active_layers"] = [
                f"DNS Local (:{dns_server.bound_port})",
                "CNAME Cloaking",
                "Cache DNS <1ms",
            ]
            if config.packet_filter.flush_windows_dns_on_start:
                flush_windows_dns_cache()
        except OSError as exc:
            LOG.warning("Porta DNS %s indisponível (%s); alternando para proxy.", config.dns_server.listen_port, exc)
            dns_server = None
            mode = "proxy"
            engine_state["mode"] = mode
            engine_state["hint"] = f"Porta DNS {config.dns_server.listen_port} ocupada ({exc}); operando via proxy."

    start_proxy = mode in ("proxy", "hybrid") or (packet_filter is None and dns_server is None)
    if start_proxy:
        proxy_server = ProxyServer(config, rules, stats, host_cache=host_cache)
        engine_state["proxy_active"] = True
        layers = list(engine_state.get("active_layers", []))
        layers.append(f"Proxy HTTP/HTTPS (:{config.listen_port})")
        engine_state["active_layers"] = layers

    engine_state["ready"] = True
    updater_task = asyncio.create_task(_scheduled_updates(config, updater, rules))
    try:
        if proxy_server is not None:
            await proxy_server.serve()
        else:
            # Em modo pacotes/DNS puro, mantém o loop ativo aguardando encerramento limpo.
            await asyncio.Event().wait()
    finally:
        updater_task.cancel()
        await asyncio.gather(updater_task, return_exceptions=True)
        if packet_filter is not None:
            packet_filter.stop()
        if dns_server is not None:
            await dns_server.stop()
        stats.save()


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Qproxy V4.0 - bloqueador de anúncios em pacotes do Windows (WinDivert), DNS local e proxy rápido"
    )
    parser.add_argument("--config", default="config.example.json", help="Arquivo JSON de configuração")
    parser.add_argument(
        "--mode",
        choices=("auto", "packet", "dns", "proxy", "hybrid"),
        help="Sobrescreve modo de operação (auto, packet, dns, proxy, hybrid)",
    )
    parser.add_argument("--host", help="Sobrescreve listen_host do proxy")
    parser.add_argument("--port", type=int, help="Sobrescreve listen_port do proxy")
    parser.add_argument("--verbose", action="store_true", help="Mostra também tráfego permitido")
    parser.add_argument("--update-lists", action="store_true", help="Atualiza listas e encerra")
    parser.add_argument(
        "--install-windivert",
        action="store_true",
        help="Baixa e verifica (SHA-256) o driver oficial WinDivert 2.2.2 em data/windivert",
    )
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s", datefmt="%H:%M:%S"
    )
    config_path = args.config if Path(args.config).exists() else None
    base = Path(config_path).resolve().parent if config_path else Path.cwd()
    config = Config.load(config_path)
    if args.mode:
        config.mode = args.mode
    if args.host:
        config.listen_host = args.host
    if args.port:
        config.listen_port = args.port
    if args.verbose:
        config.log_allowed = True

    if args.install_windivert:
        target = _resolve(base, config.packet_filter.windivert_dir)
        dll = download_and_install_windivert(target)
        print(f"WinDivert 2.2.2 verificado e instalado em: {dll.parent}")
        return

    rules, stats, updater = build_runtime(config, config_path)
    if args.update_lists:
        updater.refresh()
        counts = rules.reload()
        print(f"Listas atualizadas. Domínios bloqueados: {counts.get('blocked_domains', 0)}")
        return

    dns_cache = DnsPacketCache(
        max_entries=config.packet_filter.dns_cache_max_entries,
        min_ttl=config.packet_filter.dns_cache_min_ttl,
        max_ttl=config.packet_filter.dns_cache_max_ttl,
    )
    host_cache = HostAddressCache()

    def on_rules_changed() -> None:
        dns_cache.clear()
        host_cache.clear()

    rules.add_change_listener(on_rules_changed)

    engine_state: dict[str, object] = {
        "ready": False,
        "mode": config.mode,
        "windivert_active": False,
        "windivert_ready": False,
        "dns_server_active": False,
        "proxy_active": False,
        "is_admin": is_windows_admin(),
        "active_layers": [],
        "hint": "",
        "error": None,
    }

    def get_engine_status() -> dict:
        snap = dict(engine_state)
        snap["dns_cache"] = dns_cache.stats()
        return snap

    def handle_flush_dns() -> bool:
        dns_cache.clear()
        host_cache.clear()
        return flush_windows_dns_cache()

    dashboard = None
    if config.dashboard_enabled:
        dashboard = DashboardServer(
            config.dashboard_host,
            config.dashboard_port,
            stats,
            rules,
            updater,
            config.dashboard_token,
            engine_status_provider=get_engine_status,
            flush_dns_handler=handle_flush_dns,
        )
        dashboard.start()

    try:
        asyncio.run(
            _run(config, base, rules, stats, updater, dns_cache, host_cache, engine_state)
        )
    except KeyboardInterrupt:
        print("\nQproxy encerrado.")
    finally:
        stats.save()
        if dashboard:
            dashboard.stop()
