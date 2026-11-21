from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import webbrowser

from qproxy.browser_setup import print_browser_setup, setup_browser_companion
from qproxy.config import Config
from qproxy.windivert_setup import download_and_install_windivert, find_windivert_dll
from qproxy.windows_net import (
    capture_windows_dns,
    flush_windows_dns_cache,
    is_admin,
    relaunch_as_admin,
    restore_dns_backup_if_present,
    restore_windows_dns,
    set_windows_dns_local,
    write_dns_backup,
)

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
BACKUP_FILE = DATA_DIR / "windows_proxy_backup.json"
DNS_BACKUP_FILE = DATA_DIR / "windows_dns_backup.json"

PROXY_HOST = "127.0.0.1"
PROXY_PORT = 8899
DASHBOARD_PORT = 8900

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import winreg


def port_open(host: str, port: int, timeout: float = 0.25) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def wait_for_port(host: str, port: int, process: subprocess.Popen | None, timeout: float) -> bool:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if port_open(host, port):
            return True
        if process is not None and process.poll() is not None:
            return False
        time.sleep(0.15)
    return False


def _internet_settings_key(access: int):
    return winreg.OpenKey(
        winreg.HKEY_CURRENT_USER,
        r"Software\Microsoft\Windows\CurrentVersion\Internet Settings",
        0,
        access,
    )


def _read_registry_value(name: str) -> dict:
    with _internet_settings_key(winreg.KEY_READ) as key:
        try:
            value, value_type = winreg.QueryValueEx(key, name)
            return {"exists": True, "value": value, "type": value_type}
        except FileNotFoundError:
            return {"exists": False, "value": None, "type": None}


def capture_windows_proxy() -> dict:
    return {
        "ProxyEnable": _read_registry_value("ProxyEnable"),
        "ProxyServer": _read_registry_value("ProxyServer"),
        "ProxyOverride": _read_registry_value("ProxyOverride"),
    }


def _set_registry_value(name: str, value, value_type: int) -> None:
    with _internet_settings_key(winreg.KEY_SET_VALUE) as key:
        winreg.SetValueEx(key, name, 0, value_type, value)


def _delete_registry_value(name: str) -> None:
    with _internet_settings_key(winreg.KEY_SET_VALUE) as key:
        try:
            winreg.DeleteValue(key, name)
        except FileNotFoundError:
            pass


def notify_windows_proxy_changed() -> None:
    wininet = ctypes.windll.Wininet
    INTERNET_OPTION_REFRESH = 37
    INTERNET_OPTION_SETTINGS_CHANGED = 39
    wininet.InternetSetOptionW(None, INTERNET_OPTION_SETTINGS_CHANGED, None, 0)
    wininet.InternetSetOptionW(None, INTERNET_OPTION_REFRESH, None, 0)


def restore_windows_proxy(snapshot: dict) -> None:
    for name, item in snapshot.items():
        if item.get("exists"):
            _set_registry_value(name, item.get("value"), int(item.get("type")))
        else:
            _delete_registry_value(name)
    notify_windows_proxy_changed()


def write_backup(snapshot: dict) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    tmp = BACKUP_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(BACKUP_FILE)


def restore_backup_if_present() -> bool:
    if not BACKUP_FILE.exists():
        return False
    snapshot = json.loads(BACKUP_FILE.read_text(encoding="utf-8"))
    restore_windows_proxy(snapshot)
    try:
        BACKUP_FILE.unlink()
    except FileNotFoundError:
        pass
    return True


def windows_proxy_points_to_qproxy() -> bool:
    enabled = _read_registry_value("ProxyEnable")
    server = _read_registry_value("ProxyServer")
    return (
        bool(enabled.get("exists") and int(enabled.get("value") or 0))
        and bool(server.get("exists"))
        and f"{PROXY_HOST}:{PROXY_PORT}" in str(server.get("value") or "")
    )


def recover_stale_proxy() -> bool:
    if not IS_WINDOWS:
        return False
    changed = False
    if restore_dns_backup_if_present(DNS_BACKUP_FILE):
        print("[Qproxy] Configuração anterior de DNS do Windows restaurada.")
        changed = True

    if port_open(PROXY_HOST, PROXY_PORT):
        return changed

    if restore_backup_if_present():
        print("[Qproxy] Configuração anterior de proxy do Windows restaurada.")
        return True

    if windows_proxy_points_to_qproxy():
        _set_registry_value("ProxyEnable", 0, winreg.REG_DWORD)
        notify_windows_proxy_changed()
        print("[Qproxy] Proxy antigo do Qproxy estava ativo sem servidor. Foi desativado.")
        return True

    return changed


def enable_windows_proxy(snapshot: dict, host: str = PROXY_HOST, port: int = PROXY_PORT) -> None:
    old_override = ""
    item = snapshot.get("ProxyOverride", {})
    if item.get("exists") and item.get("value"):
        old_override = str(item["value"])

    additions = ["localhost", "127.*", "<local>"]
    existing = [part.strip() for part in old_override.split(";") if part.strip()]
    merged = existing[:]
    for part in additions:
        if part.lower() not in {value.lower() for value in merged}:
            merged.append(part)

    _set_registry_value("ProxyServer", f"{host}:{port}", winreg.REG_SZ)
    _set_registry_value("ProxyOverride", ";".join(merged), winreg.REG_SZ)
    _set_registry_value("ProxyEnable", 1, winreg.REG_DWORD)
    notify_windows_proxy_changed()


def terminate_process(process: subprocess.Popen | None) -> None:
    if process is None or process.poll() is not None:
        return
    process.terminate()
    try:
        process.wait(timeout=4)
    except subprocess.TimeoutExpired:
        process.kill()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            pass


def _wait_for_parent_exit_windows(parent_pid: int) -> None:
    kernel32 = ctypes.windll.kernel32
    SYNCHRONIZE = 0x00100000
    INFINITE = 0xFFFFFFFF
    handle = kernel32.OpenProcess(SYNCHRONIZE, False, parent_pid)
    if not handle:
        return
    try:
        kernel32.WaitForSingleObject(handle, INFINITE)
    finally:
        kernel32.CloseHandle(handle)


def _terminate_pid_windows(pid: int) -> None:
    kernel32 = ctypes.windll.kernel32
    PROCESS_TERMINATE = 0x0001
    handle = kernel32.OpenProcess(PROCESS_TERMINATE, False, pid)
    if not handle:
        return
    try:
        kernel32.TerminateProcess(handle, 0)
    finally:
        kernel32.CloseHandle(handle)


def watchdog_mode(parent_pid: int, qproxy_pid: int) -> int:
    if not IS_WINDOWS:
        return 0
    _wait_for_parent_exit_windows(parent_pid)

    try:
        restore_backup_if_present()
    except Exception:
        pass

    try:
        restore_dns_backup_if_present(DNS_BACKUP_FILE)
    except Exception:
        pass

    try:
        _terminate_pid_windows(qproxy_pid)
    except Exception:
        pass
    return 0


def start_watchdog(qproxy_pid: int) -> None:
    if not IS_WINDOWS:
        return

    flags = 0
    flags |= getattr(subprocess, "DETACHED_PROCESS", 0x00000008)
    flags |= getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x00000200)
    flags |= getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)

    subprocess.Popen(
        [
            sys.executable,
            str(Path(__file__).resolve()),
            "--watchdog",
            str(os.getpid()),
            str(qproxy_pid),
        ],
        cwd=str(ROOT),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        creationflags=flags,
    )


def _choose_windows_mode(config: Config, requested_mode: str | None) -> str:
    mode = (requested_mode or config.mode or "auto").strip().lower()
    windivert_dir = (ROOT / config.packet_filter.windivert_dir).resolve()
    has_windivert = find_windivert_dll(windivert_dir, ROOT) is not None
    admin = is_admin()

    if mode == "auto":
        if admin and config.packet_filter.enabled:
            return "packet" if has_windivert else "dns"
        return "proxy"
    if mode == "packet" and (not admin or not has_windivert):
        return "dns" if admin else "proxy"
    return mode


def _wait_for_engine_status(
    dash_host: str, dash_port: int, process: subprocess.Popen, timeout: float = 12.0
) -> dict | None:
    from urllib.request import urlopen

    deadline = time.monotonic() + timeout
    url = f"http://{dash_host}:{dash_port}/api/status"
    while time.monotonic() < deadline:
        if process.poll() is not None:
            return None
        try:
            with urlopen(url, timeout=1.0) as resp:
                data = json.load(resp)
            engine = data.get("engine") if isinstance(data, dict) else None
            if isinstance(engine, dict) and engine.get("ready"):
                return engine
        except Exception:
            pass
        time.sleep(0.15)
    return None


def run(config_path: Path, open_browser: bool = True, requested_mode: str | None = None) -> int:
    if not IS_WINDOWS:
        print("Este inicializador automático é voltado ao Windows.")
        print(f"Use: {sys.executable} -m qproxy --config {config_path}")
        return 2

    recover_stale_proxy()

    config = Config.load(config_path if config_path.exists() else None)
    effective_mode = _choose_windows_mode(config, requested_mode)
    proxy_host = config.listen_host or PROXY_HOST
    proxy_port = int(config.listen_port or PROXY_PORT)
    dash_host = config.dashboard_host or PROXY_HOST
    dash_port = int(config.dashboard_port or DASHBOARD_PORT)

    if effective_mode in ("proxy", "hybrid") and port_open(proxy_host, proxy_port):
        print(f"ERRO: a porta {proxy_port} já está em uso. O Qproxy não foi iniciado.")
        print("Feche a instância anterior e tente novamente.")
        return 1

    command = [
        sys.executable,
        "-m",
        "qproxy",
        "--config",
        str(config_path),
        "--mode",
        effective_mode,
    ]

    print(f"Qproxy V4.0 iniciando em modo: {effective_mode.upper()}...")
    process = subprocess.Popen(command, cwd=str(ROOT))
    proxy_snapshot: dict | None = None
    dns_snapshot: list[dict] | None = None

    try:
        engine = _wait_for_engine_status(dash_host, dash_port, process, timeout=15)
        dashboard_ready = engine is not None or wait_for_port(dash_host, dash_port, process, timeout=2)
        if not dashboard_ready and process.poll() is not None:
            raise RuntimeError(
                f"Qproxy encerrou durante a inicialização (código {process.returncode})."
            )

        live_windivert = bool((engine or {}).get("windivert_active"))
        live_dns = bool((engine or {}).get("dns_server_active"))
        live_dns_port = int((engine or {}).get("dns_port") or config.dns_server.listen_port)
        live_proxy = bool((engine or {}).get("proxy_active"))
        actual_mode = str((engine or {}).get("mode") or effective_mode)

        # Só altera o proxy do Windows se o proxy HTTP/HTTPS realmente abriu a porta.
        if live_proxy and (actual_mode in ("proxy", "hybrid") or not (live_windivert or live_dns)):
            if not wait_for_port(proxy_host, proxy_port, process, timeout=10):
                code = process.poll()
                raise RuntimeError(
                    f"O servidor não abriu a porta {proxy_port}. Processo encerrou com código {code}."
                )
            proxy_snapshot = capture_windows_proxy()
            write_backup(proxy_snapshot)
            enable_windows_proxy(proxy_snapshot, proxy_host, proxy_port)

        # Só aponta DNS do Windows para 127.0.0.1 se o servidor DNS local realmente estiver na porta 53.
        if live_dns and not live_windivert and live_dns_port == 53:
            dns_snapshot = capture_windows_dns()
            if dns_snapshot:
                write_dns_backup(DNS_BACKUP_FILE, dns_snapshot)
                set_windows_dns_local(dns_snapshot, config.dns_server.listen_host or "127.0.0.1")

        start_watchdog(process.pid)
        flush_windows_dns_cache()

        if config.browser_companion.auto_detect:
            try:
                _, browser_results, packages = setup_browser_companion(
                    ROOT,
                    config.browser_companion,
                )
                print_browser_setup(browser_results, packages)
            except Exception as exc:
                print(f"[Qproxy] Integração com navegadores não concluída: {exc}")

        print()
        print("=" * 64)
        if live_windivert and not live_proxy:
            print(" QPROXY V4.0 ATIVO · MODO PACOTES WINDOWS (WinDivert / WFP)")
            print(" Camadas: DNS + Cache <1ms + CNAME + TLS SNI + QUIC/HTTP3 + HTTP")
            print(" Velocidade: tráfego permitido trafega direto no kernel do Windows")
        elif live_windivert and live_proxy:
            print(" QPROXY V4.0 ATIVO · MODO HÍBRIDO (Pacotes + Proxy)")
            print(f" Proxy:   {proxy_host}:{proxy_port}")
        elif live_dns:
            print(f" QPROXY V4.0 ATIVO · MODO DNS LOCAL (127.0.0.1:{live_dns_port})")
            print(" Camadas: DNS + Cache <1ms + CNAME Cloaking (sem lentidão de proxy)")
            print(" Dica: rode `python main.py --install-windivert` para ativar também")
            print("       inspeção de pacotes TLS SNI e QUIC/HTTP3.")
        else:
            print(" QPROXY V4.0 ATIVO · MODO PROXY HTTP/HTTPS OTIMIZADO")
            print(f" Proxy:   {proxy_host}:{proxy_port}")
            print(" Dica: para bloquear direto nos pacotes do Windows (todos os apps +")
            print("       internet mais rápida), execute:")
            print("       scripts\\iniciar_qproxy_admin.bat  ou  python main.py --elevate")
        print(f" Painel:  http://{dash_host}:{dash_port}")
        print(" Feche esta janela ou pressione Ctrl+C para encerrar com segurança.")
        print("=" * 64)
        print()

        if open_browser and dashboard_ready:
            try:
                webbrowser.open(f"http://{dash_host}:{dash_port}")
            except Exception:
                pass

        while process.poll() is None:
            time.sleep(0.5)

        print(f"Qproxy encerrou inesperadamente (código {process.returncode}).")
        return process.returncode or 1

    except KeyboardInterrupt:
        print("\nEncerrando Qproxy...")
        return 0
    except Exception as exc:
        print(f"ERRO: {exc}")
        return 1
    finally:
        terminate_process(process)
        if proxy_snapshot is not None:
            try:
                restore_windows_proxy(proxy_snapshot)
            finally:
                try:
                    BACKUP_FILE.unlink()
                except FileNotFoundError:
                    pass
            print("Proxy do Windows restaurado.")
        if dns_snapshot is not None:
            try:
                restore_windows_dns(dns_snapshot)
            finally:
                try:
                    DNS_BACKUP_FILE.unlink()
                except FileNotFoundError:
                    pass
            print("DNS dos adaptadores do Windows restaurado.")
        flush_windows_dns_cache()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Qproxy V4.0 - bloqueador de anúncios em pacotes do Windows"
    )
    parser.add_argument(
        "--config",
        default=str(ROOT / "config.example.json"),
        help="arquivo JSON de configuração do Qproxy",
    )
    parser.add_argument(
        "--mode",
        choices=("auto", "packet", "dns", "proxy", "hybrid"),
        help="modo de execução (auto, packet, dns, proxy, hybrid)",
    )
    parser.add_argument("--no-browser", action="store_true", help="não abre o painel automaticamente")
    parser.add_argument(
        "--elevate",
        action="store_true",
        help="reabre o Qproxy como Administrador (UAC) para habilitar bloqueio nos pacotes",
    )
    parser.add_argument(
        "--install-windivert",
        action="store_true",
        help="baixa e verifica (SHA-256) o driver oficial WinDivert 2.2.2 em data/windivert",
    )
    parser.add_argument(
        "--restore-proxy",
        "--restore-network",
        dest="restore_proxy",
        action="store_true",
        help="restaura/desativa proxy e DNS do Qproxy no Windows",
    )
    parser.add_argument(
        "--watchdog", nargs=2, metavar=("PARENT_PID", "QPROXY_PID"), help=argparse.SUPPRESS
    )
    args = parser.parse_args()

    if args.watchdog:
        return watchdog_mode(int(args.watchdog[0]), int(args.watchdog[1]))

    if args.install_windivert:
        cfg_path = Path(args.config).resolve()
        cfg = Config.load(cfg_path if cfg_path.exists() else None)
        target = (ROOT / cfg.packet_filter.windivert_dir).resolve()
        print("Baixando e verificando SHA-256 do WinDivert 2.2.2 oficial...")
        dll = download_and_install_windivert(target)
        print(f"WinDivert instalado com sucesso em: {dll.parent}")
        return 0

    if args.restore_proxy:
        if not IS_WINDOWS:
            return 2
        changed = recover_stale_proxy()
        if not changed and windows_proxy_points_to_qproxy():
            _set_registry_value("ProxyEnable", 0, winreg.REG_DWORD)
            notify_windows_proxy_changed()
            changed = True
        flush_windows_dns_cache()
        print(
            "Rede do Windows restaurada."
            if changed
            else "Nenhuma configuração travada do Qproxy foi encontrada."
        )
        return 0

    if args.elevate and IS_WINDOWS and not is_admin():
        forwarded = [arg for arg in sys.argv[1:] if arg != "--elevate"]
        if relaunch_as_admin(Path(__file__).resolve(), forwarded):
            return 0
        print("Elevação UAC cancelada ou recusada; iniciando sem Administrador.")

    return run(
        Path(args.config).resolve(),
        open_browser=not args.no_browser,
        requested_mode=args.mode,
    )


if __name__ == "__main__":
    raise SystemExit(main())
