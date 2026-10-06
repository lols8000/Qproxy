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

ROOT = Path(__file__).resolve().parent
DATA_DIR = ROOT / "data"
BACKUP_FILE = DATA_DIR / "windows_proxy_backup.json"

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
    if port_open(PROXY_HOST, PROXY_PORT):
        return False

    if restore_backup_if_present():
        print("[Qproxy] Configuração anterior do Windows restaurada.")
        return True

    if windows_proxy_points_to_qproxy():
        _set_registry_value("ProxyEnable", 0, winreg.REG_DWORD)
        notify_windows_proxy_changed()
        print("[Qproxy] Proxy antigo do Qproxy estava ativo sem servidor. Foi desativado.")
        return True

    return False


def enable_windows_proxy(snapshot: dict) -> None:
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

    _set_registry_value("ProxyServer", f"{PROXY_HOST}:{PROXY_PORT}", winreg.REG_SZ)
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


def run(config_path: Path, open_browser: bool = True) -> int:
    if not IS_WINDOWS:
        print("Este inicializador automático é voltado ao Windows.")
        print(f"Use: {sys.executable} -m qproxy --config {config_path}")
        return 2

    recover_stale_proxy()

    if port_open(PROXY_HOST, PROXY_PORT):
        print(f"ERRO: a porta {PROXY_PORT} já está em uso. O Qproxy não foi iniciado.")
        print("Feche a instância anterior e tente novamente.")
        return 1

    command = [
        sys.executable,
        "-m",
        "qproxy",
        "--config",
        str(config_path),
    ]

    print("Qproxy iniciando...")
    process = subprocess.Popen(command, cwd=str(ROOT))
    snapshot: dict | None = None

    try:
        if not wait_for_port(PROXY_HOST, PROXY_PORT, process, timeout=15):
            code = process.poll()
            raise RuntimeError(
                f"O servidor não abriu a porta {PROXY_PORT}. "
                f"Processo encerrou com código {code}."
            )

        snapshot = capture_windows_proxy()
        write_backup(snapshot)
        enable_windows_proxy(snapshot)
        start_watchdog(process.pid)

        dashboard_ready = wait_for_port(PROXY_HOST, DASHBOARD_PORT, process, timeout=5)

        print()
        print("=" * 56)
        print(" QPROXY ATIVO")
        print(f" Proxy:   {PROXY_HOST}:{PROXY_PORT}")
        print(f" Painel:  http://{PROXY_HOST}:{DASHBOARD_PORT}")
        print(" Feche esta janela ou pressione Ctrl+C para encerrar.")
        print(" Ao encerrar, o proxy anterior do Windows será restaurado.")
        print("=" * 56)
        print()

        if open_browser and dashboard_ready:
            try:
                webbrowser.open(f"http://{PROXY_HOST}:{DASHBOARD_PORT}")
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
        if snapshot is not None:
            try:
                restore_windows_proxy(snapshot)
            finally:
                try:
                    BACKUP_FILE.unlink()
                except FileNotFoundError:
                    pass
            print("Proxy do Windows restaurado. Sua conexão ficou em modo normal.")


def main() -> int:
    parser = argparse.ArgumentParser(description="Qproxy - inicializador simples para Windows")
    parser.add_argument(
        "--config",
        default=str(ROOT / "config.example.json"),
        help="arquivo JSON de configuração do Qproxy",
    )
    parser.add_argument("--no-browser", action="store_true", help="não abre o painel automaticamente")
    parser.add_argument("--restore-proxy", action="store_true", help="restaura/desativa um proxy Qproxy travado")
    parser.add_argument("--watchdog", nargs=2, metavar=("PARENT_PID", "QPROXY_PID"), help=argparse.SUPPRESS)
    args = parser.parse_args()

    if args.watchdog:
        return watchdog_mode(int(args.watchdog[0]), int(args.watchdog[1]))

    if args.restore_proxy:
        if not IS_WINDOWS:
            return 2
        changed = recover_stale_proxy()
        if not changed and windows_proxy_points_to_qproxy():
            _set_registry_value("ProxyEnable", 0, winreg.REG_DWORD)
            notify_windows_proxy_changed()
            changed = True
        print("Proxy restaurado." if changed else "Nenhum proxy travado do Qproxy foi encontrado.")
        return 0

    return run(Path(args.config).resolve(), open_browser=not args.no_browser)


if __name__ == "__main__":
    raise SystemExit(main())
