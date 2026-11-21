"""Utilitários seguros de rede do Windows (DNS de adaptadores, flush de cache e elevação UAC).

Mantém backup atômico em `data/windows_dns_backup.json` para que o watchdog e o
comando `--restore-network` sempre devolvam a rede do Windows ao estado normal.
"""
from __future__ import annotations

import ctypes
import json
import logging
from pathlib import Path
import subprocess
import sys

LOG = logging.getLogger("qproxy")
IS_WINDOWS = sys.platform == "win32"


def is_admin() -> bool:
    if not IS_WINDOWS:
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin(script_path: Path, args: list[str]) -> bool:
    """Solicita elevação UAC no Windows para executar o Qproxy em modo pacotes."""
    if not IS_WINDOWS:
        return False
    params = subprocess.list2cmdline([str(script_path), *args])
    rc = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, params, str(script_path.parent), 1
    )
    return int(rc) > 32


def flush_windows_dns_cache() -> bool:
    """Limpa o cache DNS do Windows (`ipconfig /flushdns`) para aplicar bloqueios de imediato."""
    if not IS_WINDOWS:
        return False
    try:
        flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
        res = subprocess.run(
            ["ipconfig", "/flushdns"],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=flags,
        )
        return res.returncode == 0
    except Exception as exc:
        LOG.debug("Falha ao limpar cache DNS do Windows: %r", exc)
        return False


def _run_powershell(script: str, timeout: float = 15.0) -> subprocess.CompletedProcess[str]:
    flags = getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
    return subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            script,
        ],
        capture_output=True,
        text=True,
        timeout=timeout,
        creationflags=flags,
    )


def capture_windows_dns() -> list[dict]:
    """Captura os servidores DNS IPv4/IPv6 de cada adaptador de rede ativo."""
    if not IS_WINDOWS:
        return []
    ps = (
        "$adapters = Get-NetAdapter -Physical -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Status -eq 'Up' }; "
        "$out = @(); "
        "foreach ($a in $adapters) { "
        "  $v4 = (Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue).ServerAddresses; "
        "  $v6 = (Get-DnsClientServerAddress -InterfaceIndex $a.ifIndex -AddressFamily IPv6 -ErrorAction SilentlyContinue).ServerAddresses; "
        "  $out += [PSCustomObject]@{ ifIndex = [int]$a.ifIndex; name = [string]$a.Name; ipv4 = @($v4); ipv6 = @($v6) }; "
        "} "
        "$out | ConvertTo-Json -Compress"
    )
    res = _run_powershell(ps)
    if res.returncode != 0 or not res.stdout.strip():
        return []
    raw = json.loads(res.stdout)
    return raw if isinstance(raw, list) else [raw]


def write_dns_backup(backup_file: Path, snapshot: list[dict]) -> None:
    backup_file.parent.mkdir(parents=True, exist_ok=True)
    tmp = backup_file.with_suffix(".tmp")
    tmp.write_text(json.dumps(snapshot, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(backup_file)


def set_windows_dns_local(
    snapshot: list[dict], local_ipv4: str = "127.0.0.1", local_ipv6: str = "::1"
) -> bool:
    """Direciona IPv4 e IPv6 dos adaptadores ativos para o servidor DNS local do Qproxy."""
    if not IS_WINDOWS or not snapshot:
        return False
    indexes = [int(item["ifIndex"]) for item in snapshot if "ifIndex" in item]
    if not indexes:
        return False
    idx_list = ",".join(str(i) for i in indexes)
    ps = (
        f"foreach ($i in @({idx_list})) {{ "
        f"  Set-DnsClientServerAddress -InterfaceIndex $i -ServerAddresses @('{local_ipv4}','{local_ipv6}') -ErrorAction SilentlyContinue "
        f"}}"
    )
    res = _run_powershell(ps)
    flush_windows_dns_cache()
    return res.returncode == 0


def restore_windows_dns(snapshot: list[dict]) -> bool:
    """Restaura os servidores DNS originais (IPv4 e IPv6) de cada adaptador capturado no backup."""
    if not IS_WINDOWS or not snapshot:
        return False
    commands: list[str] = []
    for item in snapshot:
        idx = int(item["ifIndex"])
        ipv4 = [str(x) for x in (item.get("ipv4") or []) if x and x != "127.0.0.1"]
        ipv6 = [str(x) for x in (item.get("ipv6") or []) if x and x != "::1"]
        combined = [*ipv4, *ipv6]
        if combined:
            addrs = ",".join(f"'{addr}'" for addr in combined)
            commands.append(
                f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ServerAddresses @({addrs}) -ErrorAction SilentlyContinue"
            )
        else:
            commands.append(
                f"Set-DnsClientServerAddress -InterfaceIndex {idx} -ResetServerAddresses -ErrorAction SilentlyContinue"
            )
    if not commands:
        return False
    res = _run_powershell("; ".join(commands))
    flush_windows_dns_cache()
    return res.returncode == 0


def restore_dns_backup_if_present(backup_file: Path) -> bool:
    if not IS_WINDOWS or not backup_file.is_file():
        return False
    try:
        snapshot = json.loads(backup_file.read_text(encoding="utf-8"))
        if isinstance(snapshot, list) and snapshot:
            restore_windows_dns(snapshot)
    finally:
        try:
            backup_file.unlink()
        except FileNotFoundError:
            pass
    return True
