"""Detecção e instalação verificada do driver oficial WinDivert 2.2.2 (LGPLv3).

Baixa somente o pacote oficial `WinDivert-2.2.2-A.zip`, valida seu hash
SHA-256 exato e extrai `WinDivert.dll` + `WinDivert64.sys`/`WinDivert32.sys`
para a pasta local `data/windivert`.
"""
from __future__ import annotations

import ctypes
import hashlib
import io
import os
from pathlib import Path
import struct
import sys
from urllib.request import Request, urlopen
import zipfile

WINDIVERT_VERSION = "2.2.2"
WINDIVERT_DOWNLOAD_URL = (
    "https://github.com/basil00/WinDivert/releases/download/v2.2.2/WinDivert-2.2.2-A.zip"
)
WINDIVERT_ZIP_SHA256 = "63cb41763bb4b20f600b6de04e991a9c2be73279e317d4d82f237b150c5f3f15"


def is_windows_admin() -> bool:
    """Retorna True se o processo atual está rodando com privilégios de Administrador no Windows."""
    if sys.platform != "win32":
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _arch_folder() -> tuple[str, str]:
    is_64 = struct.calcsize("P") * 8 == 64
    return ("x64", "WinDivert64.sys") if is_64 else ("x86", "WinDivert32.sys")


def find_windivert_dll(windivert_dir: Path, project_root: Path | None = None) -> Path | None:
    """Localiza `WinDivert.dll` junto ao respectivo driver `.sys`."""
    _, sys_name = _arch_folder()
    candidates = [windivert_dir]
    if project_root is not None:
        candidates.append(project_root / "data" / "windivert")
        candidates.append(project_root)

    for folder in candidates:
        dll = folder / "WinDivert.dll"
        driver = folder / sys_name
        if dll.is_file() and driver.is_file():
            return dll.resolve()
    return None


def install_windivert_from_zip_bytes(zip_bytes: bytes, target_dir: Path, verify_sha256: bool = True) -> Path:
    """Valida SHA-256 e extrai WinDivert.dll + driver .sys para `target_dir`."""
    if verify_sha256:
        digest = hashlib.sha256(zip_bytes).hexdigest().lower()
        if digest != WINDIVERT_ZIP_SHA256:
            raise ValueError(
                f"SHA-256 inválido para WinDivert: esperado {WINDIVERT_ZIP_SHA256}, obtido {digest}"
            )

    arch, sys_name = _arch_folder()
    target_dir.mkdir(parents=True, exist_ok=True)
    needed = {f"{arch}/WinDivert.dll": "WinDivert.dll", f"{arch}/{sys_name}": sys_name}
    extracted: dict[str, Path] = {}

    with zipfile.ZipFile(io.BytesIO(zip_bytes)) as archive:
        for member in archive.namelist():
            norm = member.replace("\\", "/")
            for suffix, out_name in needed.items():
                if norm.endswith("/" + suffix) or norm == suffix:
                    data = archive.read(member)
                    out_path = target_dir / out_name
                    tmp = out_path.with_suffix(out_path.suffix + ".tmp")
                    tmp.write_bytes(data)
                    tmp.replace(out_path)
                    extracted[out_name] = out_path

    if "WinDivert.dll" not in extracted or sys_name not in extracted:
        raise FileNotFoundError(
            f"Pacote WinDivert incompleto: esperado {arch}/WinDivert.dll e {arch}/{sys_name}"
        )
    return extracted["WinDivert.dll"].resolve()


def download_and_install_windivert(
    target_dir: Path,
    timeout: float = 30.0,
    url: str = WINDIVERT_DOWNLOAD_URL,
) -> Path:
    """Baixa e instala a versão oficial verificada do WinDivert 2.2.2."""
    req = Request(url, headers={"User-Agent": "Qproxy/4.0 (WinDivert installer)"})
    with urlopen(req, timeout=timeout) as response:
        payload = response.read(5 * 1024 * 1024)
    return install_windivert_from_zip_bytes(payload, target_dir, verify_sha256=True)


def windivert_status(windivert_dir: Path, project_root: Path | None = None) -> dict[str, object]:
    dll = find_windivert_dll(windivert_dir, project_root)
    return {
        "platform": sys.platform,
        "is_windows": sys.platform == "win32",
        "is_admin": is_windows_admin(),
        "installed": dll is not None,
        "dll_path": str(dll) if dll else None,
        "target_dir": str(windivert_dir),
        "arch": _arch_folder()[0],
        "env_override": os.environ.get("QPROXY_WINDIVERT_DIR"),
    }
