from __future__ import annotations

from dataclasses import dataclass
import json
import os
from pathlib import Path
import sys
import zipfile

from .config import BrowserCompanionConfig

IS_WINDOWS = sys.platform == "win32"

if IS_WINDOWS:
    import winreg


@dataclass(frozen=True, slots=True)
class BrowserInfo:
    key: str
    name: str
    executable: Path


@dataclass(frozen=True, slots=True)
class BrowserSetupResult:
    browser: BrowserInfo
    status: str
    detail: str


_BROWSER_PATHS = {
    "chrome": (
        ("Google Chrome", "chrome.exe"),
        [
            ("LOCALAPPDATA", r"Google\Chrome\Application\chrome.exe"),
            ("PROGRAMFILES", r"Google\Chrome\Application\chrome.exe"),
            ("PROGRAMFILES(X86)", r"Google\Chrome\Application\chrome.exe"),
        ],
    ),
    "edge": (
        ("Microsoft Edge", "msedge.exe"),
        [
            ("PROGRAMFILES(X86)", r"Microsoft\Edge\Application\msedge.exe"),
            ("PROGRAMFILES", r"Microsoft\Edge\Application\msedge.exe"),
            ("LOCALAPPDATA", r"Microsoft\Edge\Application\msedge.exe"),
        ],
    ),
    "firefox": (
        ("Mozilla Firefox", "firefox.exe"),
        [
            ("PROGRAMFILES", r"Mozilla Firefox\firefox.exe"),
            ("PROGRAMFILES(X86)", r"Mozilla Firefox\firefox.exe"),
            ("LOCALAPPDATA", r"Mozilla Firefox\firefox.exe"),
        ],
    ),
    "brave": (
        ("Brave", "brave.exe"),
        [
            ("PROGRAMFILES", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
            ("PROGRAMFILES(X86)", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
            ("LOCALAPPDATA", r"BraveSoftware\Brave-Browser\Application\brave.exe"),
        ],
    ),
    "chromium": (
        ("Chromium", "chrome.exe"),
        [
            ("LOCALAPPDATA", r"Chromium\Application\chrome.exe"),
            ("PROGRAMFILES", r"Chromium\Application\chrome.exe"),
            ("PROGRAMFILES(X86)", r"Chromium\Application\chrome.exe"),
        ],
    ),
}


def _registry_app_path(exe_name: str) -> list[Path]:
    if not IS_WINDOWS:
        return []
    paths: list[Path] = []
    subkey = rf"Software\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}"
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (0, getattr(winreg, "KEY_WOW64_64KEY", 0), getattr(winreg, "KEY_WOW64_32KEY", 0)):
            try:
                with winreg.OpenKey(hive, subkey, 0, winreg.KEY_READ | view) as key:
                    value, _ = winreg.QueryValueEx(key, None)
                    if value:
                        paths.append(Path(str(value)))
            except OSError:
                pass
    return paths


def detect_installed_browsers(
    env: dict[str, str] | None = None,
    extra_candidates: dict[str, list[Path]] | None = None,
    use_registry: bool = True,
) -> list[BrowserInfo]:
    env = dict(os.environ if env is None else env)
    extra_candidates = extra_candidates or {}
    found: list[BrowserInfo] = []
    seen: set[tuple[str, str]] = set()

    for key, ((name, exe_name), relative_paths) in _BROWSER_PATHS.items():
        candidates: list[Path] = []
        for env_name, suffix in relative_paths:
            base = env.get(env_name)
            if base:
                candidates.append(Path(base) / suffix)
        candidates.extend(_registry_app_path(exe_name))
        candidates.extend(extra_candidates.get(key, []))

        for candidate in candidates:
            try:
                exists = candidate.is_file()
            except OSError:
                exists = False
            if not exists:
                continue
            resolved = str(candidate.resolve()).casefold()
            marker = (key, resolved)
            if marker in seen:
                continue
            seen.add(marker)
            found.append(BrowserInfo(key=key, name=name, executable=candidate.resolve()))
            break

    return found


def build_extension_packages(project_root: Path, output_dir: Path) -> tuple[Path, Path]:
    extension_dir = project_root / "browser_extension"
    if not (extension_dir / "manifest.json").is_file():
        raise FileNotFoundError("browser_extension/manifest.json não encontrado")

    output_dir.mkdir(parents=True, exist_ok=True)
    zip_path = output_dir / "qproxy-youtube-companion.zip"
    xpi_path = output_dir / "qproxy-youtube-companion.xpi"

    files = [
        path
        for path in extension_dir.rglob("*")
        if path.is_file() and path.name not in {"README.md"} and "__pycache__" not in path.parts
    ]

    for target in (zip_path, xpi_path):
        tmp = target.with_suffix(target.suffix + ".tmp")
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in files:
                archive.write(path, path.relative_to(extension_dir).as_posix())
        tmp.replace(target)

    return zip_path, xpi_path


def _next_policy_slot(key, desired_value: str) -> tuple[str, bool]:
    existing_names: set[str] = set()
    index = 0
    while True:
        try:
            name, value, _ = winreg.EnumValue(key, index)
            existing_names.add(name)
            if str(value) == desired_value:
                return name, True
            index += 1
        except OSError:
            break

    slot = 1
    while str(slot) in existing_names:
        slot += 1
    return str(slot), False


def _install_chromium_policy(policy_path: str, extension_id: str, update_url: str) -> None:
    value = f"{extension_id};{update_url}"
    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER,
        policy_path,
        0,
        winreg.KEY_READ | winreg.KEY_WRITE,
    ) as key:
        slot, already = _next_policy_slot(key, value)
        if not already:
            winreg.SetValueEx(key, slot, 0, winreg.REG_SZ, value)


def _install_firefox_policy(extension_id: str, install_url: str) -> None:
    policy = {
        extension_id: {
            "installation_mode": "force_installed",
            "install_url": install_url,
        }
    }
    compact = json.dumps(policy, separators=(",", ":"))
    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER,
        r"Software\Policies\Mozilla\Firefox",
        0,
        winreg.KEY_SET_VALUE,
    ) as key:
        winreg.SetValueEx(key, "ExtensionSettings", 0, winreg.REG_MULTI_SZ, [compact])


def _resolved_install_url(value: str, project_root: Path) -> str:
    if value.startswith(("https://", "http://", "file:///")):
        return value
    path = Path(value)
    if not path.is_absolute():
        path = (project_root / path).resolve()
    return path.as_uri()


def setup_browser_companion(
    project_root: Path,
    config: BrowserCompanionConfig,
) -> tuple[list[BrowserInfo], list[BrowserSetupResult], tuple[Path, Path]]:
    browsers = detect_installed_browsers()
    packages = build_extension_packages(
        project_root,
        (project_root / config.package_dir).resolve(),
    )

    results: list[BrowserSetupResult] = []
    if not config.auto_install:
        for browser in browsers:
            results.append(
                BrowserSetupResult(browser, "detected", "instalação automática desativada na configuração")
            )
        return browsers, results, packages

    for browser in browsers:
        if browser.key == "chrome":
            if config.managed_policy_install and config.chrome_extension_id:
                _install_chromium_policy(
                    r"Software\Policies\Google\Chrome\ExtensionInstallForcelist",
                    config.chrome_extension_id,
                    config.chrome_update_url,
                )
                results.append(BrowserSetupResult(browser, "policy_configured", "política de instalação configurada"))
            else:
                results.append(
                    BrowserSetupResult(
                        browser,
                        "store_required",
                        "Chrome requer extensão publicada/gerenciada para instalação silenciosa",
                    )
                )
        elif browser.key == "edge":
            if config.managed_policy_install and config.edge_extension_id:
                _install_chromium_policy(
                    r"Software\Policies\Microsoft\Edge\ExtensionInstallForcelist",
                    config.edge_extension_id,
                    config.edge_update_url,
                )
                results.append(BrowserSetupResult(browser, "policy_configured", "política de instalação configurada"))
            else:
                results.append(
                    BrowserSetupResult(
                        browser,
                        "store_required",
                        "Edge requer ID publicado para instalação silenciosa segura em Windows comum",
                    )
                )
        elif browser.key == "chromium":
            if config.managed_policy_install and config.chromium_extension_id:
                _install_chromium_policy(
                    r"Software\Policies\Chromium\ExtensionInstallForcelist",
                    config.chromium_extension_id,
                    config.chromium_update_url,
                )
                results.append(BrowserSetupResult(browser, "policy_configured", "política Chromium configurada"))
            else:
                results.append(
                    BrowserSetupResult(
                        browser,
                        "package_ready",
                        f"pacote preparado em {packages[0]}",
                    )
                )
        elif browser.key == "firefox":
            if config.managed_policy_install and config.firefox_signed_xpi:
                install_url = _resolved_install_url(config.firefox_signed_xpi, project_root)
                _install_firefox_policy(config.firefox_extension_id, install_url)
                results.append(BrowserSetupResult(browser, "policy_configured", "política Firefox configurada"))
            else:
                results.append(
                    BrowserSetupResult(
                        browser,
                        "signed_xpi_required",
                        "Firefox requer XPI assinado para instalação persistente automática",
                    )
                )
        elif browser.key == "brave":
            results.append(
                BrowserSetupResult(
                    browser,
                    "package_ready",
                    f"Brave detectado; pacote preparado em {packages[0]}",
                )
            )

    return browsers, results, packages


def print_browser_setup(results: list[BrowserSetupResult], packages: tuple[Path, Path]) -> None:
    print()
    print(" Navegadores / complemento:")
    if not results:
        print("   Nenhum navegador compatível detectado.")
    for result in results:
        print(f"   - {result.browser.name}: {result.status} — {result.detail}")
    print(f"   Pacote Chromium: {packages[0]}")
    print(f"   Pacote Firefox:  {packages[1]}")
