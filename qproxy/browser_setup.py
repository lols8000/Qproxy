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
}

_CHROMIUM_POLICY_PATHS = {
    "chrome": r"Software\Policies\Google\Chrome\ExtensionInstallForcelist",
    "edge": r"Software\Policies\Microsoft\Edge\ExtensionInstallForcelist",
    "brave": r"Software\Policies\BraveSoftware\Brave\ExtensionInstallForcelist",
}


def _registry_app_path(exe_name: str) -> list[Path]:
    if not IS_WINDOWS:
        return []

    paths: list[Path] = []
    subkey = rf"Software\Microsoft\Windows\CurrentVersion\App Paths\{exe_name}"
    for hive in (winreg.HKEY_CURRENT_USER, winreg.HKEY_LOCAL_MACHINE):
        for view in (
            0,
            getattr(winreg, "KEY_WOW64_64KEY", 0),
            getattr(winreg, "KEY_WOW64_32KEY", 0),
        ):
            try:
                with winreg.OpenKey(
                    hive,
                    subkey,
                    0,
                    winreg.KEY_READ | view,
                ) as key:
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
    seen_paths: set[str] = set()

    for key, ((name, exe_name), relative_paths) in _BROWSER_PATHS.items():
        candidates: list[Path] = []

        for env_name, suffix in relative_paths:
            base = env.get(env_name)
            if base:
                candidates.append(Path(base) / suffix)

        if use_registry:
            candidates.extend(_registry_app_path(exe_name))

        candidates.extend(extra_candidates.get(key, []))

        for candidate in candidates:
            try:
                if not candidate.is_file():
                    continue
                resolved_path = candidate.resolve()
            except OSError:
                continue

            marker = str(resolved_path).casefold()
            if marker in seen_paths:
                continue

            seen_paths.add(marker)
            found.append(
                BrowserInfo(
                    key=key,
                    name=name,
                    executable=resolved_path,
                )
            )
            break

    return found


def build_extension_packages(
    project_root: Path,
    output_dir: Path,
) -> tuple[Path, Path]:
    extension_dir = project_root / "browser_extension"
    if not (extension_dir / "manifest.json").is_file():
        raise FileNotFoundError("browser_extension/manifest.json não encontrado")

    output_dir.mkdir(parents=True, exist_ok=True)
    zip_path = output_dir / "qproxy-youtube-companion.zip"
    xpi_path = output_dir / "qproxy-youtube-companion.xpi"

    files = [
        path
        for path in extension_dir.rglob("*")
        if path.is_file()
        and path.name != "README.md"
        and "__pycache__" not in path.parts
    ]

    for target in (zip_path, xpi_path):
        tmp = target.with_suffix(target.suffix + ".tmp")
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as archive:
            for path in files:
                archive.write(
                    path,
                    path.relative_to(extension_dir).as_posix(),
                )
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


def _install_chromium_policy(
    browser_key: str,
    extension_id: str,
    update_url: str,
) -> None:
    policy_path = _CHROMIUM_POLICY_PATHS[browser_key]
    value = f"{extension_id};{update_url}"

    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER,
        policy_path,
        0,
        winreg.KEY_READ | winreg.KEY_WRITE,
    ) as key:
        slot, already = _next_policy_slot(key, value)
        if not already:
            winreg.SetValueEx(
                key,
                slot,
                0,
                winreg.REG_SZ,
                value,
            )


def _install_firefox_policy(
    extension_id: str,
    install_url: str,
) -> None:
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
        winreg.SetValueEx(
            key,
            "ExtensionSettings",
            0,
            winreg.REG_MULTI_SZ,
            [compact],
        )


def _resolved_install_url(
    value: str,
    project_root: Path,
) -> str:
    if value.startswith(("https://", "http://", "file:///")):
        return value

    path = Path(value)
    if not path.is_absolute():
        path = (project_root / path).resolve()

    return path.as_uri()


def _chromium_distribution(
    browser_key: str,
    config: BrowserCompanionConfig,
) -> tuple[str | None, str]:
    if browser_key == "chrome":
        return config.chrome_extension_id, config.chrome_update_url
    if browser_key == "edge":
        return config.edge_extension_id, config.edge_update_url
    if browser_key == "brave":
        return config.brave_extension_id, config.brave_update_url
    raise ValueError(f"Navegador Chromium não suportado: {browser_key}")


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
                BrowserSetupResult(
                    browser,
                    "detected",
                    "detectado; instalação automática desativada",
                )
            )
        return browsers, results, packages

    for browser in browsers:
        if browser.key in {"chrome", "edge", "brave"}:
            extension_id, update_url = _chromium_distribution(
                browser.key,
                config,
            )

            if (
                config.managed_policy_install
                and extension_id
                and IS_WINDOWS
            ):
                _install_chromium_policy(
                    browser.key,
                    extension_id,
                    update_url,
                )
                results.append(
                    BrowserSetupResult(
                        browser,
                        "install_configured",
                        "política de instalação automática aplicada",
                    )
                )
            elif extension_id:
                results.append(
                    BrowserSetupResult(
                        browser,
                        "distribution_ready",
                        "ID configurado; habilite managed_policy_install para aplicar a política",
                    )
                )
            else:
                store_name = {
                    "chrome": "Chrome Web Store",
                    "edge": "Microsoft Edge Add-ons",
                    "brave": "Chrome Web Store/canal gerenciado do Brave",
                }[browser.key]
                results.append(
                    BrowserSetupResult(
                        browser,
                        "publication_required",
                        f"detectado; falta ID publicado em {store_name}",
                    )
                )

        elif browser.key == "firefox":
            if (
                config.managed_policy_install
                and config.firefox_signed_xpi
                and IS_WINDOWS
            ):
                install_url = _resolved_install_url(
                    config.firefox_signed_xpi,
                    project_root,
                )
                _install_firefox_policy(
                    config.firefox_extension_id,
                    install_url,
                )
                results.append(
                    BrowserSetupResult(
                        browser,
                        "install_configured",
                        "política Firefox aplicada usando XPI assinado",
                    )
                )
            elif config.firefox_signed_xpi:
                results.append(
                    BrowserSetupResult(
                        browser,
                        "distribution_ready",
                        "XPI assinado configurado; habilite managed_policy_install",
                    )
                )
            else:
                results.append(
                    BrowserSetupResult(
                        browser,
                        "signature_required",
                        "detectado; falta XPI assinado/publicado",
                    )
                )

    return browsers, results, packages


def print_browser_setup(
    results: list[BrowserSetupResult],
    packages: tuple[Path, Path],
) -> None:
    print()
    print(" Navegadores / Qproxy Companion:")

    if not results:
        print("   Nenhum Chrome, Edge, Firefox ou Brave detectado.")

    labels = {
        "detected": "DETECTADO",
        "publication_required": "AGUARDANDO PUBLICAÇÃO",
        "signature_required": "AGUARDANDO ASSINATURA",
        "distribution_ready": "PRONTO PARA INSTALAR",
        "install_configured": "INSTALAÇÃO CONFIGURADA",
    }

    for result in results:
        label = labels.get(result.status, result.status.upper())
        print(f"   - {result.browser.name}: {label}")
        print(f"     {result.detail}")

    print(f"   Pacote Chrome/Edge/Brave: {packages[0]}")
    print(f"   Pacote Firefox:           {packages[1]}")
