import asyncio
import contextlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

import main as launcher
from qproxy import cli
from qproxy.config import Config, RemoteListSource
from qproxy.dns_cache import DnsPacketCache, HostAddressCache
from qproxy.stats import StatsStore


class _FakeWinReg:
    HKEY_CURRENT_USER = 1
    KEY_READ = 1
    KEY_SET_VALUE = 2
    REG_SZ = 1
    REG_DWORD = 4

    def __init__(self, initial: dict | None = None):
        self.store: dict[str, tuple[object, int]] = dict(initial or {})

    class _KeyCtx:
        def __init__(self, store):
            self.store = store
        def __enter__(self):
            return self
        def __exit__(self, *args):
            return None

    def OpenKey(self, *_args):
        return self._KeyCtx(self.store)

    def QueryValueEx(self, key, name):
        if name not in key.store:
            raise FileNotFoundError(name)
        return key.store[name]

    def SetValueEx(self, key, name, _reserved, vtype, value):
        key.store[name] = (value, vtype)

    def DeleteValue(self, key, name):
        if name not in key.store:
            raise FileNotFoundError(name)
        del key.store[name]


class CliTests(unittest.TestCase):
    def test_resolve_and_build_runtime(self):
        base = Path("/tmp/qproxy_base")
        self.assertEqual(cli._resolve(base, "data/a.txt"), (base / "data/a.txt").resolve())
        abs_p = str(Path("/tmp/abs.txt").resolve())
        self.assertEqual(cli._resolve(base, abs_p), Path(abs_p))

        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            (root / "data").mkdir()
            (root / "data" / "blocklist.txt").write_text("ads.test\n", encoding="utf-8")
            (root / "data" / "whitelist.txt").write_text("safe.test\n", encoding="utf-8")
            cfg_path = root / "cfg.json"
            cfg_path.write_text(
                json.dumps(
                    {
                        "blocklists": ["data/blocklist.txt"],
                        "whitelists": ["data/whitelist.txt"],
                        "manual_blocklist_file": "data/manual.txt",
                        "remote_blocklists": [
                            {"name": "Custom", "url": "https://example.test/list.txt", "category": "tracker"}
                        ],
                    }
                ),
                encoding="utf-8",
            )
            cfg = Config.load(cfg_path)
            rules, stats, updater = cli.build_runtime(cfg, str(cfg_path))
            self.assertTrue(rules.is_blocked("ads.test"))
            self.assertFalse(rules.is_blocked("safe.test"))
            self.assertEqual(updater.sources[0].category, "tracker")
            stats.save()
            self.assertTrue((root / "data" / "stats.json").is_file())

    def test_resolve_effective_mode_matrix(self):
        with tempfile.TemporaryDirectory() as d:
            base = Path(d)
            fake_dll = base / "data" / "windivert" / "WinDivert.dll"
            fake_dll.parent.mkdir(parents=True)
            fake_dll.write_bytes(b"dll")

            # Fora do Windows -> proxy
            cfg = Config(mode="packet")
            with patch.object(cli.sys, "platform", "linux"), patch("qproxy.cli.is_windows_admin", return_value=False):
                mode, dll, hint = cli._resolve_effective_mode(cfg, base)
                self.assertEqual(mode, "proxy")
                self.assertIsNone(dll)
                self.assertIn("Windows", hint)

            # Windows sem Admin -> proxy
            with (
                patch.object(cli.sys, "platform", "win32"),
                patch("qproxy.cli.is_windows_admin", return_value=False),
                patch("qproxy.cli.find_windivert_dll", return_value=fake_dll),
            ):
                self.assertEqual(cli._resolve_effective_mode(Config(mode="auto"), base)[0], "proxy")
                self.assertEqual(cli._resolve_effective_mode(Config(mode="packet"), base)[0], "proxy")
                self.assertEqual(cli._resolve_effective_mode(Config(mode="hybrid"), base)[0], "proxy")

            # Windows com Admin + WinDivert -> packet / hybrid
            with (
                patch.object(cli.sys, "platform", "win32"),
                patch("qproxy.cli.is_windows_admin", return_value=True),
                patch("qproxy.cli.find_windivert_dll", return_value=fake_dll),
            ):
                mode, dll, _ = cli._resolve_effective_mode(Config(mode="auto"), base)
                self.assertEqual((mode, dll), ("packet", fake_dll))
                self.assertEqual(cli._resolve_effective_mode(Config(mode="hybrid"), base)[0], "hybrid")
                self.assertEqual(cli._resolve_effective_mode(Config(mode="dns"), base)[0], "dns")
                self.assertEqual(cli._resolve_effective_mode(Config(mode="proxy"), base)[0], "proxy")

            # Windows com Admin sem WinDivert -> fallback para dns + tentativa opcional de auto_download
            cfg_dl = Config(mode="packet")
            cfg_dl.packet_filter.auto_download_windivert = True
            with (
                patch.object(cli.sys, "platform", "win32"),
                patch("qproxy.cli.is_windows_admin", return_value=True),
                patch("qproxy.cli.find_windivert_dll", return_value=None),
                patch("qproxy.cli.download_and_install_windivert", return_value=fake_dll),
            ):
                self.assertEqual(cli._resolve_effective_mode(cfg_dl, base)[:2], ("packet", fake_dll))

            with (
                patch.object(cli.sys, "platform", "win32"),
                patch("qproxy.cli.is_windows_admin", return_value=True),
                patch("qproxy.cli.find_windivert_dll", return_value=None),
                patch("qproxy.cli.download_and_install_windivert", side_effect=OSError("offline")),
            ):
                self.assertEqual(cli._resolve_effective_mode(cfg_dl, base)[0], "dns")
                self.assertEqual(cli._resolve_effective_mode(Config(mode="auto"), base)[0], "dns")

    def test_cli_main_flags_update_lists_and_install_windivert(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg_path = root / "cfg.json"
            cfg_path.write_text(
                json.dumps(
                    {
                        "blocklists": [],
                        "whitelists": [],
                        "remote_blocklists": [],
                        "remote_cache_dir": str(root / "remote"),
                        "stats_file": str(root / "stats.json"),
                        "manual_blocklist_file": str(root / "manual.txt"),
                    }
                ),
                encoding="utf-8",
            )
            buf_lists = io.StringIO()
            with (
                patch.object(sys, "argv", ["qproxy", "--config", str(cfg_path), "--update-lists"]),
                patch("qproxy.cli.BlocklistUpdater.refresh", return_value=[]) as mock_refresh,
                contextlib.redirect_stdout(buf_lists),
            ):
                cli.main()
                self.assertEqual(mock_refresh.call_count, 1)
            self.assertIn("Listas atualizadas", buf_lists.getvalue())

            fake_dll = root / "wd" / "WinDivert.dll"
            buf_wd = io.StringIO()
            with (
                patch.object(sys, "argv", ["qproxy", "--config", str(cfg_path), "--install-windivert"]),
                patch("qproxy.cli.download_and_install_windivert", return_value=fake_dll) as mock_dl,
                contextlib.redirect_stdout(buf_wd),
            ):
                cli.main()
                self.assertEqual(mock_dl.call_count, 1)
            self.assertIn("WinDivert", buf_wd.getvalue())


class CliAsyncRuntimeTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_packet_filter_and_dns_fallback(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            cfg = Config(mode="packet", update_on_start=False)
            cfg.remote_blocklists = []
            cfg.blocklists = []
            cfg.whitelists = []
            rules, stats, updater = cli.build_runtime(cfg, str(root / "cfg.json"))
            dns_cache = DnsPacketCache()
            host_cache = HostAddressCache()
            state: dict = {"ready": False}

            fake_filter = MagicMock()
            fake_filter.active_layers.return_value = ["DNS (UDP 53)", "TLS SNI (TCP 443)"]

            with (
                patch("qproxy.cli._resolve_effective_mode", return_value=("packet", root / "WinDivert.dll", "")),
                patch("qproxy.cli.WindowsPacketFilter", return_value=fake_filter),
                patch("qproxy.cli.flush_windows_dns_cache"),
            ):
                task = asyncio.create_task(
                    cli._run(cfg, root, rules, stats, updater, dns_cache, host_cache, state)
                )
                for _ in range(40):
                    if state.get("ready"):
                        break
                    await asyncio.sleep(0.02)
                self.assertTrue(state["ready"])
                self.assertTrue(state["windivert_active"])
                fake_filter.start.assert_called_once()
                task.cancel()
                with self.assertRaises(asyncio.CancelledError):
                    await task
                fake_filter.stop.assert_called_once()

            # DNS mode quando porta 53 falha -> fallback para ProxyServer
            cfg_dns = Config(mode="dns", update_on_start=False)
            cfg_dns.dns_server.listen_port = 53
            state2: dict = {"ready": False}
            fake_proxy = MagicMock()
            fake_proxy.serve = MagicMock(side_effect=lambda: asyncio.sleep(5))
            with (
                patch("qproxy.cli._resolve_effective_mode", return_value=("dns", None, "")),
                patch("qproxy.cli.LocalDnsServer.start", side_effect=OSError("port in use")),
                patch("qproxy.cli.ProxyServer", return_value=fake_proxy),
            ):
                task2 = asyncio.create_task(
                    cli._run(cfg_dns, root, rules, stats, updater, dns_cache, host_cache, state2)
                )
                for _ in range(40):
                    if state2.get("ready"):
                        break
                    await asyncio.sleep(0.02)
                self.assertTrue(state2["ready"])
                self.assertEqual(state2["mode"], "proxy")
                self.assertTrue(state2["proxy_active"])
                task2.cancel()
                await asyncio.gather(task2, return_exceptions=True)


class WindowsLauncherTests(unittest.TestCase):
    def test_proxy_registry_backup_enable_and_recover(self):
        with tempfile.TemporaryDirectory() as d:
            data_dir = Path(d) / "data"
            backup_file = data_dir / "windows_proxy_backup.json"
            dns_backup = data_dir / "windows_dns_backup.json"
            fake_reg = _FakeWinReg({"ProxyEnable": (0, 4), "ProxyOverride": ("intranet", 1)})
            fake_wininet = MagicMock()

            with (
                patch.object(launcher, "IS_WINDOWS", True),
                patch.object(launcher, "DATA_DIR", data_dir),
                patch.object(launcher, "BACKUP_FILE", backup_file),
                patch.object(launcher, "DNS_BACKUP_FILE", dns_backup),
                patch.object(launcher, "winreg", fake_reg, create=True),
                patch.object(launcher.ctypes, "windll", create=True) as mock_windll,
                patch("main.port_open", return_value=False),
            ):
                mock_windll.Wininet = fake_wininet
                snap = launcher.capture_windows_proxy()
                launcher.write_backup(snap)
                launcher.enable_windows_proxy(snap, "127.0.0.1", 8899)
                self.assertTrue(launcher.windows_proxy_points_to_qproxy())
                self.assertIn("intranet", fake_reg.store["ProxyOverride"][0])
                self.assertIn("localhost", fake_reg.store["ProxyOverride"][0])

                buf_rec = io.StringIO()
                with contextlib.redirect_stdout(buf_rec):
                    self.assertTrue(launcher.recover_stale_proxy())
                    self.assertFalse(backup_file.exists())
                    self.assertEqual(fake_reg.store["ProxyEnable"][0], 0)

                    # Sem arquivo de backup, mas com proxy apontando para Qproxy -> desativa
                    launcher.enable_windows_proxy(snap, "127.0.0.1", 8899)
                    self.assertTrue(launcher.recover_stale_proxy())
                    self.assertEqual(fake_reg.store["ProxyEnable"][0], 0)
                self.assertIn("Qproxy", buf_rec.getvalue())

    def test_choose_mode_wait_for_port_and_cli_paths(self):
        cfg = Config(mode="auto")
        with (
            patch("main.is_admin", return_value=True),
            patch("main.find_windivert_dll", return_value=Path("WinDivert.dll")),
        ):
            self.assertEqual(launcher._choose_windows_mode(cfg, None), "packet")

        with (
            patch("main.is_admin", return_value=True),
            patch("main.find_windivert_dll", return_value=None),
        ):
            self.assertEqual(launcher._choose_windows_mode(cfg, "packet"), "dns")

        with (
            patch("main.is_admin", return_value=False),
            patch("main.find_windivert_dll", return_value=None),
        ):
            self.assertEqual(launcher._choose_windows_mode(cfg, "auto"), "proxy")

        # wait_for_port quando processo morre imediatamente
        dead_proc = MagicMock()
        dead_proc.poll.return_value = 1
        with patch("main.port_open", return_value=False):
            self.assertFalse(launcher.wait_for_port("127.0.0.1", 8899, dead_proc, timeout=0.5))

        # run() fora do Windows retorna 2
        buf_nonwin = io.StringIO()
        with patch.object(launcher, "IS_WINDOWS", False), contextlib.redirect_stdout(buf_nonwin):
            self.assertEqual(launcher.run(Path("config.example.json"), open_browser=False), 2)
        self.assertIn("Windows", buf_nonwin.getvalue())

    def test_watchdog_and_main_entrypoint(self):
        with (
            patch.object(launcher, "IS_WINDOWS", True),
            patch("main._wait_for_parent_exit_windows") as mock_wait,
            patch("main.restore_backup_if_present") as mock_proxy_rest,
            patch("main.restore_dns_backup_if_present") as mock_dns_rest,
            patch("main._terminate_pid_windows") as mock_term,
        ):
            rc = launcher.watchdog_mode(100, 200)
            self.assertEqual(rc, 0)
            mock_wait.assert_called_once_with(100)
            mock_proxy_rest.assert_called_once()
            mock_dns_rest.assert_called_once()
            mock_term.assert_called_once_with(200)

        buf_rest = io.StringIO()
        with (
            patch.object(launcher, "IS_WINDOWS", True),
            patch.object(sys, "argv", ["main.py", "--restore-network"]),
            patch("main.recover_stale_proxy", return_value=True),
            patch("main.flush_windows_dns_cache") as mock_flush,
            contextlib.redirect_stdout(buf_rest),
        ):
            self.assertEqual(launcher.main(), 0)
            mock_flush.assert_called_once()
        self.assertIn("Rede do Windows restaurada", buf_rest.getvalue())

        with (
            patch.object(launcher, "IS_WINDOWS", True),
            patch.object(sys, "argv", ["main.py", "--elevate", "--mode", "auto"]),
            patch("main.is_admin", return_value=False),
            patch("main.relaunch_as_admin", return_value=True) as mock_uac,
        ):
            self.assertEqual(launcher.main(), 0)
            mock_uac.assert_called_once()


if __name__ == "__main__":
    unittest.main()
