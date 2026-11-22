import ctypes
import hashlib
import io
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch
import zipfile

from qproxy import windivert, windivert_setup, windows_net


class _FakeWinDivertDll:
    def __init__(self, fail_open: bool = False):
        self.fail_open = fail_open
        self.calls: list[tuple[str, tuple]] = []
        self.recv_packets: list[tuple[bytes, int]] = []
        self.last_error = 0
        self.WinDivertOpen = MagicMock(side_effect=self._open)
        self.WinDivertRecv = MagicMock(side_effect=self._recv)
        self.WinDivertSend = MagicMock(side_effect=self._send)
        self.WinDivertHelperCalcChecksums = MagicMock(return_value=1)
        self.WinDivertSetParam = MagicMock(return_value=1)
        self.WinDivertShutdown = MagicMock(return_value=1)
        self.WinDivertClose = MagicMock(return_value=1)

    def _open(self, filter_b, layer, priority, flags):
        self.calls.append(("open", (filter_b, layer, priority, flags)))
        if self.fail_open:
            self.last_error = 5  # ERROR_ACCESS_DENIED
            return ctypes.c_void_p(-1).value
        return 0x1234

    def _recv(self, handle, buf, buf_len, recv_len_ptr, addr_ptr):
        if not self.recv_packets:
            self.last_error = 232  # ERROR_NO_DATA
            return 0
        item = self.recv_packets.pop(0)
        if isinstance(item, int):
            self.last_error = item
            return 0
        payload, outbound = item
        ctypes.memmove(buf, payload, len(payload))
        recv_len_ptr._obj.value = len(payload)
        addr_ptr._obj.Outbound = 1 if outbound else 0
        addr_ptr._obj.Network.IfIdx = 9
        return 1

    def _send(self, handle, buf, pkt_len, send_len_ptr, addr_ptr):
        self.calls.append(("send", (pkt_len, addr_ptr._obj.Outbound)))
        send_len_ptr._obj.value = pkt_len
        return 1


class WinDivertBindingTests(unittest.TestCase):
    def test_windivert_error_messages_and_helpers(self):
        err_known = windivert.WinDivertError(5, "Falha")
        self.assertEqual(err_known.winerror, 5)
        self.assertIn("Administrador", str(err_known))

        err_unknown = windivert.WinDivertError(99999, "Outro erro")
        self.assertIn("99999", str(err_unknown))
        self.assertIsInstance(windivert.is_64bit_python(), bool)

    def test_load_dll_rejects_non_windows(self):
        with patch.object(windivert.sys, "platform", "linux"):
            with self.assertRaises(RuntimeError):
                windivert._load_windivert_dll(Path("WinDivert.dll"))

    def test_windivert_handle_lifecycle_with_mock_dll(self):
        fake_dll = _FakeWinDivertDll()
        fake_dll.recv_packets.append((b"\x45\x00\x00\x20" + b"\xaa" * 28, 1))

        with (
            patch.object(windivert.sys, "platform", "win32"),
            patch("qproxy.windivert.ctypes.CDLL", return_value=fake_dll),
            patch("qproxy.windivert.ctypes.get_last_error", side_effect=lambda: fake_dll.last_error, create=True),
        ):
            handle = windivert.WinDivertHandle(Path("WinDivert.dll"), "udp.DstPort == 53")
            handle.configure_queues(queue_length=4096, queue_time_ms=1000, queue_size_bytes=1024 * 1024)
            self.assertEqual(fake_dll.WinDivertSetParam.call_count, 3)

            item = handle.recv()
            self.assertIsNotNone(item)
            raw, addr = item
            self.assertEqual(len(raw), 32)
            self.assertEqual(addr.Outbound, 1)
            self.assertEqual(addr.Network.IfIdx, 9)

            self.assertTrue(handle.send(raw, addr, recalc_checksums=True))
            self.assertEqual(fake_dll.WinDivertHelperCalcChecksums.call_count, 1)

            # ERROR_NO_DATA (232) após shutdown limpo retorna None
            self.assertIsNone(handle.recv())

            # Erro fatal no recv levanta WinDivertError
            fake_dll.recv_packets.append(87)
            with self.assertRaises(windivert.WinDivertError):
                handle.recv()

            handle.shutdown()
            handle.close()
            # close() idempotente
            handle.close()
            self.assertEqual(fake_dll.WinDivertClose.call_count, 1)

    def test_windivert_open_failure_raises_descriptive_error(self):
        fail_dll = _FakeWinDivertDll(fail_open=True)
        with (
            patch.object(windivert.sys, "platform", "win32"),
            patch("qproxy.windivert.ctypes.CDLL", return_value=fail_dll),
            patch("qproxy.windivert.ctypes.get_last_error", side_effect=lambda: fail_dll.last_error, create=True),
        ):
            with self.assertRaises(windivert.WinDivertError) as ctx:
                windivert.WinDivertHandle(Path("WinDivert.dll"), "true")
            self.assertEqual(ctx.exception.winerror, 5)


class WinDivertSetupTests(unittest.TestCase):
    def test_find_install_download_and_status(self):
        with tempfile.TemporaryDirectory() as d:
            root = Path(d)
            arch, sys_name = windivert_setup._arch_folder()

            # Inicialmente ausente
            self.assertIsNone(windivert_setup.find_windivert_dll(root / "missing", root))

            buf = io.BytesIO()
            with zipfile.ZipFile(buf, "w") as zf:
                zf.writestr(f"WinDivert-2.2.2-A/{arch}/WinDivert.dll", b"dll-ok")
                zf.writestr(f"WinDivert-2.2.2-A/{arch}/{sys_name}", b"sys-ok")
            zip_bytes = buf.getvalue()
            expected_sha = hashlib.sha256(zip_bytes).hexdigest()

            class _FakeResp:
                def __enter__(self):
                    return self
                def __exit__(self, *args):
                    return None
                def read(self, _n=-1):
                    return zip_bytes

            target = root / "data" / "windivert"
            with (
                patch.object(windivert_setup, "WINDIVERT_ZIP_SHA256", expected_sha),
                patch("qproxy.windivert_setup.urlopen", return_value=_FakeResp()),
            ):
                dll_path = windivert_setup.download_and_install_windivert(target)
                self.assertTrue(dll_path.is_file())
                self.assertTrue((target / sys_name).is_file())

            found = windivert_setup.find_windivert_dll(root / "other", root)
            self.assertEqual(found, dll_path)

            status = windivert_setup.windivert_status(target, root)
            self.assertTrue(status["installed"])
            self.assertEqual(status["arch"], arch)
            self.assertEqual(status["dll_path"], str(dll_path))

            # Arquivo ZIP incompleto levanta FileNotFoundError
            bad_buf = io.BytesIO()
            with zipfile.ZipFile(bad_buf, "w") as zf:
                zf.writestr("README.txt", b"no binaries")
            with self.assertRaises(FileNotFoundError):
                windivert_setup.install_windivert_from_zip_bytes(
                    bad_buf.getvalue(), root / "empty_wd", verify_sha256=False
                )


class WindowsNetTests(unittest.TestCase):
    def test_non_windows_guards_and_mocked_windows_dns_flow(self):
        with patch.object(windows_net, "IS_WINDOWS", False):
            self.assertFalse(windows_net.is_admin())
            self.assertFalse(windows_net.relaunch_as_admin(Path("main.py"), []))
            self.assertFalse(windows_net.flush_windows_dns_cache())
            self.assertEqual(windows_net.capture_windows_dns(), [])
            self.assertFalse(windows_net.set_windows_dns_local([{"ifIndex": 1}]))
            self.assertFalse(windows_net.restore_windows_dns([{"ifIndex": 1}]))
            self.assertFalse(windows_net.restore_dns_backup_if_present(Path("missing.json")))

        with tempfile.TemporaryDirectory() as d:
            backup = Path(d) / "windows_dns_backup.json"
            ps_calls: list[str] = []

            def fake_run(cmd, **_kwargs):
                if cmd[0] == "ipconfig":
                    return subprocess.CompletedProcess(cmd, 0, "OK", "")
                script = cmd[-1]
                ps_calls.append(script)
                if "ConvertTo-Json" in script:
                    payload = {"ifIndex": 11, "name": "Ethernet", "ipv4": ["192.168.1.1"], "ipv6": ["::1", "fe80::1"]}
                    return subprocess.CompletedProcess(cmd, 0, json.dumps(payload), "")
                return subprocess.CompletedProcess(cmd, 0, "", "")

            fake_shell32 = MagicMock()
            fake_shell32.IsUserAnAdmin.return_value = 1
            fake_shell32.ShellExecuteW.return_value = 42

            with (
                patch.object(windows_net, "IS_WINDOWS", True),
                patch.object(windows_net, "ctypes", create=True) as mock_ctypes,
                patch("qproxy.windows_net.subprocess.run", side_effect=fake_run),
            ):
                mock_ctypes.windll.shell32 = fake_shell32
                self.assertTrue(windows_net.is_admin())
                self.assertTrue(windows_net.relaunch_as_admin(Path(d) / "main.py", ["--mode", "auto"]))
                self.assertTrue(windows_net.flush_windows_dns_cache())

                captured = windows_net.capture_windows_dns()
                self.assertEqual(len(captured), 1)
                self.assertEqual(captured[0]["ifIndex"], 11)

                windows_net.write_dns_backup(backup, captured)
                self.assertTrue(backup.is_file())

                self.assertTrue(windows_net.set_windows_dns_local(captured))
                self.assertIn("'127.0.0.1','::1'", ps_calls[-1])

                # Restauração preserva IPs originais e exclui ::1/127.0.0.1 do Qproxy
                self.assertTrue(windows_net.restore_dns_backup_if_present(backup))
                self.assertFalse(backup.exists())
                self.assertIn("'192.168.1.1','fe80::1'", ps_calls[-1])

                # Adaptador sem DNS fixo -> ResetServerAddresses
                self.assertTrue(windows_net.restore_windows_dns([{"ifIndex": 15, "ipv4": ["127.0.0.1"], "ipv6": []}]))
                self.assertIn("ResetServerAddresses", ps_calls[-1])


if __name__ == "__main__":
    unittest.main()
