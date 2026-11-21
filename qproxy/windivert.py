"""Binding ctypes nativo para o driver de pacotes WinDivert 2.2 (Windows WFP).

Não requer compilador C nem pacotes externos: carrega `WinDivert.dll` (junto
ao driver assinado `WinDivert64.sys` ou `WinDivert32.sys`) diretamente via
`ctypes` com layout binário exato da ABI WinDivert 2.2 (`sizeof == 80`).
"""
from __future__ import annotations

import ctypes
from pathlib import Path
import struct
import sys


WINDIVERT_LAYER_NETWORK = 0
WINDIVERT_SHUTDOWN_RECV = 0x1
WINDIVERT_SHUTDOWN_SEND = 0x2
WINDIVERT_SHUTDOWN_BOTH = 0x3

WINDIVERT_PARAM_QUEUE_LENGTH = 0
WINDIVERT_PARAM_QUEUE_TIME = 1
WINDIVERT_PARAM_QUEUE_SIZE = 2

_INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

_ERROR_HINTS = {
    2: "Driver WinDivert64.sys/WinDivert32.sys não encontrado ao lado de WinDivert.dll.",
    5: "Acesso negado: execute o Qproxy como Administrador para filtrar pacotes do Windows.",
    87: "Expressão de filtro ou parâmetro WinDivert inválido.",
    577: "Assinatura digital do driver WinDivert inválida.",
    654: "Outra versão incompatível do driver WinDivert já está carregada no sistema.",
    1060: "Serviço do driver WinDivert não instalado.",
    1275: "Driver WinDivert bloqueado pelo Windows Defender/antivírus ou política de segurança.",
    1753: "Serviço Base Filtering Engine (BFE) do Windows está desativado.",
}


class WinDivertError(OSError):
    def __init__(self, code: int, message: str) -> None:
        self.winerror = code
        hint = _ERROR_HINTS.get(code, "")
        detail = f"{message} (código Windows {code})" + (f": {hint}" if hint else "")
        super().__init__(detail)


class WinDivertDataNetwork(ctypes.Structure):
    _fields_ = [
        ("IfIdx", ctypes.c_uint32),
        ("SubIfIdx", ctypes.c_uint32),
    ]


class _WinDivertAddressUnion(ctypes.Union):
    _fields_ = [
        ("Network", WinDivertDataNetwork),
        ("Reserved3", ctypes.c_uint8 * 64),
    ]


class WinDivertAddress(ctypes.Structure):
    """Layout exato de WINDIVERT_ADDRESS (WinDivert 2.2, 80 bytes)."""

    _anonymous_ = ("_data",)
    _fields_ = [
        ("Timestamp", ctypes.c_int64),
        ("Layer", ctypes.c_uint64, 8),
        ("Event", ctypes.c_uint64, 8),
        ("Sniffed", ctypes.c_uint64, 1),
        ("Outbound", ctypes.c_uint64, 1),
        ("Loopback", ctypes.c_uint64, 1),
        ("Impostor", ctypes.c_uint64, 1),
        ("IPv6", ctypes.c_uint64, 1),
        ("IPChecksum", ctypes.c_uint64, 1),
        ("TCPChecksum", ctypes.c_uint64, 1),
        ("UDPChecksum", ctypes.c_uint64, 1),
        ("Reserved1", ctypes.c_uint64, 40),
        ("_data", _WinDivertAddressUnion),
    ]


assert ctypes.sizeof(WinDivertAddress) == 80, f"WINDIVERT_ADDRESS != 80 ({ctypes.sizeof(WinDivertAddress)})"
assert ctypes.sizeof(WinDivertDataNetwork) == 8


def clone_address_for_direction(
    source: WinDivertAddress,
    outbound: bool,
    is_ipv6: bool | None = None,
) -> WinDivertAddress:
    """Clona um WINDIVERT_ADDRESS preservando IfIdx/SubIfIdx com direção configurável."""
    addr = WinDivertAddress()
    addr.Layer = WINDIVERT_LAYER_NETWORK
    addr.Event = 0
    addr.Sniffed = 0
    addr.Outbound = 1 if outbound else 0
    addr.Loopback = 0
    addr.Impostor = 0
    addr.IPv6 = (1 if is_ipv6 else 0) if is_ipv6 is not None else source.IPv6
    addr.IPChecksum = 0
    addr.TCPChecksum = 0
    addr.UDPChecksum = 0
    addr.Network.IfIdx = source.Network.IfIdx
    addr.Network.SubIfIdx = source.Network.SubIfIdx
    return addr


def _load_windivert_dll(dll_path: Path):
    if sys.platform != "win32":
        raise RuntimeError("WinDivert é exclusivo para Windows")
    dll = ctypes.CDLL(str(dll_path), use_last_error=True)

    dll.WinDivertOpen.argtypes = [ctypes.c_char_p, ctypes.c_int, ctypes.c_int16, ctypes.c_uint64]
    dll.WinDivertOpen.restype = ctypes.c_void_p

    dll.WinDivertRecv.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(WinDivertAddress),
    ]
    dll.WinDivertRecv.restype = ctypes.c_int

    dll.WinDivertSend.argtypes = [
        ctypes.c_void_p,
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.POINTER(ctypes.c_uint),
        ctypes.POINTER(WinDivertAddress),
    ]
    dll.WinDivertSend.restype = ctypes.c_int

    dll.WinDivertHelperCalcChecksums.argtypes = [
        ctypes.c_void_p,
        ctypes.c_uint,
        ctypes.POINTER(WinDivertAddress),
        ctypes.c_uint64,
    ]
    dll.WinDivertHelperCalcChecksums.restype = ctypes.c_int

    dll.WinDivertSetParam.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_uint64]
    dll.WinDivertSetParam.restype = ctypes.c_int

    dll.WinDivertShutdown.argtypes = [ctypes.c_void_p, ctypes.c_int]
    dll.WinDivertShutdown.restype = ctypes.c_int

    dll.WinDivertClose.argtypes = [ctypes.c_void_p]
    dll.WinDivertClose.restype = ctypes.c_int
    return dll


class WinDivertHandle:
    """Handle gerenciado para captura, modificação e injeção de pacotes no kernel do Windows."""

    def __init__(
        self,
        dll_path: Path,
        filter_expr: str,
        layer: int = WINDIVERT_LAYER_NETWORK,
        priority: int = 0,
        flags: int = 0,
    ) -> None:
        self._dll = _load_windivert_dll(dll_path)
        self._closed = False
        handle = self._dll.WinDivertOpen(
            filter_expr.encode("ascii"),
            int(layer),
            int(priority),
            int(flags),
        )
        if not handle or handle == _INVALID_HANDLE_VALUE:
            err = ctypes.get_last_error()
            raise WinDivertError(err, "Falha ao abrir filtro WinDivert")
        self._handle = handle
        self._recv_buf = (ctypes.c_ubyte * 65535)()
        self._recv_len = ctypes.c_uint(0)

    def configure_queues(
        self,
        queue_length: int = 8192,
        queue_time_ms: int = 2000,
        queue_size_bytes: int = 16 * 1024 * 1024,
    ) -> None:
        self._dll.WinDivertSetParam(self._handle, WINDIVERT_PARAM_QUEUE_LENGTH, int(queue_length))
        self._dll.WinDivertSetParam(self._handle, WINDIVERT_PARAM_QUEUE_TIME, int(queue_time_ms))
        self._dll.WinDivertSetParam(self._handle, WINDIVERT_PARAM_QUEUE_SIZE, int(queue_size_bytes))

    def recv(self) -> tuple[bytes, WinDivertAddress] | None:
        """Recebe próximo pacote capturado pelo kernel. Retorna None após shutdown limpo."""
        addr = WinDivertAddress()
        ok = self._dll.WinDivertRecv(
            self._handle,
            self._recv_buf,
            len(self._recv_buf),
            ctypes.byref(self._recv_len),
            ctypes.byref(addr),
        )
        if not ok:
            err = ctypes.get_last_error()
            # 232 = ERROR_NO_DATA (shutdown limpo), 995 = ERROR_OPERATION_ABORTED
            if err in (232, 995):
                return None
            raise WinDivertError(err, "Falha em WinDivertRecv")
        length = self._recv_len.value
        return bytes(memoryview(self._recv_buf)[:length]), addr

    def send(self, packet: bytes, addr: WinDivertAddress, recalc_checksums: bool = False) -> bool:
        buf = (ctypes.c_ubyte * len(packet)).from_buffer_copy(packet)
        if recalc_checksums:
            self._dll.WinDivertHelperCalcChecksums(buf, len(packet), ctypes.byref(addr), 0)
        sent = ctypes.c_uint(0)
        ok = self._dll.WinDivertSend(
            self._handle,
            buf,
            len(packet),
            ctypes.byref(sent),
            ctypes.byref(addr),
        )
        return bool(ok)

    def shutdown(self) -> None:
        if not self._closed and self._handle:
            self._dll.WinDivertShutdown(self._handle, WINDIVERT_SHUTDOWN_BOTH)

    def close(self) -> None:
        if not self._closed and self._handle:
            self._closed = True
            self._dll.WinDivertShutdown(self._handle, WINDIVERT_SHUTDOWN_BOTH)
            self._dll.WinDivertClose(self._handle)
            self._handle = None


def is_64bit_python() -> bool:
    return struct.calcsize("P") * 8 == 64
