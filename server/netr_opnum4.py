import os
from typing import Optional, Tuple
from impacket.dcerpc.v5 import rpcrt

from utils_lsa import _build_fault_co

# --- Мини NDR helpers ---

class NDRPull:
    def __init__(self, data: bytes):
        self._b = memoryview(data)
        self._o = 0

    def align(self, a: int):
        m = self._o % a
        if m:
            self._o += (a - m)

    def u32(self) -> int:
        self.align(4)
        v = int.from_bytes(self._b[self._o:self._o+4], "little", signed=False)
        self._o += 4
        return v

    def u16(self) -> int:
        self.align(2)
        v = int.from_bytes(self._b[self._o:self._o+2], "little", signed=False)
        self._o += 2
        return v

    def read(self, n: int) -> bytes:
        v = self._b[self._o:self._o+n].tobytes()
        self._o += n
        return v

def _ndr_pull_LPWSTR(n: NDRPull) -> Optional[str]:
    """
    [unique, string, wchar_t*] LPWSTR (conformant/varying)
    Формат:
      - ptr (uint32 ref-id, 0=Null)
      - MaxCount (u32), Offset (u32), ActualCount (u32)
      - ActualCount * 2 байта UTF-16LE
    """
    ref = n.u32()
    if ref == 0:
        return None
    # conformant + varying
    max_count = n.u32()
    _offset   = n.u32()
    act_count = n.u32()
    if act_count == 0:
        return ""
    raw = n.read(act_count * 2)
    # Часто завершается нулём; безопасноrstrip:
    s = raw.decode("utf-16le", errors="ignore")
    # c брасываем финальный нулевой символ, если он есть
    if s and s[-1] == "\x00":
        s = s[:-1]
    return s

# --- Локальный билдер RESPONSE CO (если нет своего) ---

def _build_response_co_local(call_id: int, stub_out: bytes) -> bytes:
    """
    Минимальный MSRPC CO RESPONSE без аутентификатора (auth_length=0).
    """
    resp = rpcrt.MSRPCResponseHeader()
    resp["type"]               = rpcrt.MSRPC_RESPONSE
    resp["flags"]              = rpcrt.MSRPC_FIRST_FRAG | rpcrt.MSRPC_LAST_FRAG
    resp["auth_length"]        = 0
    resp["call_id"]            = call_id
    resp["alloc_hint"]         = len(stub_out)
    resp["p_cont_id"]          = 0
    resp["cancel_count"]       = 0
    resp["reserved"]           = 0
    return resp.get_packet() + stub_out

# --- Хранилище «schannel»-состояния на соединение ---

def _get_conn_key(server, req: rpcrt.MSRPCRequestHeader) -> Tuple[str, int]:
    """
    Простая привязка state к клиентскому сокету. Подстрой под свой сервер при желании.
    """
    try:
        peer = server.request.getpeername()   # (ip, port)
        return (peer[0], int(peer[1]))
    except Exception:
        return ("0.0.0.0", int(req["call_id"]))

def _schannel_get_map(server) -> dict:
    if not hasattr(server, "_schannel_map"):
        server._schannel_map = {}
    return server._schannel_map

# --- Собственно opnum 4 ---

def ServerReqChallenge(server, req: rpcrt.MSRPCRequestHeader, stub_in: bytes) -> Optional[bytes]:
    """
    [MS-NRPC] netr_ServerReqChallenge (opnum 4)
      IN:  ServerName (LPWSTR, unique)
           ComputerName (LPWSTR, unique)
           ClientChallenge[8]
      OUT: ServerChallenge[8]
           NTSTATUS
    """
    try:
        # 1) Разбор IN-аргументов
        n = NDRPull(stub_in)
        server_name   = _ndr_pull_LPWSTR(n)   # может быть None — это нормально
        computer_name = _ndr_pull_LPWSTR(n)
        client_chal   = n.read(8)
        if len(client_chal) != 8:
            # некорректный stub — вернём FAULT
            return _build_fault_co(call_id=int(req['call_id']), status=rpcrt.NCA_S_FAULT_UNSPEC)

        # 2) Генерация server challenge
        server_chal = os.urandom(8)

        # 3) Сохранить pair в состоянии соединения (по аналогии с Samba)
        sch_map = _schannel_get_map(server)
        ckey    = _get_conn_key(server, req)
        sch_map[ckey] = {
            "client_challenge": client_chal,
            "server_challenge": server_chal,
            "computer_name": computer_name or "",
            "server_name":   server_name or "",
        }

        # 4) Сборка OUT stub: 8 байт + NTSTATUS(0)
        # Пушер тут не обязателен — структура очень простая
        stub_out = server_chal + (0).to_bytes(4, "little", signed=False)

        # 5) Обернуть в MSRPC RESPONSE
        # Если у тебя есть свой билдер ответа — используй его.
        return _build_response_co_local(call_id=int(req['call_id']), stub_out=stub_out)

    except Exception:
        return _build_fault_co(call_id=int(req['call_id']), status=rpcrt.NCA_S_FAULT_UNSPEC)
