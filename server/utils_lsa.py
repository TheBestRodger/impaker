import struct
from typing import Tuple
import uuid
from impacket.dcerpc.v5 import rpcrt

#from ndr import NDRPush

from ndr import NDRPush
# ---- Вспомогалки CO ----
def _extract_request_stub_co(pdu: bytes) -> Tuple[bytes, bytes]:
    """
    Вернуть (stub_bytes, auth_trailer_bytes) из CO REQUEST PDU.
    Для простоты рассчитываем на отсутствие auth (bind_ack без auth).
    """
    req = rpcrt.MSRPCRequestHeader(pdu)
    frag_len = int(req['frag_len'])
    auth_len = int(req['auth_len'])
    # REQUEST: 16 (common) + 4 alloc_hint + 2 ctx_id + 2 opnum = 24
    stub_off = 16 + 8
    auth_total = 8 + auth_len if auth_len else 0
    stub_end = frag_len - auth_total
    if stub_end < stub_off:
        stub_end = stub_off
    return pdu[stub_off:stub_end], (pdu[stub_end:frag_len] if auth_total else b'')

def _pull_policy_info_level(stub_in: bytes) -> int:
    """
    В MS-LSAD уровень класса политики идёт сразу после входного POLICY_HANDLE.
    В минималке считаем, что это 16 бит (как в Samba IDL enum16).
    """
    if len(stub_in) < 22:
        return -1
    # [0:20] - handle, затем enum16 level (LE)
    return struct.unpack_from('<H', stub_in, 20)[0]

def _build_response_co(call_id: int, ctx_id: int, stub: bytes) -> bytes:
    """
    Build CO RESPONSE (ptype=2) with correct frag_len and alloc_hint.
    """
    alloc_hint = struct.pack('<I', len(stub))
    co = alloc_hint + struct.pack('<H', ctx_id) + b'\x00\x00'  # cancel_count=0, reserved=0
    body = co + stub
    ver, minor, ptype, pfc = 5, 0, 2, 0x03  # MSRPC_RESPONSE, FIRST|LAST
    drep = b'\x10\x00\x00\x00'  # LE/ASCII/IEEE
    frag_len = 16 + len(body)  # Ensure full length
    auth_len = 0
    hdr = struct.pack('<BBBB4sHHI', ver, minor, ptype, pfc, drep, frag_len, auth_len, call_id)
    print(f"[LSA] Response: frag_len={frag_len}, body_len={len(body)}, stub_len={len(stub)}")
    return hdr + body

def _build_fault_co(call_id: int, status: int) -> bytes:
    """
    CO FAULT (ptype=3). Stub = uint32(status).
    """
    stub = struct.pack('<I', status)
    alloc_hint = struct.pack('<I', len(stub))
    co = alloc_hint + b'\x00\x00\x00\x00'  # ctx_id/cancel/reserved как у RESPONSE-заголовка
    body = co + stub

    ver, minor, ptype, pfc = 5, 0, 3, 0x03
    drep = b'\x10\x00\x00\x00'
    frag_len = 16 + len(body)
    auth_len = 0
    hdr = struct.pack('<BBBB4sHHI', ver, minor, ptype, pfc, drep, frag_len, auth_len, call_id)
    return hdr + body

def _parse_sid(sid_str: str):
    """
    Разбор SID вида 'S-1-5-21-...'.
    Возвращает (rev, id_auth_6bytes, [subauth...]).
    """
    parts = sid_str.split('-')
    assert parts[0] == 'S'
    rev = int(parts[1])
    id_auth = int(parts[2])
    # id_auth в 6 байт BE (как в дом_sid2)
    id_auth6 = id_auth.to_bytes(6, 'big')
    sub = list(map(int, parts[3:]))
    return rev, id_auth6, sub