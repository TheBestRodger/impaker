# lsa.py — минимальная серверная реализация части MS-LSAD поверх MS-RPCE (ncacn_np / co)

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

# def _build_response_co(call_id: int, ctx_id: int, stub: bytes) -> bytes:
#     """
#     Собрать CO RESPONSE (ptype=2) без аутентификатора (FIRST|LAST).
#     """
#     alloc_hint = struct.pack('<I', len(stub))
#     co = alloc_hint + struct.pack('<H', ctx_id) + b'\x00\x00'  # cancel_count=0, reserved=0
#     body = co + stub

#     # common header
#     ver, minor, ptype, pfc = 5, 0, 2, 0x03  # FIRST|LAST
#     drep = b'\x10\x00\x00\x00'              # LE/ASCII/IEEE
#     frag_len = 16 + len(body)
#     auth_len = 0
#     hdr = struct.pack('<BBBB4sHHI', ver, minor, ptype, pfc, drep, frag_len, auth_len, call_id)
#     return hdr + body
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

def _mk_lsa_string_large_hdr_and_deferred(s: str | None, ref_id: int):
    """
    Возвращает (hdr_bytes, deferred_bytes).
    hdr: Length(u16), MaximumLength(u16), [unique]Buffer(u32 ref or 0)
    deferred: если Buffer!=NULL → max_count(u32), offset(u32=0), actual(u32), UTF16LE(data+NUL), align4
    """
    if not s:
        hdr = struct.pack('<HHI', 0, 0, 0)
        return hdr, b''
    w = s.encode('utf-16le')
    length_bytes = len(w)                    # без NUL
    max_bytes    = length_bytes + 2          # с NUL
    hdr = struct.pack('<HHI', length_bytes, max_bytes, ref_id)

    max_count = max_bytes // 2
    actual    = (length_bytes // 2) + 1
    deferred = struct.pack('<III', max_count, 0, actual) + w + b'\x00\x00'
    # align4
    if (len(deferred) & 3) != 0:
        deferred += b'\x00' * (4 - (len(deferred) & 3))
    return hdr, deferred

def _mk_dom_sid2_blob(sid_str: str):
    """
    Вернёт payload dom_sid2 (для отложенной части).
    """
    parts = sid_str.split('-')
    assert parts[0] == 'S'
    rev = int(parts[1]); ida = int(parts[2])
    ida6 = ida.to_bytes(6, 'big')
    subs = list(map(int, parts[3:]))
    blob = struct.pack('BB', rev, len(subs)) + ida6 + b''.join(struct.pack('<I', v) for v in subs)
    if (len(blob) & 3) != 0:
        blob += b'\x00' * (4 - (len(blob) & 3))
    return blob


# --- NDR-утилиты: UNISTR2 / GUID / DOM_SID2 ---
def _ptr_present(ndr, ref=0x00020000):
    ndr.u32(ref)  # любой ненулевой referent id

def _push_lsa_string_large(ndr: NDRPush, s: str | None):
    """
    lsa_StringLarge:
      uint16 Length;         // в байтах, без NUL
      uint16 MaximumLength;  // в байтах, обычно с учётом завершающего NUL
      [unique] wchar_t *Buffer; // RPC unique pointer -> referent + unistr2-like (max,ofs,act) + UTF-16LE + NUL
    """
    if not s:
        ndr.u16(0)
        ndr.u16(0)
        ndr.u32(0)           # NULL unique ptr
        return

    w = s.encode('utf-16le')
    length_bytes = len(w)            # без NUL
    max_bytes    = length_bytes + 2  # с завершающим NUL
    ndr.u16(length_bytes)
    ndr.u16(max_bytes)

    # unique pointer header (non-zero referent id)
    ndr.u32(0x00020000)

    # conformant & varying header for wchar_t[]
    max_count = max_bytes // 2               # элементов wchar_t
    ndr.u32(max_count)                       # max_count
    ndr.u32(0)                               # offset
    actual = (length_bytes // 2) + 1         # включая NUL
    ndr.u32(actual)                          # actual_count

    # payload
    ndr.raw(w + b'\x00\x00')
    ndr.trailer_align4()

def _push_unistr2(ndr, s: str):
    """
    MS NDR 'unistr2' (conformant & varying array of UTF-16LE):
      - max_count (U32), offset (U32=0), actual_count (U32)
      - UTF16LE chars (actual_count)
    По традиции кладём завершающий NUL и учитываем его в actual_count.
    """
    if s is None:
        s = ''
    w = (s + '\x00').encode('utf-16le')
    count = len(w) // 2  # количество 16-бит символов
    ndr.u32(count)
    ndr.u32(0)       # offset
    ndr.u32(count)   # actual_count
    ndr.raw(w)
    ndr.trailer_align4()

def _push_guid(ndr, g: uuid.UUID):
    """
    GUID в NDR (LE-поля). uuid.UUID.bytes_le уже в нужном порядке.
    """
    ndr.raw(g.bytes_le)

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

def _push_dom_sid2(ndr, sid_str: str):
    """
    dom_sid2:
      U8  revision
      U8  num_auths
      U8[6] id_authority (BE)
      U32 sub_auth[num_auths] (LE)
    """
    rev, id_auth6, sub = _parse_sid(sid_str)
    ndr.raw(struct.pack('B', rev))
    ndr.raw(struct.pack('B', len(sub)))
    ndr.raw(id_auth6)
    for v in sub:
        ndr.u32(v)
    ndr.trailer_align4()

def _pull_policy_info_level(stub_in: bytes) -> int:
    # [0:20] POLICY_HANDLE, затем enum16 level
    if len(stub_in) < 22:
        return -1
    return struct.unpack_from('<H', stub_in, 20)[0]

