# lsa.py — минимальная серверная реализация части MS-LSAD поверх MS-RPCE (ncacn_np / co)
import os
import struct
import threading
from typing import Optional

from impacket.dcerpc.v5 import rpcrt
from ndr import NDRPush  # выравнивание по NDR
import uuid

from utils_lsa import (
    _build_fault_co,
    _build_response_co,
    _extract_request_stub_co,
    _pull_policy_info_level,
    _ptr_present,
    _push_lsa_string_large,
    _push_dom_sid2,
    _push_guid,
)
from lsa_status import (
            NCA_S_OP_RNG_ERROR, 
            POLICY_INFO, 
            STATUS_INVALID_INFO_CLASS, 
            STATUS_INVALID_PARAMETER, 
            STATUS_SUCCESS,
            LSARPC_OPNUM_LsarClose, 
            LSARPC_OPNUM_LsarOpenPolicy2, 
            LSARPC_OPNUM_LsarQueryInformationPolicy2
)
# debug
def _hexdump(b: bytes, limit: int = 96) -> str:
    n = min(len(b), limit)
    s = ' '.join(f'{x:02x}' for x in b[:n])
    if len(b) > n:
        s += ' ...'
    return s

# ---- хранилище хэндлов ----
class _HandleTable:
    def __init__(self):
        self._lock = threading.Lock()
        self._map = {}  # key: uuid16 bytes -> {'type': 'policy', 'access': int}

    def put_policy(self, uuid16: bytes, access: int):
        with self._lock:
            self._map[uuid16] = {'type': 'policy', 'access': access}

    def pop(self, uuid16: bytes):
        with self._lock:
            return self._map.pop(uuid16, None)

    def has(self, uuid16: bytes) -> bool:
        with self._lock:
            return uuid16 in self._map

# инициализируется один раз на сервере lsarpc
def ensure_handle_table(server) -> _HandleTable:
    if not hasattr(server, 'lsa_handles'):
        server.lsa_handles = _HandleTable()
    return server.lsa_handles

def ensure_domain_state(server):
    """
    Инициализация доменных параметров 1 раз на процесс.
    """
    if hasattr(server, 'lsa_domain_state'):
        return server.lsa_domain_state

    st = {
        'netbios': 'SAMBA',  # == state->domain_name в самбе
        'dns':     'samba.local',
        'forest':  'samba.local',
        'sid_str': 'S-1-5-21-2935844775-1616297121-1846424283',
        'guid':    uuid.uuid4(),  # «сам придумай»
    }
    server.lsa_domain_state = st
    return st


# --- ВЕТКИ opnum 46 ---
def _op_LsarQueryInformationPolicy2_ROLE(server, req_hdr, stub_in: bytes) -> bytes:
    ndr = NDRPush()
    # present pointer на out *info (внутренняя ссылка)
    ndr.u32(0x00020001)
    # arm ROLE: u16 role; u16 pad;
    LSA_ROLE_PRIMARY = 3
    ndr.u16(LSA_ROLE_PRIMARY); ndr.u16(0)
    stub_out = ndr.getvalue() + struct.pack('<I', STATUS_SUCCESS)
    print(f"[LSA][ROLE] stub head: {_hexdump(stub_out[:64])}")
    print(f"[LSA][ROLE] stub tail: {_hexdump(stub_out[-64:])}")
    return _build_response_co(int(req_hdr['call_id']), int(req_hdr['ctx_id']), stub_out)

# == DNS/DNS_INT с deferred-поинтерами ==
def _op_LsarQueryInformationPolicy2_DNS_like(server, req_hdr, stub_in: bytes) -> bytes:
    """Return PolicyDnsDomainInfo/PolicyDnsDomainInfoInt structures."""
    st = ensure_domain_state(server)

    ndr = NDRPush()

    # Top-level present pointer to PolicyDnsDomainInfo
    _ptr_present(ndr, 0x00020001)

    # Name (LSA_STRING_LARGE)
    _push_lsa_string_large(ndr, st['netbios'])

    # Sid (unique pointer to dom_sid2)
    _ptr_present(ndr, 0x00020002)
    _push_dom_sid2(ndr, st['sid_str'])

    # DnsDomainName and DnsForestName
    _push_lsa_string_large(ndr, st['dns'])
    _push_lsa_string_large(ndr, st['forest'])

    # DomainGuid
    _push_guid(ndr, st['guid'])

    ndr.trailer_align4()

    stub_out = ndr.getvalue() + struct.pack('<I', STATUS_SUCCESS)

    print(f"[LSA][DNS] stub head: {_hexdump(stub_out[:64])}")
    print(f"[LSA][DNS] stub tail: {_hexdump(stub_out[-64:])}")

    return _build_response_co(int(req_hdr['call_id']), int(req_hdr['ctx_id']), stub_out)
# ---- Частичный парс OpenPolicy2 opnum 44 (минимум) ----
def _guess_desired_access(stub_in: bytes) -> int:
    """
    В LsarOpenPolicy2 DesiredAccess идёт последним параметром.
    Для минималки достаточно взять последние 4 байта stub.
    """
    if len(stub_in) >= 4:
        return struct.unpack_from('<I', stub_in, len(stub_in)-4)[0]
    return 0


# ---- Обработчики opnums ----
def _op_LsarOpenPolicy2(server, req_hdr, stub_in: bytes) -> bytes:
    """
    OpenPolicy2 => возвращаем POLICY_HANDLE (20 байт) + NTSTATUS.
    Атрибуты/RootDirectory игнорируем (как Samba), но сохраняем access.
    """
    handles: _HandleTable = ensure_handle_table(server)
    desired_access = _guess_desired_access(stub_in)

    uuid16 = os.urandom(16)
    policy_handle = struct.pack('<I16s', 0, uuid16)

    handles.put_policy(uuid16, desired_access)

    # Собираем stub через NDRPush (твои выравнивания уже отлажены)
    ndr = NDRPush()
    ndr.raw(policy_handle)
    ndr.u32(STATUS_SUCCESS)
    stub_out = ndr.getvalue()

    return _build_response_co(call_id=int(req_hdr['call_id']),
                              ctx_id=int(req_hdr['ctx_id']),
                              stub=stub_out)

def _op_LsarQueryInformationPolicy2(server, req_hdr, stub_in: bytes) -> bytes:
    handles = ensure_handle_table(server)
    if len(stub_in) < 20:
        return _build_response_co(call_id=int(req_hdr['call_id']), ctx_id=int(req_hdr['ctx_id']), stub=struct.pack('<I', STATUS_INVALID_PARAMETER))
    
    policy_handle_attr, uuid16 = struct.unpack_from('<I16s', stub_in, 0)
    if not handles.has(uuid16):
        return _build_response_co(call_id=int(req_hdr['call_id']), ctx_id=int(req_hdr['ctx_id']), stub=struct.pack('<I', STATUS_INVALID_HANDLE))

    level = _pull_policy_info_level(stub_in)
    name = POLICY_INFO.get(level, "UNKNOWN")
    print(f"[LSA] LsarQueryInformationPolicy2: level={level} -> {name}")

    if level == 6:
        return _op_LsarQueryInformationPolicy2_ROLE(server, req_hdr, stub_in)
    if level in (12, 13):
        return _op_LsarQueryInformationPolicy2_DNS_like(server, req_hdr, stub_in)
    if level in (9, 10, 11):
        return _build_response_co(call_id=int(req_hdr['call_id']), 
                                 ctx_id=int(req_hdr['ctx_id']), 
                                 stub=struct.pack('<I', STATUS_INVALID_PARAMETER))
    return _build_response_co(call_id=int(req_hdr['call_id']), 
                             ctx_id=int(req_hdr['ctx_id']), 
                             stub=struct.pack('<I', STATUS_INVALID_INFO_CLASS))
# ---- opnum 0 ----
def _op_LsarClose(server, req_hdr, stub_in: bytes) -> bytes:
    """
    Close => вход: POLICY_HANDLE(20), выход: NULL_HANDLE(20) + STATUS_SUCCESS.
    """
    handles: _HandleTable = ensure_handle_table(server)

    uuid16 = b''
    if len(stub_in) >= 20:
        _attr, uuid16 = struct.unpack_from('<I16s', stub_in, 0)
        handles.pop(uuid16)

    null_handle = b'\x00' * 20
    ndr = NDRPush()
    ndr.raw(null_handle)
    ndr.u32(STATUS_SUCCESS)
    stub_out = ndr.getvalue()

    return _build_response_co(call_id=int(req_hdr['call_id']),
                              ctx_id=int(req_hdr['ctx_id']),
                              stub=stub_out)


# ---- Мейн вызов----
def handle_lsa_request(server, pdu: bytes) -> Optional[bytes]:
    """
    Принять целиком REQUEST PDU, вернуть bytes ответа (RESPONSE/FAULT) или None.
    """
    try:
        req = rpcrt.MSRPCRequestHeader(pdu)
        opnum = int(req['op_num'])
    except Exception:
        return None

    stub_in, _auth = _extract_request_stub_co(pdu)

    if opnum == LSARPC_OPNUM_LsarOpenPolicy2:
        return _op_LsarOpenPolicy2(server, req, stub_in)
    
    if opnum == LSARPC_OPNUM_LsarQueryInformationPolicy2:
        return _op_LsarQueryInformationPolicy2(server, req, stub_in)
    
    if opnum == LSARPC_OPNUM_LsarClose:
        return _op_LsarClose(server, req, stub_in)

    # остальное пока не реализовано — корректный FAULT (nca_s_op_rng_error)
    return _build_fault_co(call_id=int(req['call_id']), status=NCA_S_OP_RNG_ERROR)
