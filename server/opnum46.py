import struct, uuid
from enum import IntEnum

from utils_lsa import NDRPush, _build_response_co

STATUS_SUCCESS             = 0x00000000
STATUS_INVALID_PARAMETER   = 0xC000000D
STATUS_INVALID_INFO_CLASS  = 0xC0000003
# debug
def _hexdump(b: bytes, limit: int = 96) -> str:
    n = min(len(b), limit)
    s = ' '.join(f'{x:02x}' for x in b[:n])
    if len(b) > n:
        s += ' ...'
    return s
# --- помощники ---
def _pull_level_from_stub(stub_in: bytes) -> int:
    # [0:20] POLICY_HANDLE, затем enum16 level
    return struct.unpack_from('<H', stub_in, 20)[0] if len(stub_in) >= 22 else -1

def _hexdump(b: bytes, limit=96):
    b = b[:limit]
    return ' '.join(f'{x:02x}' for x in b) + (' ...' if len(b) == limit else '')

# --- доменное состояние (подставь свои значения при желании) ---
def ensure_domain_state(server):
    if hasattr(server, 'lsa_domain_state'):
        return server.lsa_domain_state
    server.lsa_domain_state = {
        'netbios': 'SAMBA',
        'dns':     'samba.local',
        'forest':  'samba.local',
        'sid_str': 'S-1-5-21-2935844775-1616297121-1846424283',
        'guid':    uuid.uuid4(),
    }
    return server.lsa_domain_state

# --- утилиты для fixed+deferred (как у Samba ndr_push) ---
def _align4_into(b: bytearray):
    rem = (-len(b)) & 3
    if rem:
        b += b'\x00' * rem

def _mk_lsa_string_large_fixed(s: str | None, ref_id: int) -> bytes:
    """fixed часть LSA_STRING_LARGE: Length, MaximumLength, [unique] Buffer(ptr or 0)"""
    if not s:
        return struct.pack('<HHI', 0, 0, 0)
    w = s.encode('utf-16le')
    length_bytes = len(w)              # без NUL
    max_bytes    = length_bytes + 2    # с NUL
    return struct.pack('<HHI', length_bytes, max_bytes, ref_id)

def _mk_lsa_string_large_deferred(s: str | None) -> bytes:
    """deferred часть LSA_STRING_LARGE: max_count, offset, actual_count, UTF16LE+NUL, align4"""
    if not s:
        return b''
    w = s.encode('utf-16le')
    length_bytes = len(w)
    max_bytes    = length_bytes + 2
    max_count    = max_bytes // 2
    actual       = (length_bytes // 2) + 1
    out = bytearray()
    out += struct.pack('<III', max_count, 0, actual)
    out += w + b'\x00\x00'
    _align4_into(out)
    return bytes(out)

def _mk_dom_sid2_payload(sid_str: str) -> bytes:
    """SID payload (dom_sid2) для deferred: rev,u8 count,id_auth[6] BE, subauths (LE), align4"""
    parts = sid_str.split('-')
    assert parts[0] == 'S'
    rev = int(parts[1]); ida = int(parts[2])
    ida6 = ida.to_bytes(6, 'big')
    subs = list(map(int, parts[3:]))
    out = bytearray()
    out += struct.pack('BB', rev, len(subs))
    out += ida6
    for v in subs:
        out += struct.pack('<I', v)
    _align4_into(out)
    return bytes(out)

# --- помощники ---
def _pull_level_from_stub(stub_in: bytes) -> int:
    # [0:20] POLICY_HANDLE, затем enum16 level
    return struct.unpack_from('<H', stub_in, 20)[0] if len(stub_in) >= 22 else -1

def _hexdump(b: bytes, limit=96):
    b = b[:limit]
    return ' '.join(f'{x:02x}' for x in b) + (' ...' if len(b) == limit else '')

# === opnum 46: dispatcher ===
def _op_LsarQueryInformationPolicy2(server, req_hdr, stub_in: bytes) -> bytes:
    level = _pull_level_from_stub(stub_in)
    print(f"[LSA] LsarQueryInformationPolicy2: level={level}")

    if level == 6:                      # PolicyLsaServerRoleInformation
        return _op_LsarQueryInfo_ROLE(server, req_hdr)
    if level in (12, 13):               # PolicyDnsDomainInformation / PolicyDnsDomainInformationInt
        return _op_LsarQueryInfo_DNS(server, req_hdr)

    if level in (9, 10, 11):            # MOD / AUDIT_FULL_* -> INVALID_PARAMETER
        ndr = NDRPush()
        ndr.u32(STATUS_INVALID_PARAMETER)
        return _build_response_co(int(req_hdr['call_id']), int(req_hdr['ctx_id']), ndr.getvalue())

    # Остальные пока не реализованы
    ndr = NDRPush()
    ndr.u32(STATUS_INVALID_INFO_CLASS)
    return _build_response_co(int(req_hdr['call_id']), int(req_hdr['ctx_id']), ndr.getvalue())

# === ROLE arm (просто, без deferred) ===
def _op_LsarQueryInfo_ROLE(server, req_hdr) -> bytes:
    ndr = NDRPush()
    # present pointer на out *info (ненулевой)
    ndr.u32(0x00020001)
    # arm(role): u16 role; u16 pad
    LSA_ROLE_PRIMARY = 3
    ndr.u16(LSA_ROLE_PRIMARY)
    ndr.u16(0)
    # NTSTATUS
    ndr.u32(STATUS_SUCCESS)
    stub_out = ndr.getvalue()
    print(f"[LSA][ROLE] stub head: {_hexdump(stub_out[:64])}")
    return _build_response_co(int(req_hdr['call_id']), int(req_hdr['ctx_id']), stub_out)

# === DNS/DNS_INT arm (fixed + deferred, как у Samba) ===
def _op_LsarQueryInfo_DNS(server, req_hdr) -> bytes:
    st = ensure_domain_state(server)

    fixed  = bytearray()
    deferd = bytearray()

    # present pointer на out *info
    fixed += struct.pack('<I', 0x00020001)

    # Порядок arm ровно как в Samba:
    # Name (LSA_STRING_LARGE)
    fixed += _mk_lsa_string_large_fixed(st['netbios'], ref_id=0x00021001)
    deferd += _mk_lsa_string_large_deferred(st['netbios'])

    # Sid (PSID): fixed=unique ptr, deferred=dom_sid2 payload
    fixed += struct.pack('<I', 0x00022001)
    deferd += _mk_dom_sid2_payload(st['sid_str'])

    # DnsDomain
    fixed += _mk_lsa_string_large_fixed(st['dns'], ref_id=0x00021002)
    deferd += _mk_lsa_string_large_deferred(st['dns'])

    # DnsForest
    fixed += _mk_lsa_string_large_fixed(st['forest'], ref_id=0x00021003)
    deferd += _mk_lsa_string_large_deferred(st['forest'])

    # DomainGuid (GUID в fixed)
    fixed += st['guid'].bytes_le

    # Итоговый stub: present-ptr + arm(fixed) + arm(deferred) + NTSTATUS
    stub = bytes(fixed) + bytes(deferd)

    ndr = NDRPush()
    ndr.raw(stub)
    ndr.u32(STATUS_SUCCESS)
    stub_out = ndr.getvalue()

    print(f"[LSA][DNS] fixed_len={len(fixed)} deferred_len={len(deferd)} total_stub={len(stub_out)}")
    print(f"[LSA][DNS] head: {_hexdump(stub_out[:64])}")
    print(f"[LSA][DNS] tail: {_hexdump(stub_out[-64:])}")

    return _build_response_co(int(req_hdr['call_id']), int(req_hdr['ctx_id']), stub_out)

