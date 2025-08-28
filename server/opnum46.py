import struct, uuid
from enum import IntEnum

from utils_lsa import NDRPush, _build_response_co, _mk_dom_sid2_blob, _mk_lsa_string_large_hdr_and_deferred
from lsa_status import STATUS_SUCCESS, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, _HandleTable

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
    """Build PolicyDnsDomainInformation/Int for LsarQueryInformationPolicy2.

    This helper crafts the complex pointer layout returned for info levels 12
    (PolicyDnsDomainInformation) and 13 (PolicyDnsDomainInformationInt) of the
    LsarQueryInformationPolicy2 RPC (opnum 46).  It separates fixed and
    deferred data to mimic Windows' NDR encoding with explicit referent IDs.
    """

    st = ensure_domain_state(server)

    fixed = bytearray()
    deferred = bytearray()

    def off_fixed():
        return len(fixed)

    def off_def():
        return len(deferred)

    # Present pointer to returned structure
    fixed += struct.pack('<I', 0x00020001)
    print(f"[LSA][DNS] fixed start off={off_fixed()} (after present-ptr)")

    # Name: header in fixed, data in deferred
    name_hdr, name_def = _mk_lsa_string_large_hdr_and_deferred(
        st['netbios'], ref_id=0x00020002
    )
    print(f"[LSA][DNS] Name hdr off={off_fixed()} -> +{len(name_hdr)}")
    fixed += name_hdr
    print(f"[LSA][DNS] Name deferred off={off_def()} -> +{len(name_def)}")
    deferred += name_def

    # Sid pointer in fixed, sid blob in deferred
    print(f"[LSA][DNS] Sid ptr off={off_fixed()} -> +4")
    fixed += struct.pack('<I', 0x00020003)
    sid_blob = _mk_dom_sid2_blob(st['sid_str'])
    print(f"[LSA][DNS] Sid deferred off={off_def()} -> +{len(sid_blob)}")
    deferred += sid_blob

    # DnsDomainName
    dns_hdr, dns_def = _mk_lsa_string_large_hdr_and_deferred(
        st['dns'], ref_id=0x00020004
    )
    print(f"[LSA][DNS] DnsDomain hdr off={off_fixed()} -> +{len(dns_hdr)}")
    fixed += dns_hdr
    print(f"[LSA][DNS] DnsDomain deferred off={off_def()} -> +{len(dns_def)}")
    deferred += dns_def

    # DnsForestName
    forest_hdr, forest_def = _mk_lsa_string_large_hdr_and_deferred(
        st['forest'], ref_id=0x00020005
    )
    print(f"[LSA][DNS] DnsForest hdr off={off_fixed()} -> +{len(forest_hdr)}")
    fixed += forest_hdr
    print(f"[LSA][DNS] DnsForest deferred off={off_def()} -> +{len(forest_def)}")
    deferred += forest_def

    # DomainGuid
    print(f"[LSA][DNS] Guid off={off_fixed()} -> +16")
    fixed += st['guid'].bytes_le

    arm = bytes(fixed) + bytes(deferred)
    stub_out = arm + struct.pack('<I', STATUS_SUCCESS)

    print(
        f"[LSA][DNS] fixed_len={len(fixed)} deferred_len={len(deferred)} arm_len={len(arm)} total_stub={len(stub_out)}"
    )
    print(f"[LSA][DNS] stub head: {_hexdump(stub_out[:64])}")
    print(f"[LSA][DNS] stub tail: {_hexdump(stub_out[-64:])}")

    return _build_response_co(int(req_hdr['call_id']), int(req_hdr['ctx_id']), stub_out)

