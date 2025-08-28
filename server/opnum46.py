import struct, uuid
from enum import IntEnum

from utils_lsa import NDRPush, _build_response_co
from lsa_status import STATUS_SUCCESS, STATUS_INVALID_INFO_CLASS, STATUS_INVALID_PARAMETER, _HandleTable

def _mk_dom_sid2_blob(sid_str: str) -> bytes:
    """
    dom_sid2 payload для LSA DNS info:
      uint32 Count;                  # число SubAuthorities
      uint8  Revision;               # обычно 1
      uint8  NumAuths;               # == Count
      uint8  IdentifierAuthority[6]; # BE
      uint32 SubAuthority[Count];    # LE
      align4
    """
    parts = sid_str.split('-')
    assert parts[0] == 'S'
    rev  = int(parts[1])           # 1
    ida  = int(parts[2])           # 5
    subs = list(map(int, parts[3:]))

    count = len(subs)
    ida6  = ida.to_bytes(6, 'big')

    out = bytearray()
    out += struct.pack('<I', count)    # <-- ВАЖНО: 32-битный Count
    out += struct.pack('B', rev)
    out += struct.pack('B', count)
    out += ida6
    for v in subs:
        out += struct.pack('<I', v)

    # align4
    rem = (-len(out)) & 3
    if rem:
        out += b'\x00' * rem
    return bytes(out)


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

    if level == 6:
        return _op_LsarQueryInfo_ROLE(server, req_hdr, level)
    if level in (12, 13):
        return _op_LsarQueryInfo_DNS(server, req_hdr, level)

    if level in (9, 10, 11):
        ndr = NDRPush()
        ndr.u32(0)                      # NULL *info
        ndr.u32(STATUS_INVALID_PARAMETER)
        return _build_response_co(int(req_hdr['call_id']), int(req_hdr['ctx_id']), ndr.getvalue())

    ndr = NDRPush()
    ndr.u32(0)                          # NULL *info
    ndr.u32(STATUS_INVALID_INFO_CLASS)
    return _build_response_co(int(req_hdr['call_id']), int(req_hdr['ctx_id']), ndr.getvalue())


# === ROLE arm (просто, без deferred) ===
def _op_LsarQueryInfo_ROLE(server, req_hdr, level: int) -> bytes:
    ndr = NDRPush()
    # present pointer на *info
    ndr.u32(0x00020001)
    # ЯВНЫЙ тег union'а + паддинг (как того ждёт dissector)
    ndr.u16(level & 0xFFFF)
    ndr.u16(0)

    # arm(role): u16 role; u16 pad
    LSA_ROLE_PRIMARY = 3
    ndr.u16(LSA_ROLE_PRIMARY)
    ndr.u16(0)

    ndr.u32(STATUS_SUCCESS)
    stub_out = ndr.getvalue()
    print(f"[LSA][ROLE] stub head: {_hexdump(stub_out[:64])}")
    return _build_response_co(int(req_hdr['call_id']), int(req_hdr['ctx_id']), stub_out)


# === DNS/DNS_INT arm (fixed + deferred, как у Samba) ===
def _op_LsarQueryInfo_DNS(server, req_hdr, level: int) -> bytes:
    st = ensure_domain_state(server)

    fixed    = bytearray()
    deferred = bytearray()

    # present pointer на [out] *PolicyInformation
    fixed += struct.pack('<I', 0x00020001)

    # ВАЖНО: явный тег union'а (level) + паддинг
    fixed += struct.pack('<HH', level & 0xFFFF, 0)

    # ПОРЯДОК как у Samba:
    # 1) Name
    name_hdr, name_def = _mk_lsa_string_large_hdr_and_deferred(st['netbios'], ref_id=0x00021001)
    fixed    += name_hdr
    deferred += name_def

    # 2) DnsDomainName
    dns_hdr, dns_def = _mk_lsa_string_large_hdr_and_deferred(st['dns'], ref_id=0x00021002)
    fixed    += dns_hdr
    deferred += dns_def

    # 3) DnsForestName
    forest_hdr, forest_def = _mk_lsa_string_large_hdr_and_deferred(st['forest'], ref_id=0x00021003)
    fixed    += forest_hdr
    deferred += forest_def

    # 4) DomainGuid
    fixed += st['guid'].bytes_le

    # 5) Sid (PSID): ptr в fixed, payload в deferred
    fixed    += struct.pack('<I', 0x00022001)
    deferred += _mk_dom_sid2_blob(st['sid_str'])

    # arm + NTSTATUS
    arm = bytes(fixed) + bytes(deferred)

    ndr = NDRPush()
    ndr.raw(arm)
    ndr.u32(STATUS_SUCCESS)
    stub_out = ndr.getvalue()

    print(f"[LSA][DNS] fixed_len={len(fixed)} deferred_len={len(deferred)} total_stub={len(stub_out)}")
    print(f"[LSA][DNS] head: {_hexdump(stub_out[:96])}")
    print(f"[LSA][DNS] tail: {_hexdump(stub_out[-96:])}")

    return _build_response_co(int(req_hdr['call_id']), int(req_hdr['ctx_id']), stub_out)

