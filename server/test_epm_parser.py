# test_epm_pull_epm_map.py
import struct
import uuid

from epm import ndr_pull_epm_Map  # импортируй твой класс

NETLOGON = uuid.UUID("12345678-1234-abcd-ef00-01234567cffb")
DCE_NDR  = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")

def _hex(s: str) -> bytes:
    return bytes.fromhex(' '.join(s.split()))

# общий блок tower_octets из твоего дампа (ровно 0x4B = 75 байт)
TOWER_OCTETS = _hex(
    "05 00"
    # Floor 1: iface UUID (NETLOGON) + v1.0; RHS_len=02 00 + 00 00
    "13 00"
    "0d 78 56 34 12 34 12 cd ab ef 00 01 23 45 67 cf fb 01 00"
    "02 00 00 00"
    # Floor 2: NDR UUID + v2.0; RHS_len=02 00 + 00 00
    "13 00"
    "0d 04 5d 88 8a eb 1c c9 11 9f e8 08 00 2b 10 48 60 02 00"
    "02 00 00 00"
    # Floor 3: RPC-CO 5.0
    "01 00" "0b" "02 00" "00 05"
    # Floor 4: TCP 135 (BE)
    "01 00" "07" "02 00" "00 87"
    # Floor 5: IP 0.0.0.0 (BE)
    "01 00" "09" "04 00" "00 00 00 00"
)
assert len(TOWER_OCTETS) == 0x4B, f"tower_octets len mismatch: {len(TOWER_OCTETS)} != 0x4B"

def _build_stub_base(include_ref_id: bool) -> bytes:
    stub = bytearray()
    # obj_ptr = 1 + нулевой GUID
    stub += _hex("01 00 00 00")
    stub += b"\x00" * 16

    # map_ptr = 2
    stub += _hex("02 00 00 00")
    # optional ref_id перед twr_t (иногда встречается в дампах)
    if include_ref_id:
        stub += _hex("02 00 00 00")

    # twr_t header: length (=75), max_count (=75)
    stub += struct.pack("<I", 0x4B)
    stub += struct.pack("<I", 0x4B)
    # tower_octets
    stub += TOWER_OCTETS

    # выравнивание twr_t до /4
    while len(stub) % 4 != 0:
        stub += b"\x00"

    # entry_handle inline: 20 нулей
    stub += b"\x00" * 20

    # max_towers = 4
    stub += struct.pack("<I", 4)
    return bytes(stub)

def _assert_common(req):
    # базовые ожидания по твоему реальному дампу
    assert req.floors == 5
    assert req.max_towers == 4
    assert req.tower.iface_uuid == NETLOGON
    assert req.tower.iface_ver_major == 1
    assert req.tower.transfer_syntax_uuid == DCE_NDR
    assert req.tower.tcp_port == 135
    assert req.tower.ip == "0.0.0.0"

def test_epm_pull_without_refid():
    """Вариант: map_ptr, затем сразу twr_t."""
    stub = _build_stub_base(include_ref_id=False)
    req = ndr_pull_epm_Map(stub)
    _assert_common(req)

def test_epm_pull_with_refid():
    """Вариант, если между map_ptr и twr_t идёт дополнительный referent id."""
    stub = _build_stub_base(include_ref_id=True)
    req = ndr_pull_epm_Map(stub)
    _assert_common(req)

test_epm_pull_without_refid()
#test_epm_pull_with_refid()
