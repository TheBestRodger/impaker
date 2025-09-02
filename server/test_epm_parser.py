from epm import ndr_pull_epm_Map


def _hex(s: str) -> bytes:
    return bytes.fromhex(' '.join(s.split()))

# Собираем кусок REQUEST из твоего дампа
stub = bytearray()
stub += _hex("01 00 00 00")                   # obj_ptr
stub += b"\x00" * 16                          # obj uuid
stub += _hex("02 00 00 00")                   # map_ptr
# В твоём последнем дампе ref_id не выделен отдельным словом — сразу идёт twr_t
stub += _hex("4b 00 00 00 4b 00 00 00")       # tower_length=75, max_count=75

# tower_octets (floors=5) — один в один с Wireshark:
stub += _hex(
    "05 00"
    # Floor 1: iface UUID (NETLOGON) + v1.0; RHS_len=02 00 + 00 00
    "13 00 0d 78 56 34 12 34 12 cd ab ef 00 01 23 45 67 cf fb 01 00 02 00 00 00"
    # Floor 2: NDR UUID + v2.0; RHS_len=02 00 + 00 00
    "13 00 0d 04 5d 88 8a eb 1c c9 11 9f e8 08 00 2b 10 48 60 02 00 02 00 00 00"
    # Floor 3: RPC-CO 5.0
    "01 00 0b 02 00 00 05"
    # Floor 4: TCP 135 (00 87 BE)
    "01 00 07 02 00 87"
    # Floor 5: IP 0.0.0.0
    "01 00 09 04 00 00 00 00"
)
# выравнивание twr_t до /4
while len(stub) % 4 != 0:
    stub += b"\x00"

# entry_handle: 20 нулей
stub += b"\x00" * 20
# max_towers = 4
stub += _hex("04 00 00 00")

req = ndr_pull_epm_Map(stub)
print("floors:", req.tower.floors)
print("iface:", req.tower.iface_uuid, "ver", req.tower.iface_ver_major)
print("ndr  :", req.tower.transfer_syntax_uuid)
print("rpc  :", req.tower.rpc_co)
print("tcp  :", req.tower.tcp_port, "ip", req.tower.ip)
print("max_towers:", req.max_towers)
