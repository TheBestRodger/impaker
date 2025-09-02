"""epmapper.py — минимальный сервер EPM поверх MS-RPCE.
"""

import ipaddress
import struct
from typing import Optional, Tuple
import uuid

from impacket.dcerpc.v5 import rpcrt
from ndr import NDRPush  # выравнивание по NDR

from utils_lsa import (
    _build_fault_co,
    _build_response_co,
    _extract_request_stub_co,
)
from lsa_status import NCA_S_OP_RNG_ERROR
from epm import ndr_pull_epm_Map, ndr_push_epm_Map

EPM_OPNUM_EPT_INSERT             = 0
EPM_OPNUM_EPT_DELETE             = 1
EPM_OPNUM_EPT_LOOKUP             = 2
EPM_OPNUM_EPT_MAP                = 3
EPM_OPNUM_EPT_LOOKUP_HANDLE_FREE = 4
EPM_OPNUM_EPT_INQ_OBJECT         = 5
EPM_OPNUM_EPT_MGMT_DELETE        = 6

# Статусы из [MS-RPCE]: 0 - ok; 0x16C9A0D6 - not registered
EPM_S_OK            = 0x00000000
EPM_S_NOT_REGISTERED = 0x16C9A0D6

# Трансфер-синтаксис NDR (UUID + major) для Tower Floor #2 (UUID-type identifier, prefix 0x0d)
NDR_UUID = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")
NDR_VER_MAJOR = 2  # «NDR 1.1» в доке даёт тут 1..2 — на практике Windows принимает 2. :contentReference[oaicite:1]{index=1}

# Протоколы для этажей 3–5 (см. Protocol Identifiers)
PID_RPC_CO = 0x0b  # RPC connection-oriented; RHS: [minor, major] => [0x00, 0x05] для MSRPC v5
PID_TCP    = 0x07  # RHS: порт big-endian (2 байта)
PID_IP     = 0x09  # RHS: IPv4 big-endian (4 байта)
MSRPC_VER_MAJOR = 5
MSRPC_VER_MINOR = 0
IFACE_PORTS = {
    "12345778-1234-abcd-ef00-0123456789ab": ("lsarpc",   55152),
    "12345778-1234-abcd-ef00-0123456789ac": ("samr",     55153),
    "12345678-1234-abcd-ef00-01234567cffb": ("netlogon", 55154),
}



def _uuid_le_bytes(u: uuid.UUID) -> bytes:
    # В башне UUID идет в little-endian (см. Protocol Identifiers, UUID_type_identifier). :contentReference[oaicite:2]{index=2}
    return u.bytes_le

def _floor_uuid_type(u: uuid.UUID, ver_major: int) -> bytes:
    # LHS: 0x0d + UUID_LE + uint16(major)
    lhs = bytes([0x0d]) + _uuid_le_bytes(u) + ver_major.to_bytes(2,'little', signed=False)
    # RHS: для UUID_type_identifier RHS пуст
    return (len(lhs)).to_bytes(2,'little') + lhs + (0).to_bytes(2,'little')

def _floor_single_octet(proto_id: int, rhs: bytes) -> bytes:
    lhs = bytes([proto_id])
    return (len(lhs)).to_bytes(2,'little') + lhs + (len(rhs)).to_bytes(2,'little') + rhs
def _build_tower_ncacn_ip_tcp(iface_uuid: uuid.UUID, iface_ver_major: int, ip: str, port: int) -> bytes:
    # всегда как у Самбы: RPC-CO v5.0, TCP (BE), IP (0.0.0.0 если «слушаем на всех»)
    floors = []
    floors.append(_floor_uuid_type(iface_uuid, iface_ver_major or 1))
    floors.append(_floor_uuid_type(NDR_UUID, NDR_VER_MAJOR))
    floors.append(_floor_single_octet(PID_RPC_CO, bytes([MSRPC_VER_MINOR, MSRPC_VER_MAJOR])))  # 00 05
    floors.append(_floor_single_octet(PID_TCP, int(port).to_bytes(2, 'big')))                  # c0 00
    ipstr = "0.0.0.0" if ip in ("0.0.0.0", "127.0.0.1") else ip
    floors.append(_floor_single_octet(PID_IP, int(ipaddress.IPv4Address(ipstr)).to_bytes(4,'big')))
    return (len(floors)).to_bytes(2,'little') + b"".join(floors)

    
def _op_dcesrv_epm_Map(server, req_hdr, stub_in: bytes) -> bytes:
    epm = ndr_pull_epm_Map(stub_in)
    max_towers = epm.max_towers

    towers = []
    status = EPM_S_NOT_REGISTERED

    asked = epm.tower.iface_uuid   # UUID интерфейса из запроса
    ver   = epm.tower.iface_ver_major or 1
    hit = IFACE_PORTS.get(str(asked).lower()) if asked else None
    if hit:
        ip   = "0.0.0.0" 
        port = hit[1]
        tower_octets = _build_tower_ncacn_ip_tcp(asked, ver, ip, port)
        towers = [tower_octets]
        status = EPM_S_OK

    # 3) Пушим OUT-стаб «как у Самбы»
    stub = ndr_push_epm_Map().build_out(
        entry_handle_attrs=0,
        entry_handle_uuid16=None,   # нулевой handle ок
        towers_octets=towers,       # [] если не нашли — num=0
        max_towers=max_towers,      # коррелируем с запросом
        status=status,
    )

    # 4) Оборачиваем в MSRPC RESPONSE CO
    ctx_id = req_hdr['ctx_id'] if 'ctx_id' in req_hdr.fields else req_hdr['p_cont_id']
    return _build_response_co(call_id=int(req_hdr['call_id']), ctx_id=int(ctx_id), stub=stub)


# ---- Мейн вызов----
def handle_epm_request(server, pdu: bytes) -> Optional[bytes]:
    """
    Принять целиком REQUEST PDU, вернуть bytes ответа (RESPONSE/FAULT) или None.
    """
    try:
        req = rpcrt.MSRPCRequestHeader(pdu)
        opnum = int(req['op_num'])
    except Exception:
        return None

    stub_in, _auth = _extract_request_stub_co(pdu)

    if opnum == EPM_OPNUM_EPT_MAP:
        return _op_dcesrv_epm_Map(server, req, stub_in)
    else:
        print(f"NOT SUPP OPNUM {opnum}")
    # остальное пока не реализовано — корректный FAULT (nca_s_op_rng_error)
    return _build_fault_co(call_id=int(req['call_id']), status=NCA_S_OP_RNG_ERROR)
