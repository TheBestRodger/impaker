"""epmapper.py — минимальный сервер EPM поверх MS-RPCE.

Файл переписан по аналогии с реализацией протокола LSA. Никакого
функционала, не относящегося к EPM, здесь нет: оставлена только
обработка вызова ept_map(), а заголовки и FAULT'ы формируются
общими вспомогательными функциями из ``utils_lsa``.
"""

import ipaddress
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
    "12345678-1234-abcd-ef00-0123456789ab": ("netlogon", 55154),
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
    """
    Собираем tower_octet_string (без NDR-обертки twr_t).
    Этажи:
      1: RPC interface identifier (UUID_type_identifier = 0x0d)
      2: NDR transfer syntax (UUID_type_identifier = 0x0d, NDR uuid)
      3: RPC connection-oriented (0x0b), RHS: [minor, major]
      4: TCP (0x07), RHS: порт big-endian
      5: IP (0x09), RHS: IPv4 big-endian
    Спецификация башен: DCE C706, Appendix L + Appendix I. :contentReference[oaicite:3]{index=3}
    """
    floors = []
    # 1) Interface UUID + major
    floors.append(_floor_uuid_type(iface_uuid, iface_ver_major))
    # 2) NDR
    floors.append(_floor_uuid_type(NDR_UUID, NDR_VER_MAJOR))
    # 3) RPC CO (MSRPC v5.0)
    floors.append(_floor_single_octet(PID_RPC_CO, bytes([MSRPC_VER_MINOR, MSRPC_VER_MAJOR])))
    # 4) TCP порт (big-endian)
    floors.append(_floor_single_octet(PID_TCP, int(port).to_bytes(2,'big')))
    # 5) IPv4 адрес (big-endian)
    ip4 = ipaddress.IPv4Address(ip)
    floors.append(_floor_single_octet(PID_IP, int(ip4).to_bytes(4,'big')))
    floor_count = (len(floors)).to_bytes(2,'little')
    tower = floor_count + b''.join(floors)
    return tower

def _ndr_pack_twr_t(tower_octets: bytes) -> bytes:
    """
    twr_t по Appendix N: 
      uint32 tower_length; 
      [size_is(tower_length)] byte tower_octet_string[];
    NDR: сначала tower_length, потом conformant size, затем сами байты (+паддинг до кратности 4).
    :contentReference[oaicite:4]{index=4}
    """
    n = NDRPush()
    tl = len(tower_octets)
    n.u32(tl)
    n.u32(tl)           # conformant max_count
    n.raw(tower_octets)
    # выравнивание open array до 4 байт — если твой NDRPush не делает сам
    while (n.off % 4) != 0:
        n.u8(0)
    return n.getvalue()

def _guess_local_ip_for_reply(server) -> str:
    """Подобрать IP, который вернём клиенту.

    Если слушаем на 0.0.0.0, безопасным значением будет 127.0.0.1.
    """
    try:
        ip = getattr(server, "server_address", ("0.0.0.0", 0))[0]
    except Exception:
        ip = "0.0.0.0"
    return "127.0.0.1" if ip == "0.0.0.0" else ip


def _build_epm_map_stub(tower_octets: Optional[bytes], status: int) -> bytes:
    """Собрать stub-часть ответа ept_map()."""
    stub = NDRPush()

    # 1) entry_handle: сделаем не-NULL указатель на context handle (20 байт)
    # NDR: ptr referent_id, затем ndr_context_handle { uint32 attrs; uuid_t uuid; }
    stub.u32(0x20000)
    stub.u32(0)
    stub.raw(b"\x00" * 16)

    # 2) num_towers
    num = 1 if tower_octets is not None else 0
    stub.u32(num)

    # 3) ITowers (pointer на массив pointer'ов twr_p_t)
    stub.u32(0x20004 if num else 0)
    stub.u32(num)
    stub.u32(0)
    stub.u32(num)

    if num:
        stub.u32(0x20008)
        stub.raw(_ndr_pack_twr_t(tower_octets))

    # 4) status
    stub.u32(status)

    return stub.getvalue()

def _parse_requested_iface_from_map_tower(stub_in: bytes) -> Optional[Tuple[uuid.UUID,int]]:
    """
    Очень грубый парсер для [in, ptr] UUID* obj; [in, ptr] twr_p_t map_tower; ... 
    Нам нужен лишь Floor #1 из map_tower (UUID_type_identifier).
    Чтобы не тратить время на полный NDR, сделаем эвристику:
     - Найдем сигнатуру башни: сначала идет twr_t: uint32 len; uint32 len; потом 2-байтный floor_count.
     - Дальше берет первый floor: LHS_len(2), LHS, RHS_len(2), RHS
     - В LHS должен быть 0x0d + 16 байт UUID_LE + 2 байта major
    Если формат не совпал — вернем None.
    """
    try:
        # Входной порядок params: obj(ptr) -> map_tower(ptr) -> entry_handle(ptr) -> max_towers(u32)...
        # Пролистать первый указатель (4 байта referent) и возможный payload — но он ptr на UUID, часто NULL => начинаем искать twr_t с выравниваниями.
        off = 0

        # пропускаем obj(ptr refid)
        if len(stub_in) < 4: return None
        off += 4
        # Если obj не NULL, там еще uuid_t (16) — попробуем аккуратно, но без гарантий:
        # Это эвристика — при несовпадении все равно пойдем дальше.

        # Второй параметр: map_tower(ptr refid)
        if len(stub_in) < off+4: return None
        off += 4

        # Теперь ожидаем twr_t: tower_length(u32), max_count(u32)
        if len(stub_in) < off+8: return None
        tower_len = int.from_bytes(stub_in[off:off+4],'little'); off += 4
        _maxc     = int.from_bytes(stub_in[off:off+4],'little'); off += 4
        if len(stub_in) < off + tower_len: return None
        tower = stub_in[off:off+tower_len]
        # tower: [floor_count(2)] + floors...
        if len(tower) < 2: return None
        floors = int.from_bytes(tower[0:2],'little')
        p = 2
        if floors < 1: return None
        # первый floor:
        if len(tower) < p+2: return None
        lhs_len = int.from_bytes(tower[p:p+2],'little'); p += 2
        if len(tower) < p+lhs_len: return None
        lhs = tower[p:p+lhs_len]; p += lhs_len
        if len(lhs) < 1+16+2: return None
        if lhs[0] != 0x0d: return None
        u_le = lhs[1:17]
        ver_major = int.from_bytes(lhs[17:19],'little')
        # uuid из little-endian:
        uobj = uuid.UUID(bytes_le=bytes(u_le))
        return (uobj, ver_major)
    except Exception:
        return None
    
def _op_dcesrv_epm_Map(server, req_hdr, stub_in: bytes) -> bytes:
    asked = _parse_requested_iface_from_map_tower(stub_in)
    tower_octets = None
    status = EPM_S_NOT_REGISTERED

    if asked is not None:
        iface_u, ver_major = asked
        key = str(iface_u).lower()
        port_info = IFACE_PORTS.get(key)
        if port_info:
            ip = _guess_local_ip_for_reply(server)
            tower_octets = _build_tower_ncacn_ip_tcp(iface_u, ver_major or 1, ip, port_info[1])
            status = EPM_S_OK

    stub = _build_epm_map_stub(tower_octets, status)
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

    # остальное пока не реализовано — корректный FAULT (nca_s_op_rng_error)
    return _build_fault_co(call_id=int(req['call_id']), status=NCA_S_OP_RNG_ERROR)
