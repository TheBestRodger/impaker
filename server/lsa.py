# lsa.py — минимальная серверная реализация части MS-LSAD поверх MS-RPCE (ncacn_np / co)
import threading
from typing import Optional

from impacket.dcerpc.v5 import rpcrt
from ndr import NDRPush  # выравнивание по NDR

from utils_lsa import (
    _build_fault_co,
    _extract_request_stub_co,
)
from lsa_status import (
            NCA_S_OP_RNG_ERROR, 
            LSARPC_OPNUM_LsarClose, 
            LSARPC_OPNUM_LsarOpenPolicy2, 
            LSARPC_OPNUM_LsarQueryInformationPolicy2
)
from opnum46 import _op_LsarQueryInformationPolicy2
from opnum0 import _op_LsarClose
from opnum44 import _op_LsarOpenPolicy2

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
