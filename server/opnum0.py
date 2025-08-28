# ---- opnum 0 ----
import struct
from utils_lsa import NDRPush, _build_response_co
from lsa_status import STATUS_SUCCESS, _HandleTable, ensure_handle_table


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