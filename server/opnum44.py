# инициализируется один раз на сервере lsarpc
import os
import struct

from utils_lsa import NDRPush, _build_response_co
from lsa_status import STATUS_SUCCESS, _HandleTable, ensure_handle_table

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

    # Собираем stub через NDRPush
    ndr = NDRPush()
    ndr.raw(policy_handle)
    ndr.u32(STATUS_SUCCESS)
    stub_out = ndr.getvalue()

    return _build_response_co(call_id=int(req_hdr['call_id']),
                              ctx_id=int(req_hdr['ctx_id']),
                              stub=stub_out)