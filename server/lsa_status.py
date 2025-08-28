# ---- NTSTATUS / NCA ----
import threading


STATUS_SUCCESS              = 0x00000000
STATUS_INVALID_PARAMETER    = 0xC000000D
NCA_S_OP_RNG_ERROR          = 0x1C010003
STATUS_INVALID_INFO_CLASS   = 0xC0000003 
# ---- OPNUM ----
LSARPC_OPNUM_LsarClose         = 0
LSARPC_OPNUM_LsarOpenPolicy2   = 44
LSARPC_OPNUM_LsarQueryInformationPolicy2 = 46

# таблица значений POLICY_INFORMATION_CLASS из ntsecapi.h
POLICY_INFO = {
    1:  "PolicyAuditLogInformation",
    2:  "PolicyAuditEventsInformation",
    3:  "PolicyPrimaryDomainInformation",
    4:  "PolicyPdAccountInformation",
    5:  "PolicyAccountDomainInformation",
    6:  "PolicyLsaServerRoleInformation",
    7:  "PolicyReplicaSourceInformation",
    8:  "PolicyDefaultQuotaInformation",
    9:  "PolicyModificationInformation",       # должен возвращать INVALID_PARAMETER на Query
    10: "PolicyAuditFullSetInformation",       # тоже INVALID_PARAMETER на Query
    11: "PolicyAuditFullQueryInformation",
    12: "PolicyDnsDomainInformation",
    13: "PolicyDnsDomainInformationInt",
}

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
        
def ensure_handle_table(server) -> _HandleTable:
    if not hasattr(server, 'lsa_handles'):
        server.lsa_handles = _HandleTable()
    return server.lsa_handles