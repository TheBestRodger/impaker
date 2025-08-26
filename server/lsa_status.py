# ---- NTSTATUS / NCA ----
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