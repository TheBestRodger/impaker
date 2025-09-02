# netr_ndr.py — минимальный набор типов/пакеров для MS-NRPC (Netlogon)

from typing import Tuple

from ndr import NDRPull,NDRPush

# === Базовые типы ===

def ndr_push_NETLOGON_CREDENTIAL(ndr, cred8: bytes):
    assert len(cred8) == 8
    ndr.raw(cred8)

def ndr_pull_NETLOGON_CREDENTIAL(ndr) -> bytes:
    return ndr.read(8)

def ndr_push_NETLOGON_AUTHENTICATOR(ndr, cred8: bytes, timestamp: int):
    ndr_push_NETLOGON_CREDENTIAL(ndr, cred8)
    ndr.u32(timestamp)

def ndr_pull_NETLOGON_AUTHENTICATOR(ndr) -> Tuple[bytes, int]:
    c = ndr_pull_NETLOGON_CREDENTIAL(ndr)
    ts = ndr.u32()
    return c, ts

def ndr_push_NEGOTIATE_FLAGS(ndr, flags: int):
    ndr.u32(flags)

def ndr_pull_NEGOTIATE_FLAGS(ndr) -> int:
    return ndr.u32()

# UNICODE_STRING/LPWSTR — возьми из LSA (тот же код)
ndr_push_LPWSTR = your_lsa_push_LPWSTR
ndr_pull_LPWSTR = your_lsa_pull_LPWSTR

# === netr_ServerReqChallenge (opnum 4) ===

def pack_netr_ServerReqChallenge_in(server_name: str, computer_name: str, client_chal8: bytes) -> bytes:
    ndr = NDRPush()
    ndr_push_LPWSTR(ndr, server_name)
    ndr_push_LPWSTR(ndr, computer_name)
    ndr.raw(client_chal8)         # 8 bytes
    return ndr.getvalue()

def unpack_netr_ServerReqChallenge_out(stub: bytes) -> Tuple[bytes, int]:
    n = NDRPull(stub)
    server_chal8 = n.read(8)
    status = n.u32()              # NTSTATUS
    return server_chal8, status

# === netr_ServerAuthenticate2 (opnum 15) ===

def pack_netr_ServerAuthenticate2_in(server: str, account: str, sec_chan_type: int,
                                     computer: str, client_cred8: bytes, negotiate_flags: int) -> bytes:
    n = NDRPush()
    ndr_push_LPWSTR(n, server)
    ndr_push_LPWSTR(n, account)
    n.u16(sec_chan_type)
    ndr_push_LPWSTR(n, computer)
    ndr_push_NETLOGON_CREDENTIAL(n, client_cred8)
    ndr_push_NEGOTIATE_FLAGS(n, negotiate_flags)
    return n.getvalue()

def unpack_netr_ServerAuthenticate2_out(stub: bytes) -> Tuple[bytes, int, int]:
    n = NDRPull(stub)
    server_cred8 = ndr_pull_NETLOGON_CREDENTIAL(n)
    negotiated = ndr_pull_NEGOTIATE_FLAGS(n)
    status = n.u32()
    return server_cred8, negotiated, status

# === netr_LogonSamLogonWithFlags (opnum 45) — упрощённо ===
# Логон-UNION: нужно сделать switch(LogonLevel) как в epmapper union-паттерне
# Пример — только для INTERACTIVE_INFO (для остальных веток добавишь по мере надобности)

LOGON_LEVEL_INTERACTIVE = 1
VALIDATION_LEVEL_SAM   = 2  # как пример

def ndr_push_LOGON_INFORMATION(n, level: int, info: dict):
    n.u16(level)
    if level == LOGON_LEVEL_INTERACTIVE:
        # пример полей; заполни по своей IDL
        ndr_push_LPWSTR(n, info["UserName"])
        ndr_push_LPWSTR(n, info["DomainName"])
        ndr_push_LPWSTR(n, info["Workstation"])
        ndr.raw(info["LmChallengeResponse"])
        ndr.raw(info["NtChallengeResponse"])
    else:
        # другие ветки union
        raise NotImplementedError(level)

def ndr_pull_VALIDATION_INFORMATION(n, level: int) -> dict:
    if level == VALIDATION_LEVEL_SAM:
        # распакуй SAM_VALIDATION_INFO
        return {
            "LogonDomainName": ndr_pull_LPWSTR(n),
            "UserId": n.u32(),
            # …
        }
    else:
        raise NotImplementedError(level)

def pack_netr_LogonSamLogonWithFlags_in(server: str, computer: str,
                                        logon_level: int, logon_info: dict,
                                        validation_level: int, flags: int) -> bytes:
    n = NDRPush()
    ndr_push_LPWSTR(n, server)
    ndr_push_LPWSTR(n, computer)
    ndr_push_LOGON_INFORMATION(n, logon_level, logon_info)   # union со switch
    n.u16(validation_level)
    n.u32(flags)
    return n.getvalue()

def unpack_netr_LogonSamLogonWithFlags_out(stub: bytes, validation_level: int) -> Tuple[dict, bool, int, int]:
    n = NDRPull(stub)
    val_info = ndr_pull_VALIDATION_INFORMATION(n, validation_level)  # union
    authoritative = bool(n.u8())
    flags_out = n.u32()
    status = n.u32()
    return val_info, authoritative, flags_out, status

# === netr_ServerGetTrustInfo (opnum 46) — каркас ===

def pack_netr_ServerGetTrustInfo_in(server: str, account: str, sec_chan_type: int,
                                    computer: str, authenticator: Tuple[bytes, int], flags: int) -> bytes:
    n = NDRPush()
    ndr_push_LPWSTR(n, server)
    ndr_push_LPWSTR(n, account)
    n.u16(sec_chan_type)
    ndr_push_LPWSTR(n, computer)
    cred8, ts = authenticator
    ndr_push_NETLOGON_AUTHENTICATOR(n, cred8, ts)
    n.u32(flags)
    return n.getvalue()

def unpack_netr_ServerGetTrustInfo_out(stub: bytes) -> Tuple[Tuple[bytes, int], dict, int]:
    n = NDRPull(stub)
    ret_auth = ndr_pull_NETLOGON_AUTHENTICATOR(n)
    trust_info = {}   # распакуй по нужной ветке/флагам (секреты, версии и т.п.)
    status = n.u32()
    return ret_auth, trust_info, status
