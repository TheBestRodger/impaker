# netlogon.py
# dcerpc/netlogon (MS-NRPC) — обёртка и enum opnums + диспетчер

from typing import Optional, Callable, Dict
from enum import IntEnum
from impacket.dcerpc.v5 import rpcrt

# Эти утилиты ты уже используешь в LSA
from utils_lsa import (
    _extract_request_stub_co,
    _build_fault_co,
)
from netr_opnum4 import ServerReqChallenge

# UUID интерфейса NETLOGON (abstract syntax) – MS-NRPC
# Версия интерфейса часто 1.0 (CO-RPC), но проверяй в своём bind
NETLOGON_UUID = "12345678-1234-abcd-ef00-0123456789ab"

# === ENUM всех opnums (по MS-NRPC/ndr_netlogon.idl) ===
class NRPC_OPNUM(IntEnum):
    netr_LogonUasLogon                          = 0
    netr_LogonUasLogoff                         = 1
    netr_LogonSamLogon                          = 2
    netr_LogonSamLogoff                         = 3
    netr_ServerReqChallenge                     = 4
    netr_ServerAuthenticate                     = 5
    netr_ServerPasswordSet                      = 6
    netr_DatabaseDeltas                         = 7
    netr_DatabaseSync                           = 8
    netr_AccountDeltas                          = 9
    netr_AccountSync                            = 10
    netr_GetDcName                              = 11
    netr_LogonControl                           = 12
    netr_GetAnyDCName                           = 13
    netr_LogonControl2                          = 14
    netr_ServerAuthenticate2                    = 15
    netr_DatabaseSync2                          = 16
    netr_DatabaseRedo                           = 17
    netr_LogonControl2Ex                        = 18
    netr_NetrEnumerateTrustedDomains            = 19
    netr_DsRGetDCName                           = 20
    netr_LogonGetCapabilities                   = 21
    netr_NETRLOGONSETSERVICEBITS                = 22
    netr_LogonGetTrustRid                       = 23
    netr_NETRLOGONCOMPUTESERVERDIGEST           = 24
    netr_NETRLOGONCOMPUTECLIENTDIGEST           = 25
    netr_ServerAuthenticate3                    = 26
    netr_DsRGetDCNameEx                         = 27
    netr_DsRGetSiteName                         = 28
    netr_LogonGetDomainInfo                     = 29
    netr_ServerPasswordSet2                     = 30
    netr_ServerPasswordGet                      = 31
    netr_NetrLogonSendToSam                     = 32
    netr_DsRAddressToSitenamesW                 = 33
    netr_DsRGetDCNameEx2                        = 34
    netr_NETRLOGONGETTIMESERVICEPARENTDOMAIN    = 35
    netr_NetrEnumerateTrustedDomainsEx          = 36
    netr_DsRAddressToSitenamesExW               = 37
    netr_DsrGetDcSiteCoverageW                  = 38
    netr_LogonSamLogonEx                        = 39
    netr_DsrEnumerateDomainTrusts               = 40
    netr_DsrDeregisterDNSHostRecords            = 41
    netr_ServerTrustPasswordsGet                = 42
    netr_DsRGetForestTrustInformation           = 43
    netr_GetForestTrustInformation              = 44
    netr_LogonSamLogonWithFlags                 = 45
    netr_ServerGetTrustInfo                     = 46
    netr_Unused47                               = 47
    netr_DsrUpdateReadOnlyServerDnsRecords      = 48
    netr_Opnum49NotUsedOnWire                   = 49
    netr_Opnum50NotUsedOnWire                   = 50
    netr_Opnum51NotUsedOnWire                   = 51
    netr_Opnum52NotUsedOnWire                   = 52
    netr_Opnum53NotUsedOnWire                   = 53
    netr_ChainSetClientAttributes               = 54
    netr_Opnum55NotUsedOnWire                   = 55
    netr_Opnum56NotUsedOnWire                   = 56
    netr_Opnum57NotUsedOnWire                   = 57
    netr_Opnum58NotUsedOnWire                   = 58
    netr_ServerAuthenticateKerberos             = 59


# ===== Каркас обработчиков =====
# Сигнатура обработчика: (server, req_hdr, stub_in) -> bytes
HandlerFn = Callable[[object, rpcrt.MSRPCRequestHeader, bytes], Optional[bytes]]

_dispatch: Dict[int, HandlerFn] = {}


def _register(op: NRPC_OPNUM):
    """Декоратор для регистрации обработчика opnum’а."""
    def _wrap(fn: HandlerFn) -> HandlerFn:
        _dispatch[int(op)] = fn
        return fn
    return _wrap


# === Примеры «скелетов» ключевых методов (пока возвращают FAULT/UNSUPPORTED)
# Когда будешь реализовывать логику — внутри создавай RESPONSE PDU и сериализуй NDR.

@_register(NRPC_OPNUM.netr_ServerReqChallenge)
def _op_netr_ServerReqChallenge(server, req: rpcrt.MSRPCRequestHeader, stub_in: bytes) -> Optional[bytes]:
    """
    [MS-NRPC] netr_ServerReqChallenge (opnum 4)
    В проде: разобрать NDR (UNICODE_STRING ComputerName, DomainName, ClientChallenge[8]),
    сгенерить ServerChallenge[8], вернуть STATUS_SUCCESS + OUT-поля.
    Пока — FAULT как заглушка.
    """
    req = ServerReqChallenge(server, req, stub_in)
    return req

@_register(NRPC_OPNUM.netr_ServerAuthenticate2)
def _op_netr_ServerAuthenticate2(server, req: rpcrt.MSRPCRequestHeader, stub_in: bytes) -> Optional[bytes]:
    """
    [MS-NRPC] netr_ServerAuthenticate2 (opnum 15)
    В проде: проверить SecureChannelType, AccountName, ClientCredential, NegotiateFlags,
    ответить ServerCredential, NegotiatedFlags и STATUS_SUCCESS.
    """
    return _build_fault_co(call_id=int(req['call_id']), status=rpcrt.NCA_S_FAULT_UNSPEC)

@_register(NRPC_OPNUM.netr_ServerAuthenticate3)
def _op_netr_ServerAuthenticate3(server, req: rpcrt.MSRPCRequestHeader, stub_in: bytes) -> Optional[bytes]:
    """
    [MS-NRPC] netr_ServerAuthenticate3 (opnum 26)
    Как Authenticate2, но с ReturnAuthenticator и доп. проверками.
    """
    return _build_fault_co(call_id=int(req['call_id']), status=rpcrt.NCA_S_FAULT_UNSPEC)

@_register(NRPC_OPNUM.netr_LogonSamLogon)
def _op_netr_LogonSamLogon(server, req: rpcrt.MSRPCRequestHeader, stub_in: bytes) -> Optional[bytes]:
    """
    [MS-NRPC] netr_LogonSamLogon (opnum 2)
    В проде: логон интерактивный/сеть/… через LogonLevel, ValidationLevel, пр.
    """
    return _build_fault_co(call_id=int(req['call_id']), status=rpcrt.NCA_S_FAULT_UNSPEC)

@_register(NRPC_OPNUM.netr_LogonSamLogonWithFlags)
def _op_netr_LogonSamLogonWithFlags(server, req: rpcrt.MSRPCRequestHeader, stub_in: bytes) -> Optional[bytes]:
    """
    [MS-NRPC] netr_LogonSamLogonWithFlags (opnum 45)
    В проде: расширенный логон (DNS-имена, PAC, флаги).
    """
    return _build_fault_co(call_id=int(req['call_id']), status=rpcrt.NCA_S_FAULT_UNSPEC)

@_register(NRPC_OPNUM.netr_ServerGetTrustInfo)
def _op_netr_ServerGetTrustInfo(server, req: rpcrt.MSRPCRequestHeader, stub_in: bytes) -> Optional[bytes]:
    """
    [MS-NRPC] netr_ServerGetTrustInfo (opnum 46)
    В проде: вернуть доверительную инфу (доменные секреты/версии/Authenticator’ы).
    """
    return _build_fault_co(call_id=int(req['call_id']), status=rpcrt.NCA_S_FAULT_UNSPEC)

@_register(NRPC_OPNUM.netr_DsrEnumerateDomainTrusts)
def _op_netr_DsrEnumerateDomainTrusts(server, req: rpcrt.MSRPCRequestHeader, stub_in: bytes) -> Optional[bytes]:
    """
    [MS-NRPC] DsrEnumerateDomainTrusts (opnum 40) – для списка доверий (Forest/External/…).
    """
    return _build_fault_co(call_id=int(req['call_id']), status=rpcrt.NCA_S_FAULT_UNSPEC)


def handle_netr_request(server, pdu: bytes) -> Optional[bytes]:
    """
    Принять целиком REQUEST PDU по NETLOGON, вернуть bytes ответа (RESPONSE/FAULT) или None.
    Поведение аналогично твоему handle_lsa_request(...).
    """
    try:
        req = rpcrt.MSRPCRequestHeader(pdu)
        opnum = int(req['op_num'])
    except Exception:
        return None

    # Получаем stub (in) и (если надо) аутентификацию/конфиденциальность
    stub_in, _auth = _extract_request_stub_co(pdu)

    handler = _dispatch.get(opnum)
    if handler is not None:
        try:
            return handler(server, req, stub_in)
        except Exception:
            # Если наш обработчик упал — корректный FAULT вместо RST/none
            return _build_fault_co(call_id=int(req['call_id']), status=rpcrt.NCA_S_FAULT_UNSPEC)

    # Неизвестный/неподдерживаемый opnum — ровно как в LSA
    return _build_fault_co(call_id=int(req['call_id']), status=rpcrt.NCA_S_OP_RNG_ERROR)

