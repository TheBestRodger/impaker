#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import os
import sys
import time

from impacket.dcerpc.v5 import transport, lsad, lsat
from impacket.dcerpc.v5.rpcrt import DCERPCException
from impacket import ntlm

# --- COMPAT LAYER: add missing LSARPC calls for your lsad.py ------------------
from impacket.dcerpc.v5.ndr import NDRCALL
from impacket.dcerpc.v5.dtypes import NULL

# Классы для LsarCreateTrustedDomainEx (opnum 51)
class _LsarCreateTrustedDomainEx(NDRCALL):
    opnum = 51
    structure = (
        ('PolicyHandle', lsad.LSAPR_HANDLE),
        ('TrustedDomainInformation', lsad.LSAPR_TRUSTED_DOMAIN_INFORMATION_EX),
        ('AuthenticationInformation', lsad.LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION),
        ('DesiredAccess', lsad.ACCESS_MASK),
    )

class _LsarCreateTrustedDomainExResponse(NDRCALL):
    structure = (
        ('TrustedDomainHandle', lsad.LSAPR_HANDLE),
        ('ErrorCode', lsad.NTSTATUS),
    )

# Классы для LsarOpenTrustedDomainByName (opnum 55)
class _LsarOpenTrustedDomainByName(NDRCALL):
    opnum = 55
    structure = (
        ('PolicyHandle', lsad.LSAPR_HANDLE),
        ('TrustedDomainName', lsad.RPC_UNICODE_STRING),
        ('DesiredAccess', lsad.ACCESS_MASK),
    )

class _LsarOpenTrustedDomainByNameResponse(NDRCALL):
    structure = (
        ('TrustedDomainHandle', lsad.LSAPR_HANDLE),
        ('ErrorCode', lsad.NTSTATUS),
    )

# (опционально) Классы для LsarDeleteTrustedDomain (opnum 41) — удаление по SID
class _LsarDeleteTrustedDomain(NDRCALL):
    opnum = 41
    structure = (
        ('PolicyHandle', lsad.LSAPR_HANDLE),
        ('TrustedDomainSid', lsad.RPC_SID),
    )

class _LsarDeleteTrustedDomainResponse(NDRCALL):
    structure = (
        ('ErrorCode', lsad.NTSTATUS),
    )

def _hLsarCreateTrustedDomainEx(dce, policyHandle, info_ex, auth_clear, desiredAccess=None):
    req = _LsarCreateTrustedDomainEx()
    req['PolicyHandle'] = policyHandle
    req['TrustedDomainInformation'] = info_ex
    req['AuthenticationInformation'] = auth_clear
    req['DesiredAccess'] = desiredAccess if desiredAccess is not None else lsad.MAXIMUM_ALLOWED
    return dce.request(req)

def _hLsarOpenTrustedDomainByName(dce, policyHandle, name, desiredAccess=None):
    req = _LsarOpenTrustedDomainByName()
    req['PolicyHandle'] = policyHandle
    req['TrustedDomainName']['Data'] = str(name)  # см. примеры с правами в твоём lsad.py
    req['DesiredAccess'] = desiredAccess if desiredAccess is not None else lsad.MAXIMUM_ALLOWED
    return dce.request(req)

def _hLsarDeleteTrustedDomain(dce, policyHandle, sid_canonical_str):
    req = _LsarDeleteTrustedDomain()
    req['PolicyHandle'] = policyHandle
    req['TrustedDomainSid'].fromCanonical(str(sid_canonical_str))
    return dce.request(req)
# -----------------------------------------------------------------------------


def _create_trust_with_collision_handling(dce, policyHandle, tdo_info_ex, auth_info_clear,
                                          local_sid, local_nb, local_dns):
    """
    Создаёт TDO на УДАЛЁННОМ AD. Если уже есть — удаляет и создаёт заново.
    Открываем/удаляем существующий TDO по имени (DNS или NetBIOS); если не вышло — по SID.
    """
    desired = lsad.MAXIMUM_ALLOWED
    try:
        res = _hLsarCreateTrustedDomainEx(dce, policyHandle, tdo_info_ex, auth_info_clear, desired)
        return res['TrustedDomainHandle']
    except Exception as e:
        print(f"[i] CreateTrustedDomainEx failed: {e}. Trying to delete existing TDO...")

        opened = None
        for name_try in filter(None, [local_dns, local_nb]):
            try:
                o = _hLsarOpenTrustedDomainByName(dce, policyHandle, name_try, lsad.MAXIMUM_ALLOWED)
                opened = o['TrustedDomainHandle']
                print(f"[i] Found existing TDO by name: {name_try}")
                break
            except Exception:
                continue

        if opened:
            try:
                lsad.hLsarDeleteObject(dce, opened)  # Delete by handle
                print("[+] Existing TDO deleted by handle.")
            except Exception as de:
                raise RuntimeError(f"Не удалось удалить существующий TDO через DeleteObject: {de}") from de
        else:
            # Фоллбэк: удалить по SID (опnum 41)
            try:
                sid_str = local_sid.formatCanonical() if hasattr(local_sid, 'formatCanonical') else str(local_sid)
                _hLsarDeleteTrustedDomain(dce, policyHandle, sid_str)
                print("[+] Existing TDO deleted by SID.")
            except Exception as de2:
                raise RuntimeError(f"Не удалось удалить существующий TDO ни по имени, ни по SID: {de2}") from de2

        res2 = _hLsarCreateTrustedDomainEx(dce, policyHandle, tdo_info_ex, auth_info_clear, desired)
        return res2['TrustedDomainHandle']

# ------------------------- Константы LSA -------------------------
TRUST_DIRECTION_INBOUND  = 0x00000001
TRUST_DIRECTION_OUTBOUND = 0x00000002
TRUST_TYPE_UPLEVEL       = 0x00000002
TRUST_ATTRIBUTE_FOREST_TRANSITIVE = 0x00000008

TRUST_AUTH_TYPE_CLEAR = 0x00000002  # используем простой пароль доверия

# --- Политические права (в impacket нет POLICY_ALL_ACCESS) ---
POLICY_VIEW_LOCAL_INFORMATION = 0x00000001
POLICY_TRUST_ADMIN            = 0x00000008
POLICY_LOOKUP_NAMES           = 0x00000800
POLICY_NEEDED = (POLICY_VIEW_LOCAL_INFORMATION | POLICY_TRUST_ADMIN | POLICY_LOOKUP_NAMES)

DELETE_ACCESS = getattr(lsad, "DELETE", 0x00010000)

# ------------------------- Утилиты -------------------------
def _nttime_now():
    return int((time.time() + 11644473600) * 10_000_000)

def _lsa_open_policy_any(dce, desired):
    try:
        res = lsad.hLsarOpenPolicy2(dce, desiredAccess=desired)
        return res["PolicyHandle"]
    except TypeError:
        pass
    except Exception:
        pass
    try:
        res = lsad.hLsarOpenPolicy2(dce, desired)
        return res["PolicyHandle"]
    except TypeError:
        pass
    except Exception:
        pass
    try:
        res = lsad.hLsarOpenPolicy2(dce)
        return res["PolicyHandle"]
    except Exception:
        pass
    # RAW
    req = lsad.LsarOpenPolicy2()
    req["SystemName"] = None
    req["ObjectAttributes"] = None
    req["DesiredAccess"] = desired
    rsp = dce.request(req)
    return rsp["PolicyHandle"]

def _lsa_rpc_connect(ip, username, password, domain=None, do_kerberos=False, kdc=None, hashes=None):
    """Подключение к \\PIPE\\lsarpc на УДАЛЁННОМ AD."""
    binding = fr"ncacn_np:{ip}[\pipe\lsarpc]"
    rpctransport = transport.DCERPCTransportFactory(binding)

    if hasattr(rpctransport, "set_credentials"):
        lmhash = nthash = ""
        if hashes:
            parts = hashes.split(":")
            if len(parts) == 2:
                lmhash, nthash = parts
        rpctransport.set_credentials(username, password, domain or "", lmhash, nthash)
        rpctransport.set_kerberos(do_kerberos, kdcHost=kdc)

    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(lsad.MSRPC_UUID_LSAD)

    pol = _lsa_open_policy_any(dce, POLICY_NEEDED)
    dns_info = lsad.hLsarQueryInformationPolicy2(
        dce, pol, lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation
    )["PolicyInformation"]["PolicyDnsDomainInfo"]

    return dce, pol, dns_info

# --- Локальный RPC (samba) БОЛЬШЕ НЕ ИСПОЛЬЗУЕМ — оставлено для истории -----
# def _lsa_local_rpc_connect(ip, username, password, domain=None, do_kerberos=False, kdc=None, hashes=None):
#     """Открыть DCERPC к \\PIPE\\lsarpc и вернуть (dce, policyHandle, dnsInfo)."""
#     binding = fr"ncacn_np:{ip}[\pipe\lsarpc]"
#     rpctransport = transport.DCERPCTransportFactory(binding)
#     if hasattr(rpctransport, "set_credentials"):
#         lmhash = nthash = ""
#         if hashes:
#             parts = hashes.split(":")
#             if len(parts) == 2:
#                 lmhash, nthash = parts
#         rpctransport.set_credentials(username, password, domain or "", lmhash, nthash)
#         rpctransport.set_kerberos(do_kerberos, kdcHost=kdc)
#     dce = rpctransport.get_dce_rpc()
#     dce.connect()
#     dce.bind(lsad.MSRPC_UUID_LSAD)
#     pol = _lsa_open_policy_any(dce, POLICY_NEEDED)
#     dns_info = lsad.hLsarQueryInformationPolicy2(
#         dce, pol, lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation
#     )["PolicyInformation"]["PolicyDnsDomainInfo"]
#     return dce, pol, dns_info
# ---------------------------------------------------------------------------

def _rpc_unicode(s: str):
    u = lsad.RPC_UNICODE_STRING()
    u['Buffer'] = s
    u['Length'] = len(s) * 2
    u['MaximumLength'] = (len(s) + 1) * 2
    return u

def _set_unicode_field(container, field: str, value: str):
    cur = container[field]
    if isinstance(cur, str):
        container[field] = value
    else:
        container[field] = _rpc_unicode(value)

def _make_trust_info_ex(local_sid, local_dns: str, local_nb: str):
    info = lsad.LSAPR_TRUSTED_DOMAIN_INFORMATION_EX()
    _set_unicode_field(info, "Name", local_dns)      # DNS-имя локального домена (SAMBA side)
    _set_unicode_field(info, "FlatName", local_nb)   # NetBIOS локального домена
    info["Sid"] = local_sid
    info["TrustDirection"]  = TRUST_DIRECTION_INBOUND | TRUST_DIRECTION_OUTBOUND
    info["TrustType"]       = TRUST_TYPE_UPLEVEL
    info["TrustAttributes"] = TRUST_ATTRIBUTE_FOREST_TRANSITIVE
    return info

def _make_auth_info_clear(trust_password: str):
    pwd_bytes = trust_password.encode("utf-16-le")
    clear = lsad.LSAPR_AUTH_INFORMATION()
    clear["LastUpdateTime"]  = _nttime_now()
    clear["AuthType"]        = TRUST_AUTH_TYPE_CLEAR
    clear["AuthInfoLength"]  = len(pwd_bytes)
    clear["AuthInfo"]        = list(pwd_bytes)

    auth = lsad.LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION()
    auth["IncomingAuthInfos"]                         = 1
    auth["IncomingAuthenticationInformation"]         = clear
    auth["IncomingPreviousAuthenticationInformation"] = lsad.NULL
    auth["OutgoingAuthInfos"]                         = 1
    auth["OutgoingAuthenticationInformation"]         = clear
    auth["OutgoingPreviousAuthenticationInformation"] = lsad.NULL
    return auth

# ------------------------- STATIC LOCAL (SAMBA) SIDE --------------------------
# ВАЖНО: заполни эти константы корректными значениями локального (SAMBA) домена!
STATIC_LOCAL_DNS = "samba.local"      # DNS-имя локального домена (SAMBA)
STATIC_LOCAL_NB  = "SAMBA"            # NetBIOS-имя локального домена
STATIC_LOCAL_SID = "S-1-5-21-1111111111-2222222222-3333333333"  # КАНОНИЧНАЯ строка SID

def _build_local_sid_from_static(sid_str: str):
    sid = lsad.RPC_SID()
    sid.fromCanonical(sid_str)
    return sid

# ------------------------- main -------------------------
# Можно было бы тянуть из config.py, но по просьбе — держим статикой выше.
LOCAL_IP      = "127.0.0.1"          # не используется (локальный LSA выключен)
REMOTE_IP     = "192.168.69.10"
DOMAIN        = "AD.LOCAL"
USERNAME      = "Администратор"
PASSWORD      = "Mos123098!"
HASHES        = None
KERBEROS      = False
KDC           = None
TRUST_PASS    = "234"
LOCAL_NBNAME  = None

def main():
    ap = argparse.ArgumentParser(description="Create forest trust on REMOTE AD only (impacket, LSARPC, CreateTrustedDomainEx)")
    ap.add_argument("--remote-ip", default=REMOTE_IP, help="IP удалённого DC (где СОЗДАЁМ TDO для SAMBA-домена)")
    ap.add_argument("-d", "--domain", default=DOMAIN, help="Домен (удалённый AD) для аутентификации")
    ap.add_argument("-u", "--username", default=USERNAME, help="Учётка администратора удалённого AD")
    ap.add_argument("-p", "--password", default=PASSWORD, help="Пароль")
    ap.add_argument("--hashes", default=HASHES, help="LMHASH:NTHASH (альтернатива паролю)")
    ap.add_argument("--kerberos", action="store_true", default=KERBEROS, help="Kerberos вместо NTLM")
    ap.add_argument("--kdc", default=KDC, help="KDC host (для Kerberos)")
    ap.add_argument("--trust-pass", default=TRUST_PASS, help="Пароль доверия (incoming/outgoing одинаковый)")
    # локальные (SAMBA) имена можно переопределить CLI, но по умолчанию из статики:
    ap.add_argument("--local-dns", default=STATIC_LOCAL_DNS, help="DNS имя локального (SAMBA) домена")
    ap.add_argument("--local-nb",  default=STATIC_LOCAL_NB,  help="NetBIOS имя локального (SAMBA) домена")
    ap.add_argument("--local-sid", default=STATIC_LOCAL_SID, help="SID локального (SAMBA) домена (каноничная строка)")
    args = ap.parse_args()

    # --- ЛОКАЛЬНУЮ СТОРОНУ БОЛЬШЕ НЕ ЧИТАЕМ ПО RPC ---
    # print(f"[*] Connecting to LOCAL LSA at {LOCAL_IP} ...")
    # local_dce, local_policy, local_dns_info = _lsa_local_rpc_connect(
    #     LOCAL_IP, "Administrator", "NewStrong#Pass123", "samba.local", args.kerberos, args.kdc, args.hashes
    # )
    # local_sid = local_dns_info["Sid"]
    # local_dns = str(local_dns_info["DnsDomainName"])
    # local_nb  = args.local_nbname or str(local_dns_info["Name"])

    # --- Берём локальные данные ИЗ СТАТИКИ ---
    local_dns = args.local_dns
    local_nb  = args.local_nb
    local_sid = _build_local_sid_from_static(args.local_sid)

    print(f"[*] Using STATIC SAMBA domain info:")
    print(f"    Local DNS: {local_dns}, NB: {local_nb}, SID: {local_sid.formatCanonical()}")

    # 2) Удалённый DC (AD): там создаём доверие к локальному (SAMBA) домену
    print(f"[*] Connecting to REMOTE LSA at {args.remote_ip} ...")
    remote_dce, remote_policy, remote_dns_info = _lsa_rpc_connect(
        args.remote_ip, args.username, args.password, args.domain, args.kerberos, args.kdc, args.hashes
    )
    print(f"    Remote DNS: {remote_dns_info['DnsDomainName']}, NB: {remote_dns_info['Name']}")

    # 3) Структуры под создание TDO
    tdo_info_ex = _make_trust_info_ex(local_sid, local_dns, local_nb)
    auth_clear  = _make_auth_info_clear(args.trust_pass)

    # 4) Создание/пересоздание на УДАЛЁННОМ AD
    print("[*] Creating trust on REMOTE (LsarCreateTrustedDomainEx) ...")
    tdo_handle = _create_trust_with_collision_handling(
        remote_dce, remote_policy, tdo_info_ex, auth_clear,
        local_sid, local_nb, local_dns
    )
    print("[+] Trust created. Handle:", tdo_handle)

    # закрываем хэндлы по возможности
    try:
        lsad.hLsarClose(remote_dce, tdo_handle)
    except Exception:
        pass
    try:
        lsad.hLsarClose(remote_dce, remote_policy)
    except Exception:
        pass
    remote_dce.disconnect()

if __name__ == "__main__":
    main()
