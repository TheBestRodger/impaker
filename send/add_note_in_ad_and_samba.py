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
    # В твоём lsad.py RPC_UNICODE_STRING собирается установкой .['Data'] (см. примеры с правами). :contentReference[oaicite:1]{index=1}
    req['TrustedDomainName']['Data'] = str(name)
    req['DesiredAccess'] = desiredAccess if desiredAccess is not None else lsad.MAXIMUM_ALLOWED
    return dce.request(req)

def _hLsarDeleteTrustedDomain(dce, policyHandle, sid_canonical):
    # Удаление по SID (если не хочется открывать handle по имени)
    req = _LsarDeleteTrustedDomain()
    req['PolicyHandle'] = policyHandle
    req['TrustedDomainSid'].fromCanonical(str(sid_canonical))
    return dce.request(req)
# -----------------------------------------------------------------------------


def _create_trust_with_collision_handling(dce, policyHandle, tdo_info_ex, auth_info_clear,
                                          local_sid, local_nb, local_dns):
    """
    Создаёт TDO. Если уже есть — удаляет и создаёт заново.
    Открываем/удаляем существующий TDO по имени (DNS или NetBIOS) — это не требует ковырять SID.
    """
    desired = lsad.MAXIMUM_ALLOWED  # можно ужесточить маску, но MAXIMUM_ALLOWED проще
    try:
        res = _hLsarCreateTrustedDomainEx(dce, policyHandle, tdo_info_ex, auth_info_clear, desired)
        return res['TrustedDomainHandle']
    except Exception as e:
        # Проверяем, нет ли уже такого TDO. Твой lsad.py не даёт готовых констант статусов,
        # поэтому проще попробовать открыть по имени и, если удалось — удалить.
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
                # DeleteObject (opnum 34) есть в твоём файле. :contentReference[oaicite:2]{index=2}
                lsad.hLsarDeleteObject(dce, opened)
                print("[+] Existing TDO deleted by handle.")
            except Exception as de:
                raise RuntimeError(f"Не удалось удалить существующий TDO через DeleteObject: {de}") from de
        else:
            # Фоллбэк: удалить по SID (opnum 41) — у нас свой helper
            try:
                # local_sid можно получить из локальной PolicyDnsDomainInfo, но это PRPC_SID.
                # Если у тебя есть каноничная строка 'S-1-5-...', сюда её и подай.
                _hLsarDeleteTrustedDomain(dce, policyHandle, local_sid)
                print("[+] Existing TDO deleted by SID.")
            except Exception as de2:
                raise RuntimeError(f"Не удалось удалить существующий TDO ни по имени, ни по SID: {de2}") from de2

        # Повторная попытка создания
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
STANDARD_RIGHTS_REQUIRED      = 0x000F0000  # на будущее
# Минимум, который нам нужен: смотреть DNS-инфо + администрировать доверия + лукапы
POLICY_NEEDED = (POLICY_VIEW_LOCAL_INFORMATION | POLICY_TRUST_ADMIN | POLICY_LOOKUP_NAMES)

# --- DELETE бывает не определён в некоторых версиях lsad ---
DELETE_ACCESS = getattr(lsad, "DELETE", 0x00010000)
# ------------------------- Утилиты -------------------------
def _nttime_now():
    # Unix -> NTTIME (100ns ticks since 1601-01-01)
    return int((time.time() + 11644473600) * 10_000_000)

def _lsa_open_policy_any(dce, desired):
    """
    Открой PolicyHandle, совместимо с разными версиями impacket:
      1) hLsarOpenPolicy2(dce, desiredAccess=...)
      2) hLsarOpenPolicy2(dce, desired)
      3) hLsarOpenPolicy2(dce)
      4) сырой LsarOpenPolicy2 запрос (без helper'а)
    """
    # 1) hLsarOpenPolicy2(dce, desiredAccess=...)
    try:
        res = lsad.hLsarOpenPolicy2(dce, desiredAccess=desired)
        return res["PolicyHandle"]
    except TypeError:
        pass
    except Exception:
        pass

    # 2) hLsarOpenPolicy2(dce, desired)
    try:
        res = lsad.hLsarOpenPolicy2(dce, desired)
        return res["PolicyHandle"]
    except TypeError:
        pass
    except Exception:
        pass

    # 3) hLsarOpenPolicy2(dce)
    try:
        res = lsad.hLsarOpenPolicy2(dce)
        # если helper вернул хэндл с минимальными правами — оставляем как есть
        return res["PolicyHandle"]
    except Exception:
        pass

    # 4) СЫРОЙ вызов (без helper'а)
    try:
        req = lsad.LsarOpenPolicy2()
        # SystemName=NULL
        req["SystemName"] = None
        # ObjectAttributes=NULL
        req["ObjectAttributes"] = None
        req["DesiredAccess"] = desired
        rsp = dce.request(req)
        return rsp["PolicyHandle"]
    except Exception as e:
        raise RuntimeError(f"LsarOpenPolicy2 failed across all fallbacks: {e}") from e


def _lsa_rpc_connect(ip, username, password, domain=None, do_kerberos=False, kdc=None, hashes=None):
    """Открыть DCERPC к \\PIPE\\lsarpc и вернуть (dce, policyHandle, dnsInfo)."""
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

    # <-- КЛЮЧЕВАЯ СТРОКА: совместимая функция открытия Policy
    pol = _lsa_open_policy_any(dce, POLICY_NEEDED)

    dns_info = lsad.hLsarQueryInformationPolicy2(
        dce, pol, lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation
    )["PolicyInformation"]["PolicyDnsDomainInfo"]

    return dce, pol, dns_info
def _lsa_local_rpc_connect(ip, username, password, domain=None, do_kerberos=False, kdc=None, hashes=None):
    """Открыть DCERPC к \\PIPE\\lsarpc и вернуть (dce, policyHandle, dnsInfo)."""
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

    # <-- КЛЮЧЕВАЯ СТРОКА: совместимая функция открытия Policy
    pol = _lsa_open_policy_any(dce, POLICY_NEEDED)

    dns_info = lsad.hLsarQueryInformationPolicy2(
        dce, pol, lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation
    )["PolicyInformation"]["PolicyDnsDomainInfo"]

    return dce, pol, dns_info
def _rpc_unicode(s: str):
    u = lsad.RPC_UNICODE_STRING()
    u['Buffer'] = s
    u['Length'] = len(s) * 2
    u['MaximumLength'] = (len(s) + 1) * 2
    return u

def _set_unicode_field(container, field: str, value: str):
    """Совместимо с разными impacket: WSTR (str) или RPC_UNICODE_STRING."""
    cur = container[field]
    if isinstance(cur, str):
        container[field] = value
    else:
        container[field] = _rpc_unicode(value)

def _make_trust_info_ex(local_sid, local_dns: str, local_nb: str):
    """LSAPR_TRUSTED_DOMAIN_INFORMATION_EX для удалённого DC: он будет доверять локальному домену."""
    info = lsad.LSAPR_TRUSTED_DOMAIN_INFORMATION_EX()

    # Name = DNS-имя, FlatName = NetBIOS (учтём разные типы поля)
    _set_unicode_field(info, "Name", local_dns)
    _set_unicode_field(info, "FlatName", local_nb)

    # SID локального домена
    info["Sid"] = local_sid

    # Флаги доверия
    info["TrustDirection"]  = TRUST_DIRECTION_INBOUND | TRUST_DIRECTION_OUTBOUND
    info["TrustType"]       = TRUST_TYPE_UPLEVEL
    info["TrustAttributes"] = TRUST_ATTRIBUTE_FOREST_TRANSITIVE
    return info

def _make_auth_info_clear(trust_password: str):
    """
    LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION с одним CLEAR-паролем
    (incoming/outgoing одинаковы) — совместимо с твоим lsad.py.
    """
    pwd_bytes = trust_password.encode("utf-16-le")

    # 1) Одна запись LSAPR_AUTH_INFORMATION
    clear = lsad.LSAPR_AUTH_INFORMATION()
    clear["LastUpdateTime"]  = _nttime_now()                 # LARGE_INTEGER
    clear["AuthType"]        = TRUST_AUTH_TYPE_CLEAR
    clear["AuthInfoLength"]  = len(pwd_bytes)                # <-- длина задаётся ТУТ
    clear["AuthInfo"]        = list(pwd_bytes)               # <-- LPBYTE ожидает список байтов

    # 2) Упаковываем в LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION
    auth = lsad.LSAPR_TRUSTED_DOMAIN_AUTH_INFORMATION()
    auth["IncomingAuthInfos"]                         = 1
    auth["IncomingAuthenticationInformation"]         = clear
    auth["IncomingPreviousAuthenticationInformation"] = lsad.NULL

    auth["OutgoingAuthInfos"]                         = 1
    auth["OutgoingAuthenticationInformation"]         = clear
    auth["OutgoingPreviousAuthenticationInformation"] = lsad.NULL

    return auth

def _open_existing_trust(dce, policyHandle, local_sid, local_nb, local_dns):
    """Вернуть handle на уже существующий Trust (SID -> NB -> DNS)."""
    desired = lsad.TRUSTED_QUERY_DOMAIN_NAME | lsad.DELETE | lsad.TRUSTED_SET_POSIX
    # 1) по SID
    try:
        h = lsad.hLsarOpenTrustedDomain(dce, policyHandle, local_sid, desired)["TrustedDomainHandle"]
        return h
    except DCERPCException as e:
        pass

    # 2) по NetBIOS
    try:
        uni = lsad.RPC_UNICODE_STRING()
        uni["Buffer"] = local_nb
        uni["Length"] = len(local_nb) * 2
        uni["MaximumLength"] = (len(local_nb) + 1) * 2
        h = lsad.hLsarOpenTrustedDomainByName(dce, policyHandle, uni, desired)["TrustedDomainHandle"]
        return h
    except DCERPCException:
        pass

    # 3) по DNS
    try:
        uni = lsad.RPC_UNICODE_STRING()
        uni["Buffer"] = local_dns
        uni["Length"] = len(local_dns) * 2
        uni["MaximumLength"] = (len(local_dns) + 1) * 2
        h = lsad.hLsarOpenTrustedDomainByName(dce, policyHandle, uni, desired)["TrustedDomainHandle"]
        return h
    except DCERPCException:
        return None


# ------------------------- main -------------------------
# config.py
LOCAL_IP      = "127.0.0.1"
REMOTE_IP     = "192.168.69.10"
DOMAIN        = "AD.LOCAL"
USERNAME      = "Администратор"
PASSWORD      = "Mos123098!"
HASHES        = None
KERBEROS      = False
KDC           = None
TRUST_PASS    = "234"
LOCAL_NBNAME  = None

import argparse


def main():
    ap = argparse.ArgumentParser(description="Create forest trust (impacket, LSARPC, CreateTrustedDomainEx)")

    ap.add_argument("--local-ip",  default=LOCAL_IP,
                    help="IP локального DC (откуда берём SID/DNS/NB локального домена)")
    ap.add_argument("--remote-ip", default=REMOTE_IP,
                    help="IP удалённого DC (где СОЗДАЁМ объект доверия)")
    ap.add_argument("-d", "--domain", default=DOMAIN,
                    help="Домен для аутентификации (удалённый DC)")
    ap.add_argument("-u", "--username", default=USERNAME,
                    help="Администратор (удалённый домен)")
    ap.add_argument("-p", "--password", default=PASSWORD,
                    help="Пароль")
    ap.add_argument("--hashes", default=HASHES,
                    help="LMHASH:NTHASH (альтернатива паролю)")
    ap.add_argument("--kerberos", action="store_true",
                    default=KERBEROS,
                    help="Kerberos вместо NTLM")
    ap.add_argument("--kdc", default=KDC,
                    help="KDC host (для Kerberos)")
    ap.add_argument("--trust-pass", default=TRUST_PASS,
                    help="Пароль доверия (incoming/outgoing одинаковый)")
    ap.add_argument("--local-nbname", default=LOCAL_NBNAME,
                    help="Переопределить NetBIOS-имя локального домена")

    args = ap.parse_args()

    print(args)  # отладка — видим итоговые параметры

    # 1) Локальный DC: берём SID/DNS/NB
    print(f"[*] Connecting to LOCAL LSA at {args.local_ip} ...")
    local_dce, local_policy, local_dns_info = _lsa_local_rpc_connect(
        args.local_ip, "Administrator", "NewStrong#Pass123", "samba.local", args.kerberos, args.kdc, args.hashes
    )
    local_sid = local_dns_info["Sid"]
    local_dns = str(local_dns_info["DnsDomainName"])
    local_nb  = args.local_nbname or str(local_dns_info["Name"])
    print(f"    Local DNS: {local_dns}, NB: {local_nb}, SID: {local_sid.formatCanonical()}")

    # 2) Удалённый DC: там создаём доверие к локальному домену
    print(f"[*] Connecting to REMOTE LSA at {args.remote_ip} ...")
    remote_dce, remote_policy, remote_dns_info = _lsa_rpc_connect(
        args.remote_ip, args.username, args.password, args.domain, args.kerberos, args.kdc, args.hashes
    )
    print(f"    Remote DNS: {remote_dns_info['DnsDomainName']}, NB: {remote_dns_info['Name']}")

    # 3) Структуры
    tdo_info_ex = _make_trust_info_ex(local_sid, local_dns, local_nb)
    auth_clear  = _make_auth_info_clear(args.trust_pass)

    # 4) Создание с обработкой коллизии
    print("[*] Creating trust on REMOTE (LsarCreateTrustedDomainEx) ...")
    tdo_handle = _create_trust_with_collision_handling(
        remote_dce, remote_policy, tdo_info_ex, auth_clear,
        local_sid, local_nb, local_dns
    )
    print("[+] Trust created. Handle:", tdo_handle)

    # закрываем хэндлы по возможности
    try: lsad.hLsarClose(remote_dce, tdo_handle)
    except: pass
    try:
        lsad.hLsarClose(remote_dce, remote_policy)
        lsad.hLsarClose(local_dce, local_policy)
    except: pass
    remote_dce.disconnect(); local_dce.disconnect()

if __name__ == "__main__":
    main()
