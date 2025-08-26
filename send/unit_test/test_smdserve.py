# from impacket.dcerpc.v5 import lsad
# from impacket.dcerpc.v5 import transport
# from impacket.dcerpc.v5.dtypes import MAXIMUM_ALLOWED, RPC_UNICODE_STRING, DELETE

# iface_uuid = lsad.MSRPC_UUID_LSAD
# string_binding = r"ncacn_np:192.168.1.10[\PIPE\lsarpc]"
# rpc_transport = transport.DCERPCTransportFactory(string_binding)
# dce = rpc_transport.get_dce_rpc()
# dce.connect()
# dce.bind(iface_uuid)
# resp = lsad.hLsarOpenPolicy2(dce, lsad.POLICY_VIEW_LOCAL_INFORMATION)
# resp.dump()
# request = lsad.LsarQueryInformationPolicy2()
# accountHandle =  resp['PolicyHandle']
# request['PolicyHandle'] = accountHandle
# request['InformationClass'] = lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation
# resp = dce.request(request)
# resp.dump()
# resp = lsad.hLsarClose(dce, accountHandle)
# resp.dump()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from impacket.dcerpc.v5 import transport, lsad

def lsa_connect_np(
    pipe=r"ncacn_np:127.0.0.1[\PIPE\lsarpc]",
    username="",
    password="",
    domain="",
    hashes=None,          # формат: "LMHASH:NTHASH" (для PTH)
    kerberos=False,
    kdc=None,             # IP/DNS KDC для Kerberos
):
    """
    Возвращает уже привязанный к LSARPC DCE (dce.bind выполнен).
    """
    rpctransport = transport.DCERPCTransportFactory(pipe)

    # NTLM / PTH
    lmhash = nthash = ""
    if hashes:
        try:
            lmhash, nthash = hashes.split(":")
        except ValueError:
            raise ValueError("hashes должны быть в формате 'LMHASH:NTHASH'")

    if hasattr(rpctransport, "set_credentials"):
        # В impacket домен чаще указывается отдельно (username без домена)
        rpctransport.set_credentials(username, password, domain, lmhash, nthash)

        # Kerberos (опционально). Нужен валидный тикет или пароль.
        rpctransport.set_kerberos(kerberos, kdcHost=kdc)

    dce = rpctransport.get_dce_rpc()
    dce.connect()
    dce.bind(lsad.MSRPC_UUID_LSAD)
    return dce

if __name__ == "__main__":
    # ► Вариант 1: NTLM по паролю
    dce = lsa_connect_np(
        pipe=r"ncacn_np:127.0.0.1[\PIPE\lsarpc]",
        username="d.kalikin",   # ИМЯ ПОЛЬЗОВАТЕЛЯ
        password="Mos123098!",  # ПАРОЛЬ
        domain="AD",            # ДОМЕН (без слэша)
    )

    # ► Вариант 2: Pass-the-Hash (раскомментируй при необходимости)
    # dce = lsa_connect_np(
    #     pipe=r"ncacn_np:127.0.0.1[\PIPE\lsarpc]",
    #     username="d.kalikin",
    #     domain="AD",
    #     hashes="aad3b435b51404eeaad3b435b51404ee:11223344556677889900aabbccddeeff",
    # )

    # ► Вариант 3: Kerberos (нужен kdc и тикет/пароль)
    # dce = lsa_connect_np(
    #     pipe=r"ncacn_np:127.0.0.1[\PIPE\lsarpc]",
    #     username="d.kalikin",
    #     password="Mos123098!",
    #     domain="AD",
    #     kerberos=True,
    #     kdc="172.16.12.1",
    # )

    # Дальше обычные вызовы LSARPC:
    try:

        resp = lsad.hLsarOpenPolicy2(dce, lsad.POLICY_VIEW_LOCAL_INFORMATION)
        hPolicy = resp["PolicyHandle"]
        print("OpenPolicy2 OK")

        info = lsad.hLsarQueryInformationPolicy2(
            dce, hPolicy, lsad.POLICY_INFORMATION_CLASS.PolicyDnsDomainInformation
        )
        print("PolicyDnsDomainInformation:", info["PolicyInformation"]["PolicyDnsDomainInfo"])

        lsad.hLsarClose(dce, hPolicy)
    except Exception as e:
        print("LSA call failed:", e)
