#!/usr/bin/env python3
from impacket.dcerpc.v5 import transport, lsad

IP = "172.16.12.2"         # твой сервер
DOMAIN = "AD"
USER = "d.kalikin"
PASSWORD = "Mos123098!"

def main():
    binding = fr"ncacn_np:{IP}[\pipe\lsarpc]"
    rpctrans = transport.DCERPCTransportFactory(binding)
    rpctrans.set_credentials(USER, PASSWORD, DOMAIN, "", "")  # NTLM
    # rpctrans.set_kerberos(True, kdcHost="KDC_FQDN")         # если хочешь Kerberos

    dce = rpctrans.get_dce_rpc()
    print("Will auth as:", DOMAIN + "\\" + USER)

    dce.connect()
    print("[+] SMB connected, opening \\PIPE\\lsarpc")
    dce.bind(lsad.MSRPC_UUID_LSAD)  # это и вызовет у тебя BIND/ACK в хендлере
    print("[+] LSARPC bind OK")
    dce.disconnect()

if __name__ == "__main__":
    main()
