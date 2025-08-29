#!/usr/bin/env python3
import argparse, os
from impacket.dcerpc.v5 import transport, samr, nrpc
from impacket.structure import hexdump

def make_np_dce(host, pipe, port=445, username="", password="", domain="", lmhash="", nthash=""):
    # ncacn_np:<host>[\pipe\<name>]
    sb = fr"ncacn_np:{host}[\pipe\{pipe}]"
    trans = transport.DCERPCTransportFactory(sb)
    trans.set_dport(port)
    if hasattr(trans, "set_credentials"):
        trans.set_credentials(username, password, domain, lmhash, nthash)
    dce = trans.get_dce_rpc()
    dce.connect()
    return dce

def make_tcp_dce(host, port):
    # ncacn_ip_tcp:<host>[<port>]
    sb = f"ncacn_ip_tcp:{host}[{port}]"
    trans = transport.DCERPCTransportFactory(sb)
    dce = trans.get_dce_rpc()
    dce.connect()
    return dce

def probe_samr(dce):
    # Bind SAMR
    dce.bind(samr.MSRPC_UUID_SAMR)
    print("[*] SAMR: bind OK")

    # Самый простой вызов: SamrConnect (opnum 0x00)
    # Имя сервера можно пустым; DesiredAccess — минимальный
    try:
        resp = samr.hSamrConnect(dce)
        print("[+] SamrConnect returned")
        # Печать пары байт для визуального подтверждения
        try:
            hexdump(bytes(resp))
        except Exception:
            pass
    except Exception as e:
        print(f"[!] SamrConnect error: {e}")

def probe_nrpch(dce, server_name=None, computer_name=None):
    # Bind NETLOGON
    dce.bind(nrpc.MSRPC_UUID_NRPC)
    print("[*] NETLOGON: bind OK")

    # Первый вызов: NetrServerReqChallenge (opnum 0x00)
    # server_name и computer_name — UNICODE, с ведущим '\\' обычно норм
    server_name = server_name or "\\\\TESTSRV"
    computer_name = computer_name or "\\\\TESTCLI"
    client_challenge = b"\x11\x22\x33\x44\x55\x66\x77\x88"

    try:
        resp = nrpc.hNetrServerReqChallenge(
            dce,
            server_name,
            computer_name,
            client_challenge
        )
        print("[+] NetrServerReqChallenge returned")
        try:
            hexdump(bytes(resp))
        except Exception:
            pass
    except Exception as e:
        print(f"[!] NetrServerReqChallenge error: {e}")

def main():
    ap = argparse.ArgumentParser(description="Minimal DCERPC probe for SAMR/NETLOGON over ncacn_np or ncacn_ip_tcp")
    ap.add_argument("--service", choices=["samr","netlogon"], required=True)
    ap.add_argument("--transport", choices=["np","tcp"], default="np")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--np-pipe", default="samr", help="samr|netlogon (for --transport np)")
    ap.add_argument("--np-port", type=int, default=445)
    ap.add_argument("--tcp-port", type=int, default=55153, help="SAMR=55153, NETLOGON=55154 (your backend)")
    ap.add_argument("-u","--username", default="")
    ap.add_argument("-p","--password", default="")
    ap.add_argument("-d","--domain", default="")
    ap.add_argument("--lmhash", default="")
    ap.add_argument("--nthash", default="")
    args = ap.parse_args()

    if args.transport == "np":
        # pipe по имени
        pipe = args.np_pipe
        if args.service == "samr":
            pipe = "samr"
        elif args.service == "netlogon":
            pipe = "netlogon"
        dce = make_np_dce(
            args.host, pipe, port=args.np_port,
            username=args.username, password=args.password,
            domain=args.domain, lmhash=args.lmhash, nthash=args.nthash
        )
    else:
        # прямой TCP к твоему backend-порту
        port = args.tcp_port
        # удобный дефолт по сервису
        if args.service == "samr" and args.tcp_port == 55153:
            port = 55153
        if args.service == "netlogon" and args.tcp_port == 55154:
            port = 55154
        dce = make_tcp_dce(args.host, port)

    if args.service == "samr":
        probe_samr(dce)
    else:
        probe_nrpch(dce)

if __name__ == "__main__":
    main()
