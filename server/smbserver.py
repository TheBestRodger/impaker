#!/usr/bin/env python3
import os

from impacket.smbserver import SimpleSMBServer
from impacket.dcerpc.v5 import rpcrt, samr, nrpc, lsad

PIPES = [r"\PIPE\lsarpc",r"\pipe\lsarpc",r"\lsarpc",r"lsarpc", r"\PIPE\samr", r"\PIPE\netlogon", r"\pipe\samr", r"\pipe\netlogon", r"\samr", r"\netlogon", r"samr", r"netlogon"] 

UUID2NAME = {
    str(lsad.MSRPC_UUID_LSAD): "LSAD",
    str(samr.MSRPC_UUID_SAMR): "SAMR",
    str(nrpc.MSRPC_UUID_NRPC): "NETLOGON",
}

class GenericPipeHandler:
    def __init__(self, pipe_name):
        self.pipe_name = pipe_name

    def _bind_ack(self, bind_hdr, data):
        bind = rpcrt.MSRPCBind(data)
        # Отвечаем столько контекстов, сколько прислал клиент
        results = []
        for i, ctx in enumerate(getattr(bind, 'ctx_items', [])):
            try:
                abs_uuid = str(ctx.getAbstractSyntax().getUUID())
                ver = ctx.getAbstractSyntax().getVersion()
                print(f"    BIND ctx[{i}]: {UUID2NAME.get(abs_uuid, abs_uuid)} v{ver[0]}.{ver[1]}")
            except Exception:
                pass
            r = rpcrt.MSRPC_CONT_RESULTS()
            r['ack_result'] = 0
            r['ack_reason'] = 0
            r['transfer_syntax'] = rpcrt.MSRPC_UUID_SYNTAX_NDR
            results.append(r)

        ack = rpcrt.MSRPCBindAck()
        ack['max_tfrag'] = 4280
        ack['assoc_group'] = 0
        ack.setCtxItems(results or [rpcrt.MSRPC_CONT_RESULTS()])
        return ack.get_packet()

    def _fault(self, req_hdr, status='nca_s_op_rng_error'):
        fault = rpcrt.MSRPCFault()
        fault['context_id'] = req_hdr['ctx_id']
        fault['status'] = rpcrt.rpc_status_codes[status]
        return fault.get_packet()

    def handle(self, smbServer, connId, smbSession, smbRequest, pipeName):
        # лог клиента
        client_ip = "?"
        try:
            cd = smbServer.getConnectionData(connId)
            print("[+] PIPE hit from", cd.get("ClientIP"), "as", getattr(smbSession, "getUsername", lambda:"?")())
            print("    Raw SMB create to:", pipeName)
            client_ip = cd.get("ClientIP", "?")
        except Exception:
            pass
        user = getattr(smbSession, "getUsername", lambda: "?")()
        print(f"[+] PIPE {self.pipe_name} hit from {client_ip} as {user}")

        data = smbRequest['Data']
        try:
            hdr = rpcrt.MSRPCHeader(data)
        except Exception:
            print("    [!] Not an RPC PDU")
            return b""

        print(f"    RPC PDU type={hdr['type']} frag_len={hdr['frag_len']} flags=0x{hdr['flags']:02x}")

        if hdr['type'] == rpcrt.MSRPC_BIND:
            pkt = self._bind_ack(hdr, data)
            print("    [->] BIND_ACK sent")
            return pkt

        if hdr['type'] == rpcrt.MSRPC_REQUEST:
            req = rpcrt.MSRPCRequest(hdr, data=data[len(hdr):])
            print(f"    REQUEST opnum={req['opnum']} ctx_id={req['ctx_id']} alloc_hint={req['alloc_hint']}")
            return self._fault(req, 'nca_s_op_rng_error')

        return b""
from impacket.ntlm import compute_lmhash, compute_nthash
def main():
    srv = SimpleSMBServer(listenAddress="0.0.0.0", listenPort=445)

    srv.setSMB2Support(True)
    srv.setLogFile("/home/user/my_tests/ipacer/smbserver.log")
    user = r"AD\d.kalikin"   # либо просто "AD\d.kalikin"
    pwd  = "Mos123098!"

    lm = compute_lmhash(pwd)    # bytes (16 байт)
    nt = compute_nthash(pwd)    # bytes (16 байт)


    srv.addCredential(r"AD.LOCAL\d.kalikin",        1001, lm, nt)
    srv.addCredential(r"AD\d.kalikin",              1002, lm, nt)
    srv.addCredential("d.kalikin",                  1003, lm, nt)

    srv.addCredential("Администратор",              1004, lm, nt)
    srv.addCredential(r"AD.LOCAL\Администратор",    1005, lm, nt)
    srv.addCredential(r"AD\Администратор",          1006, lm, nt)



    lsa = GenericPipeHandler(r"\lsarpc")
    for name in ("lsarpc", r"\lsarpc", r"\PIPE\lsarpc"):
        try:
            # новый/правильный путь: назначить хендлер
            srv.setNamedPipeHandler(name, lsa)
        except AttributeError:
            # старые сборки: registerNamedPipe тоже принимает хендлер
            srv.registerNamedPipe(name, lsa)

    # заодно SAMR / NETLOGON
    samr_h = GenericPipeHandler(r"\samr")
    for name in ("samr", r"\samr", r"\PIPE\samr"):
        try:
            srv.setNamedPipeHandler(name, samr_h)
        except AttributeError:
            srv.registerNamedPipe(name, samr_h)

    netlogon_h = GenericPipeHandler(r"\netlogon")
    for name in ("netlogon", r"\netlogon", r"\PIPE\netlogon"):
        try:
            srv.setNamedPipeHandler(name, netlogon_h)
        except AttributeError:
            srv.registerNamedPipe(name, netlogon_h)
    # for p in PIPES:
    #     srv.registerNamedPipe(p, GenericPipeHandler(p))
    #     print(f"[i] registered pipe: {p}")
    # lsa = GenericPipeHandler(r"\lsarpc")
    # for name in ("lsarpc", r"\lsarpc", r"\PIPE\lsarpc"):
    #     srv.registerNamedPipe(name, lsa)

    # # Заодно SAMR/NETLOGON (часто идут параллельно)
    # samr_h = GenericPipeHandler(r"\samr")
    # for name in ("samr", r"\samr", r"\PIPE\samr"):
    #     srv.registerNamedPipe(name, samr_h)

    # netlogon_h = GenericPipeHandler(r"\netlogon")
    # for name in ("netlogon", r"\netlogon", r"\PIPE\netlogon"):
    #     srv.registerNamedPipe(name, netlogon_h)

    print("[+] SMB listening on 0.0.0.0:445")
    srv.start()

if __name__ == "__main__":
    main()
#!/usr/bin/env python3
# import os
# from impacket.smbserver import SimpleSMBServer
# from impacket.dcerpc.v5 import rpcrt, samr, nrpc, lsad
# from impacket.ntlm import compute_lmhash, compute_nthash

# class GenericPipeHandler:
#     def __init__(self, pipe_name): self.pipe_name = pipe_name
#     def _bind_ack(self, bind_hdr, data):
#         bind = rpcrt.MSRPCBind(data)
#         results = []
#         for i, ctx in enumerate(getattr(bind,'ctx_items', [])):
#             try:
#                 abs_uuid = str(ctx.getAbstractSyntax().getUUID())
#                 ver = ctx.getAbstractSyntax().getVersion()
#                 print(f"    BIND ctx[{i}]: {abs_uuid} v{ver[0]}.{ver[1]}")
#             except: pass
#             r = rpcrt.MSRPC_CONT_RESULTS()
#             r['ack_result'] = 0; r['ack_reason'] = 0
#             r['transfer_syntax'] = rpcrt.MSRPC_UUID_SYNTAX_NDR
#             results.append(r)
#         ack = rpcrt.MSRPCBindAck(); ack['max_tfrag']=4280; ack['assoc_group']=0
#         ack.setCtxItems(results or [rpcrt.MSRPC_CONT_RESULTS()])
#         return ack.get_packet()
#     def _fault(self, req_hdr, status='nca_s_op_rng_error'):
#         fault = rpcrt.MSRPCFault(); fault['context_id']=req_hdr['ctx_id']
#         fault['status']=rpcrt.rpc_status_codes[status]; return fault.get_packet()
#     def handle(self, smbServer, connId, smbSession, smbRequest, pipeName):
#         cd = smbServer.getConnectionData(connId) or {}
#         client_ip = cd.get("ClientIP","?"); user = getattr(smbSession,"getUsername",lambda:"?")()
#         print(f"[+] PIPE {pipeName} hit from {client_ip} as {user}")
#         data = smbRequest['Data']
#         try: hdr = rpcrt.MSRPCHeader(data)
#         except: print("    [!] Not an RPC PDU"); return b""
#         print(f"    RPC PDU type={hdr['type']} frag_len={hdr['frag_len']} flags=0x{hdr['flags']:02x}")
#         if hdr['type']==rpcrt.MSRPC_BIND:
#             pkt = self._bind_ack(hdr, data); print("    [->] BIND_ACK sent"); return pkt
#         if hdr['type']==rpcrt.MSRPC_REQUEST:
#             req = rpcrt.MSRPCRequest(hdr, data=data[len(hdr):])
#             print(f"    REQUEST opnum={req['opnum']} ctx_id={req['ctx_id']} alloc_hint={req['alloc_hint']}")
#             return self._fault(req, 'nca_s_op_rng_error')
#         return b""

# def main():
#     srv = SimpleSMBServer(listenAddress="0.0.0.0", listenPort=445)

#     # ******* ОБЯЗАТЕЛЬНО: IPC$ ********
#     try: srv.addShare("IPC$", os.getcwd(), "IPC")
#     except: pass
#     # SMB2
#     try: srv.setSMB2Support(True)
#     except: pass

#     # (Опционально для отладки) файл логов
#     try: srv.setLogFile("/home/user/my_tests/ipacer/smbserver.log")
#     except: pass

#     # Креды ДОЛЖНЫ совпадать с тем, что шлёт клиент в NTLMSSP_AUTH
#     lm = compute_lmhash("Mos123098!")
#     nt = compute_nthash("Mos123098!")
#     # Добавь все варианты имени, которые у тебя встречались в трассах
#     # , r"AD.LOCAL\d.kalikin", "d.kalikin"
#     for i,name in enumerate([r"AD\d.kalikin"], start=1001):
#         try: srv.addCredential(name, i, lm, nt)
#         except TypeError: srv.addCredential(name, i, lm.hex(), nt.hex())

#     # Зарегистрируй ВСЕ варианты имён пайпа — клиенты присылают по-разному
#     for nm in ("lsarpc", r"\lsarpc", r"\PIPE\lsarpc"):
#         srv.registerNamedPipe(nm, GenericPipeHandler(r"\lsarpc"))
#     for nm in ("samr", r"\samr", r"\PIPE\samr"):
#         srv.registerNamedPipe(nm, GenericPipeHandler(r"\samr"))
#     for nm in ("netlogon", r"\netlogon", r"\PIPE\netlogon"):
#         srv.registerNamedPipe(nm, GenericPipeHandler(r"\netlogon"))

#     print("[+] SMB listening on 0.0.0.0:445")
#     srv.start()

# if __name__ == "__main__":
#     main()
