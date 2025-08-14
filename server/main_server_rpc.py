#!/usr/bin/env python3
import os, socket, threading, socketserver, struct
from impacket.smbserver import SimpleSMBServer
from impacket.dcerpc.v5 import rpcrt
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.uuid import uuidtup_to_bin


# MS-RPCE 2.2.4.12 NDR Transfer Syntax Identifier
MSRPC_STANDARD_NDR_SYNTAX = ('8A885D04-1CEB-11C9-9FE8-08002B104860', '2.0')


class RPCPipeTCPHandler(socketserver.BaseRequestHandler):
    NAME = r"\unknown"
    
    def handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"[TCP {self.NAME}] client connected: {peer}")
        try:
            while True:
                # читаем заголовок RPC (обычно 16 байт)
                hdr = self._recv_exact(16)
                if not hdr:
                    break
                try:
                    ms = rpcrt.MSRPCHeader(hdr)
                except Exception:
                    print(f"[TCP {self.NAME}] not an RPC PDU, closing")
                    break

                body = self._recv_exact(ms['frag_len'] - len(ms))
                pdu = hdr + body
                print(f"[TCP {self.NAME}] <- PDU type={ms['type']} len={ms['frag_len']}")

                if ms['type'] == rpcrt.MSRPC_BIND:
                    pkt = self._build_bind_ack(hdr, body)
                    self.request.sendall(pkt)
                    print(f"[TCP {self.NAME}] -> BIND_ACK")
                    continue

                if ms['type'] == rpcrt.MSRPC_REQUEST:
                    req = rpcrt.MSRPCRequestHeader(pdu)
                    print
                    (
                        f"[TCP {self.NAME}] REQUEST opnum={req['op_num']} ctx_id={req['ctx_id']}"
                    )

                    fault = rpcrt.MSRPCRespHeader()
                    fault['type'] = rpcrt.MSRPC_FAULT
                    fault['ctx_id'] = req['ctx_id']
                    fault['pduData'] = struct.pack
                    (
                        '<L', rpcrt.rpc_status_codes['nca_s_op_rng_error']
                    )

                    pkt = fault.get_packet()
                    self.request.sendall(pkt)
                    print(f"[TCP {self.NAME}] -> FAULT")
                    continue

        except Exception as e:
            print(f"[TCP {self.NAME}] error: {e}")
        finally:
            print(f"[TCP {self.NAME}] client closed: {peer}")
    
    def _build_bind_ack(self, ms, body) -> bytes:
 
        bind = rpcrt.MSRPCBind(bytes(ms) + body)
        ack = rpcrt.MSRPCBindAck()

        # Заголовок
        ack['type']    = rpcrt.MSRPC_BINDACK
        # echo флаги и call_id, как пришли
        #ack['flags']   = ms['flags']
        #ack['call_id'] = ms['call_id']

        # Фрагменты
        for dst, src in (('max_tfrag','max_xmit_frag'), ('max_rfrag','max_recv_frag')):
            try:
                ack[dst] = bind[src]
            except Exception:
                ack[dst] = 4280

        ack['assoc_group'] = 0

        try:
            ack['SecondaryAddr'] = b'\x00'   # строка длины 1 с NUL
            ack['SecondaryAddrLen'] = 1
        except KeyError:
            ack['sec_addr'] = b'\x00'
            ack['sec_addr_len'] = 1

        # Контексты: принимаем только NDR32
        ndr32 = uuidtup_to_bin(MSRPC_STANDARD_NDR_SYNTAX)

        try:
            ctx_items = bind.getCtxItems()     # предпочтительно, если есть
        except Exception:
            # запасной путь
            ctx_items = []
            blob = bind['ctx_items']
            cnt  = int(bind['ctx_num'])
            off  = 0
            for _ in range(3):
                item = rpcrt.CtxItem(blob[off:])
                ctx_items.append(item)
                off += len(item)

        results_blob = b''
        ctx_count    = 0
        for item in ctx_items:
            res = rpcrt.CtxItemResult()
            # если клиент предложил не NDR32
            if item['TransferSyntax'] != ndr32:
                res['Result'] = rpcrt.MSRPC_CONT_RESULT_PROV_REJECT
                res['Reason'] = 2 
                res['TransferSyntax'] = ndr32
            else:
                res['Result'] = rpcrt.MSRPC_CONT_RESULT_ACCEPT
                res['Reason'] = 0
                res['TransferSyntax'] = ndr32

            results_blob += res.getData()
            ctx_count    += 1

        # Если клиент прислал 0 контекстов, вернём 1 accept NDR32
        if ctx_count == 0:
            res = rpcrt.CtxItemResult()
            res['Result'] = rpcrt.MSRPC_CONT_RESULT_ACCEPT
            res['Reason'] = 0
            res['TransferSyntax'] = ndr32
            results_blob = res.getData()
            ctx_count    = 1

        ack['ctx_num']   = ctx_count
        ack['ctx_items'] = results_blob

        try:
            base_size = rpcrt.MSRPCBindAck._SIZE
            sec_len   = ack['SecondaryAddrLen']
        except KeyError:
            base_size = rpcrt.MSRPCBindAck._SIZE
            sec_len   = ack['sec_addr_len']

        pad_len   = (4 - ((base_size + sec_len) % 4)) % 4
        ack['Pad'] = b'\x00' * pad_len

        # Итоговый пакет
        return ack.get_packet()

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                return b""
            buf += chunk
        return buf

# без этого вообще не откроются pipe lsa net samr
def start_pipe_backend(name, host, port):
    class _H(RPCPipeTCPHandler):
        NAME = name
    srv = socketserver.ThreadingTCPServer((host, port), _H)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f"[TCP {name}] listening on {host}:{port}")
    return srv
# SMB == NCACN_NP - This protocol sequence specifies RPC directly over SMB.
def main():
    srv = SimpleSMBServer(listenAddress="0.0.0.0", listenPort=445)

    # SMB2
    try:
        srv.setSMB2Support(True)
    except Exception:
        pass

    # Логи
    try:
        srv.setLogFile("/home/user/my_tests/ipacer/smbserver.log")
    except Exception:
        pass

    # NewStrong#Pass123 | r"AD\d.kalikin", r"AD.LOCAL\d.kalikin", "d.kalikin",   # | AD
    # lm = compute_lmhash("Mos123098!") # | AD
    # nt = compute_nthash("Mos123098!") # | AD

    lm = compute_lmhash("NewStrong#Pass123") # | SAMBA
    nt = compute_nthash("NewStrong#Pass123") # | SAMBA
    # for i, name in enumerate([r"AD\d.kalikin", r"AD.LOCAL\d.kalikin", "d.kalikin"], start=1001): | AD
    for i, name in enumerate([r"samba.local\Administrator","Administrator"], start=1001): # | SAMBA
        try:
            srv.addCredential(name, i, lm, nt)
        except TypeError:
            srv.addCredential(name, i, lm.hex(), nt.hex())

    # Поднять локальные TCP-бекенды для пайпов
    lsa_host, lsa_port              = "127.0.0.1", 49152
    samr_host, samr_port            = "127.0.0.1", 49153
    netlogon_host, netlogon_port    = "127.0.0.1", 49154

    start_pipe_backend(r"\lsarpc",   lsa_host,   lsa_port)
    start_pipe_backend(r"\samr",     samr_host,  samr_port)
    start_pipe_backend(r"\netlogon", netlogon_host, netlogon_port)

    # Зарегистрировать пайпы как ПРОКСИ на TCP
    for nm in ("lsarpc", r"\lsarpc", r"\PIPE\lsarpc"):
        srv.registerNamedPipe(nm, (lsa_host, lsa_port))
    for nm in ("samr", r"\samr", r"\PIPE\samr"):
        srv.registerNamedPipe(nm, (samr_host, samr_port))
    for nm in ("netlogon", r"\netlogon", r"\PIPE\netlogon"):
        srv.registerNamedPipe(nm, (netlogon_host, netlogon_port))

    print("[+] SMB listening on 0.0.0.0:445; pipes proxied to 127.0.0.1:{49152,49153,49154}")
    srv.start()

if __name__ == "__main__":
    main()
