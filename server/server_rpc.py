#!/usr/bin/env python3
import os, socket, threading, socketserver
from impacket.smbserver import SimpleSMBServer
from impacket.dcerpc.v5 import rpcrt, lsad, samr, nrpc
from impacket.ntlm import compute_lmhash, compute_nthash

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
                #data = bytes(ms) + body
                print(f"[TCP {self.NAME}] <- PDU type={ms['type']} len={ms['frag_len']}")

                if ms['type'] == rpcrt.MSRPC_BIND:
                    # BIND_ACK
                    ack = rpcrt.MSRPCBindAck()
                    ack['max_tfrag'] = 4280
                    ack['assoc_group'] = 0
                    # принимаем NDR32
                    ctx = rpcrt.MSRPC_CONT_RESULT_ACCEPT
                    ctx['ack_result'] = 0
                    ctx['ack_reason'] = 0
                    ctx['transfer_syntax'] = rpcrt.MSRPC_UUID_SYNTAX_NDR
                    ack.setCtxItems([ctx])
                    pkt = ack.get_packet()
                    self.request.sendall(pkt)
                    print(f"[TCP {self.NAME}] -> BIND_ACK")
                    continue

                if ms['type'] == rpcrt.MSRPC_REQUEST:
                    req = rpcrt.MSRPCRequest(ms, data=data[len(ms):])
                    print(f"[TCP {self.NAME}] REQUEST opnum={req['opnum']} ctx_id={req['ctx_id']}")
                    fault = rpcrt.MSRPCFault()
                    fault['context_id'] = req['ctx_id']
                    fault['status'] = rpcrt.rpc_status_codes['nca_s_op_rng_error']
                    pkt = fault.get_packet()
                    self.request.sendall(pkt)
                    print(f"[TCP {self.NAME}] -> FAULT")
                    continue

        except Exception as e:
            print(f"[TCP {self.NAME}] error: {e}")
        finally:
            print(f"[TCP {self.NAME}] client closed: {peer}")

    def _recv_exact(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.request.recv(n - len(buf))
            if not chunk:
                return b""
            buf += chunk
        return buf

def start_pipe_backend(name, host, port):
    class _H(RPCPipeTCPHandler):
        NAME = name
    srv = socketserver.ThreadingTCPServer((host, port), _H)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f"[TCP {name}] listening on {host}:{port}")
    return srv

def main():
    srv = SimpleSMBServer(listenAddress="0.0.0.0", listenPort=445)

    # IPC$ обязателен    srv.addShare("IPC$", os.getcwd(), "IPC")

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

    lm = compute_lmhash("Mos123098!")
    nt = compute_nthash("Mos123098!")
    for i, name in enumerate([r"AD\d.kalikin", r"AD.LOCAL\d.kalikin", "d.kalikin"], start=1001):
        try:
            srv.addCredential(name, i, lm, nt)
        except TypeError:
            srv.addCredential(name, i, lm.hex(), nt.hex())

    # Поднять локальные TCP-бекенды для пайпов
    lsa_host, lsa_port = "127.0.0.1", 49152
    samr_host, samr_port = "127.0.0.1", 49153
    netlogon_host, netlogon_port = "127.0.0.1", 49154

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
