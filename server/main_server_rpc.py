#!/usr/bin/env python3
import threading, socketserver
from impacket.smbserver import SimpleSMBServer
from impacket.dcerpc.v5 import rpcrt
from impacket.ntlm import compute_lmhash, compute_nthash

from parsers import FEAT_BIN, FEAT_TUP, NDR32_BIN, NDR32_TUP, NDR64_BIN, NDR64_TUP, build_bind_ack_co, parse_bind_co, parse_ncacn_header




class RPCPipeTCPHandler(socketserver.BaseRequestHandler):
    #NAME = r"\lsarpc"
    
    # один bind на соединение, как в Samba
    def __init__(self, request, client_address, server):
        super().__init__(request, client_address, server)
        # ваша дополнительная инициализация здесь
    
    def setup(self):
        super().setup()  # вызов родительского setup если нужно
        self.allow_bind = True

    def handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"[TCP {self.NAME}] client connected: {peer}")

        try:
            while True:
                # 1) читаем ровно 16 байт заголовка DCERPC
                hdr_bytes = self._recv_exact(16)
                if not hdr_bytes:
                    break

                # 2) парсим заголовок (rpc_vers, ptype, flags, frag_len, auth_len, call_id)
                try:
                    hdr = parse_ncacn_header(hdr_bytes)  # ← из нашего помощника
                except Exception as e:
                    print(f"[TCP {self.NAME}] not an RPC PDU ({e}); closing")
                    break

                # 3) дочитываем тело PDU по frag_len
                body_len = int(hdr['frag_len']) - 16
                if body_len < 0:
                    print(f"[TCP {self.NAME}] bad frag_len={hdr['frag_len']}; closing")
                    break
                body_bytes = self._recv_exact(body_len)
                if len(body_bytes) != body_len:
                    print(f"[TCP {self.NAME}] short read ({len(body_bytes)}<{body_len}); closing")
                    break

                pdu = hdr_bytes + body_bytes
                ptype = int(hdr['ptype'])
                print(
                    f"[TCP {self.NAME}] <- PDU ptype={ptype} len={hdr['frag_len']} "
                    f"flags=0x{int(hdr['flags']):02x} call_id={int(hdr['call_id'])} "
                    f"auth_len={int(hdr['auth_len'])}"
                )

                # 4) первая ассоциация: BIND
                if ptype == 11:  # MSRPC_BIND
                    if not getattr(self, "allow_bind", True):
                        print(f"[TCP {self.NAME}] second BIND not allowed; closing")
                        break

                    try:
                        # разбор bind тела: фрагменты + контексты (abstract/tx_list)
                        bind_hdr, rx_max_xmit, rx_max_recv, assoc, contexts = parse_bind_co(pdu)
                    except Exception as e:
                        print(f"[TCP {self.NAME}] BIND parse error: {e}")
                        break

                    # «как Samba»: 2048..4280, кратно 8
                    negotiated = max(2048, min(int(rx_max_xmit), int(rx_max_recv)))
                    negotiated = min(negotiated, 4280) & 0xFFF8

                    results_tx = []
                    for c in (contexts or []):
                        lst = c.get('tx_list') or []
                        if lst and isinstance(lst[0], (bytes, bytearray)) and len(lst[0]) == 20:
                            results_tx.append(lst[0])
                    # если клиент не прислал — подстрахуемся
                    if not results_tx:
                        results_tx = [NDR32_BIN]

                    # строим корректный bind_ack (sec_addr пустой; без auth-trailer)
                    ack = build_bind_ack_co(
                        call_id=hdr['call_id'],
                        req_flags=hdr['flags'],
                        max_xmit=negotiated,
                        max_recv=negotiated,
                        assoc_group=0x000006e7,
                        results_transfer_syntaxes=results_tx,
                        sec_addr=b'\\pipe\\lsass\0',
                        auth_trailer=b'',
                    )
                    self.request.sendall(ack)
                    print(f"[TCP {self.NAME}] -> BIND_ACK (accept-all)")
                    self.allow_bind = False
                    continue
                elif ptype == 0:

                    print("ОПА ЧИНАЗЕЗС. СЮДАА")
                    try: 
                        req = rpcrt.MSRPCRequestHeader(pdu) 
                        opnum = int(req['op_num']) 
                        ctx_id = int(req['ctx_id']) 
                        print(f"[TCP {self.NAME}] REQUEST opnum={opnum} ctx_id={ctx_id}") 
                        if opnum == 44:
                            STATUS_SUCCESS = 0x00000000
                    
                    except Exception as e: 
                        print(f"[TCP {self.NAME}] malformed REQUEST: {e}") 
                        break 
                    # 5) прочие PDU пока не поддерживаем — закрываем (или тут можешь вернуть FAULT)
                    print(f"[TCP {self.NAME}] unsupported ptype={ptype}; closing")
                    break

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
    lm = compute_lmhash("Mos123098!") # | AD
    nt = compute_nthash("Mos123098!") # | AD

    # lm = compute_lmhash("NewStrong#Pass123") # | SAMBA
    # nt = compute_nthash("NewStrong#Pass123") # | SAMBA
    for i, name in enumerate([r"AD\d.kalikin", r"AD.LOCAL\d.kalikin", "d.kalikin"], start=1001): #| AD
    # for i, name in enumerate([r"samba.local\Administrator","Administrator"], start=1001): # | SAMBA
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




# MS-RPCE (спеки Microsoft): 
# формат DCERPC BIND/BIND_ACK, 
# список presentation contexts и список presentation results,
# обязательность эхо call_id, выравнивание 4-байт, 
# необходимость возвращать результат на каждый контекст.

# OSF DCE/RPC (C706): исходная спецификация RPC, синтаксис тот же.