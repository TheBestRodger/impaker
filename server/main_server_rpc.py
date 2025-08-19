#!/usr/bin/env python3
import os, socket, threading, socketserver, struct
from impacket.smbserver import SimpleSMBServer
from impacket.dcerpc.v5 import rpcrt
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.uuid import uuidtup_to_bin
from enum import Enum

# MS-RPCE 2.2.4.12 NDR Transfer Syntax Identifier
MSRPC_STANDARD_NDR_SYNTAX = ('8A885D04-1CEB-11C9-9FE8-08002B104860', '2.0')
class dcerpc_bind_nak_reason(Enum):
	DCERPC_BIND_NAK_REASON_NOT_SPECIFIED                    =(int)(0),
	DCERPC_BIND_NAK_REASON_TEMPORARY_CONGESTION             =(int)(1),
	DCERPC_BIND_NAK_REASON_LOCAL_LIMIT_EXCEEDED             =(int)(2),
	DCERPC_BIND_NAK_REASON_PROTOCOL_VERSION_NOT_SUPPORTED   =(int)(4),
	DCERPC_BIND_NAK_REASON_INVALID_AUTH_TYPE                =(int)(8),
	DCERPC_BIND_NAK_REASON_INVALID_CHECKSUM                 =(int)(9)

import socketserver
import struct

from impacket.dcerpc.v5 import rpcrt
# если есть tuple-синтаксис, пригодится:
try:
    from impacket.uuid import uuidtup_to_bin
except Exception:
    uuidtup_to_bin = None


class RPCPipeTCPHandler(socketserver.BaseRequestHandler):
    NAME = r"\lsarpc"

    # один bind на соединение, как в Samba
    def setup(self):
        self.allow_bind = True

    def handle(self):
        peer = f"{self.client_address[0]}:{self.client_address[1]}"
        print(f"[TCP {self.NAME}] client connected: {peer}")
        try:
            while True:
                hdr = self._recv_exact(16)
                if not hdr:
                    break

                try:
                    ms = rpcrt.MSRPCHeader(hdr)
                except Exception:
                    print(f"[TCP {self.NAME}] not an RPC PDU, closing")
                    break

                body_len = int(ms['frag_len']) - len(ms)
                body = self._recv_exact(body_len) if body_len > 0 else b""
                pdu = hdr + body

                print(f"[TCP {self.NAME}] <- PDU type={ms['type']} len={ms['frag_len']}")

                if ms['type'] == getattr(rpcrt, 'MSRPC_BIND', 11):
                    if not self.allow_bind:
                        print(f"[TCP {self.NAME}] second BIND not allowed; close")
                        break
                    pkt = self._dcesrv_bind(pdu, ms)
                    self.request.sendall(pkt)
                    self.allow_bind = False
                    print(f"[TCP {self.NAME}] -> BIND_ACK")
                    continue

                if ms['type'] == getattr(rpcrt, 'MSRPC_REQUEST', 0):
                    try:
                        req = rpcrt.MSRPCRequestHeader(pdu)
                        opnum  = int(req['op_num'])
                        ctx_id = int(req['ctx_id'])
                    except Exception:
                        print(f"[TCP {self.NAME}] malformed REQUEST; closing")
                        break

                    print(f"[TCP {self.NAME}] REQUEST opnum={opnum} ctx_id={ctx_id}")

                    fault = rpcrt.MSRPCRespHeader()
                    fault['type']    = getattr(rpcrt, 'MSRPC_FAULT', 3)
                    fault['call_id'] = ms['call_id']
                    # ТОЛЬКО FIRST|LAST
                    FF = getattr(rpcrt, 'PFC_FIRST_FRAG', getattr(rpcrt, 'MSRPC_FIRST_FRAG', 0x01))
                    LF = getattr(rpcrt, 'PFC_LAST_FRAG',  getattr(rpcrt, 'MSRPC_LAST_FRAG',  0x02))
                    fault['flags']   = (FF | LF) & 0xFF
                    fault['ctx_id']  = ctx_id
                    fault['pduData'] = struct.pack('<L', rpcrt.rpc_status_codes['nca_s_op_rng_error'])
                    self.request.sendall(fault.get_packet())
                    print(f"[TCP {self.NAME}] -> FAULT(op_rng_error)")
                    continue

                print(f"[TCP {self.NAME}] unsupported ptype={ms['type']}; closing")
                break

        except Exception as e:
            print(f"[TCP {self.NAME}] error: {e}")
        finally:
            print(f"[TCP {self.NAME}] client closed: {peer}")


    import struct
    from impacket.dcerpc.v5 import rpcrt

    def _parse_bind_raw(self, pdu):
        """
        Возвращает: (max_xmit, max_recv, assoc_group_id, ctx_num, syntaxes[list of 20-byte]])
        """
        # 16 байт заголовок уже распарсен в ms, тело:
        body = pdu[16:]
        if len(body) < 12:
            raise ValueError("BIND body too short")

        max_xmit, max_recv, assoc = struct.unpack_from('<HHI', body, 0)
        ctx_num = struct.unpack_from('<H', body, 8)[0]
        # bytes 10,11 = reserved
        off = 12

        syntaxes = []
        for _ in range(ctx_num):
            if len(body) - off < 24:
                break  # обрыв
            # H (ctx_id), B (num_tx), x (reserved)
            ctx_id, num_tx = struct.unpack_from('<HBx', body, off)
            off += 4
            # abstract syntax 20 байт (пропускаем)
            if len(body) - off < 20:
                break
            off += 20

            chosen = None
            for j in range(num_tx):
                if len(body) - off < 20:
                    break
                tx = body[off:off+20]
                off += 20
                if chosen is None:
                    chosen = tx
            syntaxes.append(chosen or b'\x00' * 20)

        return max_xmit, max_recv, assoc, ctx_num, syntaxes


    def _dcesrv_bind(self, pdu, ms) -> bytes:
        """
        «Как Samba»: формируем корректный BIND_ACK из сырых полей BIND.
        """
        # 1) Сырый парсинг BIND
        max_xmit, max_recv, assoc_req, ctx_num, syntaxes = self._parse_bind_raw(pdu)

        # 2) (опционально) посмотрим на auth_len из заголовка MSRPCBind
        try:
            bind_hdr = rpcrt.MSRPCBind(pdu)  # только чтобы узнать auth_len
            auth_len = int(bind_hdr.get('auth_len', 0)) if hasattr(bind_hdr, 'get') else int(bind_hdr['auth_len'])
        except Exception:
            auth_len = 0
        print(f"[TCP {self.NAME}] BIND auth_len={auth_len}, ctx_num={ctx_num}")

        if auth_len:
            print(f"[TCP {self.NAME}] WARNING: client requested RPC auth in BIND; "
                f"this PoC does not include auth_verifier in the BindAck")

        # 3) Согласуем фрагменты как Samba
        negotiated = max(2048, min(max_xmit, max_recv))
        transport_max = 4280   # для SMB-пайпа
        negotiated = min(negotiated, transport_max)
        negotiated &= 0xFFF8   # кратно 8

        # 4) Собираем BindAck
        ack = rpcrt.MSRPCBindAck()
        ack['type']    = getattr(rpcrt, 'MSRPC_BINDACK', 12)
        ack['call_id'] = ms['call_id']

        # ТОЛЬКО FIRST|LAST
        FF = getattr(rpcrt, 'PFC_FIRST_FRAG', getattr(rpcrt, 'MSRPC_FIRST_FRAG', 0x01))
        LF = getattr(rpcrt, 'PFC_LAST_FRAG',  getattr(rpcrt, 'MSRPC_LAST_FRAG',  0x02))
        ack['flags']   = (FF | LF) & 0xFF

        ack['max_tfrag']   = negotiated
        ack['max_rfrag']   = negotiated
        ack['assoc_group'] = 0  # Samba ставит свой id; для PoC ноль — ок

        # Secondary address: endpoint name "lsarpc" как ASCIZ (Windows это любит)
        sec = b'lsarpc\x00'
        if 'SecondaryAddr' in ack.fields:
            ack['SecondaryAddr']    = sec
            ack['SecondaryAddrLen'] = len(sec)
        else:
            ack['sec_addr']     = sec
            ack['sec_addr_len'] = len(sec)

        # 5) Результаты по контекстам: ACCEPT + тот же TransferSyntax
        if not syntaxes:
            # на всякий — одна заглушка
            syntaxes = [b'\x00' * 20]
            ctx_num = 1

        results_blob = b''
        for tx in syntaxes[:ctx_num]:
            # диагностика
            try:
                guid = tx[:16].hex()
                ver  = f"{int.from_bytes(tx[16:18],'little')}.{int.from_bytes(tx[18:20],'little')}"
                print(f"[TCP {self.NAME}]   ctx tx GUID={guid} ver={ver}")
            except Exception:
                pass
            r = rpcrt.CtxItemResult()
            r['Result']         = rpcrt.MSRPC_CONT_RESULT_ACCEPT
            r['Reason']         = 0
            r['TransferSyntax'] = tx
            results_blob += r.getData()

        ack['ctx_num']   = len(syntaxes[:ctx_num])
        ack['ctx_items'] = results_blob

        # 6) Паддинг после secondary address (выравнивание на 4) — как у Samba
        base_size = getattr(rpcrt.MSRPCBindAck, '_SIZE', 0)
        try:
            sec_len = int(ack['SecondaryAddrLen'])
        except Exception:
            try:
                sec_len = int(ack['sec_addr_len'])
            except Exception:
                sec_len = 0
        pad_len = (4 - ((base_size + sec_len) % 4)) % 4
        try:
            ack['Pad'] = b'\x00' * pad_len
        except Exception:
            pass

        return ack.get_packet()


    def _parse_ctx_items_raw(self, bind):
        data = bind['ctx_items']
        try:
            cnt = int(bind['ctx_num'])
        except Exception:
            cnt = 1

        off = 0
        syntaxes = []
        for _ in range(cnt):
            if len(data) - off < 24:
                break
            # H (ctx_id), B (num_tx), x (reserved)
            ctx_id, num_tx = struct.unpack_from('<HBx', data, off)
            off += 4

            # abstract syntax (20)
            if len(data) - off < 20:
                break
            abs_syntax = data[off:off+20]
            off += 20

            chosen = None
            for i in range(num_tx):
                if len(data) - off < 20:
                    break
                tx = data[off:off+20]
                off += 20
                if chosen is None:
                    chosen = tx
            syntaxes.append(chosen or b'\x00' * 20)
        return syntaxes
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