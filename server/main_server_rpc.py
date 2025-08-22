#!/usr/bin/env python3
import os, socket, threading, socketserver, struct
from impacket.smbserver import SimpleSMBServer
from impacket.dcerpc.v5 import rpcrt
from impacket.ntlm import compute_lmhash, compute_nthash
from impacket.uuid import uuidtup_to_bin
from enum import Enum


# RPC PDU Encodings
# PDU Type Protocol Type Value
# request   CO/CL   0
# ping      CL      1
# response  CO/CL    2
# fault     CO/CL 3
# working CL 4
# nocall CL 5
# reject CL 6
# ack CL 7
# cl_cancel CL 8
# fack CL 9
# cancel_ack CL 10
# bind CO 11
# bind_ack              CO 12
# bind_nak              CO 13
# alter_context         CO 14
# alter_context_resp    CO 15
# shutdown              CO 17
# co_cancel             CO 18
# orphaned              CO 19



# MS-RPCE 2.2.4.12 NDR Transfer Syntax Identifier
#MSRPC_STANDARD_NDR_SYNTAX = ('8A885D04-1CEB-11C9-9FE8-08002B104860', '2.0')
# 20-байтовые «сигнатуры» transfer syntax (UUID + major + minor LE)

# Transfer Syntaxes (GUID + версия)
# NDR32 (v2.0)
NDR32_TUP  = ('8a885d04-1ceb-11c9-9fe8-08002b104860', 2, 0)
NDR32_BIN  = uuidtup_to_bin(NDR32_TUP)  # 20 байт

# NDR64 (v1.0)
NDR64_TUP  = ('71710533-beba-4937-8319-b5dbef9ccc36', 1, 0)
NDR64_BIN  = uuidtup_to_bin(NDR64_TUP)

# Bind-Time Feature Negotiation (Windows) — версия может «гулять», нас интересует только GUID
FEAT_TUP   = ('6cb71c2c-9812-4540-0300-000000000000', 1, 0)
FEAT_BIN   = uuidtup_to_bin(FEAT_TUP)


class dcerpc_bind_nak_reason(Enum):
	DCERPC_BIND_NAK_REASON_NOT_SPECIFIED                    =(int)(0),
	DCERPC_BIND_NAK_REASON_TEMPORARY_CONGESTION             =(int)(1),
	DCERPC_BIND_NAK_REASON_LOCAL_LIMIT_EXCEEDED             =(int)(2),
	DCERPC_BIND_NAK_REASON_PROTOCOL_VERSION_NOT_SUPPORTED   =(int)(4),
	DCERPC_BIND_NAK_REASON_INVALID_AUTH_TYPE                =(int)(8),
	DCERPC_BIND_NAK_REASON_INVALID_CHECKSUM                 =(int)(9)

DCERPC_PTYPE_BIND = 11
DCERPC_PTYPE_BIND_ACK = 12
PFC_FIRST = 0x01
PFC_LAST  = 0x02

import socketserver
import struct

from impacket.dcerpc.v5 import rpcrt
# если есть tuple-синтаксис, пригодится:
try:
    from impacket.uuid import uuidtup_to_bin
except Exception:
    uuidtup_to_bin = None

class NDRPush:
    def __init__(self):
        self.buf = bytearray()
        self.off = 0
    def _ensure(self, n):
        need = self.off + n - len(self.buf)
        if need > 0:
            self.buf.extend(b'\x00'*need)
    def align(self, n):
        pad = (-self.off) & (n-1)
        if pad:
            self._ensure(pad)
            self.off += pad
    def u8(self, v):
        self._ensure(1); self.buf[self.off:self.off+1] = struct.pack('<B', v); self.off += 1
    def u16(self, v):
        self.align(2); self._ensure(2); self.buf[self.off:self.off+2] = struct.pack('<H', v); self.off += 2
    def u32(self, v):
        self.align(4); self._ensure(4); self.buf[self.off:self.off+4] = struct.pack('<I', v); self.off += 4
    def raw(self, b: bytes):
        n = len(b); self._ensure(n); self.buf[self.off:self.off+n] = b; self.off += n
    def trailer_align4(self):
        self.align(4)
    def getvalue(self) -> bytes:
        return bytes(self.buf)

class NDRPull:
    def __init__(self, data: bytes):
        self.b = memoryview(data)
        self.off = 0
    def align(self, n):
        self.off = (self.off + (n-1)) & ~(n-1)
    def u8(self):
        v = struct.unpack_from('<B', self.b, self.off)[0]; self.off += 1; return v
    def u16(self):
        self.align(2); v = struct.unpack_from('<H', self.b, self.off)[0]; self.off += 2; return v
    def u32(self):
        self.align(4); v = struct.unpack_from('<I', self.b, self.off)[0]; self.off += 4; return v
    def raw(self, n):
        v = self.b[self.off:self.off+n].tobytes(); self.off += n; return v





def parse_ncacn_header(pdu: bytes):
    # Минимум 16 байт
    if len(pdu) < 16:
        raise ValueError("PDU too short")
    # rpc_vers, minor, ptype, flags, drep[4], frag_len, auth_len, call_id
    rpc_vers, rpc_minor, ptype, flags = struct.unpack_from('<BBBB', pdu, 0)
    drep = pdu[4:8]        # 4 bytes
    frag_len, auth_len, call_id = struct.unpack_from('<HHI', pdu, 8)
    return {
        'rpc_vers': rpc_vers, 'rpc_minor': rpc_minor, 'ptype': ptype,
        'flags': flags, 'drep': drep, 'frag_len': frag_len,
        'auth_len': auth_len, 'call_id': call_id
    }

def parse_bind_co(pdu: bytes):
    """
    Возвращает (hdr, max_xmit, max_recv, assoc, contexts),
    где contexts = [{'id':ctx_id, 'abstract':20b, 'tx_list':[20b,...]}...]
    """
    hdr = parse_ncacn_header(pdu)
    assert hdr['ptype'] == DCERPC_PTYPE_BIND
    body = memoryview(pdu)[16:16 + (hdr['frag_len'] - 16 - hdr['auth_len'])]

    # max_xmit, max_recv, assoc
    max_xmit, max_recv, assoc = struct.unpack_from('<HHI', body, 0)
    ctx_num = struct.unpack_from('<H', body, 8)[0]
    off = 12

    contexts = []
    for _ in range(ctx_num):
        # HBx + abstract(20)
        if len(body) - off < 24: break
        ctx_id, n_tx = struct.unpack_from('<HBx', body, off); off += 4
        abstract = bytes(body[off:off+20]); off += 20
        tx_list = []
        for __ in range(n_tx):
            if len(body) - off < 20: break
            tx_list.append(bytes(body[off:off+20])); off += 20
        contexts.append({'id': ctx_id, 'abstract': abstract, 'tx_list': tx_list})

    return hdr, max_xmit, max_recv, assoc, contexts



def build_bind_ack_co(call_id: int,
                      req_flags: int,
                      max_xmit: int, max_recv: int,
                      assoc_group: int,
                      # список результатов той же длины, что contexts в запросе
                      results_transfer_syntaxes: list[bytes],
                      sec_addr: bytes = b'',
                      auth_trailer: bytes = b'') -> bytes:
    """
    Собираем полноценный rpcconn_bind_ack:
      - заголовок 16 байт
      - тело: max_xmit,max_recv,assoc + sec_addr_len/addr + align4
              + result_list (n_results, reserved, p_result_t[])
      - trailer align(4)
      - опционально auth_trailer (если нужен)
    result[i] = (ACCEPT, reason=0, transfer_syntax=20b)
    """
    # 1) Тело bind_ack
    ndr = NDRPush()
    # [max_xmit][max_recv][assoc]
    ndr.u16(max_xmit)
    ndr.u16(max_recv)
    ndr.u32(assoc_group)

    # Secondary address (CO): длина + байты, затем паддинг до /4
    # В CO вариации это plain bytes, без NUL обязаловки — пустая строка допустима
    ndr.u16(len(sec_addr))
    if sec_addr:
        ndr.raw(sec_addr)
    # паддинг до кратности 4 (как в Samba trailer_align для полей переменной длины)
    ndr.trailer_align4()

    # Result list: n_results (H) + reserved(H)
    n_results = max(1, len(results_transfer_syntaxes))
    ndr.u16(n_results)
    ndr.u16(0)  # reserved

    # p_result_t[]: {result(H), reason(H), transfer_syntax(20)}
    MSRPC_CONT_RESULT_ACCEPT = 0
    for tx in results_transfer_syntaxes or [b'\x00'*20]:
        if not isinstance(tx, (bytes, bytearray)) or len(tx) != 20:
            tx = b'\x00'*20
        ndr.u16(MSRPC_CONT_RESULT_ACCEPT)
        ndr.u16(0)            # reason
        ndr.raw(tx)           # 20 bytes

    # trailer align(4) — см. ndr_push_trailer_align(4) в Samba
    ndr.trailer_align4()
    body = ndr.getvalue()

    # 2) DCERPC header (16 байт)
    rpc_vers = 5
    rpc_minor = 0
    ptype = DCERPC_PTYPE_BIND_ACK
    flags = (req_flags | PFC_FIRST | PFC_LAST) & 0xFF
    drep = b'\x10\x00\x00\x00'  # little-endian/IEEE/ASCII

    # auth_length = len(auth_trailer) (если добавляешь verifier)
    auth_length = len(auth_trailer)
    frag_len = 16 + len(body) + auth_length

    hdr = struct.pack('<BBBB4sHHI',
                      rpc_vers, rpc_minor, ptype, flags,
                      drep,
                      frag_len, auth_length, call_id)

    return hdr + body + (auth_trailer or b'')







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

                    # для каждого контекста берем 1-й предложенный transfer syntax (20b) или заглушку
                    results_tx = []
                    for c in (contexts or [{}]):
                        lst = c.get('tx_list', [])
                        tx = lst[0] if (lst and isinstance(lst[0], (bytes, bytearray)) and len(lst[0]) == 20) else b'\x00'*20
                        results_tx.append(tx)
                    if not results_tx:
                        results_tx = [b'\x00'*20]

                    # строим корректный bind_ack (sec_addr пустой; без auth-trailer)
                    ack = build_bind_ack_co(
                        call_id=hdr['call_id'],
                        req_flags=hdr['flags'],
                        max_xmit=negotiated,
                        max_recv=negotiated,
                        assoc_group=0,
                        results_transfer_syntaxes=results_tx,
                        sec_addr=b'',
                        auth_trailer=b'',
                    )
                    self.request.sendall(ack)
                    print(f"[TCP {self.NAME}] -> BIND_ACK (accept-all)")
                    self.allow_bind = False
                    continue
                elif ptype == getattr(rpcrt, 'MSRPC_REQUEST', 0):
                    try:
                        req = rpcrt.MSRPCRequestHeader(pdu)
                        opnum  = int(req['op_num'])
                        ctx_id = int(req['ctx_id'])
                        print(f"[TCP {self.NAME}] REQUEST opnum={opnum} ctx_id={ctx_id}")
                    except Exception as e:
                        print(f"[TCP {self.NAME}] malformed REQUEST: {e}")
                        break

                    fault = rpcrt.MSRPCRespHeader()
                    fault['type']    = getattr(rpcrt, 'MSRPC_FAULT', 3)
                    fault['flags']   = (PFC_FIRST | PFC_LAST) & 0xFF
                    fault['call_id'] = hdr['call_id']
                    fault['ctx_id']  = req['ctx_id']
                    fault['pduData'] = struct.pack('<L', rpcrt.rpc_status_codes['nca_s_op_rng_error'])
                    self.request.sendall(fault.get_packet())
                    print(f"[TCP {self.NAME}] -> FAULT(op_rng_error)")
                    continue
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