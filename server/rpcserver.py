#!/usr/bin/env python3
import os
import threading, socketserver
from impacket.smbserver import SimpleSMBServer
from impacket.dcerpc.v5 import rpcrt
from impacket.ntlm import compute_lmhash, compute_nthash
from lsa import handle_lsa_request
from bind_parsers import (
                    NDR32_BIN, 
                    build_bind_ack_co, 
                    parse_bind_co, 
                    parse_ncacn_header
                )
from utils_lsa import _build_fault_co
from epmapper import handle_epm_request


# UUID интерфейсов (abstract syntax), чтобы логировать/фильтровать
LSARPC_UUID     = "12345778-1234-abcd-ef00-0123456789ab"
SAMR_UUID       = "12345778-1234-abcd-ef00-0123456789ac"
NETLOGON_UUID   = "12345678-1234-abcd-ef00-0123456789ab"  # проверь свою версию при необходимости
EPM_UUID        = "e1af8308-5d1f-11c9-91a4-08002b14a0fa"#"00000000-0000-0000-0000-000000000000"
# NCA статус-коды для FAULT
NCA_S_OK            = 0x00000000
NCA_S_OP_RNG_ERROR  = 0x1C010002  # неизвестный opnum
NCA_S_UNK_IF        = 0x1C010003  # неизвестный интерфейс

# Быстрая таблица известных интерфейсов (по UUID) → метка сервиса
KNOWN_IFACES = {
    LSARPC_UUID.lower():   "lsarpc",
    SAMR_UUID.lower():     "samr",
    NETLOGON_UUID.lower(): "netlogon",
    EPM_UUID.lower(): "epmapper",
}
IFACE_BY_UUID = {
    LSARPC_UUID.lower():   "lsarpc",
    SAMR_UUID.lower():     "samr",
    NETLOGON_UUID.lower(): "netlogon",
    EPM_UUID.lower(): "epmapper",
}
import uuid

def normalize_uuid(u) -> str:
    if not u:
        return ""
    if isinstance(u, (bytes, bytearray)):
        # парсеры возвращают 16 байт в LE; если BE — то bytes
        try:
            return str(uuid.UUID(bytes_le=bytes(u))).lower()
        except Exception:
            try:
                return str(uuid.UUID(bytes=bytes(u))).lower()
            except Exception:
                return ""
    # строка
    s = str(u).strip().lower()
    # убрать фигурные скобки, если есть
    if s.startswith("{") and s.endswith("}"):
        s = s[1:-1]
    try:
        return str(uuid.UUID(s)).lower()
    except Exception:
        try:
            return str(uuid.UUID(s.replace("-", ""))).lower()
        except Exception:
            return ""
def lookup_iface_by_uuid(u) -> str | None:
    auuid = normalize_uuid(u)
    if not isinstance(IFACE_BY_UUID, dict):
        local = {
            LSARPC_UUID.lower():   "lsarpc",
            SAMR_UUID.lower():     "samr",
            NETLOGON_UUID.lower(): "netlogon",
        }
        return local.get(auuid)
    return IFACE_BY_UUID.get(auuid)

class RPCPipeTCPHandler(socketserver.BaseRequestHandler):
    #NAME = r"\lsarpc"
    def _service_hint_from_name(self) -> str | None:
        """Вывести сервис из self.NAME: '\lsarpc', 'ncacn_ip_tcp:lsarpc', '\samr', '\netlogon'."""
        nm = (getattr(self, "NAME", "") or "").lower().strip()
        if nm.startswith("ncacn_ip_tcp:"):
            nm = nm.split(":", 1)[1]
        nm = nm.strip("\\/")
        if nm.endswith("lsarpc"):
            return "lsarpc"
        if nm.endswith("samr"):
            return "samr"
        if nm.endswith("netlogon"):
            return "netlogon"
        if nm.endswith("epmapper"):
            return "epmapper"
        return None

    def _remember_default_service(self):
        """Запомнить дефолтный сервис на соединение, если его можно вывести из имени."""
        if not hasattr(self, "_default_service") or self._default_service is None:
            self._default_service = self._service_hint_from_name()

    def _service_from_ctx(self, ctx_id: int) -> str | None:
        """Вернуть сервис по ctx_id, либо дефолтный (по имени пайпа/слушателя) как фолбэк."""
        svc = self.ctx_map.get(ctx_id)
        if svc is None:
            self._remember_default_service()
            return getattr(self, "_default_service", None)
        return svc
        # один bind на соединение, как в Samba
    def __init__(self, request, client_address, server):
            super().__init__(request, client_address, server)
    
    def setup(self):
        super().setup()
        self.allow_bind = True
        self.ctx_map = {}           # ctx_id -> 'lsarpc'|'samr'|'netlogon'|None
        self._default_service = None

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

                    self.ctx_map.clear()
                    self._remember_default_service() 
                    
                    results_tx = []
                    for c in (contexts or []):

                        if isinstance(c, dict):
                            ctx = int(c.get('ctx_id', 0))
                            abstr = c.get('abstract') or {}
                            auuid_raw = (abstr.get('uuid') if isinstance(abstr, dict) else None) or ""
                        else:
                            try:
                                ctx = int(getattr(c, 'ctx_id', 0))
                            except Exception:
                                ctx = 0
                            try:
                                auuid_raw = getattr(getattr(c, 'abstract', None), 'uuid', "") or ""
                            except Exception:
                                auuid_raw = ""

                        service = lookup_iface_by_uuid(auuid_raw)
                        if service is None:
                            service = getattr(self, "_default_service", None)

                        self.ctx_map[ctx] = service
                        
                        lst = c.get('tx_list') or []
                        if lst and isinstance(lst[0], (bytes, bytearray)) and len(lst[0]) == 20:
                            results_tx.append(lst[0])
                    # если клиент не прислал
                    if not results_tx:
                        results_tx = [NDR32_BIN]

                    # строим корректный bind_ack (sec_addr пустой; без auth-trailer)
                    ack = build_bind_ack_co(
                        call_id=hdr['call_id'],
                        req_flags=hdr['flags'],
                        max_xmit=negotiated,
                        max_recv=negotiated,
                        assoc_group=0x000006e7, # хз
                        results_transfer_syntaxes=results_tx,
                        sec_addr=b'\\pipe\\lsass\0', # хз
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
                        opnum  = int(req['op_num'])
                        ctx_id = int(req['ctx_id'])
                        call_id = int(hdr['call_id'])
                        print(f"[TCP {self.NAME}] REQUEST opnum={opnum} ctx_id={ctx_id}")
                    except Exception as e:
                        print(f"[TCP {self.NAME}] malformed REQUEST: {e}")
                        break

                    service = self.ctx_map.get(ctx_id)
                    if service is None:
                        # Неизвестный интерфейс в этом presentation context
                        fault = _build_fault_co(call_id, ctx_id, NCA_S_UNK_IF)
                        self.request.sendall(fault)
                        print(f"[TCP {self.NAME}] -> FAULT nca_s_unk_if (ctx_id={ctx_id})")
                        continue

                    # Диспетчеризация по сервису
                    resp = None
                    if service == "lsarpc":
                        resp = handle_lsa_request(self.server, pdu)
                    elif service == "samr":
                        print("PROTOCOL - samr")
                        # TODO: resp = handle_samr_request(...)
                        pass
                    elif service == "netlogon":
                        print("PROTOCOL - netlogon")
                        # TODO: resp = handle_netlogon_request(...)
                        pass
                    elif service == "epmapper":
                        print("PROTOCOL - epmapper")
                        resp = handle_epm_request(self.server, pdu)
                    if resp:
                        self.request.sendall(resp)
                        continue
                    else:
                        # Не поддерживаемый opnum
                        fault = _build_fault_co(call_id, ctx_id, NCA_S_OP_RNG_ERROR)
                        self.request.sendall(fault)
                        print(f"[TCP {self.NAME}] -> FAULT nca_s_op_rng_error (opnum={opnum})")
                        continue

                else:
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

def start_dcerpc_tcp(name, host, port, abstract_uuid=None):
    class _H(RPCPipeTCPHandler):
        NAME = f"ncacn_ip_tcp:{name}"
        ABSTRACT_UUID = abstract_uuid
        IS_TCP = True
    srv = socketserver.ThreadingTCPServer((host, port), _H)
    srv.daemon_threads = True
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    print(f"[TCP ncacn_ip_tcp:{name}] listening on {host}:{port}")
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

    start_dcerpc_tcp("lsarpc", "0.0.0.0", 55152, abstract_uuid=LSARPC_UUID)
    start_dcerpc_tcp("samr",   "0.0.0.0", 55153, abstract_uuid=SAMR_UUID)
    start_dcerpc_tcp("netlogon","0.0.0.0",55154, abstract_uuid=NETLOGON_UUID)
    start_dcerpc_tcp("epmapper", "0.0.0.0", 135, abstract_uuid=EPM_UUID)
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