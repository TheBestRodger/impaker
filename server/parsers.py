import struct
from utils import DCERPC_PTYPE_BIND, DCERPC_PTYPE_BIND_ACK, FEAT_BIN, FEAT_TUP, NDR32_BIN, NDR32_TUP, NDR64_BIN, NDR64_TUP, PFC_FIRST, PFC_LAST, NDRPush


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
                      results_transfer_syntaxes: list[bytes],
                      sec_addr: bytes = b'',
                      auth_trailer: bytes = b'') -> bytes:
    """
    Builds a proper rpcconn_bind_ack with Samba-like results:
      - 3 results: Acceptance (NDR32), Provider rejection (NDR64), Negotiate ACK (bind-time feature)
      - Header: 16 bytes
      - Body: max_xmit, max_recv, assoc, sec_addr_len/addr, align4, result_list
      - Trailer: align(4)
      - Optional auth_trailer
    """
    ndr = NDRPush()
    ndr.u16(max_xmit)
    ndr.u16(max_recv)
    ndr.u32(assoc_group)


    ndr.u16(len(sec_addr))
    if sec_addr:
        ndr.raw(sec_addr)
    ndr.trailer_align4()

    # Подготовим result list в нужном порядке
    MSRPC_CONT_RESULT_ACCEPT        = 0
    MSRPC_CONT_RESULT_PROV_REJECT   = 2
    MSRPC_CONT_RESULT_NEGOTIATE_ACK = 3
    
    # reason для provider-rejection
    REASON_PROPOSED_TX_NOT_SUPPORTED = 2

    def _is(tx, pat):  # сравнить 16 байт GUID
        return isinstance(tx, (bytes, bytearray)) and len(tx) >= 16 and tx[:16] == pat[:16]

    results = []
    for tx in (results_transfer_syntaxes or []):
        tx20 = tx if isinstance(tx, (bytes, bytearray)) and len(tx) == 20 else b'\x00'*20

        if _is(tx20, NDR32_BIN):
            results.append( (MSRPC_CONT_RESULT_ACCEPT, 0, NDR32_BIN) )

        elif _is(tx20, NDR64_BIN):
            results.append( (MSRPC_CONT_RESULT_PROV_REJECT, REASON_PROPOSED_TX_NOT_SUPPORTED, NDR64_BIN) )

        elif _is(tx20, FEAT_BIN):
            # bind-time features: 0x0003 = multiplexing + keep-on-orphan
            results.append( (MSRPC_CONT_RESULT_NEGOTIATE_ACK, 0x0003, FEAT_BIN) )

        else:
            # неизвестное — отклоняем так же, как NDR64
            results.append( (MSRPC_CONT_RESULT_PROV_REJECT, REASON_PROPOSED_TX_NOT_SUPPORTED, tx20) )

    if not results:
        results = [ (MSRPC_CONT_RESULT_ACCEPT, 0, NDR32_BIN) ]

    # n_results (H) + reserved(H)
    ndr.u16(len(results))
    ndr.u16(0)

    # p_result_t[]
    for res, reason, tx20 in results:
        ndr.u16(res)
        ndr.u16(reason)
        ndr.raw(tx20 if isinstance(tx20, (bytes, bytearray)) and len(tx20) == 20 else b'\x00'*20)

    ndr.trailer_align4()
    body = ndr.getvalue()
    
    # --- заголовок DCERPC ---
    rpc_vers = 5
    rpc_minor = 0
    ptype = DCERPC_PTYPE_BIND_ACK
    flags = (req_flags | PFC_FIRST | PFC_LAST) & 0xFF
    drep = b'\x10\x00\x00\x00'
    auth_length = len(auth_trailer)
    frag_len = 16 + len(body) + auth_length

    hdr = struct.pack('<BBBB4sHHI',
                      rpc_vers, rpc_minor, ptype, flags,
                      drep,
                      frag_len, auth_length, call_id)

    return hdr + body + (auth_trailer or b'')





