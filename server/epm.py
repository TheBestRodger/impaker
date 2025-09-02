# ndr_pull_epm_Map.py
from dataclasses import dataclass
from typing import Optional, List, Tuple, Dict
import uuid
import ipaddress

# ---------- минимальный NDR-пуллер (LE) ----------
class _NDRPull:
    def __init__(self, data: bytes):
        self.buf = data
        self.off = 0

    def _need(self, n: int):
        if self.off + n > len(self.buf):
            raise ValueError(f"NDR underflow: need {n} at {self.off}, size={len(self.buf)}")

    def align4(self):
        self.off = (self.off + 3) & ~3

    def u8(self) -> int:
        self._need(1)
        v = self.buf[self.off]
        self.off += 1
        return v

    def u16(self) -> int:
        self.align4()  # Samba GUID/полиси хэндлы идут с align(4); в башне — без выравниваний.
        self._need(2)
        v = int.from_bytes(self.buf[self.off:self.off+2], 'little')
        self.off += 2
        return v

    def u16_raw(self) -> int:
        # «сырой» 16-бит без выравнивания — это важно внутри twr_octets
        self._need(2)
        v = int.from_bytes(self.buf[self.off:self.off+2], 'little')
        self.off += 2
        return v

    def u32(self) -> int:
        self.align4()
        self._need(4)
        v = int.from_bytes(self.buf[self.off:self.off+4], 'little')
        self.off += 4
        return v

    def raw(self, n: int) -> bytes:
        self._need(n)
        v = self.buf[self.off:self.off+n]
        self.off += n
        return v

    # GUID по NDR (SCALARS): align(4) + 16 байт + trailer_align(4)
    def guid(self) -> uuid.UUID:
        self.align4()
        self._need(16)
        # в NDR GUID хранится в little-endian-представлении полей → bytes_le подходит идеально
        g = uuid.UUID(bytes_le=bytes(self.buf[self.off:self.off+16]))
        self.off += 16
        self.align4()
        return g

    # policy_handle (20 байт): u32 handle_type + GUID (NDR)
    def policy_handle(self) -> Tuple[int, uuid.UUID]:
        self.align4()
        handle_type = self.u32()  # уже с align4
        g = self.guid()
        return handle_type, g


@dataclass
class TowerFloor:
    prot_id: int
    lhs: bytes
    rhs: bytes


@dataclass
class TowerInfo:
    floors: int
    raw_octets: bytes
    floors_list: List[TowerFloor]
    iface_uuid: Optional[uuid.UUID]
    iface_ver_major: Optional[int]
    transfer_syntax_uuid: Optional[uuid.UUID]
    transfer_ver_major: Optional[int]
    rpc_co: bool
    tcp_port: Optional[int]
    ip: Optional[str]


class ndr_pull_epm_Map:
    """
    Самодостаточный парсер ept_map (EPM) запроса в стиле Samba ndr_pull_epm_Map.
    Передайте bytes stub — получите разобранные object/map_tower/entry_handle/max_towers
    и 'раскрытую' башню.
    """

    def __init__(self, stub: bytes):
        self._stub = stub

        # IN-параметры
        self.object_ptr: int = 0
        self.object_guid: Optional[uuid.UUID] = None

        self.map_tower_ptr: int = 0
        self.tower_octets: bytes = b""

        self.entry_handle_type: int = 0
        self.entry_handle_uuid: uuid.UUID = uuid.UUID(int=0)

        self.max_towers: int = 1

        # разбор самой башни
        self.tower: TowerInfo = TowerInfo(
            floors=0, raw_octets=b"", floors_list=[],
            iface_uuid=None, iface_ver_major=None,
            transfer_syntax_uuid=None, transfer_ver_major=None,
            rpc_co=False, tcp_port=None, ip=None
        )

        self._parse()

    # ---------- публичные удобства ----------
    @property
    def floors(self) -> int:
        return self.tower.floors

    # ---------- внутренности ----------
    def _parse(self):
        p = _NDRPull(self._stub)

        # 1) object (unique ptr) + GUID (если не NULL)
        self.object_ptr = p.u32()
        if self.object_ptr != 0:
            self.object_guid = p.guid()

        # 2) map_tower (unique ptr) + epm_twr_t
        self.map_tower_ptr = p.u32()
        if self.map_tower_ptr != 0:
            # epm_twr_t (как у самбы): два u32 с align4, затем "ровно tower_length" октетов без доп. заголовков
            tlen1 = p.u32()
            tlen2 = p.u32()
            # На практике оба равны длине башни; Samba читает массив длиной size_is(length)
            # В сетевых дампах пойдут сразу биты башни — без NDR-конформант заголовка.
            self.tower_octets = p.raw(tlen1)

        # 3) entry_handle (policy_handle) — Samba тянет как SCALARS (20 байт)
        try:
            self.entry_handle_type, self.entry_handle_uuid = p.policy_handle()
        except ValueError:
            # если буфера не хватило — допустим "нулевой" хэндл
            self.entry_handle_type, self.entry_handle_uuid = 0, uuid.UUID(int=0)

        # 4) max_towers (u32)
        try:
            self.max_towers = p.u32()
            if not (0 < self.max_towers <= 1024):
                self.max_towers = 1
        except ValueError:
            self.max_towers = 1

        # 5) распарсить башню по этажам
        if self.tower_octets:
            self.tower = self._parse_tower_octets(self.tower_octets)

    def _parse_tower_octets(self, blob: bytes) -> TowerInfo:
        # Локальные helpers без какого-либо выравнивания
        i = 0
        n = len(blob)

        def need(k: int):
            if i + k > n:
                raise ValueError(f"tower_octets truncated: need {k} at {i}, size={n}")

        def u16() -> int:
            nonlocal i
            need(2)
            v = int.from_bytes(blob[i:i+2], 'little')
            i += 2
            return v

        def take(k: int) -> bytes:
            nonlocal i
            need(k)
            v = blob[i:i+k]
            i += k
            return v

        # 1) Кол-во этажей
        floors = u16()
        floors_list = []

        iface_uuid = None
        iface_ver_major = None
        xfer_uuid = None
        xfer_ver_major = None
        rpc_co = False
        tcp_port = None
        ip_addr = None

        for floor_idx in range(floors):
            # 2) LHS_len + LHS
            lhs_len = u16()
            lhs = take(lhs_len)

            # 3) RHS_len + RHS
            rhs_len = u16()
            rhs = take(rhs_len)

            prot_id = lhs[0] if lhs_len > 0 else -1
            floors_list.append(TowerFloor(prot_id=prot_id, lhs=lhs, rhs=rhs))

            # Распознаём этажи
            if prot_id == 0x0D and lhs_len >= 1 + 16 + 2:
                # g = uuid.UUID(bytes_le=bytes(self.buf[self.off:self.off+16]))
                u = uuid.UUID(bytes_le=bytes(lhs[1:17]))
                maj = int.from_bytes(lhs[17:19], 'little')
                # Первый встреченный 0x0D считаем интерфейсным UUID (как в твоём дампе)
                if iface_uuid is None:
                    iface_uuid = u
                    iface_ver_major = maj
                else:
                    # Второй 0x0D — это transfer syntax (обычно DCE NDR)
                    xfer_uuid = u
                    xfer_ver_major = maj

            elif prot_id == 0x0B and len(rhs) >= 2:
                # RPC-CO: rhs = [minor, major]
                rpc_co = True
                # major = rhs[1]; minor = rhs[0] — если надо сохранить

            elif prot_id == 0x07 and len(rhs) >= 2:
                # TCP порт (big-endian!)
                tcp_port = int.from_bytes(rhs[:2], 'big')

            elif prot_id == 0x09 and len(rhs) >= 4:
                # IPv4 (big-endian)
                ip_addr = str(ipaddress.IPv4Address(int.from_bytes(rhs[:4], 'big')))

        # Иногда второй UUID (NDR transfer syntax) идёт отдельным этажом 0x0d
        # Пройдём ещё раз и отделим "интерфейсный" UUID от transfer-syntax по сигнатурам:
        # DCE NDR v2: 8a885d04-1ceb-11c9-9fe8-08002b104860 (major=2)
        DCE_NDR = uuid.UUID("8a885d04-1ceb-11c9-9fe8-08002b104860")
        for f in floors_list:
            if f.prot_id == 0x0D and len(f.lhs) >= 1 + 16 + 2:
                u = uuid.UUID(bytes_le=f.lhs[1:17])
                maj = int.from_bytes(f.lhs[17:19], 'little')
                if u == DCE_NDR:
                    xfer_uuid = u
                    xfer_ver_major = maj

        return TowerInfo(
            floors=floors,
            raw_octets=blob,
            floors_list=floors_list,
            iface_uuid=iface_uuid,
            iface_ver_major=iface_ver_major,
            transfer_syntax_uuid=xfer_uuid,
            transfer_ver_major=xfer_ver_major,
            rpc_co=rpc_co,
            tcp_port=tcp_port,
            ip=ip_addr
        )

    def debug_print(self):
        print("object_ptr:", hex(self.object_ptr))
        print("object_guid:", str(self.object_guid) if self.object_guid else None)
        print("map_tower_ptr:", hex(self.map_tower_ptr))
        print("entry_handle_type:", hex(self.entry_handle_type))
        print("entry_handle_uuid:", str(self.entry_handle_uuid))
        print("max_towers:", self.max_towers)
        print("floors:", self.tower.floors)
        print("iface_uuid:", self.tower.iface_uuid)
        print("iface_ver_major:", self.tower.iface_ver_major)
        print("xfer_uuid:", self.tower.transfer_syntax_uuid)
        print("xfer_ver_major:", self.tower.transfer_ver_major)
        print("rpc_co:", self.tower.rpc_co)
        print("tcp_port:", self.tower.tcp_port)
        print("ip:", self.tower.ip)
        # детальный дамп этажей
        for i, f in enumerate(self.tower.floors_list, 1):
            print(f"  floor#{i}: prot=0x{f.prot_id:02x}, lhs={f.lhs.hex(' ')}, rhs={f.rhs.hex(' ')}")

