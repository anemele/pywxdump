import ctypes
import json
import os
import re

from pymem.pattern import pattern_scan_all, pattern_scan_module

from .consts import BITS
from .ps import ADDR_LEN, MODULE, PM, WX_VERSION, address_len
from .utils import verify_key

ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
void_p = ctypes.c_void_p


def search_memory_value(value: bytes) -> int:
    module = MODULE
    if module is None:
        return 0

    tmp: list = PM.pattern_scan_module(value, module, return_multiple=True)  # type: ignore
    if len(tmp) == 0:
        return 0

    return tmp[-1] - module.lpBaseOfDll


def get_key_bias1() -> int:
    module = MODULE
    if module is None:
        return 0

    byteLen = address_len  # 4 if self.bits == 32 else 8  # 4字节或8字节

    keyLenOffset = 0x8C if BITS == 32 else 0xD0
    keyWindllOffset = 0x90 if BITS == 32 else 0xD8

    keyBytes = b'-----BEGIN PUBLIC KEY-----\n...'
    publicKeyList: list = pattern_scan_all(
        PM.process_handle, keyBytes, return_multiple=True
    )  # type: ignore

    keyaddrs = []
    for addr in publicKeyList:
        keyBytes = addr.to_bytes(byteLen, byteorder="little", signed=True)  # 低位在前
        may_addrs: int | list = pattern_scan_module(
            PM.process_handle, module, keyBytes, return_multiple=True
        )  # type: ignore
        if may_addrs == 0:
            continue
        if isinstance(may_addrs, list) and len(may_addrs) > 0:
            for addr in may_addrs:
                keyLen = PM.read_uchar(addr - keyLenOffset)
                if keyLen != 32:
                    continue
                keyaddrs.append(addr - keyWindllOffset)

    if len(keyaddrs) == 0:
        return 0
    return keyaddrs[-1] - module.lpBaseOfDll


def search_key(key: bytes) -> int:
    key = re.escape(key)  # 转义特殊字符
    key_addr: int = PM.pattern_scan_all(key, return_multiple=False)  # type: ignore
    key = key_addr.to_bytes(address_len, byteorder='little', signed=True)
    return search_memory_value(key)


def get_key_bias2(db_path: str) -> int:
    def read_key_bytes(h_process, address, address_len=8) -> bytes | None:
        array = ctypes.create_string_buffer(address_len)
        if ReadProcessMemory(h_process, void_p(address), array, address_len, 0) == 0:
            return
        address = int.from_bytes(array, byteorder='little')  # 逆序转换为int地址（key地址）
        key = ctypes.create_string_buffer(32)
        if ReadProcessMemory(h_process, void_p(address), key, 32, 0) == 0:
            return

        return bytes(key)

    MicroMsg_path = os.path.join(db_path, "MSG\\MicroMsg.db")

    module = MODULE
    if module is None:
        return 0

    type1_addrs: list[int] = PM.pattern_scan_module(
        b"iphone\x00", module, return_multiple=True
    )  # type: ignore
    type2_addrs: list[int] = PM.pattern_scan_module(
        b"android\x00", module, return_multiple=True
    )  # type: ignore
    type3_addrs: list[int] = PM.pattern_scan_module(
        b"ipad\x00", module, return_multiple=True
    )  # type: ignore

    if len(type1_addrs) >= 2:
        type_addrs = type1_addrs
    elif len(type2_addrs) >= 2:
        type_addrs = type2_addrs
    elif len(type3_addrs) >= 2:
        type_addrs = type3_addrs
    else:
        return 0

    for i in type_addrs[::-1]:
        for j in range(i, i - 2000, -ADDR_LEN):
            key_bytes = read_key_bytes(PM.process_handle, j, ADDR_LEN)
            if key_bytes is None:
                continue
            if verify_key(key_bytes, MicroMsg_path):
                return j - module.lpBaseOfDll
    return 0


def get_bias_by_info(
    account: bytes,
    mobile: bytes,
    name: bytes,
    key: str | None,
    db_path: str | None,
):
    if key is None:
        bkey = b""
    else:
        bkey = bytes.fromhex(key)

    if db_path is None or not os.path.exists(db_path):
        db_path = ""

    account_bias = search_memory_value(account)
    mobile_bias = search_memory_value(mobile)
    name_bias = search_memory_value(name)
    key_bias = get_key_bias1()
    if key is not None and key_bias <= 0:
        key_bias = search_key(bkey)
    if db_path is not None and key_bias <= 0:
        key_bias = get_key_bias2(db_path)

    data = {
        WX_VERSION: dict(
            name=name_bias,
            account=account_bias,
            phone=mobile_bias,
            email=0,
            key=key_bias,
        )
    }

    return data


def update_bias_data(bias_data_file: str, rdata: dict[str, dict[str, int]]):
    with open(bias_data_file, "rb") as fp:
        data = json.load(fp)
    data.update(rdata)
    with open(bias_data_file, "w") as fp:
        json.dump(data, fp, indent=2)
