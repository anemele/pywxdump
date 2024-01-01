import ctypes
import glob
import json
import logging
import os
import os.path as op
import winreg
from dataclasses import dataclass
from itertools import chain

import psutil
import pymem
from psutil import Process

from .consts import BIAS_DATA_FILE, WX_DLL, WX_EXE
from .ps import ADDR_LEN, WX_VERSION
from .utils import pattern_scan_all, verify_key

logger = logging.getLogger(__file__)
ReadProcessMemory = ctypes.windll.kernel32.ReadProcessMemory
void_p = ctypes.c_void_p


# 读取内存中的字符串(非key部分)
def get_info_without_key(h_process, address, n_size=64) -> str | None:
    array = ctypes.create_string_buffer(n_size)
    if ReadProcessMemory(h_process, void_p(address), array, n_size, 0) == 0:
        return
    array = bytes(array)
    if b"\x00" in array:
        array = array.split(b"\x00", 1)[0]
    text = array.decode('utf-8', errors='ignore')
    return text.strip() or None


def get_info_wxid(h_process) -> str | None:
    find_num = 100
    addrs: list = pattern_scan_all(
        h_process, br'\\Msg\\FTSContact', return_multiple=True, find_num=find_num
    )  # type: ignore
    wxids = []
    for addr in addrs:
        array = ctypes.create_string_buffer(80)
        if ReadProcessMemory(h_process, void_p(addr - 30), array, 80, 0) == 0:
            return
        array = bytes(array)  # .split(b"\\")[0]
        array = array.split(b"\\Msg", 1)[0]
        array = array.rsplit(b"\\", 1)[-1]
        wxids.append(array.decode('utf-8', errors='ignore'))
    if len(wxids) > 0:
        return max(wxids, key=wxids.count)


def _get_w_dir() -> str:
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, "Software\\Tencent\\WeChat", 0, winreg.KEY_READ
        ) as key:
            w_dir, _ = winreg.QueryValueEx(key, "FileSavePath")
        return w_dir
    except OSError:
        pass

    try:
        path_3ebffe94 = op.expanduser(
            "~\\AppData\\Roaming\\Tencent\\WeChat\\All Users\\config\\3ebffe94.ini"
        )
        with open(path_3ebffe94, encoding="utf-8") as fp:
            w_dir = fp.read()
        return w_dir
    except (FileNotFoundError, IOError):
        pass

    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders",
        ) as key:
            w_dir, _ = winreg.QueryValueEx(key, "Personal")
        return op.expandvars(w_dir)
    except OSError:
        return op.expanduser('~\\Documents')


def get_info_filePath(wxid="all") -> str | None:
    if not wxid:
        return

    w_dir = _get_w_dir()
    msg_dir = op.join(w_dir, "WeChat Files")

    if wxid == "all" and op.exists(msg_dir):
        return msg_dir

    filePath = op.join(msg_dir, wxid)
    if op.exists(filePath):
        return filePath


def get_key(pid: int, db_path, addr_len) -> str | None:
    def read_key_bytes(h_process, address, address_len=8) -> bytes | None:
        array = ctypes.create_string_buffer(address_len)
        if ReadProcessMemory(h_process, void_p(address), array, address_len, 0) == 0:
            return
        address = int.from_bytes(array, byteorder='little')  # 逆序转换为int地址（key地址）
        key = ctypes.create_string_buffer(32)
        if ReadProcessMemory(h_process, void_p(address), key, 32, 0) == 0:
            return

        return bytes(key)

    pm = pymem.Pymem(pid)
    module = WX_DLL

    MicroMsg_path = op.join(db_path, "MSG\\MicroMsg.db")

    type1_addrs = pm.pattern_scan_module(b"iphone\x00", module, return_multiple=True)
    type2_addrs = pm.pattern_scan_module(b"android\x00", module, return_multiple=True)
    type3_addrs = pm.pattern_scan_module(b"ipad\x00", module, return_multiple=True)

    type_addrs = []
    if len(type1_addrs) >= 2:
        type_addrs.extend(type1_addrs)
    if len(type2_addrs) >= 2:
        type_addrs.extend(type2_addrs)
    if len(type3_addrs) >= 2:
        type_addrs.extend(type3_addrs)
    if len(type_addrs) == 0:
        return

    type_addrs.sort()  # 从小到大排序

    for i in type_addrs[::-1]:
        for j in range(i, i - 2000, -addr_len):
            key_bytes = read_key_bytes(pm.process_handle, j, addr_len)
            if key_bytes is None:
                continue
            if verify_key(key_bytes, MicroMsg_path):
                return key_bytes.hex()


def get_all_wx_process():
    keys = ['name', 'exe', 'pid', 'cmdline']
    for process in psutil.process_iter(keys):
        if process.name() == 'WeChat.exe':
            yield process


@dataclass
class BiasData:
    name: int
    account: int
    phone: int
    email: int
    key: int


def read_bias_data(path: str) -> dict[str, BiasData]:
    with open(path, 'rb') as fp:
        data = json.load(fp)
    return {
        k: BiasData(
            name=v['name'],
            account=v['account'],
            phone=v['phone'],
            email=v['email'],
            key=v['key'],
        )
        for k, v in data.items()
    }


@dataclass
class WxInfo:
    name: str | None = None
    account: str | None = None
    phone: str | None = None
    email: str | None = None
    key: str | None = None
    wxid: str | None = None
    filepath: str | None = None


def read_wx_process(process: Process, bias: BiasData) -> WxInfo:
    base_addr = 0
    for module in process.memory_maps(grouped=False):
        if module.path and WX_DLL in module.path:
            base_addr = int(module.addr, 16)
            break
    if base_addr == 0:
        print(f"not found: {WX_DLL}")

    Handle = ctypes.windll.kernel32.OpenProcess(0x1F0FFF, False, process.pid)
    info = WxInfo(wxid=get_info_wxid(Handle))

    if bias.name != 0:
        info.name = get_info_without_key(Handle, base_addr + bias.name, 64)
    if bias.account != 0:
        info.account = get_info_without_key(Handle, base_addr + bias.account, 32)
    if bias.phone != 0:
        info.phone = get_info_without_key(Handle, base_addr + bias.phone, 64)
    if bias.email != 0:
        info.email = get_info_without_key(Handle, base_addr + bias.email, 64)

    if info.wxid is not None:
        info.filepath = get_info_filePath(info.wxid)
    if info.filepath is not None:
        info.key = get_key(process.pid, info.filepath, ADDR_LEN)

    return info


def read_info(bias_data_file: str | None = None) -> list[WxInfo] | None:
    bias = read_bias_data(bias_data_file or BIAS_DATA_FILE).get(WX_VERSION)
    if bias is None:
        print(f'not support version: {WX_VERSION}', 'get bias first?', sep='\n')
        return

    wechat_process = list(get_all_wx_process())

    if len(wechat_process) == 0:
        print(f"no process found: {WX_EXE}")
        return

    return [read_wx_process(process, bias) for process in wechat_process]


def get_wx_db(
    require_list: list[str] | str,
    msg_dir: str | None = None,
    wxid: list[str] | str | None = None,
):
    if msg_dir is None:
        msg_dir = get_info_filePath(wxid="all")

    if msg_dir is None or not op.exists(msg_dir):
        print('not found: msg_dir')
        return

    files = set(os.listdir(msg_dir))
    if wxid is not None:
        if isinstance(wxid, str):
            wxid = wxid.split(";")
        files &= set(wxid)
    else:
        files -= {"All Users", "Applet", "WMPF"}
    user_dirs = [op.join(msg_dir, file_name) for file_name in files]
    logger.debug(f'{user_dirs=}')

    if isinstance(require_list, str):
        require_list = require_list.split(";")
    logger.debug(f'{require_list=}')

    if "all" in require_list:
        pattern_list = ("**/*.db",)
    else:
        pattern_list = (f"**/{require}*.db" for require in require_list)

    ret = {
        user_dir: list(
            chain.from_iterable(
                glob.iglob(pattern, root_dir=user_dir, recursive=True)
                for pattern in pattern_list
            )
        )
        for user_dir in user_dirs
    }

    print(f"共有 {len(ret)} 个微信账号")
    return ret
