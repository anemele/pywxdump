from psutil import Process
from pymem import Pymem
from pymem.exception import ProcessNotFound
from pymem.process import module_from_name

from .consts import WX_DLL, WX_EXE
from .utils import compare_version, get_exe_bit, get_exe_version

try:
    PM = Pymem(WX_EXE)
    PM.check_wow64()
except ProcessNotFound as e:
    print(e)
    exit(1)

MODULE = module_from_name(PM.process_handle, WX_DLL)
if MODULE is None:
    print(f'not found: {WX_DLL}')
    exit(1)

PROCESS = Process(PM.process_id)

_exe_path = PROCESS.exe()
ADDR_LEN = get_exe_bit(_exe_path) // 8
WX_VERSION = get_exe_version(_exe_path)
if compare_version(WX_VERSION, '3.9.2') > 0:
    address_len = 8
else:
    address_len = 4
