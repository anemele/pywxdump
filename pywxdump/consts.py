import sys

WX_EXE = "WeChat.exe"
WX_DLL = "WeChatWin.dll"

# self.bits = 64 if sys.maxsize > 2**32 else 32  # 系统：32位或64位
BITS = 64 if sys.maxsize > 2**32 else 32

BIAS_DATA_FILE = 'bias-data.json'
