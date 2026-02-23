#!/usr/bin/env python3
"""
Translate ONT_V100R002C00SPC253.exe from Chinese to English.

This script modifies the PE resource section of the Huawei ONT maintenance
tool to replace Chinese UI strings with English translations.

Usage:
    python3 translate_ont_tool.py <input.exe> <output.exe>

Requirements:
    pip install pefile
"""

import sys
import struct
import copy
import pefile

# PE optional header offsets and data directory indices
DATA_DIRECTORY_OFFSET = 96      # Offset to DataDirectory in OptionalHeader (PE32)
SIZE_OF_IMAGE_OFFSET = 56       # Offset to SizeOfImage in OptionalHeader
BASE_RELOCATION_INDEX = 5       # DataDirectory index for BASE_RELOCATION
RESOURCE_INDEX = 2              # DataDirectory index for RESOURCE

# ============================================================
# Translation tables
# ============================================================

# String table translations (block 7, IDs 96-111)
STRING_TABLE_TRANSLATIONS = {
    101: "&About OBSCTool...",
    102: "Enable Pkg 1---For most V3 version devices",
    103: "Enable Pkg 2---For most V5 version devices",
    104: "Enable Pkg 3---For some new devices",
}

# Dialog translations: {dialog_id: {chinese_string: english_string}}
DIALOG_TRANSLATIONS = {
    102: {
        "维修使能工具 EchoLife ONT Tools V100R002C00SPC253":
            "Maintenance Tool EchoLife ONT Tools V100R002C00SPC253",
        "启动": "Start",
        "升级": "Upgrade",
        "维修使能": "Maint Enable",
        "取消使能": "Disable",
        "本地网卡：": "Local NIC:",
        "组播服务器IP：": "Multicast IP:",
        "帧大小：": "Frame Size:",
        "发送间隔：": "Interval:",
        "帧个数：": "Frame Cnt:",
        "发送进度：": "Progress:",
        "停止": "Stop",
        "成功总数：": "Success:",
        "升级版本包：": "Upgrade Pkg:",
        "字节": "Bytes",
        "毫秒": "ms",
        "组播配置": "Multicast Config",
        "删除备份配置": "Del Backup Cfg",
        "版本包配置": "Package Config",
        "包大小：": "Pkg Size:",
        "软件版本：": "SW Version:",
        "支持产品：": "Products:",
        "使能版本包：": "Enable Pkg:",
        "刷新": "Refresh",
        "日志级别：": "Log Level:",
        "详细信息": "Details",
        "清除界面日志": "Clear Log",
        "失败总数：": "Failed:",
    },
    155: {
        "License信息": "License Info",
        "注册": "Register",
        "继续使用": "Continue",
        "License：": "License:",
        "过期日期：": "Expiry Date:",
        "试用版": "Trial",
        "注册日期：": "Reg. Date:",
        "版权所有（c）华为技术有限公司 2017 保留一切权利":
            "Copyright(c) Huawei Technologies 2017 All Rights Reserved",
        "请联系华为供应商进行License注册":
            "Contact Huawei supplier for License registration",
    },
    1321: {
        "请输入合法的License": "Enter a valid License",
        "确定": "OK",
        "取消": "Cancel",
        "本机邀请码": "Invitation Code",
    },
    1322: {
        "警告": "Warning",
        "退出": "Exit",
    },
}

# Hardcoded UTF-16LE strings in .rdata section
# Format: {file_offset: (chinese, english, max_bytes)}
# max_bytes = distance from string start to next string start
RDATA_TRANSLATIONS = {
    # ListView table column headers
    0x3c8520: ("序号", "No.", 8),
    0x3c8528: ("单板条码", "Board", 12),
    0x3c8534: ("Mac地址", "MAC", 12),
    0x3c8540: ("21条码", "21Cod", 12),
    0x3c854c: ("开始错误码", "StErr", 12),
    0x3c8558: ("结束错误码", "EnErr", 12),
    0x3c8564: ("开始时间", "Start", 12),
    0x3c8570: ("结束时间", "End", 12),
    0x3c857c: ("耗时(秒)", "T(s)", 12),
    0x3c8598: ("使能包", "Pkg", 8),
    # License / error message strings
    0x3cfe00: ("License不合法，请重新输入合法的License！",
               "Invalid License, re-enter!", 56),
    0x3cfe38: ("注册License", "Reg.Lic.", 20),
    0x3cfe4c: ("License信息被破坏。", "Lic.corrupted", 28),
    0x3cfe68: ("license未注册或已到期，请输入合法的License",
               "Lic.expired, enter valid Lic.", 60),
    0x3cfea4: ("初始化License信息失败", "Init Lic.fail", 32),
    0x3cfec4: ("试用版", "Tri", 8),
    0x3cfecc: ("请重新申请License.", "Reapply Lic.", 28),
    0x3cfee8: (" 是否强制初始化license信息？", " Force init Lic.?", 40),
    0x3cff10: ("版权所有（c）华", "Copyright(c)Hua", 32),
}

# Notice text (multi-line, separate because of special handling)
NOTICE_TRANSLATION = {
    "offset": 0x3c85b8,
    "chinese": ("注意：\r\n"
                "1、此工具仅限代维点维修国内发货版本 \r\n"
                "2、请勿连接光纤！若已连接，请拔掉光纤并重启后再操作 \r\n"
                "3、请在光猫重启后5分钟内使用\r\n"
                "4、请关闭防火墙\r\n\r\n"),
    "english": ("Note:\r\n"
                "1.Domestic only\r\n"
                "2.No fiber! Reboot\r\n"
                "3.5min after boot\r\n"
                "4.No firewall\r\n\r\n"),
    "max_bytes": 172,
}

# GBK-encoded strings in .rdata section
# Format: {file_offset: (chinese_gbk_text, english_text, max_bytes)}
GBK_RDATA_TRANSLATIONS = {
    # Bug tracking fields
    0x3cd49c: ("问题单号:", "Issue ID:", 12),
    0x3cd4a8: ("原单单号:", "Orig.ID:", 12),
    0x3cd4b4: ("基线版本:", "Baseline:", 12),
    0x3cd4c0: ("问题简要描述:", "Brief Desc:", 16),
    0x3cd4d0: ("严重程度:", "Severity:", 12),
    0x3cd4dc: ("问题单当前状态:", "Curr.Status:", 16),
    0x3cd4ec: ("当前处理人:", "Handler:", 12),
    0x3cd4f8: ("滞留时间:", "Hold Time:", 12),
    0x3cd504: ("问题提交人ID:", "Submitter ID:", 16),
    0x3cd514: ("问题创建时间:", "Created Time:", 16),
    0x3cd524: ("开发人员实施修改", "Dev Implemented", 20),
    0x3cd538: ("最后处理时间", "Last Proc.Time", 16),
    0x3cd548: ("简要描述", "Brief Desc", 12),
    0x3cd554: ("审核人员审核修改", "Review Approved", 20),
    0x3cd568: ("CMO归档", "CMO Arc", 8),
    0x3cd570: ("特性", "Feat", 8),
    0x3cd578: ("模块", "Mod.", 8),
    0x3cd580: ("问题引入版本", "Intro Version", 3764),
    # Error/log messages
    0x3ce434: ("【ERROR】初始化试用版信息时，检测到之前已经初始化！",
               "[ERR]Trial init:already initialized!", 52),
    0x3ce468: ("【ERROR】创建Data文件失败！",
               "[ERR]Create Data file fail!", 28),
    0x3ce484: ("【ERROR】初始化data文件信息失败！",
               "[ERR]Init data file info fail!", 36),
    0x3ce4a8: ("【ERROR】清除data文件失败！",
               "[ERR]Clear data file fail!", 28),
    0x3ce4c4: ("【ERROR】获取data文件创建时间失败！",
               "[ERR]Get data create time fail!", 36),
    0x3ce4e8: ("【ERROR】获取邀请码特征字符串正文失败！",
               "[ERR]Get invite code feature body fail!", 40),
    0x3ce510: ("【ERROR】获取邀请码特征字符串失败！",
               "[ERR]Get invite code str fail!", 36),
    0x3ce534: ("【ERROR】获取试用版校验和失败！",
               "[ERR]Get trial checksum fail!", 40),
    0x3ce55c: ("【ERROR】记录data文件创建时间失败！",
               "[ERR]Record data file time fail!", 36),
    0x3ce580: ("【ERROR】记录邀请码特征字符串正文失败！",
               "[ERR]Record invite code body fail!", 40),
    0x3ce5a8: ("【ERROR】记录下一个邀请码特征字符串正文失败！",
               "[ERR]Record next invite code body fail!", 48),
    0x3ce5d8: ("【ERROR】记录试用版最后使用时间失败！",
               "[ERR]Record trial last use time fail!", 40),
    0x3ce600: ("【ERROR】记录试用版的试用状态失败！",
               "[ERR]Record trial status fail!", 36),
    0x3ce624: ("【ERROR】记录试用版校验和失败！",
               "[ERR]Record trial chksum fail!", 32),
    0x3ce644: ("【ERROR】写入data文件出现异常，异常信息:",
               "[ERR]Write data file exception:", 44),
    0x3ce670: ("【ERROR】将data文件路径写入注册表失败！",
               "[ERR]Write data path to registry fail!", 40),
    0x3ce698: ("【ERROR】保存数据到文件失败！",
               "[ERR]Save data to file fail!", 32),
    0x3ce6b8: ("【ERROR】清除注册表信息失败！",
               "[ERR]Clear registry info fail!", 32),
    0x3ce6d8: ("【ERROR】写入data文件出现异常，异常信息:%s:",
               "[ERR]Write data file exception:%s:", 44),
    0x3ce704: ("【ERROR】注册表路径或工具特征字符串为空！",
               "[ERR]Registry path or tool str empty!", 44),
    0x3ce730: ("【ERROR】读取注册表中的data文件路径失败！",
               "[ERR]Read data file path from reg fail!", 48),
    0x3ce760: ("【ERROR】注册表中记录的data文件路径解密失败(注册表中保存的是加密的数据)或文件不存在！",
               "[ERR]Decrypt data path fail or file missing!", 124),
    0x3ce7dc: ("【ERROR】获取历史注册license信息失败！",
               "[ERR]Get hist reg license info fail!", 40),
    0x3ce804: ("【ERROR】获取当前license信息失败！",
               "[ERR]Get current license info fail!", 36),
    0x3ce828: ("【ERROR】获取总的有效月数失败！",
               "[ERR]Get total valid months!", 32),
    0x3ce848: ("【ERROR】更新最后使用时间失败！",
               "[ERR]Update last use time fail!", 32),
    0x3ce868: ("【ERROR】更新校验和失败！",
               "[ERR]Update checksum fail!", 28),
    0x3ce884: ("【ERROR】获取当前试用是否可用失败！",
               "[ERR]Get trial availability fail!", 236),
    0x3ce970: ("【ERROR】License为空！",
               "[ERR]License is empty!", 148),
    0x3cea04: ("【ERROR】获取当前时间或data文件创建时间失败！",
               "[ERR]Get time or data create time fail!", 88),
    0x3cea5c: ("【ERROR】License字符串校验不通过！",
               "[ERR]License string verify failed!", 100),
    0x3ceac0: ("【ERROR】Data文件状态不正确，文件被拷贝移动过！",
               "[ERR]Data file status wrong,copied!", 48),
    0x3ceaf0: ("【ERROR】解析License中的有效可用月数失败！",
               "[ERR]Parse license valid months fail!", 44),
    0x3ceb1c: ("【ERROR】查询历史license失败！",
               "[ERR]Query hist license fail!", 32),
    0x3ceb3c: ("【ERROR】生成License有效时间校验和失败！",
               "[ERR]Gen license time checksum fail!", 92),
    0x3ceb98: ("【ERROR】License已被使用！",
               "[ERR]License already used!", 88),
    0x3cebf0: ("【ERROR】记录license到data文件失败！",
               "[ERR]Record license to data fail!", 40),
    0x3cec18: ("【ERROR】记录license注册时间失败！",
               "[ERR]Record license reg time fail!", 36),
    0x3cec3c: ("【ERROR】记录最后使用时间失败！",
               "[ERR]Record last use time fail!", 32),
    0x3cec5c: ("【ERROR】禁用试用版失败！",
               "[ERR]Disable trial fail!", 28),
    0x3cec78: ("【ERROR】记录信息到注册表失败！",
               "[ERR]Record info to registry fail!", 88),
    0x3cecd0: ("【ERROR】更新邀请码失败！",
               "[ERR]Update invite code fail!", 100),
    0x3ced34: ("【ERROR】更新下一个邀请码失败！",
               "[ERR]Update next invite code!", 32),
    0x3ced54: ("【ERROR】记录信息到data文件失败！",
               "[ERR]Record info to data file fail!", 68),
    0x3ced98: ("【ERROR】禁用试用版时，计算校验和失败！",
               "[ERR]Disable trial:checksum fail!", 44),
    0x3cedc4: ("【ERROR】禁用试用版时，设置试用状态失败！",
               "[ERR]Disable trial:set status fail!", 44),
    0x3cedf0: ("【ERROR】取记录的Data文件创建时间失败！",
               "[ERR]Get Data file create time fail!", 40),
    0x3cee18: ("【ERROR】禁用试用版时，获取data文件创建时间失败！",
               "[ERR]Disable trial:get create time fail!", 52),
    0x3cee4c: ("【ERROR】从注册表查询License信息失败！",
               "[ERR]Query License info from reg fail!", 40),
    0x3cee74: ("【ERROR】获取最后使用时间节点失败！",
               "[ERR]Get last use time node fail!", 36),
    0x3cee98: ("【ERROR】获取是否可以试用失败！",
               "[ERR]Get trial available fail!", 32),
    0x3ceeb8: ("【ERROR】获取校验和节点失败！",
               "[ERR]Get checksum node fail!", 32),
    0x3ceed8: ("【ERROR】从注册表中获取license信息失败！",
               "[ERR]Get license info from reg fail!", 44),
    0x3cef04: ("【ERROR】从注册表中获取有效可用月数信息失败！",
               "[ERR]Get valid months from reg fail!", 48),
    0x3cef34: ("【ERROR】获取License注册时间节点失败！",
               "[ERR]Get License reg time node fail!", 40),
    0x3cef5c: ("【ERROR】获取data文件创建时间节点失败！",
               "[ERR]Get data create time node fail!", 40),
    0x3cef84: ("【ERROR】获取历史license信息失败！",
               "[ERR]Get hist license info fail!", 128),
    0x3cf004: ("【ERROR】参数为空！",
               "[ERR]Param is null!", 84),
    0x3cf058: ("【ERROR】传入参数无效！",
               "[ERR]Invalid param!", 24),
    0x3cf070: ("【ERROR】最后使用时间小于Data文件创建时间！",
               "[ERR]Last use time < Data create time!", 44),
    0x3cf09c: ("【ERROR】当前时间小于最后使用时间！",
               "[ERR]Current time < last use time!", 36),
    0x3cf0c0: ("【ERROR】当前时间超过有效时间！",
               "[ERR]Current time > valid time!", 32),
    0x3cf0e0: ("【ERROR】当前时间不在有效期内！",
               "[ERR]Time not in valid period!", 32),
    0x3cf100: ("【ERROR】有效时间校验和验证失败！",
               "[ERR]Time checksum verify fail!", 36),
    0x3cf124: ("【ERROR】当前License不包含License头！",
               "[ERR]License missing License header!", 64),
    0x3cf164: ("【ERROR】License不包含License头！",
               "[ERR]License no License header!", 36),
    0x3cf188: ("【ERROR】解析出来的有效月数异常！",
               "[ERR]Parsed valid months abnormal!", 144),
    0x3cf218: ("【ERROR】获取License注册时间失败！",
               "[ERR]Get License reg time fail!", 44),
    0x3cf244: ("【ERROR】加载加密的xml文件失败",
               "[ERR]Load encrypted xml file fail", 40),
    0x3cf26c: ("【ERROR】初始化root节点信息失败",
               "[ERR]Init root node info fail", 32),
    0x3cf28c: ("【ERROR】初始化信息时打开文件失败",
               "[ERR]Init info:open file fail", 36),
    0x3cf2b0: ("【ERROR】初始化信息时读取文件失败",
               "[ERR]Init info:read file fail", 36),
    0x3cf2d4: ("【ERROR】初始化信息时解析文件失败",
               "[ERR]Init info:parse file fail", 36),
    0x3cf2f8: ("【ERROR】保存xml数据时初始化失败",
               "[ERR]Save xml data:init fail", 36),
    0x3cf31c: ("【ERROR】保存xml数据时创建文件失败",
               "[ERR]Save xml:create file fail", 36),
    0x3cf340: ("【ERROR】保存xml数据时写入数据失败",
               "[ERR]Save xml:write data fail", 72),
    0x3cf388: ("【ERROR】查询邀请码特征字符串失败",
               "[ERR]Query invite code str fail", 44),
    0x3cf3b4: ("【ERROR】邀请码特征字符串为空",
               "[ERR]Invite code str empty", 32),
    0x3cf3d4: ("【ERROR】邀请码特征字符串为空！",
               "[ERR]Invite code str is empty!", 32),
    0x3cf3f4: ("【ERROR】XML根节点为空",
               "[ERR]XML root node null", 24),
    0x3cf40c: ("【ERROR】添加requestCode节点失败！",
               "[ERR]Add requestCode node fail!", 36),
    0x3cf430: ("【ERROR】添加requestCodeFeatureBody节点失败！",
               "[ERR]Add reqCodeFeatureBody node fail!", 92),
    0x3cf48c: ("【ERROR】查询记录的Data文件创建时间失败",
               "[ERR]Query Data file create time fail", 40),
    0x3cf4b4: ("【ERROR】记录的Data文件创建时间为空",
               "[ERR]Data file create time empty", 36),
    0x3cf4d8: ("【ERROR】Data文件创建时间为空！",
               "[ERR]Data file create time!", 32),
    0x3cf4f8: ("【ERROR】添加time节点失败！",
               "[ERR]Add time node fail!", 28),
    0x3cf514: ("【ERROR】添加dataFileCreateTime节点失败！",
               "[ERR]Add dataFileCreateTime node fail!", 72),
    0x3cf55c: ("【ERROR】data文件路径为空或解密失败！",
               "[ERR]Data path empty or decrypt fail!", 40),
    0x3cf584: ("【ERROR】data文件路径为空！",
               "[ERR]Data file path empty!", 28),
    0x3cf5a0: ("【ERROR】加密data文件路径失败！",
               "[ERR]Encrypt data file path fail!", 56),
    0x3cf5d8: ("【ERROR】查询试用版最后使用时间失败",
               "[ERR]Query trial last use time fail", 36),
    0x3cf5fc: ("【ERROR】记录的试用版最后使用时间为空",
               "[ERR]Trial last use time empty", 52),
    0x3cf630: ("【ERROR】记录的试用版是否可用值为空",
               "[ERR]Trial available value empty", 48),
    0x3cf660: ("【ERROR】查询试用版校验和失败",
               "[ERR]Query trial checksum fail", 32),
    0x3cf680: ("【ERROR】记录的试用版校验和为空",
               "[ERR]Trial checksum empty", 32),
    0x3cf6a0: ("【ERROR】最后使用时间为空！",
               "[ERR]Last use time empty!", 28),
    0x3cf6bc: ("【ERROR】添加trial节点失败！",
               "[ERR]Add trial node fail!", 32),
    0x3cf6dc: ("【ERROR】添加lastUsedTime节点失败！",
               "[ERR]Add lastUsedTime node fail!", 36),
    0x3cf700: ("【ERROR】试用版是否可用状态为空！",
               "[ERR]Trial available status null!", 36),
    0x3cf724: ("【ERROR】添加试用版是否可用状态节点失败！",
               "[ERR]Add trial status node fail!", 44),
    0x3cf750: ("【ERROR】试用版校验和为空！",
               "[ERR]Trial checksum null!", 28),
    0x3cf76c: ("【ERROR】添加校验和节点失败！",
               "[ERR]Add checksum node fail!", 48),
    0x3cf79c: ("【ERROR】读取注册表中的license失败！",
               "[ERR]Read license from registry fail!", 68),
    0x3cf7e0: ("【ERROR】读取注册表中的license注册时间失败！",
               "[ERR]Read license reg time from reg fail!", 60),
    0x3cf81c: ("【ERROR】查询注册版最后使用时间失败",
               "[ERR]Query reg last use time fail", 36),
    0x3cf840: ("【ERROR】记录的注册版最后使用时间为空",
               "[ERR]Reg last use time empty", 68),
    0x3cf884: ("【ERROR】读取注册表中的注册版可用月数失败！",
               "[ERR]Read reg valid months from reg fail!", 60),
    0x3cf8c0: ("【ERROR】历史license节点丢失！",
               "[ERR]Hist license node missing!", 40),
    0x3cf8e8: ("【ERROR】历史license子项信息丢失！",
               "[ERR]Hist license subitem missing!", 36),
    0x3cf90c: ("【ERROR】查询注册版校验和失败",
               "[ERR]Query reg checksum fail", 32),
    0x3cf92c: ("【ERROR】记录的注册版校验和为空",
               "[ERR]Reg checksum empty", 32),
    0x3cf94c: ("【ERROR】license为空",
               "[ERR]License empty", 24),
    0x3cf964: ("【ERROR】记录license到注册表失败",
               "[ERR]Record license to reg fail", 36),
    0x3cf988: ("【ERROR】license注册时间为空",
               "[ERR]License reg time empty", 32),
    0x3cf9a8: ("【ERROR】记录license注册时间到注册表失败",
               "[ERR]Record license reg time fail", 44),
    0x3cf9d4: ("【ERROR】添加licensed节点失败",
               "[ERR]Add licensed node fail", 32),
    0x3cf9f4: ("【ERROR】添加licensed最后使用时间节点失败",
               "[ERR]Add licensed last time node fail", 44),
    0x3cfa20: ("【ERROR】License可用月数为空",
               "[ERR]License valid months null", 32),
    0x3cfa40: ("【ERROR】记录License可用月数到注册表失败",
               "[ERR]Record License months to reg fail", 44),
    0x3cfa6c: ("【ERROR】历史license为空！",
               "[ERR]Hist license empty!", 28),
    0x3cfa88: ("【ERROR】添加历史license节点失败",
               "[ERR]Add hist license node fail", 36),
    0x3cfaac: ("【ERROR】添加历史license子项节点失败",
               "[ERR]Add hist license sub node fail", 40),
    0x3cfad4: ("【ERROR】license校验和为空！",
               "[ERR]License checksum null!", 32),
    0x3cfaf4: ("【ERROR】添加licensed校验和节点失败",
               "[ERR]Add licensed checksum node fail", 722),
}


# ============================================================
# Dialog resource parser/rebuilder (DLGTEMPLATEEX format)
# ============================================================

def align_to(value, alignment):
    """Align value up to the given alignment boundary."""
    return ((value + alignment - 1) // alignment) * alignment


def align4(offset):
    """Align offset to 4-byte boundary."""
    return align_to(offset, 4)


def read_word(data, offset):
    return struct.unpack_from('<H', data, offset)[0], offset + 2


def read_dword(data, offset):
    return struct.unpack_from('<I', data, offset)[0], offset + 4


def read_sz_or_ord(data, offset):
    """Read a sz_Or_Ord field (null-terminated string or ordinal)."""
    w = struct.unpack_from('<H', data, offset)[0]
    if w == 0x0000:
        return ('empty', ''), offset + 2
    elif w == 0xFFFF:
        ordinal = struct.unpack_from('<H', data, offset + 2)[0]
        return ('ord', ordinal), offset + 4
    else:
        end = offset
        while end < len(data) - 1:
            ch = struct.unpack_from('<H', data, end)[0]
            if ch == 0:
                break
            end += 2
        s = data[offset:end].decode('utf-16-le')
        return ('str', s), end + 2


def write_word(value):
    return struct.pack('<H', value)


def write_dword(value):
    return struct.pack('<I', value)


def write_sz_or_ord(kind, value):
    """Write a sz_Or_Ord field."""
    if kind == 'empty':
        return struct.pack('<H', 0)
    elif kind == 'ord':
        return struct.pack('<HH', 0xFFFF, value)
    else:  # 'str'
        return value.encode('utf-16-le') + b'\x00\x00'


def pad_to_align4(buf):
    """Pad buffer to 4-byte alignment."""
    remainder = len(buf) % 4
    if remainder:
        buf += b'\x00' * (4 - remainder)
    return buf


def parse_and_rebuild_dialog(data, translations):
    """Parse a DLGTEMPLATEEX dialog and rebuild with translated strings."""
    offset = 0

    # Read DLGTEMPLATEEX header
    dlg_ver, signature = struct.unpack_from('<HH', data, offset)
    offset += 4

    if dlg_ver != 1 or signature != 0xFFFF:
        raise ValueError("Not a DLGTEMPLATEEX resource")

    help_id, ex_style, style, cdit, x, y, cx, cy = struct.unpack_from(
        '<IIIHHHHH', data, offset)
    offset += 22

    # Menu
    menu, offset = read_sz_or_ord(data, offset)
    # Window class
    wclass, offset = read_sz_or_ord(data, offset)
    # Title
    title, offset = read_sz_or_ord(data, offset)

    # Translate title
    if title[0] == 'str' and title[1] in translations:
        title = ('str', translations[title[1]])

    # Font info (if DS_SETFONT=0x40 or DS_SHELLFONT=0x48)
    has_font = bool(style & 0x40)
    font_data = None
    if has_font:
        pointsize, weight, italic, charset = struct.unpack_from(
            '<HHBB', data, offset)
        offset += 6
        typeface, offset = read_sz_or_ord(data, offset)
        font_data = (pointsize, weight, italic, charset, typeface)

    # Parse items
    items = []
    for i in range(cdit):
        offset = align4(offset)

        item_help_id, item_ex_style, item_style, item_x, item_y, item_cx, item_cy, item_id = \
            struct.unpack_from('<IIIHHHHI', data, offset)
        offset += 24

        item_class, offset = read_sz_or_ord(data, offset)
        item_title, offset = read_sz_or_ord(data, offset)

        # Translate item title
        if item_title[0] == 'str' and item_title[1] in translations:
            item_title = ('str', translations[item_title[1]])

        extra_count, offset = read_word(data, offset)
        extra_data = b''
        if extra_count > 0:
            extra_data = data[offset:offset + extra_count]
            offset += extra_count

        items.append({
            'help_id': item_help_id,
            'ex_style': item_ex_style,
            'style': item_style,
            'x': item_x, 'y': item_y,
            'cx': item_cx, 'cy': item_cy,
            'id': item_id,
            'class': item_class,
            'title': item_title,
            'extra_count': extra_count,
            'extra_data': extra_data,
        })

    # Rebuild the dialog resource
    buf = bytearray()

    # Header
    buf += write_word(dlg_ver)
    buf += write_word(signature)
    buf += write_dword(help_id)
    buf += write_dword(ex_style)
    buf += write_dword(style)
    buf += write_word(cdit)
    buf += write_word(x)
    buf += write_word(y)
    buf += write_word(cx)
    buf += write_word(cy)

    # Menu, class, title
    buf += write_sz_or_ord(*menu)
    buf += write_sz_or_ord(*wclass)
    buf += write_sz_or_ord(*title)

    # Font
    if has_font:
        pointsize, weight, italic, charset, typeface = font_data
        buf += struct.pack('<HHBB', pointsize, weight, italic, charset)
        buf += write_sz_or_ord(*typeface)

    # Items
    for item in items:
        buf = pad_to_align4(buf)

        buf += write_dword(item['help_id'])
        buf += write_dword(item['ex_style'])
        buf += write_dword(item['style'])
        buf += write_word(item['x'])
        buf += write_word(item['y'])
        buf += write_word(item['cx'])
        buf += write_word(item['cy'])
        buf += write_dword(item['id'])

        buf += write_sz_or_ord(*item['class'])
        buf += write_sz_or_ord(*item['title'])

        buf += write_word(item['extra_count'])
        if item['extra_count'] > 0:
            buf += item['extra_data']

    return bytes(buf)


# ============================================================
# String table resource builder
# ============================================================

def parse_string_table(data):
    """Parse a string table block (16 strings)."""
    strings = {}
    offset = 0
    for i in range(16):
        if offset + 2 > len(data):
            break
        length = struct.unpack_from('<H', data, offset)[0]
        offset += 2
        if length > 0:
            s = data[offset:offset + length * 2].decode('utf-16-le',
                                                         errors='replace')
            strings[i] = s
            offset += length * 2
        else:
            strings[i] = ''
    return strings


def build_string_table(strings, block_id, translations):
    """Build a string table block with translations applied."""
    buf = bytearray()
    for i in range(16):
        string_id = (block_id - 1) * 16 + i
        s = strings.get(i, '')
        if string_id in translations:
            s = translations[string_id]
        encoded = s.encode('utf-16-le')
        buf += struct.pack('<H', len(s))
        buf += encoded
    return bytes(buf)


# ============================================================
# PE resource patching
# ============================================================

def find_rsrc_section(pe):
    for s in pe.sections:
        if b'.rsrc' in s.Name:
            return s
    raise ValueError("No .rsrc section found")


def find_reloc_section(pe):
    for s in pe.sections:
        if b'.reloc' in s.Name:
            return s
    return None


def patch_rdata_strings(file_data):
    """Patch hardcoded UTF-16LE strings in the .rdata section."""
    count = 0

    # Patch individual strings
    for offset, (chinese, english, max_bytes) in RDATA_TRANSLATIONS.items():
        cn_encoded = chinese.encode('utf-16-le')
        en_encoded = english.encode('utf-16-le') + b'\x00\x00'

        # Verify the Chinese string is at the expected offset
        if file_data[offset:offset + len(cn_encoded)] != cn_encoded:
            print(f"  WARNING: Expected '{chinese}' at 0x{offset:x}, skipping")
            continue

        if len(en_encoded) > max_bytes:
            print(f"  WARNING: '{english}' too long for 0x{offset:x}, skipping")
            continue

        # Write English string and zero-fill remaining space
        file_data[offset:offset + max_bytes] = (
            en_encoded + b'\x00' * (max_bytes - len(en_encoded)))
        count += 1

    # Patch notice text
    nt = NOTICE_TRANSLATION
    cn_encoded = nt["chinese"].encode('utf-16-le')
    en_encoded = nt["english"].encode('utf-16-le') + b'\x00\x00'
    off = nt["offset"]

    if file_data[off:off + len(cn_encoded)] == cn_encoded:
        if len(en_encoded) <= nt["max_bytes"]:
            file_data[off:off + nt["max_bytes"]] = (
                en_encoded + b'\x00' * (nt["max_bytes"] - len(en_encoded)))
            count += 1
        else:
            print(f"  WARNING: Notice translation too long, skipping")
    else:
        print(f"  WARNING: Notice text not found at 0x{off:x}, skipping")

    print(f"  Patched {count} .rdata strings")


def patch_rdata_gbk_strings(file_data):
    """Patch hardcoded GBK-encoded strings in the .rdata section."""
    count = 0

    for offset, (chinese, english, max_bytes) in GBK_RDATA_TRANSLATIONS.items():
        cn_encoded = chinese.encode('gbk')
        en_encoded = english.encode('gbk') + b'\x00'

        if file_data[offset:offset + len(cn_encoded)] != cn_encoded:
            print(f"  WARNING: Expected GBK '{chinese}' at 0x{offset:x}, skipping")
            continue

        if len(en_encoded) > max_bytes:
            print(f"  WARNING: GBK '{english}' too long for 0x{offset:x}, skipping")
            continue

        file_data[offset:offset + max_bytes] = (
            en_encoded + b'\x00' * (max_bytes - len(en_encoded)))
        count += 1

    print(f"  Patched {count} .rdata GBK strings")


def patch_pe_resources(input_path, output_path):
    """Main function to patch PE resources with translations."""
    pe = pefile.PE(input_path)
    file_data = bytearray(pe.__data__)

    # Patch hardcoded strings in .rdata section first
    patch_rdata_strings(file_data)
    patch_rdata_gbk_strings(file_data)

    rsrc = find_rsrc_section(pe)
    reloc = find_reloc_section(pe)

    # Calculate how much additional space we need
    # First, build all translated resources and measure their sizes
    new_resources = {}  # (type_id, res_id, lang_id) -> new_data

    # Process dialog resources
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id == 5:  # RT_DIALOG
            for sub in entry.directory.entries:
                dialog_id = sub.id
                if dialog_id not in DIALOG_TRANSLATIONS:
                    continue
                for lang in sub.directory.entries:
                    rva = lang.data.struct.OffsetToData
                    size = lang.data.struct.Size
                    data = pe.get_data(rva, size)
                    new_data = parse_and_rebuild_dialog(
                        data, DIALOG_TRANSLATIONS[dialog_id])
                    new_resources[(5, dialog_id, lang.id)] = {
                        'data': new_data,
                        'old_size': size,
                        'struct_offset': lang.data.struct.get_file_offset(),
                        'old_rva': rva,
                    }
                    print(f"  Dialog {dialog_id}: {size} -> {len(new_data)} bytes")

    # Process string table resources
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        if entry.id == 6:  # RT_STRING
            for sub in entry.directory.entries:
                for lang in sub.directory.entries:
                    rva = lang.data.struct.OffsetToData
                    size = lang.data.struct.Size
                    data = pe.get_data(rva, size)
                    strings = parse_string_table(data)
                    new_data = build_string_table(
                        strings, sub.id, STRING_TABLE_TRANSLATIONS)
                    new_resources[(6, sub.id, lang.id)] = {
                        'data': new_data,
                        'old_size': size,
                        'struct_offset': lang.data.struct.get_file_offset(),
                        'old_rva': rva,
                    }
                    print(f"  String block {sub.id}: {size} -> {len(new_data)} bytes")

    # Calculate total extra space needed for resources that must be relocated
    extra_needed = 0
    for key, res in new_resources.items():
        if len(res['data']) > res['old_size']:
            # Full size needed (old space is abandoned)
            extra_needed += len(res['data'])
            extra_needed += 4  # alignment padding

    # Round up to file alignment (512)
    file_align = pe.OPTIONAL_HEADER.FileAlignment
    extra_alloc = align_to(extra_needed, file_align)
    if extra_alloc == 0:
        extra_alloc = file_align  # minimum one block

    print(f"\n  Extra space needed: {extra_needed} bytes, allocating: {extra_alloc} bytes")

    # Check if we can fit within existing virtual space
    rsrc_virt_end = rsrc.VirtualAddress + rsrc.Misc_VirtualSize
    sect_align = pe.OPTIONAL_HEADER.SectionAlignment
    next_section_va = align_to(rsrc_virt_end, sect_align)
    available_virtual = next_section_va - rsrc.VirtualAddress - rsrc.SizeOfRawData
    print(f"  Available virtual padding: {available_virtual} bytes")

    if extra_alloc > available_virtual:
        print(f"  Need to expand .rsrc section in file")

    # Strategy: Expand the .rsrc section's raw data and shift .reloc forward
    rsrc_file_end = rsrc.PointerToRawData + rsrc.SizeOfRawData
    reloc_file_start = reloc.PointerToRawData if reloc else len(file_data)

    # Insert extra_alloc bytes before .reloc
    new_file_data = bytearray()
    new_file_data += file_data[:rsrc_file_end]
    new_file_data += b'\x00' * extra_alloc
    new_file_data += file_data[reloc_file_start:]

    # Update .rsrc section header
    new_rsrc_raw_size = rsrc.SizeOfRawData + extra_alloc
    new_rsrc_virt_size = rsrc.Misc_VirtualSize + extra_alloc

    # Patch section header for .rsrc
    rsrc_header_offset = rsrc.get_file_offset()
    # SizeOfRawData is at offset 16 in section header
    struct.pack_into('<I', new_file_data, rsrc_header_offset + 16,
                     new_rsrc_raw_size)
    # Misc_VirtualSize is at offset 8
    struct.pack_into('<I', new_file_data, rsrc_header_offset + 8,
                     new_rsrc_virt_size)

    # Update .reloc section header (PointerToRawData shifted)
    if reloc:
        reloc_header_offset = reloc.get_file_offset()
        new_reloc_raw_offset = reloc.PointerToRawData + extra_alloc
        struct.pack_into('<I', new_file_data, reloc_header_offset + 20,
                         new_reloc_raw_offset)

    # Update SizeOfImage in optional header
    # Need to recalculate based on new virtual sizes
    new_rsrc_virt_aligned = align_to(new_rsrc_virt_size, sect_align)
    old_rsrc_virt_aligned = align_to(rsrc.Misc_VirtualSize, sect_align)
    image_size_delta = new_rsrc_virt_aligned - old_rsrc_virt_aligned

    if image_size_delta > 0:
        # Need to shift .reloc virtual address too
        if reloc:
            new_reloc_va = reloc.VirtualAddress + image_size_delta
            struct.pack_into('<I', new_file_data, reloc_header_offset + 12,
                             new_reloc_va)

            # Update data directory for relocations
            dd_offset = pe.OPTIONAL_HEADER.get_file_offset()
            reloc_dd_offset = (dd_offset + DATA_DIRECTORY_OFFSET +
                               BASE_RELOCATION_INDEX * 8)
            struct.pack_into('<I', new_file_data, reloc_dd_offset,
                             new_reloc_va)

        # Update SizeOfImage
        size_of_image_offset = (pe.OPTIONAL_HEADER.get_file_offset() +
                                SIZE_OF_IMAGE_OFFSET)
        new_size_of_image = pe.OPTIONAL_HEADER.SizeOfImage + image_size_delta
        struct.pack_into('<I', new_file_data, size_of_image_offset,
                         new_size_of_image)

    # Now place translated resource data in the new free space
    # New data goes at the end of the original .rsrc raw data
    new_data_file_offset = rsrc_file_end  # start of newly allocated space
    new_data_rva = rsrc.VirtualAddress + rsrc.SizeOfRawData  # RVA of new space

    for key, res in new_resources.items():
        new_data = res['data']

        if len(new_data) <= res['old_size']:
            # Fits in place - write at original location
            old_file_offset = pe.get_offset_from_rva(res['old_rva'])
            new_file_data[old_file_offset:old_file_offset + len(new_data)] = new_data
            # Zero-fill remaining space
            remaining = res['old_size'] - len(new_data)
            if remaining > 0:
                new_file_data[old_file_offset + len(new_data):
                              old_file_offset + res['old_size']] = b'\x00' * remaining

            # Update size in resource data entry
            struct_off = res['struct_offset']
            struct.pack_into('<I', new_file_data, struct_off + 4,
                             len(new_data))
        else:
            # Doesn't fit - place in new area
            # Align to 4 bytes
            if new_data_file_offset % 4:
                pad = 4 - (new_data_file_offset % 4)
                new_data_file_offset += pad
                new_data_rva += pad

            new_file_data[new_data_file_offset:
                          new_data_file_offset + len(new_data)] = new_data

            # Update resource data entry: OffsetToData (RVA) and Size
            struct_off = res['struct_offset']
            struct.pack_into('<I', new_file_data, struct_off, new_data_rva)
            struct.pack_into('<I', new_file_data, struct_off + 4,
                             len(new_data))

            new_data_file_offset += len(new_data)
            new_data_rva += len(new_data)

    # Update RESOURCE data directory size
    dd_offset = pe.OPTIONAL_HEADER.get_file_offset()
    rsrc_dd_offset = dd_offset + DATA_DIRECTORY_OFFSET + RESOURCE_INDEX * 8
    struct.pack_into('<I', new_file_data, rsrc_dd_offset + 4,
                     new_rsrc_virt_size)

    # Write the modified PE, then fix checksum
    with open(output_path, 'wb') as f:
        f.write(new_file_data)

    # Reopen and fix checksum
    pe_out = pefile.PE(output_path)
    pe_out.OPTIONAL_HEADER.CheckSum = pe_out.generate_checksum()
    pe_out.write(output_path)

    print(f"\n  Translated PE written to: {output_path}")
    print(f"  Original size: {len(file_data)} bytes")
    print(f"  New size: {len(new_file_data)} bytes")


def main():
    if len(sys.argv) != 3:
        print(f"Usage: {sys.argv[0]} <input.exe> <output.exe>")
        sys.exit(1)

    input_path = sys.argv[1]
    output_path = sys.argv[2]

    print("Translating ONT tool from Chinese to English...")
    patch_pe_resources(input_path, output_path)
    print("Done!")


if __name__ == '__main__':
    main()
