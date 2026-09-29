# -*- coding: utf-8 -*-
"""文本读取与换行归一（单一来源）。

引擎与依赖清单解析都依赖"行号 == 编辑器行号"这一不变量，因此把读取逻辑收敛到
本模块，避免两处各写一份、各自漂移。
"""
from __future__ import annotations

import re

MAX_FILE_SIZE = 2 * 1024 * 1024        # 单文件最大读取 2MB
READ_ENCODINGS = ("utf-8", "utf-8-sig", "gb18030", "latin-1")

# 编辑器（VS Code / Notepad++ / IDE）的行模型只认 \n、\r\n、\r
_CR_RE = re.compile(r"\r\n?")
# 少数环境用异形行分隔符；仅当文件完全没有 CR/LF 时才把它们视作换行
_EXOTIC = ("\x0b", "\x0c", "\x1c", "\x1d", "\x1e", "\x85", "\u2028", "\u2029")


def normalize_newlines(text: str) -> str:
    """归一换行：CRLF/CR -> LF。

    异形行分隔符（NEL / LS / PS / VT / FF）默认保留为行内字符，以保证行号与
    用户编辑器一致。只有当这些字符明显构成该文件的主要分行方式时，才把它们
    转成 LF——否则整个文件会被当成一行，扫描结果完全不可用。
    """
    text = _CR_RE.sub("\n", text)
    lf = text.count("\n")
    exotic = sum(text.count(ch) for ch in _EXOTIC)
    if exotic >= 2 and exotic > lf:
        for ch in _EXOTIC:
            if ch in text:
                text = text.replace(ch, "\n")
    return text


def read_text(abs_path: str, max_size: int = MAX_FILE_SIZE):
    """安全读取文本文件，返回 (内容, 编码)。

    内容是换行归一后的结果，这是行号正确性的前提：调用方用 content.count("\\n")
    算行号、用 content.split("\\n") 取行文本；若改用 str.splitlines()，它会把
    \\x85(NEL)、\\u2028、\\x0b 也当换行，与 count("\\n") 分叉。实测在
    application.properties 上偏移 4 行——点开漏洞行看到的是无关代码。
    """
    try:
        with open(abs_path, "rb") as f:
            raw = f.read(max_size + 1)
    except (OSError, PermissionError):
        return None, None
    truncated = len(raw) > max_size
    if truncated:
        raw = raw[:max_size]
    if b"\x00" in raw[:4096]:
        return None, None            # 二进制文件
    for enc in READ_ENCODINGS:
        try:
            return normalize_newlines(raw.decode(enc)), enc
        except UnicodeDecodeError:
            continue
    return normalize_newlines(raw.decode("utf-8", errors="replace")), "utf-8(replace)"
