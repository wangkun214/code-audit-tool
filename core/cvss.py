# -*- coding: utf-8 -*-
"""CVSS 基础分计算（纯标准库）。

为什么自己算而不用现成库：本项目坚持零第三方依赖。OSV 记录里给的是 **CVSS 向量**
（如 `CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`），要拿到可比大小的分数就要按
规范算基础分。实现依据 FIRST 官方规范（CVSS v3.1 / v2.0）。

未实现 CVSS v4.0：v4 的分值依赖 MacroVector 查找表，体积与出错风险都不划算。
遇到只有 V4 向量的记录时，退回使用数据库自带的文本等级（CRITICAL/HIGH/…），
并在结果里标注 severity_source，让用户知道这一条的等级不是算出来的。
"""
from __future__ import annotations

import math
import re

# ---------------------------------------------------------------- CVSS v3.0/3.1
_AV3 = {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.20}
_AC3 = {"L": 0.77, "H": 0.44}
_PR3_U = {"N": 0.85, "L": 0.62, "H": 0.27}     # 作用域不变
_PR3_C = {"N": 0.85, "L": 0.68, "H": 0.50}     # 作用域改变
_UI3 = {"N": 0.85, "R": 0.62}
_CIA3 = {"H": 0.56, "L": 0.22, "N": 0.0}

# -------------------------------------------------------------------- CVSS v2.0
_AV2 = {"L": 0.395, "A": 0.646, "N": 1.0}
_AC2 = {"H": 0.35, "M": 0.61, "L": 0.71}
_AU2 = {"M": 0.45, "S": 0.56, "N": 0.704}
_CIA2 = {"N": 0.0, "P": 0.275, "C": 0.660}


def _roundup(value: float) -> float:
    """CVSS v3 规范的 Roundup：向上取整到 1 位小数。"""
    i = int(round(value * 100000))
    if i % 10000 == 0:
        return i / 100000.0
    return (math.floor(i / 10000) + 1) / 10.0


def _metrics(vector: str) -> dict:
    parts = (vector or "").split("/")
    if parts and parts[0].upper().startswith("CVSS:"):
        parts = parts[1:]
    out = {}
    for p in parts:
        if ":" in p:
            k, v = p.split(":", 1)
            out[k.strip().upper()] = v.strip().upper()
    return out


def cvss3_base_score(vector: str):
    """CVSS v3.0 / v3.1 基础分；向量非法返回 None。"""
    if not vector or "cvss:3" not in vector.lower():
        return None
    d = _metrics(vector)
    scope_changed = d.get("S") == "C"
    try:
        av, ac = _AV3[d["AV"]], _AC3[d["AC"]]
        pr = (_PR3_C if scope_changed else _PR3_U)[d["PR"]]
        ui = _UI3[d["UI"]]
        c, i, a = _CIA3[d["C"]], _CIA3[d["I"]], _CIA3[d["A"]]
    except KeyError:
        return None
    iss = 1 - (1 - c) * (1 - i) * (1 - a)
    impact = (7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15) if scope_changed else 6.42 * iss
    exploitability = 8.22 * av * ac * pr * ui
    if impact <= 0:
        return 0.0
    raw = min((1.08 if scope_changed else 1.0) * (impact + exploitability), 10.0)
    return _roundup(raw)


def cvss2_base_score(vector: str):
    """CVSS v2.0 基础分；向量非法返回 None。

    注意：OSV/NVD 的 CVSS_V2 向量通常**不带** `CVSS:2.0/` 前缀
    （形如 `AV:N/AC:L/Au:N/C:P/I:P/A:P`），所以这里两种形态都要认。
    """
    v = (vector or "").strip()
    if not v:
        return None
    if not v.lower().replace(" ", "").startswith("cvss:2") and not is_v2_vector(v):
        return None
    d = _metrics(v)
    try:
        c, i, a = _CIA2[d["C"]], _CIA2[d["I"]], _CIA2[d["A"]]
        impact = 10.41 * (1 - (1 - c) * (1 - i) * (1 - a))
        exploitability = 20 * _AV2[d["AV"]] * _AC2[d["AC"]] * _AU2[d["AU"]]
    except KeyError:
        return None
    f_impact = 0.0 if impact == 0 else 1.176
    score = ((0.6 * impact) + (0.4 * exploitability) - 1.5) * f_impact
    return max(0.0, min(10.0, round(score, 1)))


def base_score(vector: str):
    """按向量形态自动选择 v3 / v2，返回 (分数, 版本标记)。

    v3 必须带 `CVSS:3.x/` 前缀；v2 允许无前缀（OSV/NVD 的常态），
    以 v2 独有的 `Au:` 度量作为判别依据，避免与 v3 的 `PR:`/`UI:` 混淆。
    """
    low = (vector or "").lower().replace(" ", "")
    if low.startswith("cvss:3"):
        return cvss3_base_score(vector), "CVSS_V3"
    if low.startswith("cvss:2") or is_v2_vector(vector):
        return cvss2_base_score(vector), "CVSS_V2"
    return None, ""


def score_to_severity(score) -> str:
    """CVSS 分数 -> 本项目等级（与规则引擎一致：critical/high/medium/low/info）。"""
    if score is None:
        return ""
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0:
        return "low"
    return "info"


# 各数据库的文本等级 -> 本项目等级
TEXT_SEVERITY = {
    "CRITICAL": "critical",
    "HIGH": "high",
    "IMPORTANT": "high",
    "MODERATE": "medium",
    "MEDIUM": "medium",
    "LOW": "low",
    "MINOR": "low",
    "UNKNOWN": "info",
    "INFORMATIONAL": "info",
    "NONE": "info",
}


def text_to_severity(text) -> str:
    if not text:
        return ""
    return TEXT_SEVERITY.get(str(text).strip().upper(), "")


_LEVEL_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def rank(severity: str) -> int:
    return _LEVEL_RANK.get(severity, 9)


def is_cvss_vector(text: str) -> bool:
    """是否为可识别的 CVSS 向量（v3 带前缀；v2 允许无前缀）。"""
    t = (text or "").strip()
    if re.match(r"^\s*CVSS:", t, re.I):
        return True
    return bool(is_v2_vector(t))


# v2 向量的度量顺序是固定的：AV/AC/Au/C/I/A。按这个强模式识别，
# 既兼容无前缀写法，又能可靠排除 v3（v3 没有 Au:，是 PR:/UI:）。
_V2_RE = re.compile(r"^AV:[NAL]/AC:[HML]/AU:[MSN]/C:[NPC]/I:[NPC]/A:[NPC]"
                    r"(/[^/\s]+)*\s*$", re.I)


def is_v2_vector(text: str) -> bool:
    return bool(_V2_RE.match((text or "").strip()))
