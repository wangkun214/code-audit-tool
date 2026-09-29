# -*- coding: utf-8 -*-
"""离线自检：规则语义夹具 + 行号一致性不变量（无需启动服务）。

    python ruletest.py                 # 只跑内置夹具
    python ruletest.py <目录> [规则ID]  # 额外统计该目录的规则命中分布
"""
from __future__ import annotations

import os
import re
import shutil
import sys
import tempfile
from collections import Counter

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.engine import AuditEngine, read_text   # noqa: E402
from core.rules import RULES                     # noqa: E402

PASS, FAIL = [], []


def check(name, cond, extra=""):
    (PASS if cond else FAIL).append(name)
    mark = "\033[32mPASS\033[0m" if cond else "\033[31mFAIL\033[0m"
    print(f"  {mark}  {name}" + (f"  — {extra}" if extra else ""))
    return cond


# =================================================================== 规则夹具
# SEC-KEY-004：覆盖 SEC-KEY-001 的盲区（未加引号的配置项凭据）。
# 每项 (行文本, 是否应命中, 说明)。判定复用引擎的 excludes / 注释行语义。
KEY004_CASES = [
    # ---------------- 正样本：真实凭据特征，必须命中 ----------------
    ("spring.datasource.password=Plaintext99",        True, "properties 明文口令"),
    ("DB_PASSWORD=Adm1nP@ssw0rd",                     True, ".env 未加引号口令（含 @）"),
    ("api_key: 9f8a7b6C5d4E3f2A",                     True, "yaml 未加引号 api_key"),
    ("secretKey=Zx9Kq2Wm7Lp4",                        True, "驼峰键名 + 混合字符"),
    ("  jwt_secret = Tk8Ln3Qw9Zx2",                   True, "缩进 + 空格分隔"),
    ("aws_secret_access_key=wJalrXUtnFEMI7K7MDENG",   True, "AWS SecretKey（非 EXAMPLE 占位）"),
    ("REDIS_AUTH_TOKEN=Nz8Xq2Lm9Wy4Kd",               True, "全大写键名 + token"),
    ("export DB_PASS=Qw3Er5Ty7Ui9",                   True, "shell export 前缀"),
    ("client_secret: Ab3Cd5Ef7Gh9",                   True, "OAuth client_secret"),
    ("private_key=MIICdg9K8Lm2Np4Q",                  True, "私钥片段"),
    ("enn.gateway.SecretKey=ek1SaFJ2SlJ0dnJwbmRUdTY1", True, "网关密钥（真实样本形态）"),
    # ---------------- 负样本：必须静默 ----------------
    ("spring.datasource.password=${DB_PASSWORD}",     False, "占位符引用（归配置注入）"),
    ('password = os.getenv("DB_PASSWORD")',           False, "环境变量读取"),
    ("password = getPassword1()",                     False, "函数调用取值"),
    ('password = "Str0ngPassw0rd"',                   False, "带引号 -> 归 SEC-KEY-001"),
    ("# DB_PASSWORD=OldValue99",                      False, "注释行"),
    ("password: String",                              False, "类型名"),
    ("password = changeme",                           False, "占位符 changeme"),
    ("api_key = your_api_key_here",                   False, "占位符 your_"),
    ("secret = XXXXXXXXXX",                           False, "掩码"),
    ("private_key = <YOUR_KEY_HERE>",                 False, "尖括号占位"),
    ("password = none",                               False, "空值语义词"),
    ("apiToken = this.props.apiToken",                False, "属性取值（非字面量）"),
    ("password = process.env.DB_PASS2",               False, "Node 环境变量（含 . 属性链）"),
    ("password = MD5('123456')",                      False, "SQL 表达式"),
    ("password_hash = 5f4dcc3b5aa765d6",              False, "纯十六进制哈希（无大写，主动取舍）"),
    ("password = hunter2",                            False, "过短且无大写"),
    ("secret: some_plain_words_only",                 False, "纯小写长词"),
    ('--password="Quoted1"',                          False, "命令行带引号"),
    ("const adminPassword = config.value",            False, "变量赋值（非字面量）"),
]


def test_rule_fixtures():
    print("\n[1] 规则夹具：SEC-KEY-004（未加引号的配置项凭据）")
    rule = next((r for r in RULES if r["id"] == "SEC-KEY-004"), None)
    if not check("规则 SEC-KEY-004 已注册", rule is not None):
        return
    pat = re.compile(rule["pattern"])
    exc = [re.compile(e) for e in rule.get("excludes", [])]

    def judge(line):
        if not pat.search(line):
            return False
        if any(e.search(line) for e in exc):
            return False
        return not line.strip().startswith(("//", "*", "#!"))

    bad = [c for c in KEY004_CASES if judge(c[0]) != c[1]]
    for line, want, note in KEY004_CASES:
        ok = judge(line) == want
        print(f"    {'·' if ok else '×'} {'命中' if want else '静默'}  {note}")
    check("正负样本全部判定正确",
          not bad, f"{len(KEY004_CASES) - len(bad)}/{len(KEY004_CASES)} 项"
                   + (f"，失败：{bad[0][2]}" if bad else ""))


# ============================================================== 行号一致性
SEP, LS, FF, CR = "\u0085", "\u2028", "\x0c", "\r"
LINENO_BODY = [
    ("# 模拟被错误转码的文件头", False),
    ("server.port=8080" + SEP, False),
    ("spring.datasource.driver=com.mysql.cj.jdbc.Driver" + SEP, False),
    ("cache.enabled=true", False),
    ("# 下面这行才是真正的凭据", False),
    ('spring.datasource.password="R3alS3cretPwd"', True),
    ("logging.level.root=INFO" + LS, False),
    ("cache.timeout=3600" + FF, False),
    ("app.name=demo-service", False),
    ('api.secret="AbCdEf123456"', True),
    ("redis.auth.password=ReD1sPwd99", True),
    ("last.line=ok" + CR, False),
]


def _scan_dir(root, files, title):
    for rel, data in files.items():
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data)
    eng = AuditEngine(root)
    eng.scan()

    want = sum(1 for _, h in LINENO_BODY if h)
    ok = check(f"{title}：命中 {want} 条", len(eng.findings) == want,
               f"实际 {len(eng.findings)} 条")
    # 不变量①：FileEntry.lines 与 count("\n")+1 一致
    for fe in eng.files:
        c, _ = read_text(os.path.join(root, fe.rel))
        if fe.lines != c.count("\n") + 1:
            ok = False
            print(f"      × {fe.rel} lines={fe.lines} != count(\\n)+1={c.count(chr(10)) + 1}")
    # 不变量②：报告行号取回的文本 == 命中的 code
    # 不变量③：snippet 高亮行号 == 命中行号
    for f in eng.findings:
        c, _ = read_text(os.path.join(root, f["file"]))
        norm = c.split("\n")
        ln = f["line"]
        actual = norm[ln - 1].strip() if 0 < ln <= len(norm) else "<越界>"
        marked = [s["n"] for s in f["snippet"] if s["hit"]]
        if actual != f["code"]:
            ok = False
            print(f"      × {f['file']}:{ln} code={f['code'][:40]!r} 该行实际={actual[:40]!r}")
        if marked != [ln]:
            ok = False
            print(f"      × snippet 高亮错位 {marked} != [{ln}]")
    check(f"{title}：行号 / 片段 / 高亮三者一致", ok,
          f"{len(eng.findings)} 条命中，{len(eng.files)} 个文件")


def test_line_numbers():
    print("\n[2] 行号一致性（NEL/LS/FF/CR 异形换行不得导致错位）")
    tmp = tempfile.mkdtemp(prefix="audit_line_")
    try:
        body = "\n".join(t for t, _ in LINENO_BODY).encode("utf-8")
        _scan_dir(os.path.join(tmp, "lf"), {"application.properties": body},
                  "LF 主体 + 行内异形字符（行号须与编辑器一致）")
        nel = ("\n".join(t for t, _ in LINENO_BODY).replace("\n", SEP) + "\n").encode("utf-8")
        _scan_dir(os.path.join(tmp, "nel"), {"only-nel.properties": nel},
                  "全文仅用 NEL 分行（须回落为换行）")
        crlf = ("\r\n".join(t for t, _ in LINENO_BODY)).encode("utf-8")
        _scan_dir(os.path.join(tmp, "crlf"), {"win.properties": crlf}, "标准 CRLF 文件")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def report_dir(target, focus=""):
    print(f"\n[3] 目录命中分布：{target}")
    eng = AuditEngine(target)
    eng.scan()
    by_rule = Counter(f["rule_id"] for f in eng.findings)
    print(f"    文件 {len(eng.files)} | 命中 {len(eng.findings)} | "
          f"降噪抑制 {eng.suppressed} | 耗时 {eng.elapsed}s")
    for rid, c in sorted(by_rule.items(), key=lambda kv: -kv[1])[:24]:
        print(f"      {rid:<20}{c:>5}" + ("   <== 关注" if rid == focus else ""))
    if focus:
        hits = [f for f in eng.findings if f["rule_id"] == focus]
        print(f"    [{focus}] 明细 {len(hits)} 条：")
        for f in hits[:60]:
            print(f"      {f['file']}:{f['line']}  {f['code'][:96]}")
        if len(hits) > 60:
            print(f"      … 其余 {len(hits) - 60} 条省略")


if __name__ == "__main__":
    print("=" * 74)
    print("  源代码静态审计平台 · 离线规则与引擎自检")
    print("=" * 74)
    test_rule_fixtures()
    test_line_numbers()
    if len(sys.argv) > 1:
        report_dir(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "")
    print("\n" + "=" * 74)
    print(f"  结果：\033[32m{len(PASS)} 项通过\033[0m"
          + (f"，\033[31m{len(FAIL)} 项失败\033[0m" if FAIL else "，全部通过 ✓"))
    for f in FAIL:
        print("   - 失败：", f)
    print("=" * 74)
    sys.exit(1 if FAIL else 0)
