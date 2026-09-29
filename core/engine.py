# -*- coding: utf-8 -*-
"""
静态审计引擎：文件遍历 -> 语言识别 -> 规则匹配 -> 上下文降噪 -> 风险评级。
"""
from __future__ import annotations

import math
import os
import re
import threading
import time
from collections import Counter, defaultdict

from . import manifests
from .rules import (
    BINARY_EXT, CATEGORY_META, DEFAULT_EXCLUDES, EXT_LANG, FILENAME_LANG,
    RULES, SEVERITY_META, SEVERITY_ORDER,
)
# 读取与换行归一收敛在 core/textio.py —— 行号不变量（行号 == 编辑器行号）的唯一来源，
# 依赖清单解析必须共用同一套读取逻辑，故不在此处重新实现。
from .textio import MAX_FILE_SIZE, normalize_newlines, read_text  # noqa: F401

MAX_SCAN_FILES = 20000                  # 单次扫描文件数上限
SNIPPET_PAD = 3                         # 命中行上下文行数
RISK_HALF_SCALE = 3000.0                # 风险指数饱和尺度（W 达到该值时指数约 63）

# 测试/示例代码路径（命中则风险等级自动下调一级）
TEST_PATH_RE = re.compile(
    r"(?i)(^|/)(test[^/]*|mock[^/]*|fake[^/]*|stub[^/]*|fixture[^/]*|sample[^/]*|example[^/]*"
    r"|e2e|integration|__tests__|golden|dbtest|gittest|testutil)(/|$)"
    r"|_test\.(go|py|rb|java|cs|php)$"
    r"|\.(test|spec)\.[jt]sx?$"
)
# 文档路径（命中则降为「提示」级，文档中的示例密钥需人工确认）
DOC_PATH_RE = re.compile(r"(?i)\.(md|markdown|rst|adoc|txt)$|(^|/)docs?(/)")

_SEV_FALLBACK = {"high": "medium", "medium": "low", "low": "low"}   # 置信度降级映射

# 预编译规则。
# 全部正则统一加 re.M：pattern/excludes/guard/suppress_if 中的 ^ $ 一律按「行」锚定。
# 否则 ^ 只匹配文件首行（如 CFG-CI-001 的缩进键、SEC-KEY-004 的注释行排除将静默失效）。
# 规则内联的 (?m) 与此等价，不受影响。
_COMPILED = []
for _r in RULES:
    _COMPILED.append({
        "rule": _r,
        "re": re.compile(_r["pattern"], re.M),
        "excludes": [re.compile(e, re.M) for e in _r.get("excludes", [])],
        "path_exclude": re.compile(_r["path_exclude"]) if _r.get("path_exclude") else None,
        "guard": (re.compile(_r["guard"]["pattern"], re.M), _r["guard"].get("window", 6)) if _r.get("guard") else None,
        "suppress_if": re.compile(_r["suppress_if"], re.M) if _r.get("suppress_if") else None,
    })

# 同行冲突合并的择优顺序：severity 降序 -> confidence 降序 -> id 字典序。
# 与 rules.py 头部「规则优先级与冲突处理策略」第 2 条一一对应，修改时须同步。
_CONF_RANK = {"high": 0, "medium": 1, "low": 2}


def _better_hit(a, b):
    """返回两命中中应保留者（按冲突策略择优）。"""
    ka = (SEVERITY_ORDER.index(a["rule"]["severity"]),
          _CONF_RANK.get(a["rule"]["confidence"], 3), a["rule"]["id"])
    kb = (SEVERITY_ORDER.index(b["rule"]["severity"]),
          _CONF_RANK.get(b["rule"]["confidence"], 3), b["rule"]["id"])
    return a if ka <= kb else b


def detect_language(path: str) -> str | None:
    """根据文件名/扩展名识别语言。"""
    name = os.path.basename(path).lower()
    if name in FILENAME_LANG:
        return FILENAME_LANG[name]
    if name.startswith("dockerfile") or name.endswith(".dockerfile"):
        return "dockerfile"
    ext = os.path.splitext(name)[1]
    return EXT_LANG.get(ext)


# 读取与换行归一收敛在 core/textio.py —— 行号不变量(行号==编辑器行号)的唯一来源，
# 依赖清单解析也必须用同一套读取逻辑，故不在此处重复实现。


class FileEntry:
    __slots__ = ("rel", "abs", "size", "lang", "lines")

    def __init__(self, rel, abs_path, size, lang, lines):
        self.rel = rel
        self.abs = abs_path
        self.size = size
        self.lang = lang
        self.lines = lines

    def to_dict(self):
        return {
            "path": self.rel, "size": self.size,
            "lang": self.lang, "lines": self.lines,
        }


class AuditEngine:
    """单次扫描任务的状态容器与执行器。"""

    def __init__(self, root: str, excludes=None, severities=None,
                 categories=None, max_files=None):
        self.root = os.path.abspath(root)
        self.excludes = set(excludes or DEFAULT_EXCLUDES)
        self.severities = set(severities) if severities else set(SEVERITY_ORDER)
        self.categories = set(categories) if categories else set(CATEGORY_META)
        self.max_files = max_files or MAX_SCAN_FILES

        self.files: list[FileEntry] = []
        self.findings: list[dict] = []
        self.suppressed = 0
        self.conflict_dropped = 0   # 同行跨规则冲突中被择优淘汰的命中数
        self.total_lines = 0
        self.lang_stat = Counter()
        self.start_time = 0.0
        self.elapsed = 0.0
        self.deps: list[dict] = []
        self.deps_meta: dict = {}

        # 进度
        self.progress = {"phase": "pending", "current": 0, "total": 0,
                         "file": "", "done": False, "error": None}

    # ------------------------------------------------------------------ 遍历
    def _is_excluded(self, rel_path: str) -> bool:
        parts = rel_path.replace("\\", "/").split("/")
        for p in parts[:-1]:
            if p in self.excludes:
                return True
            if p.startswith(".") and p not in (".github",):
                return True
        if parts and parts[-1] in self.excludes:
            return True
        return False

    def walk(self):
        root = self.root
        scanned = 0
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames
                           if d not in self.excludes
                           and (not d.startswith(".git") or d == ".github")
                           and (not d.startswith(".") or d == ".github")]
            for fn in filenames:
                abs_path = os.path.join(dirpath, fn)
                rel = os.path.relpath(abs_path, root).replace("\\", "/")
                if self._is_excluded(rel):
                    continue
                ext = os.path.splitext(fn)[1].lower()
                if ext in BINARY_EXT:
                    continue
                lang = detect_language(abs_path)
                try:
                    size = os.path.getsize(abs_path)
                except OSError:
                    continue
                if size == 0 or size > MAX_FILE_SIZE:
                    continue
                content, _enc = read_text(abs_path)
                if content is None:
                    continue
                line_count = content.count("\n") + 1
                self.files.append(FileEntry(rel, abs_path, size, lang or "text", line_count))
                self.total_lines += line_count
                self.lang_stat[lang or "text"] += 1
                scanned += 1
                if scanned >= self.max_files:
                    break
            if scanned >= self.max_files:
                break

        self.files.sort(key=lambda f: f.rel)

    # ------------------------------------------------------------------ 扫描
    def _active_rules(self, lang: str):
        for c in _COMPILED:
            r = c["rule"]
            if r["severity"] not in self.severities:
                continue
            if r["category"] not in self.categories:
                continue
            langs = r["languages"]
            if "*" not in langs and lang not in langs:
                continue
            yield c

    def scan(self):
        self.start_time = time.time()
        self.progress.update({"phase": "walking", "current": 0, "total": 0})
        self.walk()

        self.progress.update({"phase": "scanning", "current": 0,
                              "total": len(self.files), "file": ""})

        fid = 0
        for idx, fe in enumerate(self.files, 1):
            self.progress["current"] = idx
            self.progress["file"] = fe.rel

            content, _ = read_text(fe.abs)
            if content is None:
                continue
            lines = content.split("\n")   # 与 count("\n") 同源，保证行号==行文本
            # 语言规则 + 全局规则
            rules = list(self._active_rules(fe.lang))
            if not rules:
                continue

            file_hits = []
            for c in rules:
                r = c["rule"]
                if c["path_exclude"] and c["path_exclude"].search(fe.rel):
                    continue
                # 文件级豁免（缺失型检查）：文件内容命中 suppress_if 则整条规则静默
                if c["suppress_if"] and c["suppress_if"].search(content):
                    self.suppressed += 1
                    continue
                for m in c["re"].finditer(content):
                    line_no = content.count("\n", 0, m.start()) + 1
                    line_text = lines[line_no - 1] if 0 < line_no <= len(lines) else ""
                    stripped = line_text.strip()

                    # 排除：注释行
                    if stripped.startswith("//") or stripped.startswith("*") or stripped.startswith("#!"):
                        continue
                    # 排除：同规则自带 excludes
                    if any(e.search(line_text) for e in c["excludes"]):
                        continue

                    guarded = False
                    if c["guard"]:
                        g_re, g_win = c["guard"]
                        lo = max(0, line_no - 1 - g_win)
                        ctx = "\n".join(lines[lo:line_no - 1])
                        if g_re.search(ctx):
                            guarded = True

                    file_hits.append({
                        "rule": r, "line": line_no,
                        "start": m.start(), "end": m.end(),
                        "text": stripped or line_text.strip(),
                        "guarded": guarded,
                        "_lines": lines,
                    })

            # 同一文件内：先按（规则，行）去重，再做同行跨规则冲突合并。
            # 合并策略见 _better_hit 与 rules.py 头部「规则优先级与冲突处理策略」。
            seen = set()
            unique = []
            for h in file_hits:
                key = (h["rule"]["id"], h["line"])
                if key in seen:
                    continue
                seen.add(key)
                unique.append(h)

            by_line = {}
            for h in unique:
                by_line.setdefault(h["line"], []).append(h)

            final_hits = []
            for _ln, hits in by_line.items():
                if len(hits) == 1:
                    final_hits.append(hits[0])
                    continue
                best = hits[0]
                for h in hits[1:]:
                    best = _better_hit(best, h)
                self.conflict_dropped += len(hits) - 1
                final_hits.append(best)

            for h in final_hits:
                if h["guarded"]:
                    self.suppressed += 1
                    continue

                fid += 1
                r = h["rule"]

                # ---- 作用域判定：测试/示例代码降一级，文档降为提示 ----
                scope, scope_note = "production", ""
                if DOC_PATH_RE.search(fe.rel):
                    scope = "doc"
                    scope_note = "该文件为文档/说明文件，其中的敏感信息多为示例，请人工确认是否为真实凭据。"
                elif TEST_PATH_RE.search(fe.rel):
                    scope = "test"
                    scope_note = "该文件位于测试/示例/集成目录，通常不进入生产运行环境，风险等级已自动下调一级。"

                sev = r["severity"]
                conf = r["confidence"]
                if scope == "doc":
                    sev, conf = "info", "low"
                elif scope == "test" and sev != "info":
                    sev = SEVERITY_ORDER[min(SEVERITY_ORDER.index(sev) + 1, len(SEVERITY_ORDER) - 1)]
                    conf = _SEV_FALLBACK.get(conf, conf)

                sev_meta = SEVERITY_META[sev]
                conf_factor = {"high": 1.0, "medium": 0.85, "low": 0.7}.get(conf, 0.8)
                score = round(sev_meta["score"] * conf_factor, 2)

                ls = h["_lines"]
                lo = max(0, h["line"] - 1 - SNIPPET_PAD)
                hi = min(len(ls), h["line"] + SNIPPET_PAD)
                snippet = [{"n": i + 1, "text": ls[i][:400], "hit": (i + 1) == h["line"]}
                           for i in range(lo, hi)]

                self.findings.append({
                    "id": f"F{fid:05d}",
                    "rule_id": r["id"],
                    "title": r["title"],
                    "severity": sev,
                    "severity_label": sev_meta["label"],
                    "rule_severity": r["severity"],
                    "category": r["category"],
                    "category_label": CATEGORY_META[r["category"]],
                    "scope": scope,
                    "scope_note": scope_note,
                    "file": fe.rel,
                    "lang": fe.lang,
                    "line": h["line"],
                    "column": h["start"] - (content.rfind("\n", 0, h["start"]) + 1) + 1,
                    "code": h["text"][:300],
                    "snippet": snippet,
                    "description": r["description"],
                    "remediation": r["remediation"],
                    "cwe": r["cwe"],
                    "confidence": conf,
                    "score": score,
                    "references": r.get("references", []),
                })

        # 依赖清单
        self._parse_deps()

        # 排序：严重程度 -> 风险分 -> 文件 -> 行号
        order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        self.findings.sort(key=lambda f: (order[f["severity"]], -f["score"], f["file"], f["line"]))

        self.elapsed = round(time.time() - self.start_time, 2)
        self.progress.update({"phase": "done", "done": True, "current": len(self.files),
                              "file": "", "elapsed": self.elapsed})

    # ------------------------------------------------------------ 依赖清单
    def _parse_deps(self):
        """递归发现并解析各生态依赖清单，供漏洞库比对。

        真正的解析工作在 core/manifests.py，本方法只负责把引擎扫到的文件交给它，
        并保留解析概况（哪些清单被读到、多少条无法定位版本、是否截断）。
        """
        try:
            self.deps, self.deps_meta = manifests.parse(self.files)
        except Exception:                     # noqa: BLE001  清单解析失败不应让扫描失败
            self.deps, self.deps_meta = [], {"total": 0, "manifests": 0,
                                             "by_manifest_kind": {}, "by_ecosystem": {},
                                             "unresolved": 0, "floored": 0,
                                             "truncated": False, "error": True}

    # -------------------------------------------------------------- 汇总
    def file_meta(self):
        """按文件聚合命中数，供文件树展示。"""
        mp = defaultdict(lambda: {"counts": Counter(), "total": 0, "worst": None})
        order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        for f in self.findings:
            e = mp[f["file"]]
            e["counts"][f["severity"]] += 1
            e["total"] += 1
            if e["worst"] is None or order[f["severity"]] < order[e["worst"]]:
                e["worst"] = f["severity"]
        return {
            k: {"total": v["total"], "worst": v["worst"], "counts": dict(v["counts"])}
            for k, v in mp.items()
        }

    def summary(self):
        by_sev = Counter(f["severity"] for f in self.findings)
        by_cat = Counter(f["category"] for f in self.findings)
        by_rule = Counter(f["rule_id"] for f in self.findings)
        by_scope = Counter(f.get("scope", "production") for f in self.findings)
        by_file = Counter(f["file"] for f in self.findings)
        total = len(self.findings)

        # 每个文件的最严重等级（用于热点文件排序展示）
        order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        file_worst = {}
        for f in self.findings:
            cur = file_worst.get(f["file"])
            if cur is None or order[f["severity"]] < order[cur]:
                file_worst[f["file"]] = f["severity"]

        # 规则元数据索引：把类型 / 等级带进 TOP 规则，供报告与看板直接使用
        rule_meta = {r["id"]: r for r in RULES}

        def _rule_item(rid, c):
            r = rule_meta.get(rid, {})
            return {
                "rule_id": rid,
                "count": c,
                "category": r.get("category", ""),
                "category_label": CATEGORY_META.get(r.get("category", ""), ""),
                "severity": r.get("severity", "info"),
                "severity_label": SEVERITY_META.get(r.get("severity", "info"), {}).get("label", ""),
                "confidence": r.get("confidence", ""),
            }

        # 风险指数（0-100）：对「等级加权分」做对数饱和，兼顾严重程度与问题规模。
        #   W = Σ 等级基础分 × 置信度系数
        #   index = 100 × (1 − e^(−W / RISK_HALF_SCALE))
        # 单条严重问题不会把指数顶满，海量低危也不会把指数压到 0。
        weight = sum(f["score"] for f in self.findings)
        risk_index = (round(100.0 * (1.0 - math.exp(-weight / RISK_HALF_SCALE)), 1)
                      if weight > 0 else 0.0)

        return {
            "total": total,
            "suppressed": self.suppressed,
            "conflict_dropped": self.conflict_dropped,
            "by_severity": {s: by_sev.get(s, 0) for s in SEVERITY_ORDER},
            "by_category": {k: by_cat.get(k, 0) for k in CATEGORY_META},
            "by_scope": {k: by_scope.get(k, 0) for k in ("production", "test", "doc")},
            "top_rules": [_rule_item(rid, c) for rid, c in by_rule.most_common(15)],
            "top_files": [
                {"file": fp, "count": c, "worst": file_worst.get(fp, "info")}
                for fp, c in by_file.most_common(15)
            ],
            "risk_index": risk_index,
            "severity_weight": round(weight, 1),
            "files_total": len(self.files),
            "files_with_findings": len(by_file),
            "lines_total": self.total_lines,
            "lang_stat": dict(self.lang_stat.most_common()),
            "deps_count": len(self.deps),
            "elapsed": self.elapsed,
            "root": self.root,
            "scanned_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
