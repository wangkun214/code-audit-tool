# -*- coding: utf-8 -*-
"""审计项目隔离：每一次扫描都是一个独立的、可追溯的项目。

设计要点
--------
1. **唯一标识**：项目 ID = ``P + 时间戳 + 4 位随机``（如 ``P20260928-183000-a3f2``）。
   时间戳保证天然按时间排序，随机段避免同秒冲突。
2. **物理隔离**：每个项目一个目录 ``projects/<pid>/``，含两份文件：
   - ``project.json``  项目元数据（小，列表页只读它，不碰大文件）
   - ``result.json``   完整快照（summary + 全部 findings + 依赖 + 漏洞结果）
   项目之间互不引用、互不影响；删除项目 = 删除其目录，无级联副作用。
3. **只增不改**：规则扫描完成时写一次 result.json，漏洞分析完成后补写一次
   （漏洞是异步的）。除此之外没有任何原地修改路径，保证快照与当时扫描一致。
4. **与全局资源的关系**：漏洞库缓存 ``vulndb/`` 是参考数据（OSV 公告），所有项目
   共享；报告归档 ``reports/`` 按文件名带时间戳，同属全局。隔离的对象是
   「审计结果与配置」，不是漏洞知识库——这与 SCA 的语义一致。
"""
from __future__ import annotations

import json
import os
import secrets
import shutil
import time

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PROJECTS_DIR = os.path.join(BASE_DIR, "projects")

META_FILE = "project.json"
RESULT_FILE = "result.json"

# 概览统计块版本：升级后老项目会在首次被读取时惰性回填（见 _backfill）。
# v1 = 仅 7 个标量字段（findings_total/risk_index/…）；v2 = 完整统计（严重度分布、
# 类别与语言 TOP、依赖与漏洞概要、耗时、状态），供「扫描历史」列表页与详情页使用。
SNAPSHOT_VERSION = 2

SEVS = ("critical", "high", "medium", "low", "info")

# 扫描结果状态：完成 / 部分完成（静态扫描成功但附加分析有告警）/ 中断 / 失败
STATUS_LABEL = {
    "completed":   "已完成",
    "partial":     "部分完成",
    "interrupted": "已中断",
    "error":       "失败",
}


def new_id() -> str:
    return "P" + time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(2)


def _dir(pid: str) -> str:
    if not pid or any(c in pid for c in "\\/:."):
        raise ValueError("非法项目 ID")
    return os.path.join(PROJECTS_DIR, pid)


def create(meta: dict) -> str:
    """创建项目目录并写入元数据，返回项目 ID。"""
    pid = meta["id"]
    d = _dir(pid)
    os.makedirs(d, exist_ok=True)
    _write_json(os.path.join(d, META_FILE), meta)
    return pid


def _write_json(path: str, data: dict) -> None:
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, ensure_ascii=False)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)                      # 原子替换，进程中断不留半截文件


def _stats_of(result: dict) -> dict:
    """把完整快照提炼成「列表页/详情页概览」统计块。

    只保留标量与小数组，便于放进 project.json —— 列表页因此无需读取 result.json
    （单次扫描的快照可达数 MB），历史记录再多也能秒开。
    """
    s = result.get("summary") or {}
    by = s.get("by_severity") or {}
    dm = result.get("deps_meta") or {}
    vs = ((result.get("vulns") or {}).get("summary")) or {}
    sev = {k: int(by.get(k, 0) or 0) for k in SEVS}

    def _top(mapping, n=8):
        pairs = [(k, int(v or 0)) for k, v in (mapping or {}).items() if v]
        pairs.sort(key=lambda kv: (-kv[1], kv[0]))
        return [{"key": k, "count": c} for k, c in pairs[:n]]

    return {
        "stats_version": SNAPSHOT_VERSION,
        "findings_total": int(s.get("total", 0) or 0),
        "risk_index": s.get("risk_index", 0),
        "severity_weight": s.get("severity_weight", 0),
        "by_severity": sev,
        "high_total": sev["critical"] + sev["high"],
        "suppressed_total": int(s.get("suppressed", 0) or 0),
        "conflict_dropped": int(s.get("conflict_dropped", 0) or 0),
        "files_total": int(s.get("files_total", 0) or 0),
        "files_with_findings": int(s.get("files_with_findings", 0) or 0),
        "lines_total": int(s.get("lines_total", 0) or 0),
        "elapsed": s.get("elapsed", 0),
        "scanned_at": s.get("scanned_at", ""),
        "top_categories": _top(s.get("by_category")),
        "top_languages": _top(s.get("lang_stat")),
        "deps_total": int(dm.get("total", s.get("deps_count", 0)) or 0),
        "manifests": int(dm.get("manifests", 0) or 0),
        "deps_by_ecosystem": dm.get("by_ecosystem") or {},
        "deps_unresolved": int(dm.get("unresolved", 0) or 0),
        "deps_truncated": bool(dm.get("truncated")),
        "vuln_total": int(vs.get("vuln_total", 0) or 0),
        "vuln_packages": int(vs.get("vuln_packages", 0) or 0),
        "vuln_fixable": int(vs.get("fixable", 0) or 0),
        "vuln_no_fix": int(vs.get("no_fix", 0) or 0),
        "vuln_critical": int(vs.get("critical", 0) or 0),
        "vuln_high": int(vs.get("high", 0) or 0),
    }


def _safe_write_meta(pid: str, meta: dict) -> None:
    if not pid:
        return
    try:
        _write_json(os.path.join(_dir(pid), META_FILE), meta)
    except (OSError, ValueError):
        pass                                       # 回填失败不影响读取


def _status_from(result: dict | None) -> str:
    """按快照内容判定状态。

    无快照说明扫描进程中断；快照里漏洞分析带 error 说明静态扫描完整但附加
    分析有告警（部分完成）；其余为完成。以内容为准可保证「SCA 失败后重试成功」
    时状态自动回到 completed，无需人工订正。
    """
    if not result or not result.get("summary"):
        return "interrupted"
    if (result.get("vulns") or {}).get("error"):
        return "partial"
    return "completed"


def status_of(meta: dict, result: dict | None = None) -> str:
    """归一化扫描状态。

    优先采信显式写入的 ``status``；老项目（v1.5 时代建档）没有该字段，
    则按快照内容推断。
    """
    st = (meta or {}).get("status")
    if st in STATUS_LABEL:
        return st
    if result is None:
        pid = (meta or {}).get("id") or ""
        result = load(pid) if pid else None
    return _status_from(result)


def _dir_size(pid: str) -> int:
    total = 0
    try:
        d = _dir(pid)
        for fn in os.listdir(d):
            fp = os.path.join(d, fn)
            if os.path.isfile(fp):
                total += os.path.getsize(fp)
    except (OSError, ValueError):
        pass
    return total


def _backfill(meta: dict) -> dict:
    """老项目惰性补齐：缺统计块时读一次 result.json 提炼，并回写 project.json。

    只发生一次（回写后 stats_version 命中），因此对列表接口的性能影响可忽略。
    """
    if not meta or meta.get("stats_version") == SNAPSHOT_VERSION:
        return meta
    pid = meta.get("id") or ""
    result = load(pid) if pid else None
    if result and result.get("summary"):
        meta.update(_stats_of(result))
        vulns = result.get("vulns") or {}
        if not meta.get("sca"):
            meta["sca"] = ("failed" if vulns.get("error")
                           else "done" if vulns.get("summary") else "off")
        if vulns.get("summary"):
            # 老项目没有记录漏洞分析完成时刻，用快照落盘时刻近似（时间线不留空）
            meta.setdefault("sca_at", meta.get("finished_at") or 0)
    else:
        meta["stats_version"] = SNAPSHOT_VERSION       # 无快照：标记已处理，避免反复读盘
    meta["status"] = status_of(meta, result)
    if meta.get("status") in ("completed", "partial"):
        meta.setdefault("scan_at", meta.get("finished_at") or meta.get("created_at") or 0)
    _safe_write_meta(pid, meta)
    return meta


def save_result(pid: str, result: dict, *, status: str = "", sca: str = "",
                error: str = "") -> bool:
    """写入/更新完整结果快照，并把列表页所需的概览统计回写元数据。

    项目不存在时返回 False。写入顺序：先落快照、再更新元数据——列表页读到的
    统计永不领先于它描述的快照。
    """
    try:
        d = _dir(pid)
        if not os.path.isdir(d):
            return False
        _write_json(os.path.join(d, RESULT_FILE), result)

        meta_path = os.path.join(d, META_FILE)
        meta = {}
        if os.path.isfile(meta_path):
            with open(meta_path, encoding="utf-8") as fh:
                meta = json.load(fh)
        now = time.time()
        vulns = result.get("vulns") or {}
        meta.update(_stats_of(result))
        meta.setdefault("scan_at", now)            # 首次落盘时刻 = 静态扫描完成
        meta["finished_at"] = now                  # 最近一次落盘（漏洞分析会再补写）
        if vulns.get("summary"):
            meta["sca_at"] = now
        if not meta.get("sca"):
            meta["sca"] = ("failed" if vulns.get("error")
                           else "done" if vulns.get("summary") else "off")
        meta["status"] = status or _status_from(result)
        if error:
            meta["error"] = error
        elif meta["status"] != "error":
            meta.pop("error", None)
        _write_json(meta_path, meta)
        return True
    except OSError:
        return False


def mark_status(pid: str, status: str, *, error: str = "", sca: str = "") -> bool:
    """只更新元数据状态，不动快照。用于扫描失败/中断、SCA 结束通知。"""
    try:
        meta_path = os.path.join(_dir(pid), META_FILE)
        if not os.path.isfile(meta_path):
            return False
        with open(meta_path, encoding="utf-8") as fh:
            meta = json.load(fh)
        meta["status"] = status
        if error:
            meta["error"] = error
        elif status != "error":
            meta.pop("error", None)
        if sca:
            meta["sca"] = sca
            if sca in ("done", "failed"):
                meta["sca_at"] = time.time()
        _write_json(meta_path, meta)
        return True
    except (OSError, ValueError):
        return False



def load_meta(pid: str) -> dict | None:
    p = os.path.join(_dir(pid), META_FILE)
    if not os.path.isfile(p):
        return None
    try:
        with open(p, encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def load(pid: str) -> dict | None:
    """返回完整快照（含 meta），不存在或损坏返回 None。"""
    d = _dir(pid)
    res = os.path.join(d, RESULT_FILE)
    meta = load_meta(pid)
    if meta is None:
        return None
    if os.path.isfile(res):
        try:
            with open(res, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return None
    return {"meta": meta}                     # 扫描中断只有元数据


def list_all(enrich: bool = True) -> list[dict]:
    """列出全部项目（按创建时间倒序）。

    enrich=True 时补齐统计块（老项目惰性回填）、状态文案与占用体积，
    列表页因此只需一次请求即可渲染完整记录卡。
    """
    out = []
    if not os.path.isdir(PROJECTS_DIR):
        return out
    for pid in os.listdir(PROJECTS_DIR):
        m = load_meta(pid)
        if not m:
            continue
        if enrich:
            m = _backfill(m)
            m["status_label"] = STATUS_LABEL.get(m.get("status", ""), m.get("status", ""))
            m["size_bytes"] = _dir_size(pid)
            m["has_snapshot"] = os.path.isfile(os.path.join(_dir(pid), RESULT_FILE))
        out.append(m)
    out.sort(key=lambda m: m.get("id", ""), reverse=True)
    return out


def aggregate(items: list[dict]) -> dict:
    """列表页顶部概览条：累计统计（与筛选解耦，始终按全量计算）。"""
    sev = {k: 0 for k in SEVS}
    for m in items:
        bs = m.get("by_severity") or {}
        for k in SEVS:
            sev[k] += int(bs.get(k, 0) or 0)
    times = [m.get("created_at") or 0 for m in items if m.get("created_at")]
    return {
        "scans": len(items),
        "findings": sum(int(m.get("findings_total", 0) or 0) for m in items),
        "vulns": sum(int(m.get("vuln_total", 0) or 0) for m in items),
        "files": sum(int(m.get("files_total", 0) or 0) for m in items),
        "lines": sum(int(m.get("lines_total", 0) or 0) for m in items),
        "by_severity": sev,
        "high_total": sev["critical"] + sev["high"],
        "targets": len({(m.get("target") or {}).get("root", "") for m in items}),
        "first_at": min(times) if times else 0,
        "last_at": max(times) if times else 0,
        "by_status": {k: sum(1 for m in items if m.get("status") == k)
                      for k in STATUS_LABEL},
    }


def detail(pid: str, *, top_findings: int = 60, rule_count: int = 0) -> dict | None:
    """组装「扫描详情页」所需的完整数据。

    返回结构按页面的信息区块组织，任一区块缺失时前端降级为占位文案：

      meta       项目元数据（含统计块、状态、体积）
      target     审计目标 {name, root, kind}
      config     扫描配置（可追溯当时用的是哪套参数）
      severity   严重程度分布
      findings   高危隐患清单（严重度 → 置信度 → 文件行号 排序后截断）
      index      聚合索引（按类别 / 按规则 / 按语言）
      deps       依赖与漏洞摘要
      timeline   时间线（建档 → 扫描完成 → 漏洞分析完成）
      integrity  数据完整性（源目录是否仍存在、快照体积）
      advice     由实际数据推导的下一步处置建议
    """
    meta = load_meta(pid)
    if meta is None:
        return None
    meta = _backfill(meta)
    meta["status_label"] = STATUS_LABEL.get(meta.get("status", ""), meta.get("status", ""))
    meta["size_bytes"] = _dir_size(pid)
    meta["has_snapshot"] = os.path.isfile(os.path.join(_dir(pid), RESULT_FILE))

    result = load(pid) or {}
    summary = result.get("summary") or {}
    findings = result.get("findings") or []
    vulns = result.get("vulns") or {}
    dm = result.get("deps_meta") or {}
    target = meta.get("target") or {}
    root = target.get("root") or meta.get("root") or ""

    # ---- 严重程度分布（以完整快照为准，元数据作为兜底）----
    sev = {k: 0 for k in SEVS}
    for f in findings:
        k = f.get("severity")
        if k in sev:
            sev[k] += 1
    if not findings:
        sev = {k: int((meta.get("by_severity") or {}).get(k, 0) or 0) for k in SEVS}

    # ---- 高危隐患清单：严重度 → 置信度 → 文件/行号 ----
    conf_rank = {"high": 0, "medium": 1, "low": 2}
    sev_rank = {k: i for i, k in enumerate(SEVS)}
    ordered = sorted(
        findings,
        key=lambda f: (sev_rank.get(f.get("severity"), 9),
                       conf_rank.get(f.get("confidence"), 3),
                       str(f.get("file") or ""), int(f.get("line") or 0)),
    )
    items = [{
        "id": f.get("id", ""),
        "rule_id": f.get("rule_id", ""),
        "title": f.get("title", ""),
        "severity": f.get("severity", "info"),
        "severity_label": f.get("severity_label", ""),
        "category": f.get("category", ""),
        "category_label": f.get("category_label", ""),
        "confidence": f.get("confidence", ""),
        "cwe": f.get("cwe", ""),
        "scope": f.get("scope", "production"),
        "file": f.get("file", ""),
        "line": f.get("line", ""),
        "code": (f.get("code") or "")[:240],
        "remediation": (f.get("remediation") or "")[:400],
    } for f in ordered[:top_findings]]

    # ---- 聚合索引 ----
    def _tally(mapping, label_map, n=12):
        pairs = [(k, int(v or 0)) for k, v in (mapping or {}).items() if v]
        pairs.sort(key=lambda kv: (-kv[1], kv[0]))
        return [{"key": k, "label": (label_map or {}).get(k, k), "count": c}
                for k, c in pairs[:n]]

    vuln_sum = vulns.get("summary") or {}
    deps = {
        "total": int(dm.get("total", 0) or 0),
        "manifests": int(dm.get("manifests", 0) or 0),
        "by_ecosystem": dm.get("by_ecosystem") or {},
        "by_manifest_kind": dm.get("by_manifest_kind") or {},
        "unresolved": int(dm.get("unresolved", 0) or 0),
        "floored": int(dm.get("floored", 0) or 0),
        "truncated": bool(dm.get("truncated")),
        "sca": meta.get("sca", ""),
        "vuln": {
            "summary": vuln_sum,
            "by_severity": vulns.get("by_severity") or {},
            "error": vulns.get("error") or "",
            "offline": bool(vulns.get("offline")),
            "source": vulns.get("source", ""),
            "queried": int(vulns.get("queried", 0) or 0),
            "elapsed": vulns.get("elapsed", 0),
            "top": [{
                "vuln_id": v.get("vuln_id", ""),
                "cve": v.get("cve", ""),
                "title": (v.get("title") or "")[:160],
                "severity": v.get("severity", ""),
                "cvss": v.get("cvss", ""),
                "package": v.get("package", ""),
                "version": v.get("version", ""),
                "ecosystem": v.get("ecosystem", ""),
                "has_fix": bool(v.get("has_fix")),
                "fixed": v.get("fixed", ""),
                "advice": (v.get("advice") or "")[:240],
            } for v in (vulns.get("findings") or [])[:20]],
        },
    }

    # ---- 时间线（老项目缺 sca_at/scan_at 时用快照落盘时刻兜底，避免出现"未发生"）----
    fin = meta.get("finished_at") or 0
    timeline = [
        {"key": "created", "label": "任务建档", "at": meta.get("created_at") or 0,
         "note": "分配唯一项目 ID " + pid},
        {"key": "scanned", "label": "静态扫描完成", "at": meta.get("scan_at") or fin,
         "note": f"{int(meta.get('files_total', 0) or 0)} 文件 / "
                 f"{int(meta.get('lines_total', 0) or 0):,} 行 / "
                 f"命中 {int(meta.get('findings_total', 0) or 0)} 项 / "
                 f"耗时 {meta.get('elapsed', 0)}s"},
        {"key": "vuln", "label": "依赖漏洞分析",
         "at": meta.get("sca_at") or (fin if vuln_sum else 0),
         "note": (f"{int(vuln_sum.get('vuln_total', 0) or 0)} 条漏洞 / "
                  f"受影响依赖 {int(vuln_sum.get('vuln_packages', 0) or 0)} 个"
                  if vuln_sum else
                  ("分析失败：" + str(vulns.get("error"))[:60] if vulns.get("error")
                   else "未启用或无可分析依赖"))},
    ]

    # ---- 下一步处置建议（全部由实际数据推导，不允许出现"通用套话"）----
    advice = []
    if meta.get("status") == "error":
        advice.append("本次扫描失败：" + str(meta.get("error") or "原因未记录")
                      + "——请确认目录可读后重新发起扫描。")
    if meta.get("status") == "interrupted":
        advice.append("本次任务未生成结果快照（扫描进程中断），只能查看建档信息；"
                      "如需完整数据请重新扫描该目录。")
    if not int(meta.get("files_total", 0) or 0):
        advice.append("未扫描到可审计源码文件：请确认审计目录是否正确，"
                      "或该目录是否被排除规则整体跳过。")
    if sev["critical"] or sev["high"]:
        advice.append(f"优先处置 {sev['critical'] + sev['high']} 项严重/高危问题"
                      f"（严重 {sev['critical']} / 高危 {sev['high']}），"
                      "建议在合并代码前完成修复。")
    fixable = int(vuln_sum.get("fixable", 0) or 0)
    if fixable:
        advice.append(f"{fixable} 个依赖漏洞已有官方修复版本，升级成本最低，建议优先安排。")
    if int(vuln_sum.get("no_fix", 0) or 0):
        advice.append(f"{int(vuln_sum.get('no_fix', 0))} 个漏洞暂无官方修复版本，"
                      "需通过隔离、降权或替换组件缓解。")
    if deps["unresolved"]:
        advice.append(f"{deps['unresolved']} 个依赖版本无法确定（区间或通配符声明），"
                      "SCA 未覆盖，建议锁定精确版本后重新扫描。")
    if deps["truncated"]:
        advice.append("依赖清单解析达到上限，结果可能不完整，建议拆分大型清单文件。")
    if not deps["manifests"] and meta.get("status") == "completed":
        advice.append("未识别到依赖清单文件：若项目存在第三方依赖，"
                      "请补充 package.json / pom.xml / go.mod 等清单以启用依赖漏洞扫描。")
    if vulns.get("error"):
        advice.append("依赖漏洞分析未成功（静态扫描结果不受影响）："
                      + str(vulns.get("error"))[:120])
    if int(meta.get("suppressed_total", 0) or 0):
        advice.append(f"另有 {int(meta.get('suppressed_total', 0))} 处命中被规则文件级豁免"
                      "（如已启用 USER 非 root 的 Dockerfile），可复核豁免条件是否仍然成立。")
    if int(meta.get("conflict_dropped", 0) or 0):
        advice.append(f"{int(meta.get('conflict_dropped', 0))} 处同一行多规则命中已按"
                      "「严重度 → 置信度 → 规则 ID」择优合并，属去重而非漏报。")

    return {
        "meta": meta,
        "target": target,
        "config": {
            "kind": target.get("kind", "path"),
            "root": root,
            "excludes": meta.get("excludes") or [],
            "severities": meta.get("severities") or [],
            "categories": meta.get("categories") or [],
            "vulndb_enabled": bool(meta.get("vulndb_enabled")),
            "tool_version": meta.get("version", ""),
            "rule_count": rule_count,
            "stats_version": meta.get("stats_version", 0),
        },
        "summary": summary,
        "severity": {"by_severity": sev,
                     "total": sum(sev.values()),
                     "high_total": sev["critical"] + sev["high"]},
        "findings": items,
        "index": {
            "total": len(findings),
            "shown": len(items),
            "by_category": _tally(summary.get("by_category"), None),
            "by_rule": summary.get("top_rules") or [],
            "by_language": _tally(summary.get("lang_stat"), None),
            "by_scope": summary.get("by_scope") or {},
            "top_files": summary.get("top_files") or [],
        },
        "deps": deps,
        "timeline": timeline,
        "integrity": {
            "root": root,
            "root_exists": bool(root) and os.path.isdir(root),
            "has_snapshot": meta.get("has_snapshot", False),
            "size_bytes": meta.get("size_bytes", 0),
        },
        "advice": advice,
    }


def delete(pid: str) -> bool:
    try:
        d = _dir(pid)
    except ValueError:
        return False
    if not os.path.isdir(d):
        return False
    shutil.rmtree(d, ignore_errors=True)
    return True
