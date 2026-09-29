# -*- coding: utf-8 -*-
"""
审计报告导出：HTML / JSON / Markdown / CSV / DOCX。

DOCX 由本目录的 docx.py（零依赖 OOXML 生成器）产出，
输出为规范的 Word 报告：封面 → 概览 → 统计 → 隐患清单 → 验证计划 → 附录。
"""
from __future__ import annotations

import csv
import html
import io
import json
import urllib.parse as _urlparse
from datetime import datetime

from . import docx as _docx
from .meta import (FEEDBACK_EMAIL, FEEDBACK_SUBJECT_PREFIX, FEEDBACK_TITLE,
                   TOOL_NAME, TOOL_VERSION)
from .rules import CATEGORY_META, SEVERITY_META, SEVERITY_ORDER

SCOPE_CN = {"production": "生产代码", "test": "测试/示例代码", "doc": "文档"}

# 反馈入口文案：统一追加在三种文本类报告的页脚，便于报告流转后使用者回馈问题。
# HTML 报告中另给出带主题预填的 mailto 链接，收件端可按版本归档检索。
FEEDBACK_LINE = f"{FEEDBACK_TITLE}：{FEEDBACK_EMAIL}"
FEEDBACK_MAILTO = ("mailto:" + FEEDBACK_EMAIL + "?subject="
                   + _urlparse.quote(f"{FEEDBACK_SUBJECT_PREFIX} 审计报告反馈"))

# 依赖漏洞修复跨度（与 core/vulndb.py 的 fix_kind 对应）
FIX_CN = {"same-branch": "同版本线内升级", "minor-up": "升到更高次版本线",
          "major-up": "跨主版本升级", "none": "暂无修复版本"}
ECO_CN = {"go": "Go Modules", "npm": "npm / Node", "pypi": "Python (PyPI)",
          "maven": "Maven", "gradle": "Gradle", "rubygems": "RubyGems",
          "packagist": "Composer / PHP", "crates.io": "Rust / crates.io",
          "nuget": ".NET / NuGet", "pub": "Dart / Pub"}


def vuln_result(engine):
    """取引擎上挂载的依赖漏洞分析结果（可能为 None）。"""
    return getattr(engine, "vulns", None) or None


def vuln_headline(v: dict) -> str:
    s = v.get("summary") or {}
    return (f"共 {s.get('vuln_total', 0)} 条已知漏洞，涉及 {s.get('vuln_packages', 0)} 个依赖"
            f"（严重 {s.get('critical', 0)} / 高危 {s.get('high', 0)}）；"
            f"其中 {s.get('fixable', 0)} 条存在修复版本，{s.get('no_fix', 0)} 条暂无修复版本。")


def _ts():
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


# --------------------------------------------------------------------- JSON
def to_json(engine) -> str:
    return json.dumps({
        "meta": {
            "tool": TOOL_NAME,
            "version": TOOL_VERSION,
            "generated_at": _ts(),
            **engine.summary(),
        },
        "dependencies": engine.deps,
        "dependency_meta": getattr(engine, "deps_meta", {}),
        "vulnerabilities": vuln_result(engine),
        "files": [f.to_dict() for f in engine.files],
        "findings": engine.findings,
    }, ensure_ascii=False, indent=2)


# ----------------------------------------------------------------------- CSV
def to_csv(engine) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["序号", "风险等级", "风险分", "类型", "规则编号", "问题名称", "作用域",
                "文件", "行号", "列号", "CWE", "置信度", "代码片段", "风险说明", "修复建议"])
    for i, f in enumerate(engine.findings, 1):
        w.writerow([
            i, f["severity_label"], f["score"], f["category_label"], f["rule_id"],
            f["title"], SCOPE_CN.get(f.get("scope", "production"), "生产代码"),
            f["file"], f["line"], f["column"], f["cwe"],
            f["confidence"], f["code"].replace("\n", " "),
            f["description"].replace("\n", " "), f["remediation"].replace("\n", " "),
        ])
    # 第二张表：第三方依赖已知漏洞（两张表用空行分隔，Excel 可直接打开）
    v = vuln_result(engine)
    findings = (v or {}).get("findings") or []
    if findings:
        buf.write("\n")
        w.writerow(["依赖漏洞清单（数据源：OSV.dev）"])
        w.writerow(["序号", "严重等级", "CVSS", "漏洞编号", "CVE", "风险名称",
                    "受影响依赖", "当前版本", "生态", "所在清单", "修复版本",
                    "修复跨度", "修复建议", "版本可信度", "参考链接"])
        for i, f in enumerate(findings, 1):
            w.writerow([
                i, SEVERITY_META.get(f["severity"], {}).get("label", f["severity"]),
                f["cvss"] if f["cvss"] is not None else "", f["vuln_id"], f["cve"],
                f["title"], f["package"], f["version"],
                ECO_CN.get(f["ecosystem"], f["ecosystem"]), f["manifest"],
                f["fixed"] or "—", FIX_CN.get(f["fix_kind"], f["fix_kind"]),
                f["advice"].replace("\n", " "),
                {"exact": "精确", "floor": "区间下界（推定）",
                 "unresolved": "未解析"}.get(f["version_kind"], f["version_kind"]),
                " ".join(r["url"] for r in (f["references"] or [])[:2]),
            ])
    return buf.getvalue()


# ------------------------------------------------------------------ Markdown
def to_markdown(engine) -> str:
    s = engine.summary()
    L = []
    L.append("# 源代码安全审计报告\n")
    L.append(f"- **审计目标**：`{s['root']}`")
    L.append(f"- **生成时间**：{s['scanned_at']}")
    L.append(f"- **扫描引擎耗时**：{s['elapsed']} 秒")
    L.append(f"- **代码规模**：{s['files_total']} 个文件 / {s['lines_total']:,} 行")
    L.append(f"- **风险指数**：**{s['risk_index']} / 100**")
    sc = s.get("by_scope", {})
    L.append(f"- **作用域分布**：生产代码 {sc.get('production',0)} 项 / 测试示例代码 {sc.get('test',0)} 项 / 文档 {sc.get('doc',0)} 项")
    L.append("")

    L.append("## 一、风险总览\n")
    L.append("| 风险等级 | 数量 |")
    L.append("| :--- | ---: |")
    for sev in SEVERITY_ORDER:
        L.append(f"| {SEVERITY_META[sev]['label']} | {s['by_severity'][sev]} |")
    L.append(f"| **合计** | **{s['total']}** |\n")

    L.append("## 二、类型分布\n")
    L.append("| 漏洞类型 | 数量 |")
    L.append("| :--- | ---: |")
    for cat, label in CATEGORY_META.items():
        if s["by_category"].get(cat):
            L.append(f"| {label} | {s['by_category'][cat]} |")
    L.append("")

    L.append("## 三、隐患清单与整改建议\n")
    cur = None
    for i, f in enumerate(engine.findings, 1):
        if f["severity"] != cur:
            cur = f["severity"]
            L.append(f"### {SEVERITY_META[cur]['label']}\n")
        L.append(f"#### {i}. [{f['severity_label']}] {f['title']}\n")
        L.append(f"- **规则编号**：`{f['rule_id']}`　**CWE**：{f['cwe']}　**置信度**：{f['confidence']}　**风险分**：{f['score']}")
        if f.get("scope") and f["scope"] != "production":
            L.append(f"- **作用域**：{SCOPE_CN.get(f['scope'], f['scope'])} —— {f.get('scope_note','')}")
        L.append(f"- **文件定位**：`{f['file']}:{f['line']}:{f['column']}`")
        L.append(f"- **问题代码**：\n\n```\n{f['code']}\n```\n")
        L.append(f"- **风险说明**：{f['description']}")
        L.append(f"- **修复建议**：\n\n```\n{f['remediation']}\n```\n")

    L.append("## 四、验证计划\n")
    for i, line in enumerate(VALIDATION_PLAN, 1):
        L.append(f"{i}. {line}")
    L.append("")

    v = vuln_result(engine)
    vf = (v or {}).get("findings") or []
    if vf:
        s = v.get("summary") or {}
        L.append("## 五、第三方依赖已知漏洞（SCA）\n")
        L.append(f"> 数据源：OSV.dev（https://osv.dev），分析时间："
                 f"{datetime.now().strftime('%Y-%m-%d %H:%M')}，"
                 f"查询 {s.get('queried', 0)} 个依赖，耗时 {v.get('elapsed', 0)} 秒。\n")
        L.append(vuln_headline(v) + "\n")
        L.append("| # | 等级 | CVSS | 漏洞编号 | CVE | 受影响依赖 | 当前版本 | 修复版本 | 修复跨度 |")
        L.append("| ---: | :--- | ---: | :--- | :--- | :--- | :--- | :--- | :--- |")
        for i, f in enumerate(vf, 1):
            L.append(f"| {i} | {SEVERITY_META.get(f['severity'], {}).get('label', f['severity'])} "
                     f"| {f['cvss'] if f['cvss'] is not None else '—'} "
                     f"| `{f['vuln_id']}` | {f['cve'] or '—'} "
                     f"| `{f['package']}` | {f['version']} "
                     f"| {f['fixed'] or '—'} | {FIX_CN.get(f['fix_kind'], f['fix_kind'])} |")
        L.append("")
        L.append("### 5.1 修复建议明细\n")
        for i, f in enumerate(vf, 1):
            L.append(f"**{i}. [{SEVERITY_META.get(f['severity'], {}).get('label', f['severity'])}]"
                     f" {f['title']}**\n")
            L.append(f"- **受影响依赖**：`{f['package']}@{f['version']}`"
                     f"（{ECO_CN.get(f['ecosystem'], f['ecosystem'])}，来源 `{f['manifest']}`）")
            L.append(f"- **漏洞编号**：`{f['vuln_id']}`"
                     + (f" / {f['cve']}" if f["cve"] else "")
                     + (f"　**其它别名**：{', '.join(f.get('also_ids') or [])}" if f.get("also_ids") else ""))
            if f["cvss"] is not None:
                L.append(f"- **CVSS 基础分**：{f['cvss']}（{f['cvss_vector']}）")
            L.append(f"- **修复建议**：{f['advice']}")
            if f.get("command"):
                L.append(f"- **升级命令**：\n\n```\n{f['command']}\n```")
            if f.get("references"):
                L.append(f"- **参考链接**：{f['references'][0]['url']}")
            L.append("")

    if engine.deps:
        L.append(f"## 六、第三方依赖清单（共 {len(engine.deps)} 项）\n")
        L.append("| 依赖包 | 版本 | 版本可信度 | 生态 | 作用域 | 来源清单 |")
        L.append("| :--- | :--- | :--- | :--- | :--- | :--- |")
        vk = {"exact": "精确", "floor": "区间下界", "unresolved": "未解析"}
        for d in engine.deps[:300]:
            L.append(f"| `{d['name']}` | {d['version'] or '—'} "
                     f"| {vk.get(d.get('version_kind'), '')} "
                     f"| {ECO_CN.get(d.get('ecosystem', ''), d.get('ecosystem', ''))} "
                     f"| {d.get('scope', '')} | {d.get('manifest', '')} |")
        L.append("")
        dm = getattr(engine, "deps_meta", {}) or {}
        if dm.get("unresolved"):
            L.append(f"> 注：其中 {dm['unresolved']} 项依赖的版本由外部父 POM / BOM 管理，"
                     "源码内无法解析，未纳入漏洞比对。执行 "
                     "`mvn dependency:tree -DoutputFile=deps.txt` 后重新扫描可获得精确版本。\n")

    L.append("---")
    L.append(f"*本报告由「{TOOL_NAME} v{TOOL_VERSION}」于 {_ts()} 自动生成。"
             "静态分析存在误报可能，请结合人工复核确认。*")
    L.append("")
    L.append(f"> {FEEDBACK_TITLE}：**{FEEDBACK_EMAIL}** —— 发现误报 / 漏报、希望新增规则，"
             "或对工具有任何改进建议，欢迎来信反馈。")
    return "\n".join(L)


VALIDATION_PLAN = [
    "按风险等级由高到低逐项确认整改，严重 / 高危项建议 7 日内闭环，中危项纳入当迭代，低危与提示项随版本一并处理。",
    "对每一项修复补充单元测试或安全测试用例，验证漏洞不可复现；凭据类问题须同步完成密钥轮换与历史记录清理。",
    "重新执行本审计工具对同一代码库扫描，确认对应规则命中数归零或下降至可接受阈值。",
    "将本审计工具接入 CI 流水线，对新增的严重 / 高危问题设置构建门禁（Quality Gate），阻止带病合入。",
    "每季度复扫一次，记录风险指数变化，形成风险收敛趋势台账，作为安全整改有效性的量化证明。",
]


# ---------------------------------------------------------------------- HTML
_SEV_CLS = {"critical": "sev-critical", "high": "sev-high", "medium": "sev-medium",
            "low": "sev-low", "info": "sev-info"}


def to_html(engine) -> str:
    s = engine.summary()
    e = html.escape

    cards = "".join(
        f'<div class="kpi {_SEV_CLS[sev]}"><div class="kpi-num">{s["by_severity"][sev]}</div>'
        f'<div class="kpi-lab">{SEVERITY_META[sev]["label"]}</div></div>'
        for sev in SEVERITY_ORDER
    )

    cat_rows = "".join(
        f"<tr><td>{e(label)}</td><td class='num'>{s['by_category'][cat]}</td></tr>"
        for cat, label in CATEGORY_META.items() if s["by_category"].get(cat)
    )

    rows = []
    for i, f in enumerate(engine.findings, 1):
        snip = "".join(
            f'<div class="cl{" hit" if ln["hit"] else ""}">'
            f'<span class="lno">{ln["n"]}</span><span class="ct">{e(ln["text"])}</span></div>'
            for ln in f["snippet"]
        )
        rows.append(f"""
<article class="finding {_SEV_CLS[f['severity']]}" data-sev="{f['severity']}" data-cat="{f['category']}">
  <header>
    <span class="idx">#{i}</span>
    <span class="badge">{f['severity_label']}</span>
    <span class="cat">{e(f['category_label'])}</span>
    <h3>{e(f['title'])}</h3>
    <span class="score">风险分 {f['score']}</span>
  </header>
  <div class="meta">
    <span><b>规则</b> <code>{e(f['rule_id'])}</code></span>
    <span><b>CWE</b> {e(f['cwe'])}</span>
    <span><b>置信度</b> {e(f['confidence'])}</span>
    <span><b>作用域</b> {e(SCOPE_CN.get(f.get('scope', 'production'), '生产代码'))}</span>
    <span><b>定位</b> <code>{e(f['file'])}:{f['line']}:{f['column']}</code></span>
  </div>
  {f'<p class="scopenote">⚠ {e(f["scope_note"])}</p>' if f.get("scope_note") else ''}
  <div class="codebox">{snip}</div>
  <div class="blocks">
    <div class="blk"><h4>风险说明</h4><p>{e(f['description'])}</p></div>
    <div class="blk fix"><h4>修复建议</h4><pre>{e(f['remediation'])}</pre></div>
  </div>
</article>""")

    deps = ""
    if engine.deps:
        dl = "".join(
            f"<li title=\"{e(d.get('manifest',''))}\"><code>{e(d['name'])}</code> "
            f"<span>{e(d['version']) or '—'}</span> "
            f"<em>{e(ECO_CN.get(d.get('ecosystem',''), d.get('ecosystem','')))}</em></li>"
            for d in engine.deps[:160])
        dm = getattr(engine, "deps_meta", {}) or {}
        note = ""
        if dm.get("unresolved"):
            note = (f"<p class='hint'>其中 {dm['unresolved']} 项依赖的版本由外部父 POM / BOM 管理，"
                    "源码内无法解析，未纳入漏洞比对；执行 "
                    "<code>mvn dependency:tree -DoutputFile=deps.txt</code> 后重新扫描可获得精确版本。</p>")
        deps = f"""
<section class="panel">
  <h2>六、第三方依赖清单（共 {len(engine.deps)} 项）</h2>
  <p class="hint">来源：pom.xml / build.gradle / package.json / go.mod / requirements.txt 等清单文件。
  版本可信度分三档：<b>精确</b>（锁定文件或明确版本）、<b>区间下界</b>（如 ^1.2.3 取下界，可能偏旧）、
  <b>未解析</b>（由外部父 POM 提供）。</p>
  <ul class="deps">{dl}</ul>
  {note}
  {"<p class='hint'>（仅展示前 160 项，完整清单请导出 CSV / JSON）</p>" if len(engine.deps) > 160 else ""}
</section>"""

    # ---- 依赖已知漏洞（SCA）----
    vuln_html = ""
    v = vuln_result(engine)
    vf = (v or {}).get("findings") or []
    if vf:
        vs = v.get("summary") or {}
        rows = []
        for i, f in enumerate(vf, 1):
            sev = f["severity"]
            rows.append(
                f"<tr><td class='num'>{i}</td>"
                f"<td><span class='badge b-{sev}'>{e(SEVERITY_META.get(sev, {}).get('label', sev))}</span></td>"
                f"<td class='num'>{f['cvss'] if f['cvss'] is not None else '—'}</td>"
                f"<td><code>{e(f['vuln_id'])}</code></td><td>{e(f['cve'] or '—')}</td>"
                f"<td>{e(f['title'][:90])}</td>"
                f"<td><code>{e(f['package'])}</code><br><span class='muted'>{e(f['version'])}</span></td>"
                f"<td><code>{e(f['fixed'] or '—')}</code></td>"
                f"<td>{e(FIX_CN.get(f['fix_kind'], f['fix_kind']))}</td></tr>")
        detail = "".join(
            f"<article class='finding {_SEV_CLS.get(f['severity'], '')}'>"
            f"<h3>{i}. [{e(SEVERITY_META.get(f['severity'], {}).get('label', f['severity']))}] "
            f"{e(f['title'])}</h3>"
            f"<div class='meta'><span>漏洞编号 <code>{e(f['vuln_id'])}</code></span>"
            + (f"<span>别名 <code>{e(', '.join((f.get('also_ids') or [])[:3]))}</code></span>"
               if f.get("also_ids") else "")
            + (f"<span>CVSS <b>{f['cvss']}</b></span>" if f["cvss"] is not None else "")
            + f"</div>"
            f"<div class='blk'><h4>受影响依赖</h4><pre>{e(f['package'])}@{e(f['version'])}"
            f"  （{e(ECO_CN.get(f['ecosystem'], f['ecosystem']))}，来源 {e(f['manifest'])}）</pre></div>"
            f"<div class='blk fix'><h4>修复建议</h4><pre>{e(f['advice'])}</pre></div>"
            + (f"<div class='blk'><h4>升级命令</h4><pre>{e(f['command'])}</pre></div>"
               if f.get("command") else "")
            + (f"<div class='blk'><h4>参考链接</h4>"
               f"<a href=\"{e(f['references'][0]['url'])}\" target=\"_blank\" rel=\"noopener\">"
               f"{e(f['references'][0]['url'])}</a></div>" if f.get("references") else "")
            + "</article>"
            for i, f in enumerate(vf, 1))
        meta_line = (f"数据源 <b>OSV.dev</b>　查询 {vs.get('queried', 0)} 个依赖　"
                     f"耗时 {v.get('elapsed', 0)} 秒　"
                     + (f"<span class='warn'>注意：本次分析未成功联网 —— {e(v.get('error', ''))}</span>"
                        if v.get("error") and not v.get("online") else "在线数据已更新"))
        vuln_html = f"""
<section class="panel">
  <h2>五、第三方依赖已知漏洞（SCA）</h2>
  <p class="hint">{meta_line}</p>
  <p>{e(vuln_headline(v))}</p>
  <table>
    <thead><tr><th>#</th><th>等级</th><th>CVSS</th><th>漏洞编号</th><th>CVE</th>
    <th>风险名称</th><th>受影响依赖</th><th>修复版本</th><th>修复跨度</th></tr></thead>
    <tbody>{"".join(rows)}</tbody>
  </table>
</section>
<section class="panel"><h2>5.1 修复建议明细</h2>{detail}</section>"""
    elif v is not None and v.get("error"):
        vuln_html = f"""
<section class="panel">
  <h2>五、第三方依赖已知漏洞（SCA）</h2>
  <p class="warn">依赖漏洞分析未完成：{e(v.get('error', '未知错误'))}。
  可稍后在界面中点击「更新漏洞库」重试。</p>
</section>"""

    top_rules = "".join(
        f"<tr><td><code>{e(t['rule_id'])}</code></td><td class='num'>{t['count']}</td></tr>"
        for t in s["top_rules"]
    )

    sc = s.get("by_scope", {}) or {}

    return f"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<title>源代码安全审计报告 - {e(s['root'])}</title>
<style>
  :root {{
    --c-critical:#b91c1c; --c-high:#dc2626; --c-medium:#d97706; --c-low:#0284c7; --c-info:#64748b;
    --bg:#f6f7f9; --fg:#1f2937; --line:#e5e7eb; --card:#fff; --muted:#6b7280;
  }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; background:var(--bg); color:var(--fg); font-size:14px;
         font-family:-apple-system,"Segoe UI","Microsoft YaHei",system-ui,sans-serif; line-height:1.65; }}
  .wrap {{ max-width:1080px; margin:0 auto; padding:32px 24px 80px; }}
  header.top {{ background:linear-gradient(135deg,#0f172a,#1e3a5f); color:#fff; border-radius:14px;
                padding:28px 32px; margin-bottom:22px; }}
  header.top h1 {{ margin:0 0 10px; font-size:24px; letter-spacing:.5px; }}
  header.top .sub {{ opacity:.85; font-size:13px; }}
  header.top .sub code {{ background:rgba(255,255,255,.14); padding:1px 6px; border-radius:4px; }}
  .kpis {{ display:grid; grid-template-columns:repeat(5,1fr); gap:12px; margin:18px 0 6px; }}
  .kpi {{ background:rgba(255,255,255,.10); border-radius:10px; padding:12px; text-align:center;
          border:1px solid rgba(255,255,255,.18); }}
  .kpi-num {{ font-size:26px; font-weight:700; line-height:1.2; }}
  .kpi-lab {{ font-size:12px; opacity:.85; }}
  .kpi.sev-critical .kpi-num {{ color:#fca5a5; }} .kpi.sev-high .kpi-num {{ color:#fda4af; }}
  .kpi.sev-medium .kpi-num {{ color:#fcd34d; }} .kpi.sev-low .kpi-num {{ color:#7dd3fc; }}
  .kpi.sev-info .kpi-num {{ color:#cbd5e1; }}
  .panel {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px 24px; margin-bottom:18px; }}
  .panel h2 {{ font-size:16px; margin:0 0 14px; padding-bottom:10px; border-bottom:2px solid var(--line); }}
  table {{ width:100%; border-collapse:collapse; font-size:13px; }}
  th,td {{ text-align:left; padding:7px 10px; border-bottom:1px solid var(--line); }}
  th {{ background:#f8fafc; color:var(--muted); font-weight:600; }}
  td.num, th.num {{ text-align:right; font-variant-numeric:tabular-nums; }}
  .hint {{ color:var(--muted); font-size:12px; margin:8px 0 0; }}
  .filters {{ display:flex; gap:8px; flex-wrap:wrap; margin-bottom:14px; }}
  .filters button {{ border:1px solid var(--line); background:#fff; border-radius:999px; padding:5px 14px;
                     cursor:pointer; font-size:13px; color:var(--fg); }}
  .filters button.on {{ background:#0f172a; color:#fff; border-color:#0f172a; }}
  .finding {{ background:var(--card); border:1px solid var(--line); border-left:5px solid var(--muted);
              border-radius:10px; padding:16px 20px; margin-bottom:14px; }}
  .finding.sev-critical {{ border-left-color:var(--c-critical); }}
  .finding.sev-high {{ border-left-color:var(--c-high); }}
  .finding.sev-medium {{ border-left-color:var(--c-medium); }}
  .finding.sev-low {{ border-left-color:var(--c-low); }}
  .finding.sev-info {{ border-left-color:var(--c-info); }}
  .finding header {{ display:flex; align-items:center; gap:10px; flex-wrap:wrap; }}
  .finding h3 {{ font-size:15px; margin:0; flex:1; }}
  .idx {{ color:var(--muted); font-size:12px; }}
  .badge {{ font-size:12px; font-weight:700; color:#fff; padding:2px 10px; border-radius:999px; background:var(--muted); }}
  .sev-critical .badge {{ background:var(--c-critical); }}
  .sev-high .badge {{ background:var(--c-high); }}
  .sev-medium .badge {{ background:var(--c-medium); }}
  .sev-low .badge {{ background:var(--c-low); }}
  .sev-info .badge {{ background:var(--c-info); }}
  .badge.b-critical {{ background:var(--c-critical); }} .badge.b-high {{ background:var(--c-high); }}
  .badge.b-medium {{ background:var(--c-medium); }} .badge.b-low {{ background:var(--c-low); }}
  .badge.b-info {{ background:var(--c-info); }}
  .warn {{ color:#b45309; background:#fffbeb; border:1px solid #fde68a; border-radius:6px;
           padding:8px 12px; font-size:12.5px; }}
  .muted {{ color:var(--muted); font-size:11.5px; }}
  .cat {{ font-size:12px; color:var(--muted); border:1px solid var(--line); padding:1px 8px; border-radius:4px; }}
  .score {{ font-size:12px; color:var(--muted); }}
  .meta {{ display:flex; gap:18px; flex-wrap:wrap; font-size:12px; color:var(--muted); margin:10px 0; }}
  .meta code {{ background:#f1f5f9; padding:1px 6px; border-radius:4px; color:#0f172a; }}
  .scopenote {{ margin:8px 0 0; padding:6px 10px; font-size:12px; line-height:1.6;
                background:#fffbeb; border:1px solid #fde68a; border-radius:6px; color:#92400e; }}
  .codebox {{ background:#0f172a; border-radius:8px; padding:10px 0; overflow:auto; font-family:Consolas,Menlo,monospace;
              font-size:12.5px; line-height:1.7; }}
  .cl {{ display:flex; white-space:pre; }}
  .cl .lno {{ width:52px; flex:0 0 52px; text-align:right; padding-right:14px; color:#64748b; user-select:none; }}
  .cl .ct {{ color:#e2e8f0; padding-right:16px; }}
  .cl.hit {{ background:#7f1d1d; }} .cl.hit .ct {{ color:#fff; font-weight:600; }}
  .blocks {{ display:grid; grid-template-columns:1fr 1fr; gap:14px; margin-top:12px; }}
  .blk h4 {{ font-size:13px; margin:0 0 6px; color:#0f172a; }}
  .blk p {{ margin:0; font-size:13px; color:#374151; }}
  .blk pre {{ margin:0; background:#f8fafc; border:1px solid var(--line); border-radius:8px; padding:10px 12px;
              font-size:12.5px; white-space:pre-wrap; font-family:Consolas,Menlo,monospace; color:#0f172a; }}
  .blk.fix h4 {{ color:#047857; }}
  ul.deps {{ columns:3; font-size:12.5px; margin:6px 0 0; padding-left:18px; }}
  ul.deps code {{ color:#0f172a; }} ul.deps span {{ color:var(--muted); }}
  ul.deps em {{ font-style:normal; font-size:10.5px; color:#94a3b8; border:1px solid #e2e8f0;
                border-radius:4px; padding:0 5px; margin-left:4px; }}
  footer {{ text-align:center; color:var(--muted); font-size:12px; margin-top:26px; }}
  @media print {{ .filters {{ display:none; }} body {{ background:#fff; }} }}
  @media (max-width:820px) {{ .kpis {{ grid-template-columns:repeat(2,1fr); }} .blocks {{ grid-template-columns:1fr; }} ul.deps {{ columns:1; }} }}
</style>
</head>
<body>
<div class="wrap">
  <header class="top">
    <h1>源代码安全审计报告</h1>
    <div class="sub">
      审计目标 <code>{e(s['root'])}</code>　|　生成时间 {s['scanned_at']}　|　耗时 {s['elapsed']}s<br>
      代码规模 {s['files_total']} 个文件 / {s['lines_total']:,} 行　|　命中文件 {s['files_with_findings']} 个　|　
      风险指数 <b>{s['risk_index']} / 100</b>　|　规则命中 {s['total']} 项（已按上下文降噪 {s['suppressed']} 项）<br>
      作用域分布：生产代码 <b>{sc.get('production', 0)}</b> 项 · 测试/示例代码 <b>{sc.get('test', 0)}</b> 项 · 文档 <b>{sc.get('doc', 0)}</b> 项
    </div>
    <div class="kpis">{cards}</div>
  </header>

  <section class="panel">
    <h2>一、风险总览</h2>
    <table>
      <tr><th>风险等级</th><th class="num">数量</th><th>说明</th></tr>
      <tr><td>严重</td><td class="num">{s['by_severity']['critical']}</td><td>可直接导致凭据泄露 / 代码执行，须立即处置</td></tr>
      <tr><td>高危</td><td class="num">{s['by_severity']['high']}</td><td>可造成数据泄露或服务被控，优先整改</td></tr>
      <tr><td>中危</td><td class="num">{s['by_severity']['medium']}</td><td>需在特定条件下利用，纳入迭代整改</td></tr>
      <tr><td>低危</td><td class="num">{s['by_severity']['low']}</td><td>加固项，建议随版本一并修复</td></tr>
      <tr><td>提示</td><td class="num">{s['by_severity']['info']}</td><td>信息性提示，人工确认是否整改</td></tr>
    </table>
  </section>

  <section class="panel">
    <h2>二、类型分布与高频规则</h2>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:24px;">
      <table><tr><th>漏洞类型</th><th class="num">数量</th></tr>{cat_rows}</table>
      <table><tr><th>高频规则 TOP10</th><th class="num">命中</th></tr>{top_rules}</table>
    </div>
  </section>

  <section class="panel">
    <h2>三、隐患清单</h2>
    <div class="filters">
      <button class="on" data-f="all">全部 {s['total']}</button>
      <button data-f="critical">严重 {s['by_severity']['critical']}</button>
      <button data-f="high">高危 {s['by_severity']['high']}</button>
      <button data-f="medium">中危 {s['by_severity']['medium']}</button>
      <button data-f="low">低危 {s['by_severity']['low']}</button>
      <button data-f="info">提示 {s['by_severity']['info']}</button>
    </div>
    <div id="list">
    {''.join(rows) if rows else '<p class="hint">未发现符合当前规则的隐患。</p>'}
    </div>
  </section>

  <section class="panel">
    <h2>四、验证计划</h2>
    <ol>
      {''.join(f'<li>{v}</li>' for v in VALIDATION_PLAN)}
    </ol>
  </section>

  {vuln_html}

  {deps}

  <footer>本报告由「{TOOL_NAME} v{TOOL_VERSION}」于 {_ts()} 自动生成。<br>
  静态分析存在误报可能，请结合人工复核与动态测试确认。<br>
  {FEEDBACK_TITLE}：<a href="{FEEDBACK_MAILTO}">{FEEDBACK_EMAIL}</a>
  —— 发现误报 / 漏报或希望新增规则，欢迎来信。</footer>
</div>
<script>
document.querySelectorAll('.filters button').forEach(function (b) {{
  b.addEventListener('click', function () {{
    document.querySelectorAll('.filters button').forEach(function (x) {{ x.classList.remove('on'); }});
    b.classList.add('on');
    var f = b.dataset.f;
    document.querySelectorAll('.finding').forEach(function (el) {{
      el.style.display = (f === 'all' || el.dataset.sev === f) ? '' : 'none';
    }});
  }});
}});
</script>
</body>
</html>"""


# ---------------------------------------------------------------------- DOCX
def _docx_severity_chart(doc, engine, s):
    items = []
    for sev in SEVERITY_ORDER:
        cnt = s["by_severity"][sev]
        items.append((SEVERITY_META[sev]["label"], cnt, _docx.SEVERITY_COLOR[sev]))
    doc.add_bar_chart(items)


def to_docx(engine, detail: str = "full", max_findings: int = 0) -> bytes:
    """生成 Word 审计报告。

    detail = "full"    完整明细（每条隐患含代码片段 / 说明 / 修复建议）
    detail = "summary" 仅清单表格（适合条目极多的场景）
    max_findings        明细条数上限，0 表示不限制（summary 模式默认也不限制）
    """
    s = engine.summary()
    e = html.escape
    findings = engine.findings
    truncated = False
    if detail == "full" and max_findings and len(findings) > max_findings:
        findings = findings[:max_findings]
        truncated = True

    doc = _docx.DocxBuilder(
        header_text=f"{TOOL_NAME} · 源代码安全审计报告",
        footer_left=f"{TOOL_NAME} v{TOOL_VERSION} 自动生成 · 反馈 {FEEDBACK_EMAIL}",
    )

    # ============================================== 封面
    doc.add_spacer(1200)
    doc.add_title("源代码安全审计报告", "Source Code Security Audit Report")
    doc.add_spacer(240)
    doc.add_divider()
    doc.add_spacer(200)
    doc.add_kv_line("审计目标", s["root"])
    doc.add_kv_line("报告生成时间", _ts())
    doc.add_kv_line("代码规模", f"{s['files_total']:,} 个文件 / {s['lines_total']:,} 行")
    doc.add_kv_line("扫描耗时", f"{s['elapsed']} 秒")
    doc.add_kv_line("规则命中", f"{s['total']} 项（上下文降噪 {s['suppressed']} 项）")
    doc.add_kv_line("风险指数", f"{s['risk_index']} / 100")
    doc.add_spacer(200)
    doc.add_note(
        "本报告由自动化静态审计引擎生成，采用「正则模式匹配 + 上下文守护降噪」机制。"
        "静态分析存在误报与漏报的可能，报告中列出的每一项均建议结合人工复核确认后再行整改。"
    )
    doc.add_page_break()

    # ============================================== 一、审计概况
    doc.add_heading("一、审计概况", 1)
    doc.add_paragraph(
        f"本次审计针对目录 {s['root']} 下的源代码实施静态安全扫描，"
        f"覆盖 {s['files_total']:,} 个代码与配置文件、累计 {s['lines_total']:,} 行，"
        f"共命中 {s['total']} 项安全风险，其中命中风险的文件 {s['files_with_findings']} 个，"
        f"整体风险指数 {s['risk_index']} / 100。"
    )
    doc.add_table(
        ["指标", "数值", "说明"],
        [
            ["扫描文件数", f"{s['files_total']:,}", "纳入语言识别范围的源码与配置文件"],
            ["代码总行数", f"{s['lines_total']:,}", "所有被扫描文件的物理行数合计"],
            ["命中文件数", f"{s['files_with_findings']:,}", "至少包含一项风险的源文件数量"],
            ["风险项总数", f"{s['total']:,}", "全部严重等级的风险条目合计"],
            ["上下文降噪", f"{s['suppressed']:,}", "因邻近存在长度校验 / 资源释放等防护而被抑制的候选"],
            ["风险指数", f"{s['risk_index']} / 100", "按等级加权归一化后的整体风险度量，越高越危险"],
            ["引擎耗时", f"{s['elapsed']} 秒", "文件遍历 + 全量规则匹配的总耗时"],
            ["生产代码风险", f"{(s.get('by_scope') or {}).get('production', 0)} 项",
             "作用域为生产代码的风险条目（不含测试与文档）"],
        ],
        widths=[2200, 2200, 5238],
        align_right=(1,),
    )

    doc.add_heading("1.1 作用域分布", 2)
    doc.add_paragraph(
        "为避免测试代码与文档示例造成的噪声，引擎对作用域做了区分：测试 / 示例目录下的命中自动下调一级风险，"
        "文档文件中的命中降为「提示」级，需人工确认是否为真实凭据。"
    )
    scope_rows = []
    scope_cn = {"production": "生产代码", "test": "测试 / 示例代码", "doc": "文档与说明文件"}
    scope_desc = {
        "production": "会进入生产运行环境，需优先整改",
        "test": "通常不进入生产，风险降级处理",
        "doc": "说明性内容，多为示例，需人工确认",
    }
    for k in ("production", "test", "doc"):
        scope_rows.append([scope_cn[k], (s.get("by_scope") or {}).get(k, 0), scope_desc[k]])
    doc.add_table(["作用域", "风险项数", "处置建议"], scope_rows,
                  widths=[2400, 1800, 5438], align_right=(1,))

    # ============================================== 二、风险总览
    doc.add_page_break()
    doc.add_heading("二、风险总览", 1)
    doc.add_paragraph("按下述等级标准对全部风险条目进行分级，等级越高越需要优先处置。")
    sev_desc = {
        "critical": "可直接导致凭据泄露或代码执行，须立即处置",
        "high": "可造成数据泄露或服务被控，优先整改",
        "medium": "需在特定条件下被利用，纳入迭代计划整改",
        "low": "安全加固项，建议随版本一并修复",
        "info": "信息性提示，人工确认是否需要整改",
    }
    doc.add_table(
        ["风险等级", "数量", "占比", "处置要求"],
        [
            [SEVERITY_META[sev]["label"], s["by_severity"][sev],
             (f"{s['by_severity'][sev] / s['total'] * 100:.1f}%" if s["total"] else "0.0%"),
             sev_desc[sev]]
            for sev in SEVERITY_ORDER
        ] + [["合计", s["total"], "100.0%", "—"]],
        widths=[1400, 1100, 1200, 5938],
        align_right=(1, 2),
    )
    doc.add_heading("2.1 等级分布图", 2)
    _docx_severity_chart(doc, engine, s)

    # ============================================== 三、类型与热点
    doc.add_page_break()
    doc.add_heading("三、漏洞类型与风险热点", 1)

    doc.add_heading("3.1 漏洞类型分布", 2)
    cat_items = [(label, s["by_category"][cat], "2563EB")
                 for cat, label in CATEGORY_META.items() if s["by_category"].get(cat)]
    if cat_items:
        doc.add_table(["漏洞类型", "数量", "占比"],
                      [[lab, v, f"{v / s['total'] * 100:.1f}%" if s["total"] else "0.0%"]
                       for lab, v, _ in cat_items],
                      widths=[4400, 1400, 1400, 2438], align_right=(1, 2))
    else:
        doc.add_paragraph("未发现任何类型的漏洞命中。")

    doc.add_heading("3.2 风险热点文件 TOP15", 2)
    top_files = s.get("top_files") or []
    if top_files:
        doc.add_table(
            ["序号", "文件路径", "命中数", "最高等级"],
            [[i, tf["file"], tf["count"], SEVERITY_META.get(tf.get("worst", "info"), {}).get("label", "—")]
             for i, tf in enumerate(top_files[:15], 1)],
            widths=[700, 5738, 1200, 2000], align_right=(0, 2), mono_cols=(1,),
        )
    else:
        doc.add_paragraph("无热点文件记录。")

    doc.add_heading("3.3 高频规则 TOP10", 2)
    if s["top_rules"]:
        doc.add_table(
            ["规则编号", "命中次数", "所属类型", "风险等级"],
            [[t["rule_id"], t["count"], t.get("category_label", "—"),
              SEVERITY_META.get(t.get("severity", "info"), {}).get("label", "—")]
             for t in s["top_rules"]],
            widths=[2400, 1400, 2838, 2000], align_right=(1,), mono_cols=(0,),
        )
    else:
        doc.add_paragraph("无规则命中记录。")

    # ============================================== 四、隐患清单
    doc.add_page_break()
    doc.add_heading("四、隐患清单与整改建议", 1)

    if detail == "summary":
        doc.add_paragraph(
            f"本清单以表格形式列出全部 {len(findings)} 项风险，"
            "包含风险等级、规则编号、问题名称与代码定位，便于批量跟踪整改。"
        )
        rows = []
        for i, f in enumerate(findings, 1):
            rows.append([
                i, f["severity_label"], f["title"],
                f"{f['file']}:{f['line']}",
                f["rule_id"], f["category_label"],
            ])
        doc.add_table(["序号", "等级", "问题名称", "代码定位", "规则编号", "类型"],
                      rows, widths=[600, 800, 2600, 3038, 1400, 1200],
                      align_right=(0,), mono_cols=(3, 4), font_size=17)
    else:
        doc.add_paragraph(
            f"以下按风险等级由高到低列出全部 {len(findings)} 项风险明细，"
            "每项包含规则信息、代码定位、命中代码片段、风险说明与修复建议。"
            + (f"（因条目过多，本报告明细仅列出前 {len(findings)} 项，"
               "完整数据请导出 JSON 或 CSV 格式。）" if truncated else "")
        )

        summary_by_sev = {}
        for f in findings:
            summary_by_sev.setdefault(f["severity"], []).append(f)

        seq = 0
        for sev in SEVERITY_ORDER:
            group = summary_by_sev.get(sev)
            if not group:
                continue
            doc.add_heading(f"4.{SEVERITY_ORDER.index(sev) + 1} {SEVERITY_META[sev]['label']}（{len(group)} 项）", 2)
            for f in group:
                seq += 1
                doc.add_heading(f"{seq}. [{f['severity_label']}] {f['title']}", 3)
                doc.add_kv_line("规则编号 / CWE",
                                f"{f['rule_id']}　/　{f['cwe']}　/　置信度 {f['confidence']}　/　风险分 {f['score']}")
                doc.add_kv_line("代码定位",
                                f"{f['file']}　第 {f['line']} 行 第 {f['column']} 列　"
                                f"（语言 {f.get('lang', 'text')}）")
                if f.get("scope") and f["scope"] != "production":
                    doc.add_kv_line("作用域", SCOPE_CN.get(f["scope"], f["scope"]))
                if f.get("scope_note"):
                    doc.add_note(f["scope_note"])

                snip = f.get("snippet") or []
                if snip:
                    start_no = snip[0]["n"]
                    doc.add_paragraph("命中代码", size=19, bold=True, color="334155", before=60, after=40)
                    doc.add_code_block(
                        [ln["text"] for ln in snip],
                        start_no=start_no,
                        hit_lines={ln["n"] for ln in snip if ln.get("hit")},
                    )

                doc.add_paragraph("风险说明", size=19, bold=True, color="334155", before=60, after=40)
                doc.add_paragraph(f["description"], size=19)

                doc.add_paragraph("修复建议", size=19, bold=True, color="047857", before=60, after=40)
                rem = (f.get("remediation") or "").split("\n")
                doc.add_code_block(rem, start_no=1)

                refs = f.get("references") or []
                if refs:
                    doc.add_paragraph("参考资料：" + "　".join(str(r) for r in refs[:3]),
                                      size=17, color="6B7280")
                doc.add_divider()

    # ============================================== 五、验证计划
    doc.add_page_break()
    doc.add_heading("五、验证与闭环计划", 1)
    doc.add_paragraph("整改完成后须按下述步骤逐项验证，确保风险真实收敛且不出现回归。")
    for i, line in enumerate(VALIDATION_PLAN, 1):
        doc.add_ordered(i, line)

    # ============================================== 六、依赖已知漏洞（SCA）
    v = vuln_result(engine)
    vf = (v or {}).get("findings") or []
    if vf:
        doc.add_page_break()
        doc.add_heading("六、第三方依赖已知漏洞（SCA）", 1)
        vs = v.get("summary") or {}
        doc.add_paragraph(vuln_headline(v))
        doc.add_paragraph(
            f"数据源：OSV.dev（https://osv.dev）；查询依赖 {vs.get('queried', 0)} 个，"
            f"分析耗时 {v.get('elapsed', 0)} 秒。"
            + (f"本次未能联网（{v.get('error')}），结果基于本地缓存，时效性可能不足。"
               if v.get("error") and not v.get("online") else "在线数据已在本次分析中更新。")
            + (f"另有 {vs.get('unresolved', 0)} 个依赖因版本由外部父 POM / BOM 管理而无法比对，"
               f"需执行 mvn dependency:tree 后复扫。" if vs.get("unresolved") else ""),
            size=19, color="6B7280")
        rows = [[i, SEVERITY_META.get(f["severity"], {}).get("label", f["severity"]),
                 f["cvss"] if f["cvss"] is not None else "—",
                 f["vuln_id"], f["cve"] or "—", f["title"][:70],
                 f["package"], f["version"], f["fixed"] or "—",
                 FIX_CN.get(f["fix_kind"], f["fix_kind"])]
                for i, f in enumerate(vf, 1)]
        doc.add_table(["#", "等级", "CVSS", "漏洞编号", "CVE", "风险名称",
                       "受影响依赖", "当前版本", "修复版本", "修复跨度"],
                      rows, widths=[300, 620, 480, 1500, 1250, 2200, 1500, 900, 900, 1100],
                      align_right=(0, 2), mono_cols=(3, 6, 7, 8), font_size=14)
        doc.add_heading("6.1 修复建议明细", 2)
        for i, f in enumerate(vf, 1):
            doc.add_heading(f"{i}. [{SEVERITY_META.get(f['severity'], {}).get('label', f['severity'])}]"
                            f" {f['title']}", 3)
            doc.add_bullet(f"受影响依赖：{f['package']}@{f['version']}"
                           f"（{ECO_CN.get(f['ecosystem'], f['ecosystem'])}，"
                           f"来源清单 {f['manifest']}）")
            doc.add_bullet(f"漏洞编号：{f['vuln_id']}"
                           + (f" / {f['cve']}" if f["cve"] else "")
                           + (f"　其它别名：{', '.join((f.get('also_ids') or [])[:3])}"
                              if f.get("also_ids") else ""))
            if f["cvss"] is not None:
                doc.add_bullet(f"CVSS 基础分：{f['cvss']}（{f['cvss_vector']}）")
            doc.add_bullet(f"修复建议：{f['advice']}")
            if f.get("command"):
                doc.add_bullet(f"升级命令：{f['command']}")
            if f.get("references"):
                doc.add_bullet(f"参考链接：{f['references'][0]['url']}")

    # ============================================== 七、依赖清单
    if engine.deps:
        doc.add_page_break()
        doc.add_heading("七、第三方依赖清单", 1)
        dm = getattr(engine, "deps_meta", {}) or {}
        doc.add_paragraph(
            f"从代码库的清单文件中解析到 {len(engine.deps)} 项第三方依赖"
            f"（清单文件 {dm.get('manifests', 0)} 个）。版本可信度说明："
            "「精确」来自锁定文件或明确版本声明；「区间下界」由 ^1.2.3 一类区间取下界得到，"
            "可能比实际安装版本更旧；「未解析」的版本由外部父 POM / BOM 提供，未纳入漏洞比对。"
        )
        dep_rows = [[i, d["name"], d["version"] or "—",
                     {"exact": "精确", "floor": "区间下界",
                      "unresolved": "未解析"}.get(d.get("version_kind"), ""),
                     ECO_CN.get(d.get("ecosystem", ""), d.get("ecosystem", "")),
                     "是" if d.get("indirect") else "否", d.get("manifest", "")]
                    for i, d in enumerate(engine.deps[:400], 1)]
        doc.add_table(["序号", "依赖包", "版本", "版本可信度", "生态", "间接", "来源清单"],
                      dep_rows, widths=[500, 2500, 1600, 900, 1400, 600, 2138],
                      align_right=(0,), mono_cols=(1, 2), font_size=15)
        if len(engine.deps) > 400:
            doc.add_paragraph(f"（依赖共 {len(engine.deps)} 项，本表仅列出前 400 项，"
                              "完整清单请导出 CSV 或 JSON。）", size=18, color="6B7280")

    # ============================================== 附录
    doc.add_page_break()
    doc.add_heading("附录：审计方法与局限说明", 1)
    doc.add_heading("A.1 技术方法", 2)
    doc.add_bullet("引擎类型：基于规则的静态应用安全测试（Pattern-based SAST），无需编译或构建索引。")
    doc.add_bullet("规则体系：内置规则按 10 类风险划分，覆盖注入、越界、敏感信息泄露、认证授权、"
                   "加密与随机数、不安全反序列化、路径遍历、配置缺陷、资源管理、代码质量等。")
    doc.add_bullet("三层降噪：① 同行排除（注释行、已使用安全 API 的行）；"
                   "② 上下文守护（向上若干行内若存在长度校验、资源释放等防护则抑制告警）；"
                   "③ 作用域降级（测试 / 示例代码降一级，文档降为提示）。")
    doc.add_bullet("风险评分：等级基础分 × 置信度系数，按全量归一化后得到 0-100 的风险指数。")
    doc.add_bullet("依赖漏洞检测（SCA）：解析 pom.xml / build.gradle / package.json / "
                   "package-lock.json / go.mod / requirements.txt / pyproject.toml / "
                   "Gemfile.lock / composer.lock / Cargo.lock / *.csproj 等清单，"
                   "向 OSV.dev 查询已知漏洞；CVSS 基础分按 FIRST 规范在本地计算，"
                   "修复版本由公告的版本区间（introduced / fixed / last_affected）推导。")

    doc.add_heading("A.2 已知局限", 2)
    doc.add_bullet("不具备跨文件数据流 / 污点追踪能力，无法还原「入口接收参数 → 跨函数传递 → 汇点拼接」的完整链路。")
    doc.add_bullet("以模式匹配为主，对动态拼接、反射调用、序列化框架包装等间接写法存在漏报。")
    doc.add_bullet("越界检查、资源释放等规则的误报率相对偏高，已在规则元数据中标记为低置信度，需人工复核。")
    doc.add_bullet("不进行依赖漏洞的可达性分析：报告中列出的依赖漏洞表示「该版本存在已知漏洞」，"
                   "是否真正可被利用需结合调用链与部署配置人工判断。")
    doc.add_bullet("依赖清单以源码内清单文件为准，不解析传递依赖（除非仓库内存在 lockfile 或 "
                   "mvn dependency:tree 输出）。版本由外部父 POM / BOM 提供的依赖无法比对，"
                   "报告中已单独说明数量。")
    doc.add_bullet("OSV.dev 的公告可能存在更新延迟；报告中的漏洞库数据龄期可在界面查看。")
    doc.add_bullet("不提供自动修复：升级操作涉及业务兼容性，须由研发评估后执行并回归测试。")
    doc.add_bullet("建议将本工具作为第一遍快速筛查，并与 CodeQL / Semgrep / gosec 等工具形成互补。")

    doc.add_heading("A.3 免责声明", 2)
    doc.add_note(
        "本报告由自动化工具生成，仅作为安全评估的辅助输入，不构成任何形式的安全保证。"
        "报告结论应结合业务上下文、人工代码审计与动态渗透测试综合判断。"
    )

    doc.add_heading("A.4 问题反馈与沟通", 2)
    doc.add_paragraph(
        f"使用过程中如遇到误报 / 漏报、规则命中不符合预期、导出异常，"
        f"或希望新增审计规则、改进汇报口径，欢迎反馈至：{FEEDBACK_EMAIL}"
    )
    doc.add_bullet(f"反馈邮箱：{FEEDBACK_EMAIL}")
    doc.add_bullet(f"邮件主题建议：{FEEDBACK_SUBJECT_PREFIX} 简要问题描述")
    doc.add_bullet("为便于定位问题，请在邮件中附上：工具版本号（见本页页脚）、"
                   "操作系统与 Python 版本、可复现的操作步骤，以及界面上「反馈」面板"
                   "一键复制的环境诊断信息。")
    doc.add_bullet("工具界面右上角「反馈」按钮同样提供邮件入口与诊断信息复制，无需手工整理。")

    return doc.to_bytes()
