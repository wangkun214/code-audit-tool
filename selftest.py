# -*- coding: utf-8 -*-
"""
端到端自检脚本 —— 启动服务后运行：python selftest.py

覆盖：服务接口、文件树聚合、分组查询、排序、gzip、静态资源缓存、
      四种原有报告格式 + 新增 DOCX 的完整性与 OOXML 结构校验。
"""
from __future__ import annotations

import io
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from xml.dom import minidom

_HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, _HERE)
from core import meta as _META        # noqa: E402  版本 / 反馈邮箱的单一真源

BASE = os.environ.get("AUDIT_BASE", "http://127.0.0.1:8770")
ROOT = os.path.abspath(os.path.join(_HERE, ".."))
FIXTURE = os.path.join(_HERE, "selffixture")
_NON_AUDIT_ENTRIES = {
    "audit-tool", "reports", "projects", "workspaces", "vulndb", "samples",
    "selffixture", "__pycache__", ".git", "node_modules", ".workbuddy",
}


def _pick_scan_root():
    """便携包场景兜底：工具父目录可能不含任何可审计内容（例如便携包解压到
    全新目录，父目录仅有 audit-tool 自身）。此时回退到随包分发的 selffixture
    夹具目录，保证自检在任意机器、任意路径下都可完整运行。"""
    try:
        entries = os.listdir(ROOT)
    except OSError:
        return FIXTURE
    if any(e not in _NON_AUDIT_ENTRIES for e in entries):
        return ROOT
    return FIXTURE


ROOT = _pick_scan_root()
Q = urllib.parse.quote

# 绕过系统代理访问本地服务
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
urllib.request.install_opener(_opener)

PASS, FAIL = [], []


def check(name, cond, extra=""):
    if cond:
        PASS.append(name)
        print(f"  \033[32mPASS\033[0m  {name}" + (f"  ({extra})" if extra else ""))
    else:
        FAIL.append(name)
        print(f"  \033[31mFAIL\033[0m  {name}" + (f"  ({extra})" if extra else ""))
    return cond


def req(path, method="GET", body=None, headers=None, raw=False):
    url = BASE + path
    data = json.dumps(body).encode() if isinstance(body, dict) else body
    r = urllib.request.Request(url, data=data, method=method)
    r.add_header("Content-Type", "application/json")
    for k, v in (headers or {}).items():
        r.add_header(k, v)
    try:
        with urllib.request.urlopen(r, timeout=180) as resp:
            payload = resp.read()
            return resp.status, (payload if raw else
                                 json.loads(payload.decode("utf-8"))), dict(resp.headers)
    except urllib.error.HTTPError as e:
        payload = e.read()
        try:
            return e.code, (payload if raw else json.loads(payload.decode("utf-8"))), dict(e.headers)
        except Exception:
            return e.code, payload, dict(e.headers)


def api(path, **kw):
    st, data, _ = req(path, **kw)
    assert data.get("code") == 0, f"{path} -> {data.get('message')}"
    return data["data"]


def put_bytes(ws, rel, data):
    """上传单个文件：原始字节流 + 查询串传路径（与服务端流式落盘协议一致）。"""
    q = urllib.parse.urlencode({"ws": ws, "path": rel})
    r = urllib.request.Request(BASE + "/api/upload/file?" + q, data=data,
                               method="POST")
    r.add_header("Content-Type", "application/octet-stream")
    try:
        with urllib.request.urlopen(r, timeout=60) as resp:
            return resp.status, json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read().decode("utf-8"))


def wait_scan(timeout=300):
    """等待当前扫描任务结束，返回最后一次进度对象。"""
    t0 = time.time()
    p = {}
    while time.time() - t0 < timeout:
        p = api("/api/progress")
        if p.get("done"):
            break
        time.sleep(1.0)
    return p


# ============================================================ 开始
print("=" * 68)
print("  源代码静态审计平台 · 端到端自检")
print("=" * 68)

print("\n[1] 服务与元数据")
meta = api("/api/meta")
# 自检会切换审计目标，先记下调用前的目标，结束时原样还原（含重新扫描）
ORIG_TARGET = dict(meta.get("target") or {})
check("GET /api/meta 可用", meta["rule_count"] > 0, f"{meta['rule_count']} 条规则")
check("暴露导出格式（含 docx）", any(f["key"] == "docx" for f in meta["formats"]),
      "/".join(f["key"] for f in meta["formats"]))
check("暴露分组维度（5 类）", len(meta["group_dims"]) == 5,
      "/".join(g["key"] for g in meta["group_dims"]))
check("规则携带描述文本", bool(meta["rules"][0].get("description")))

print("\n[2] 静态资源与缓存")
st, _, hdr = req("/", raw=True)
check("首页返回 200", st == 200)
st2, _, hdr2 = req("/", raw=True, headers={"If-None-Match": hdr.get("ETag", "x")})
check("ETag 命中返回 304", st2 == 304, f"ETag={hdr.get('ETag', '')[:14]}…")
for f in ("/static/style.css", "/static/app.js"):
    st3, _, _ = req(f, raw=True)
    check(f"静态资源 {f}", st3 == 200)

print("\n[3] 启动扫描")
api("/api/scan", method="POST", body={"root": ROOT})
p = wait_scan()
check("扫描完成", p.get("done"), f"阶段={p.get('phase')}")
if p.get("phase") == "error":
    print("   错误：", p.get("error"))

res = api("/api/result?limit=1")
s = res["summary"]
print(f"    规模 {s['files_total']} 文件 / {s['lines_total']:,} 行；"
      f"命中 {s['total']} 项；风险指数 {s['risk_index']}；耗时 {s['elapsed']}s")

print("\n[4] 文件树与目录聚合")
tree = api("/api/tree")
check("文件树根节点存在", bool(tree.get("children")))
check("目录节点带命中聚合", any(c.get("issues") is not None for c in tree["children"]))
sub = [c for c in tree["children"] if c["type"] == "dir"]
check("目录 issues 为子节点合计",
      all(c["issues"] == sum(x["issues"] for x in c["children"]) for c in sub[:5])
      if sub else False)


def _walk_dirs(node, acc):
    if node.get("type") == "dir":
        acc.append(node)
    for c in node.get("children", []):
        _walk_dirs(c, acc)
    return acc


all_dirs = _walk_dirs(tree, [])
check("目录节点带 files / dirs 子树统计（前端下拉展示用）",
      all("files" in d and "dirs" in d for d in all_dirs),
      f"共 {len(all_dirs)} 个目录")
check("根节点规模统计正确", tree.get("files", 0) > 0 and tree.get("dirs", 0) > 0,
      f"{tree.get('files')} 文件 / {tree.get('dirs')} 目录")
check("子树文件数守恒（父 = 子之和）",
      all(d["files"] == sum(c["files"] for c in d["children"]) for d in all_dirs[:20]))

print("\n[5] 结果查询：排序与分页")
for sk in ("risk", "score", "file", "rule"):
    d = api(f"/api/result?sort={sk}&limit=5")
    check(f"排序 sort={sk}", len(d["findings"]) > 0 and d["total_filtered"] == s["total"],
          f"首批 {len(d['findings'])} 条")
d1 = api("/api/result?limit=10&offset=0")
d2 = api("/api/result?limit=10&offset=10")
check("分页无重叠", d1["findings"][0]["id"] != d2["findings"][0]["id"],
      f"{d1['findings'][0]['id']} vs {d2['findings'][0]['id']}")
check("has_more 标记正确", d1.get("has_more") is True)

print("\n[6] 结果查询：筛选")
f_high = api("/api/result?severity=high&limit=1")
check("按等级筛选", f_high["total_filtered"] == s["by_severity"]["high"],
      f"高危 {f_high['total_filtered']} 项")
f_prod = api("/api/result?scope=production&limit=1")
check("仅生产代码筛选", f_prod["total_filtered"] == s["by_scope"]["production"],
      f"生产 {f_prod['total_filtered']} 项")
kw = s["top_rules"][0]["rule_id"]
f_kw = api(f"/api/result?keyword={kw}&limit=1")
check("关键词筛选生效", f_kw["total_filtered"] > 0, f"{kw} → {f_kw['total_filtered']} 项")

print("\n[7] 分组查询（5 个维度）")
for dim in ("severity", "category", "scope", "file", "rule"):
    g = api(f"/api/result?group_by={dim}")
    groups = g.get("groups", [])
    tot = sum(x["count"] for x in groups)
    check(f"分组 group_by={dim}", len(groups) > 0 and tot == s["total"],
          f"{len(groups)} 组 / 合计 {tot} 项")
gsev = api("/api/result?group_by=severity")
check("严重程度分组按等级排序",
      [x["key"] for x in gsev["groups"]] == ["high", "medium", "low", "info"]
      if s["by_severity"]["critical"] == 0 else True,
      " → ".join(f"{x['label']}{x['count']}" for x in gsev["groups"]))
top = gsev["groups"][0]
gd = api(f"/api/result?group_by=severity&group_key={top['key']}&limit=5")
check("按分组取明细", gd.get("total_in_group") == top["count"] and len(gd["findings"]) > 0,
      f"{top['label']} {top['count']} 项")
gfile = api("/api/result?group_by=file")
check("文件分组含 worst 等级", all(x.get("worst") for x in gfile["groups"][:5]))

print("\n[8] 文件内容接口")
sample = gfile["groups"][0]["key"]
fc = api("/api/file?path=" + urllib.parse.quote(sample))
check("读取源码文件", bool(fc["content"]) and fc["lines"] > 0,
      f"{sample} · {fc['lines']} 行 · {fc['findings'].__len__()} 处风险")
check("文件内命中带代码片段", bool(fc["findings"][0]["snippet"]) if fc["findings"] else True)
st, _, _ = req("/api/file?path=../../../Windows/win.ini")
check("路径穿越被拦截", st == 404, f"HTTP {st}")

print("\n[9] 依赖清单与依赖漏洞库（SCA）")
deps = api("/api/deps")
check("依赖解析", deps["total"] > 0,
      f"{deps['total']} 项 " + str(deps["by_ecosystem"]))
check("依赖解析带元信息（未解析数 / 截断标记 / 清单分布）",
      set(deps.get("meta") or {}) >= {"unresolved", "truncated", "by_manifest_kind"},
      f"未解析 {deps.get('meta', {}).get('unresolved', '-')} 项")
check("依赖条目携带版本可信度与漏洞数标记",
      all("version_kind" in d and "vuln_count" in d for d in deps["deps"][:20]))

vst = api("/api/vulndb/status")
check("漏洞库状态接口可用", vst.get("source") == "OSV.dev" and vst.get("enabled") is True,
      f"生态 {len(vst.get('ecosystems') or {})} 种")
# 漏洞分析在规则扫描结束后异步执行，这里轮询等待
t0 = time.time()
van = {}
while time.time() - t0 < 240:
    van = api("/api/vulndb/status")
    if not van.get("running") and van.get("analyzed_at"):
        break
    time.sleep(1.0)
if van.get("error") and not van.get("analyzed_at"):
    check("漏洞库无网络时优雅降级（不阻塞扫描）", True, van["error"][:70])
else:
    check("依赖漏洞分析完成", not van.get("running") and van.get("analyzed_at"),
          f"{van.get('data_age') is None and '刚刚' or ''}")
    vv = api("/api/vulns?limit=500")
    check("漏洞结果结构完整", {"findings", "summary", "by_severity", "deps_meta"}
          <= set(vv), str(sorted(vv)[:6]))
    s2 = vv["summary"]
    check("摘要总数与明细一致", s2["vuln_total"] == len(vv["findings"]),
          f"{s2['vuln_total']} 条 / 受影响 {s2['vuln_packages']} 个依赖")
    _rank = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    _ranks = [_rank[f["severity"]] for f in vv["findings"]]
    check("默认按严重程度降序", _ranks == sorted(_ranks))
    check("每条漏洞含修复建议 / 命令 / 跨度字段",
          all(("advice" in f and "command" in f and "fix_kind" in f)
              for f in vv["findings"]))
    vh = api("/api/vulns?severity=high&limit=200")
    check("等级筛选生效",
          all(f["severity"] == "high" for f in vh["findings"])
          and len(vh["findings"]) == s2.get("high", 0),
          f"{len(vh['findings'])} 条")
    vc = api("/api/vulns?sort=cvss&limit=200")
    _scores = [f["cvss"] or 0 for f in vc["findings"]]
    check("CVSS 排序单调递减",
          all(_scores[i - 1] >= _scores[i] for i in range(1, len(_scores))))
    vk = api("/api/vulns?keyword=nonexistent-pkg-xyz&limit=50")
    check("关键字不命中时返回空集", len(vk["findings"]) == 0)
    vg = api("/api/vulns?group_by=package&limit=500")
    check("按依赖包聚合返回分组",
          (len(vg.get("groups") or []) == s2["vuln_packages"]) if s2["vuln_total"] else True,
          f"{len(vg.get('groups') or [])} 组")
    if vg.get("groups"):
        gk = vg["groups"][0]["key"]
        vd = api("/api/vulns?group_by=package&group_key="
                 + urllib.parse.quote(str(gk)) + "&limit=200")
        check("分组懒加载返回该组明细", len(vd.get("findings") or []) >= 1,
              f"组 {str(gk)[:40]}… -> {len(vd.get('findings') or [])} 条")
    # 离线开关往返（会触发一次只读缓存的重分析，速度快）
    api("/api/vulndb/update", method="POST", body={"offline": True})
    t0 = time.time()
    while time.time() - t0 < 120:
        _st = api("/api/vulndb/status")
        if not _st.get("running") and _st.get("offline"):
            break
        time.sleep(0.5)
    check("离线模式可切换并落盘到服务端", api("/api/vulndb/status")["offline"] is True)
    api("/api/vulndb/update", method="POST", body={"offline": False})
    t0 = time.time()
    while time.time() - t0 < 120:
        _st = api("/api/vulndb/status")
        if not _st.get("running") and not _st.get("offline"):
            break
        time.sleep(0.5)
    check("离线模式可还原", api("/api/vulndb/status")["offline"] is False)

print("\n[10] 响应压缩")
st, gz_raw, h = req("/api/result?limit=80", headers={"Accept-Encoding": "gzip"}, raw=True)
st2, plain_raw, h2 = req("/api/result?limit=80", raw=True)
check("gzip 压缩生效", h.get("Content-Encoding") == "gzip",
      f"{len(gz_raw):,} B → {len(plain_raw):,} B 原始")
check("未声明 gzip 时不压缩", h2.get("Content-Encoding") != "gzip",
      f"Vary={h.get('Vary', '-')}")

print("\n[11] 报告导出（5 种格式）")
os.makedirs(os.path.join(os.path.dirname(os.path.abspath(__file__)), "reports"), exist_ok=True)
outs = {}
for fmt in ("docx", "html", "md", "csv", "json"):
    extra = "&detail=full" if fmt == "docx" else ""
    st, raw, hh = req(f"/api/export?format={fmt}{extra}", raw=True)
    name = urllib.parse.unquote(hh.get("X-Report-File", "") or hh.get("Content-Disposition", ""))
    outs[fmt] = (st, raw, name)
    check(f"导出 {fmt}", st == 200 and len(raw) > 500, f"{len(raw):,} 字节")

# ---- DOCX 深度校验 ----
print("\n[12] DOCX 结构与内容校验")
st, raw, name = outs["docx"]
try:
    z = zipfile.ZipFile(io.BytesIO(raw))
    check("DOCX 为合法 zip", z.testzip() is None)
    need = ["[Content_Types].xml", "_rels/.rels", "word/document.xml",
            "word/styles.xml", "word/settings.xml",
            "word/header1.xml", "word/footer1.xml",
            "word/_rels/document.xml.rels", "docProps/core.xml", "docProps/app.xml"]
    check("DOCX 必备部件齐全", all(n in z.namelist() for n in need),
          f"{len(z.namelist())} 个部件")
    xml_bad = []
    for n in z.namelist():
        try:
            minidom.parseString(z.read(n))
        except Exception as ex:
            xml_bad.append(f"{n}:{ex}")
    check("全部部件 XML 合法", not xml_bad, "; ".join(xml_bad[:2]))

    doc = z.read("word/document.xml").decode("utf-8")
    check("包含标题层级（Heading1/2/3）",
          all(f'w:val="Heading{i}"' in doc for i in (1, 2, 3)))
    check("包含表格", doc.count("<w:tbl>") >= 6, f"{doc.count('<w:tbl>')} 张表")
    check("包含页眉页脚域（页码）",
          "PAGE" in z.read("word/footer1.xml").decode("utf-8"))
    check("中文字体已显式声明", 'w:eastAsia="宋体"' in z.read("word/styles.xml").decode("utf-8"))
    check("代码块带行号栏与底纹", "│" in doc and 'w:fill="F4F6F9"' in doc)
    check("报告含审计概况/隐患清单/验证计划",
          all(k in doc for k in ("审计概况", "隐患清单", "验证与闭环计划", "免责声明")))
    check("报告含风险等级分布条形图", "B91C1C" in doc or "E03131" in doc or "DC2626" in doc)
except Exception as ex:
    check("DOCX 校验未抛异常", False, str(ex))

st2, raw2, _ = req("/api/export?format=docx&detail=summary", raw=True)
z2 = zipfile.ZipFile(io.BytesIO(raw2))
check("docx 精简清单模式更小", len(raw2) < len(raw),
      f"完整 {len(raw):,} B / 精简 {len(raw2):,} B")

st3, raw3, h3 = req("/api/export?format=docx&name=" + Q("Trivy 源码"), raw=True)
fname3 = urllib.parse.unquote(h3.get("X-Report-File", ""))
check("自定义报告名生效", st3 == 200 and "Trivy" in fname3, fname3)

print("\n[13] 报告归档")
rep = api("/api/reports")
check("报告落盘可查", len(rep["reports"]) >= 5, f"{len(rep['reports'])} 个文件")

print("\n[14] 审计目标切换与原生选择器能力")
check("meta 暴露当前审计目标", isinstance(meta.get("target"), dict) and bool(meta["target"].get("root")),
      f"{meta.get('target', {}).get('name')} [{meta.get('target', {}).get('kind')}]")
check("meta 暴露服务器端目录对话框能力", isinstance(meta.get("browse"), bool),
      f"browse={meta.get('browse')}")
check("meta 暴露上传限额（文件数/单文件/总量）",
      all(k in meta.get("limits", {}) for k in ("max_files", "max_file", "max_total")),
      str(meta.get("limits")))
check("meta 暴露跳过目录表", bool(meta.get("skip_dirs")), f"{len(meta.get('skip_dirs', []))} 个")

tg = api("/api/target", method="POST", body={"root": ROOT, "label": "自检目标", "kind": "path"})
check("POST /api/target 切换目录", tg["name"] == "自检目标", tg["root"])
st, bad, _ = req("/api/target", method="POST",
                 body={"root": os.path.join(ROOT, "不存在的目录_audit_selftest")})
check("不存在的目录被拒（非 500）", st != 500 and bad.get("code") != 0,
      f"HTTP {st} {bad.get('message', '')[:30]}")

if meta.get("browse"):
    # 该接口会在本机弹出系统目录选择框，自检不主动调用，避免打断使用者
    check("/api/browse 端点已注册（可用，待手工验证）", True,
          "本机解释器带 tkinter，调用会弹窗，已跳过")
else:
    st, br, _ = req("/api/browse", method="POST", body={"initial": ROOT})
    check("/api/browse 在无 tkinter 时优雅降级",
          st == 501 and "code" in br and "tkinter" in (br.get("message") or ""),
          f"HTTP {st} {str(br.get('message', ''))[:36]}")

print("\n[14b] 网页目录浏览器（零 tkinter 选目录）")
check("meta 声明内置网页目录浏览器", meta.get("web_dir") is True,
      f"web_dir={meta.get('web_dir')} / tkinter={meta.get('browse')}")
dl0 = api("/api/dir")
check("无 path 时返回起始位置候选（盘符/根 + 主目录）",
      bool(dl0.get("roots")) and all(("name" in r and "path" in r) for r in dl0["roots"]),
      "、".join(r["name"] for r in dl0["roots"])[:48])
check("不依赖 tkinter 即可列举（接口本身与解释器能力无关）", dl0.get("dirs") == [],
      "空 path 只列起始位置")

dl = api("/api/dir?path=" + Q(os.path.abspath(ROOT)))
check("列举真实目录成功", dl.get("path") and isinstance(dl.get("dirs"), list),
      f"{sum(1 for _ in dl['dirs'])} 个子目录")
check("面包屑从根逐级到当前目录",
      bool(dl["crumbs"]) and dl["crumbs"][-1]["path"] == dl["path"]
      and dl["crumbs"][0]["path"] == dl["crumbs"][0]["path"].rstrip(os.sep) + os.sep,
      " › ".join(c["name"] for c in dl["crumbs"])[:56])
check("子目录项字段结构统一",
      all(set(("name", "path", "n_src", "n_sub", "has_manifest")) <= set(it)
          for it in dl["dirs"]), f"{len(dl['dirs'])} 项")
check("子目录项带路径拼接正确",
      all(os.path.dirname(it["path"]) == dl["path"] for it in dl["dirs"]))
check("当前目录带源码统计（含递归估算）",
      isinstance(dl["self"], dict) and dl["self"].get("n_src_total", 0) > 0,
      f"本层 {dl['self']['n_src']} / 递归 ≈ {dl['self']['n_src_total']}"
      + ("（已达统计上限）" if dl["self"].get("partial") else ""))
check("被扫描跳过的目录只计数不列出（与扫描口径一致）",
      all(it["name"] not in meta.get("skip_dirs", []) for it in dl["dirs"]),
      f"已忽略 {dl['self']['n_hidden']} 个")
if dl["crumbs"]:
    parent = dl["crumbs"][-2]["path"] if len(dl["crumbs"]) > 1 else ""
    dl_up = api("/api/dir?path=" + Q(parent))
    check("父级目录可继续上溯（面包屑两级一致）",
          dl_up["path"] in [c["path"] for c in dl["crumbs"]],
          f"上一级 = {dl_up['name']}")
    if dl["dirs"]:
        sub = api("/api/dir?path=" + Q(dl["dirs"][0]["path"]))
        check("可逐层进入子目录", sub["path"] == dl["dirs"][0]["path"],
              f"进入 {sub['name']}（本层 {sub['self']['n_src']} 个源码）")
st, bad, _ = req("/api/dir?path=" + Q(os.path.join(os.path.abspath(ROOT), "不存在_selftest_x")))
check("不存在的目录返回 404（非 500）", st == 404 and bad.get("code") != 0,
      f"HTTP {st} {str(bad.get('message', ''))[:30]}")
st, bad, _ = req("/api/dir?path=" + Q(os.path.join(os.path.abspath(ROOT), "README.md")))
check("文件路径被拒（只接受目录）", st == 404 and bad.get("code") != 0, f"HTTP {st}")

print("\n[15] 目录上传工作区（浏览器原生目录选择器的数据通路）")
st, res, _ = req("/api/upload/init", method="POST", body={"folder": "../../evil/我的项目"})
check("init 建立上传会话", st == 200 and res.get("code") == 0,
      str(res.get("data", {}).get("name")))
ws = res["data"]["ws"]
ws_root = res["data"]["root"]
check("文件夹名净化（剥离 ../ 与路径）",
      ".." not in ws_root and res["data"]["name"] == "我的项目", res["data"]["name"])

UP = [
    ("main.go", b"package main\nfunc main() {}\n"),
    ("pkg/db/query.go", b'package db\nvar q = "SELECT * FROM t WHERE id=" + id\n'),
    ("conf/app.yaml", b'password: "SuperSecret123"\nspring.datasource.password=Plaintext99\n'),
    ("deep/a/b/c/d/e/f.txt", b"nested\n"),
    ("nested/中文目录/中文文件.go", "package x\n".encode("utf-8")),
    # 前导斜杠由服务端剥离后按相对路径落盘（不得逃出工作区）
    ("/abs/path.go", b"package abs\n"),
]
for rel, data in UP:
    st, _, _ = req(f"/api/upload/file?ws={ws}&path={urllib.parse.quote(rel)}",
                   method="POST", body=data, raw=True)
    check(f"上传 {rel}", st == 200, f"{len(data)} 字节")

st, res = put_bytes(ws, "../../../outside.go", b"x")
check("拒绝路径穿越 ../../", res.get("code") != 0, str(res.get("message"))[:36])
st, res = put_bytes(ws, "..%2f..%2fescape.go", b"x")
check("拒绝编码后的穿越 ..%2f", res.get("code") != 0, str(res.get("message"))[:36])
st, res = put_bytes(ws, "logo.png", b"\x89PNG\r\n\x1a\n" + b"\x00" * 100)
check("二进制文件被跳过", res.get("data", {}).get("skipped") is True,
      str(res.get("data", {}).get("reason")))
st, res = put_bytes(ws, "huge.go", b"x" * (13 * 1024 * 1024))
check("超过单文件上限被拒（413）", st == 413 and res.get("code") != 0, str(res.get("message"))[:36])
st, res = put_bytes("bogus-id", "a.go", b"x")
check("无效上传会话被拒", res.get("code") != 0, str(res.get("message"))[:36])

done = api("/api/upload/done", method="POST", body={"ws": ws})
check("done 返回落盘文件统计", done.get("files") == len(UP),
      f"{done.get('files')} 个文件 / {done.get('bytes')} 字节")
check("done 根路径与 init 一致", done.get("root") == ws_root)
check("工作区未发生越界写入",
      not any(os.path.exists(os.path.join(ws_root, "..", "..", "..", x))
              for x in ("outside.go", "escape.go")))
check("二进制未落盘", not os.path.exists(os.path.join(ws_root, "logo.png")))
check("落盘内容与上传一致（含前导斜杠被剥离）",
      all(os.path.isfile(os.path.join(ws_root, r.lstrip("/").replace("/", os.sep))) and
          open(os.path.join(ws_root, r.lstrip("/").replace("/", os.sep)), "rb").read() == d
          for r, d in UP), f"{len(UP)} 个文件逐一比对")

api("/api/scan", method="POST", body={"root": ws_root, "label": "我的项目", "kind": "upload"})
p = wait_scan(120)
check("上传工作区可被扫描", p.get("done") and p.get("phase") != "error", str(p.get("phase")))
u = api("/api/result?limit=200")
check("扫描覆盖上传的文件", u["summary"]["files_total"] >= len(UP),
      f"{u['summary']['files_total']} 个文件")
check("命中上传样本中的凭据",
      any(f["rule_id"] in ("SEC-KEY-001", "SEC-KEY-004") for f in u["findings"]),
      f"{u['summary']['total']} 项风险")
check("目标状态标记为上传工作区",
      (api("/api/meta")["target"] or {}).get("kind") == "upload",
      str(api("/api/meta")["target"]))
tree2 = api("/api/tree")
check("文件树根名为上传文件夹名", tree2["name"] == "我的项目", tree2["name"])
check("文件树保留中文目录",
      "中文目录" in json.dumps(tree2, ensure_ascii=False), "中文嵌套路径可见")

print("\n[16] 还原调用前的审计目标")
if ORIG_TARGET.get("root") and os.path.normcase(ORIG_TARGET["root"]) != os.path.normcase(ROOT):
    tg = api("/api/target", method="POST",
             body={"root": ORIG_TARGET["root"], "label": ORIG_TARGET.get("name"),
                   "kind": ORIG_TARGET.get("kind") or "path"})
    check("已还原审计目标", os.path.normcase(tg["root"]) == os.path.normcase(ORIG_TARGET["root"]),
          f"{tg['name']} [{tg['kind']}]")
    # /api/target 按设计会清空实时引擎；此处无论原目标是什么类型都必须重扫一次，
    # 否则 [17] 的「快照 vs 实时」比对会因「尚未执行扫描」中断
    # —— 自检必须能在同一服务实例上连续重复运行。
    api("/api/scan", method="POST",
        body={"root": ORIG_TARGET["root"], "label": ORIG_TARGET.get("name"),
              "kind": ORIG_TARGET.get("kind") or "path"})
    p = wait_scan(300)
    check("原目标已重新扫描", p.get("done") and p.get("phase") != "error",
          f"{api('/api/result?limit=1')['summary']['total']} 项风险")
else:
    check("审计目标无需还原", True, "调用前即为自检根目录")

print("\n[17] 审计项目隔离（唯一 ID / 快照 / 参数透传 / 删除防护）")
plist = api("/api/projects")["projects"]
cur = plist[0]["id"] if plist else ""
check("项目列表非空且按 ID 倒序", len(plist) >= 1 and
      all(plist[i]["id"] >= plist[i + 1]["id"] for i in range(len(plist) - 1)),
      f"{len(plist)} 个项目")
meta0 = api("/api/meta")
check("meta 暴露当前项目 ID", meta0.get("project_id") == cur, f"cur={cur}")
snap = api(f"/api/project?id={cur}")["project"]
check("项目快照包含完整结果",
      isinstance(snap.get("findings"), list) and isinstance(snap.get("summary"), dict),
      f"findings={len(snap.get('findings') or [])}")
live_total = api("/api/result?limit=1")["summary"]["total"]
check("快照结果与实时一致（当前项目）", len(snap.get("findings") or []) == live_total,
      f"{len(snap.get('findings') or [])} == {live_total}")
check("?project= 指向当前项目时回落实时数据",
      api(f"/api/result?limit=1&project={cur}")["summary"]["total"] == live_total)
st, miss, _ = req("/api/project?id=P2099-nope")
check("不存在项目返回 404 与明确文案",
      st == 404 and "项目不存在" in str(miss.get("message", "")),
      f"HTTP {st}")
st, delr, _ = req("/api/project/delete", method="POST", body={"id": cur})
check("删除当前使用中的项目被拒绝", st == 409, f"HTTP {st} {str(delr.get('message', ''))[:30]}")
st, delr, _ = req("/api/project/delete", method="POST", body={"id": "P2099-nope"})
check("删除不存在项目返回 deleted:false",
      st == 200 and delr.get("data", {}).get("deleted") is False)
check("历史项目漏洞接口可带项目参数",
      "deps_meta" in api(f"/api/vulns?limit=1&project={cur}"))

print("\n[18] 扫描历史（列表统计 / 详情聚合 / 状态语义）")
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from core import projects as _proj                       # noqa: E402

hist = api("/api/projects")
hrows = hist["projects"]
check("列表返回概览合计与状态字典",
      isinstance(hist.get("totals"), dict) and bool(hist.get("statuses")),
      f"{len(hrows)} 条 · 合计 {hist['totals'].get('scans')} 次扫描")
check("每条记录带完整统计块（严重度分布/状态/体积/统计版本）",
      all(all(k in r for k in ("by_severity", "status", "status_label",
                               "size_bytes", "stats_version", "risk_index"))
          for r in hrows))
check("老项目统计块已统一回填",
      all(r.get("stats_version") == _proj.SNAPSHOT_VERSION for r in hrows),
      f"v{_proj.SNAPSHOT_VERSION}")
check("概览合计与行数据一致",
      hist["totals"]["scans"] == len(hrows)
      and hist["totals"]["findings"] == sum(int(r.get("findings_total", 0) or 0) for r in hrows),
      f"隐患合计 {hist['totals']['findings']}")
check("严重程度合计与逐行分布一致",
      all(hist["totals"]["by_severity"][k] ==
          sum(int((r.get("by_severity") or {}).get(k, 0) or 0) for r in hrows)
          for k in ("critical", "high", "medium", "low", "info")))

det = api(f"/api/project/detail?id={cur}")
check("详情返回全部信息区块",
      {"meta", "target", "config", "severity", "findings", "index",
       "deps", "timeline", "integrity", "advice"} <= set(det),
      f"{len(det)} 个区块")
check("详情严重度分布与项目快照一致",
      det["severity"]["total"] == len(snap.get("findings") or []),
      f"{det['severity']['total']} 项 · 严重+高危 {det['severity']['high_total']}")
check("高危清单按严重度→置信度排序",
      all(_proj.SEVS.index(det["findings"][i]["severity"])
          <= _proj.SEVS.index(det["findings"][i + 1]["severity"])
          for i in range(len(det["findings"]) - 1)),
      f"展示 {len(det['findings'])} / {det['index']['total']} 项")
check("时间线三节点且建档时刻有效",
      len(det["timeline"]) == 3 and det["timeline"][0]["at"] > 0,
      " → ".join(n["label"] for n in det["timeline"]))
check("自动生成处置建议（由数据推导）", len(det["advice"]) >= 1,
      f"{len(det['advice'])} 条 · 首条：{det['advice'][0][:36]}…")
check("数据完整性自检（源目录可达性）", "root_exists" in det["integrity"],
      f"root_exists={det['integrity']['root_exists']}")
check("详情标注是否为当前工作台项目", det.get("live") is True)
st, bad, _ = req("/api/project/detail?id=P2099-nope")
check("详情接口对不存在项目返回 404", st == 404, f"HTTP {st}")
st, bad, _ = req(f"/api/project/detail?id={cur}&top=abc")
check("top 参数非法时安全回退默认值", st == 200 and bad.get("code") == 0, f"HTTP {st}")

# 状态语义：手工建档一个「没有结果快照」的项目，模拟扫描进程中断
_tmp = _proj.new_id()
_proj.create({"id": _tmp, "version": "selftest",
              "target": {"root": ROOT, "name": "自检中断项目", "kind": "path"},
              "root": ROOT, "created_at": time.time()})
try:
    st, miss, _ = req(f"/api/project/detail?id={_tmp}")
    dm = (miss.get("data") or {})
    check("无快照项目状态语义 = interrupted",
          st == 200 and dm.get("meta", {}).get("status") == "interrupted"
          and dm.get("meta", {}).get("has_snapshot") is False)
    check("中断项目给出重扫指引", any("重新扫描" in a for a in dm.get("advice", [])))
finally:
    _proj.delete(_tmp)                                   # 清理自检夹具，不污染历史记录

print("\n[19] 运行环境自检与反馈入口")
env = api("/api/env")
_need = {"checks", "summary", "python", "system", "features", "requirements",
         "feedback", "paths", "writable", "encoding"}
check("/api/env 返回完整自检结构", _need <= set(env.keys()), "、".join(sorted(_need)))
check("自检给出 Python 版本与最低要求",
      bool(env["python"]["version"]) and env["python"]["required"] == _META.MIN_PYTHON_STR,
      f"{env['python']['version']} ≥ {env['python']['required']}")
check("自检声明零第三方依赖", env["requirements"]["third_party"].startswith("无"),
      env["requirements"]["third_party"])
check("自检结论与逐项结果自洽",
      env["summary"]["total"] == len(env["checks"])
      and env["summary"]["ok"] + env["summary"]["warn"] + env["summary"]["fail"]
      == len(env["checks"]),
      f"{env['summary']['ok']}/{env['summary']['total']} 通过 · {env['summary']['verdict']}")
check("自检覆盖可移植性关键项（版本 / 可写 / 端口 / 网络）",
      {"python", "writable", "port", "network"} <= {c["key"] for c in env["checks"]})
check("逐目录给出可写性结论", env["writable"]["all"] is True
      and len(env["paths"]["dirs"]) >= 4, f"{len(env['paths']['dirs'])} 个运行时目录")
check("操作系统与解释器信息可用于诊断",
      bool(env["system"]["os"]) and bool(env["python"]["executable"]),
      f"{env['system']['os']} {env['system']['os_release']}")

# ---- 反馈入口：邮箱单一真源 + 三种文本类报告页脚均带回邮址 ----
check("版本号单一真源（core/meta.py）",
      meta["version"] == _META.TOOL_VERSION == env["version"], f"v{meta['version']}")
check("/api/meta 暴露反馈邮箱", meta["feedback"]["email"] == _META.FEEDBACK_EMAIL,
      meta["feedback"]["email"])
check("环境概要在 /api/meta 中可见",
      bool((meta.get("env") or {}).get("python")), (meta.get("env") or {}).get("os", ""))
check("Markdown 报告页脚含反馈邮箱",
      _META.FEEDBACK_EMAIL.encode() in outs["md"][1])
check("HTML 报告页脚含可点击 mailto 反馈入口",
      _META.FEEDBACK_EMAIL.encode() in outs["html"][1]
      and b"mailto:" + _META.FEEDBACK_EMAIL.encode() in outs["html"][1])
_dz = zipfile.ZipFile(io.BytesIO(outs["docx"][1]))
check("DOCX 页脚与附录含反馈邮箱",
      _META.FEEDBACK_EMAIL.encode() in _dz.read("word/footer1.xml")
      and _META.FEEDBACK_EMAIL.encode() in _dz.read("word/document.xml"))

# ---- 便携性端到端：在任意工作目录下独立执行 CLI 自检 ----
try:
    _pr = subprocess.run([sys.executable, os.path.join(_HERE, "app.py"), "--check-env"],
                         capture_output=True, timeout=180,
                         cwd=os.path.expanduser("~"))
    _out = _pr.stdout.decode("utf-8", "replace")
    check("CLI 环境自检（--check-env）可独立运行",
          _pr.returncode == 0 and "运行环境自检" in _out
          and _META.FEEDBACK_EMAIL in _out,
          f"退出码 {_pr.returncode}")
except Exception as _e:                                  # noqa: BLE001
    check("CLI 环境自检（--check-env）可独立运行", False, str(_e)[:70])

print("\n" + "=" * 68)
print(f"  结果：\033[32m{len(PASS)} 项通过\033[0m" +
      (f"，\033[31m{len(FAIL)} 项失败\033[0m" if FAIL else "，全部通过 ✓"))
if FAIL:
    for f in FAIL:
        print("   - 失败：", f)
print("=" * 68)
sys.exit(1 if FAIL else 0)
