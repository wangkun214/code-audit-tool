# -*- coding: utf-8 -*-
"""
依赖漏洞库（SCA）核心离线测试 —— 不发起任何网络请求。

夹具取自 OSV.dev 真实公告的录制形态（lodash 命令注入、Spring 多分支修复、
containerd 同线升级等），覆盖：
  版本比较 / 预发布识别 / 区间归属判定 / 修复版本推导 / 修复跨度分级 /
  CVSS v3 + v2 评分 / 等级归一 / 修复命令生成 / 别名去重 /
  analyze() 端到端（Mock HTTP + 临时缓存 + 缓存命中 + 离线模式）。

运行：python vulntest.py
"""
from __future__ import annotations

import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import cvss, vulndb                                    # noqa: E402

PASS, FAIL = [], []


def check(name, cond, extra=""):
    if cond:
        PASS.append(name)
        print(f"  \033[32mPASS\033[0m  {name}" + (f"  ({extra})" if extra else ""))
    else:
        FAIL.append(name)
        print(f"  \033[31mFAIL\033[0m  {name}" + (f"  ({extra})" if extra else ""))
    return cond


def section(title):
    print(f"\n{title}")


# ================================================================ 夹具数据
# 形态录制自 OSV.dev 真实公告（字段与区间事件顺序均按线上原样，数值未改动）。

V_LODASH = {
    "id": "GHSA-35jh-r3h4-6jhm",
    "summary": "lodash command injection via template",
    "details": "lodash versions prior to 4.17.21 are vulnerable to command injection "
               "via the template function.",
    "aliases": ["CVE-2021-23337", "GHSA-r5fr-rjxr-66jc"],
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"name": "lodash", "ecosystem": "npm"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "4.17.11"}, {"fixed": "4.17.21"}]}],
        "versions": ["4.17.20"],
    }],
    "database_specific": {"severity": "HIGH", "cwe_ids": ["CWE-77"]},
    "references": [
        {"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"},
        {"type": "WEB", "url": "https://security.netapp.com/advisory/ntap-20210416-0006/"},
        {"type": "WEB", "url": "https://github.com/lodash/lodash/pull/5755"},
        {"type": "WEB", "url": "https://www.cve.org/CVERecord?id=CVE-2021-23337"},
    ],
    "published": "2021-02-15T00:00:00Z",
    "modified": "2024-01-09T00:00:00Z",
}

# 同一漏洞的重复公告：信息较少（无 CVSS 向量、引用更少），应被去重合并
V_LODASH_DUP = {
    "id": "GHSA-r5fr-rjxr-66jc",
    "summary": "lodash command injection via template",
    "aliases": ["CVE-2021-23337"],
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"name": "lodash", "ecosystem": "npm"},
        "ranges": [{"type": "ECOSYSTEM",
                    "events": [{"introduced": "4.17.11"}, {"fixed": "4.17.21"}]}],
    }],
    "database_specific": {"severity": "HIGH"},
    "references": [{"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-23337"}],
}

# 多分支案例：5.3.x 分支 last_affected（无修复），6.2.x 有 fixed。
# 若实现简单取"所有 fixed 的最小值"，会误报"升 6.2.7 即可"却掩盖分支事实。
V_SPRING = {
    "id": "GHSA-spring-branches",
    "summary": "Spring Framework DataBinder case-sensitive match issue",
    "aliases": ["CVE-2024-38820"],
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"name": "org.springframework:spring-webmvc", "ecosystem": "Maven"},
        "ranges": [
            {"type": "ECOSYSTEM",
             "events": [{"introduced": "5.3.0"}, {"last_affected": "5.3.39"}]},
            {"type": "ECOSYSTEM",
             "events": [{"introduced": "6.2.0"}, {"fixed": "6.2.7"}]},
        ],
    }],
    "database_specific": {"severity": "HIGH"},
    "references": [{"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2024-38820"}],
}

# 预发布规避案例：命中分支只给了候选版 2.5.0.CR1，更高主版本才有正式版 3.1.0。
V_PRE = {
    "id": "GHSA-pre-release",
    "summary": "only a CR candidate is published for the hit branch",
    "aliases": [],
    "severity": [{"type": "CVSS_V3",
                  "score": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}],
    "affected": [{
        "package": {"name": "acme-lib", "ecosystem": "npm"},
        "ranges": [
            {"type": "ECOSYSTEM",
             "events": [{"introduced": "2.0.0"}, {"fixed": "2.5.0.CR1"}]},
            {"type": "ECOSYSTEM",
             "events": [{"introduced": "3.0.0"}, {"fixed": "3.1.0"}]},
        ],
    }],
    "database_specific": {"severity": "HIGH"},
}

# 今日实测案例：containerd/v2 2.4.0 -> 2.4.1 同版本线升级
V_CONTAINERD = {
    "id": "GHSA-pg57-6jwg-q645",
    "summary": "Containerd has image-pull DoS via crafted OCI index graph amplification",
    "aliases": ["CVE-2026-53493"],
    "severity": [],
    "affected": [{
        "package": {"name": "github.com/containerd/containerd/v2", "ecosystem": "Go"},
        "ranges": [{"type": "SEMVER",
                    "events": [{"introduced": "2.0.0"}, {"fixed": "2.4.1"}]}],
    }],
    "database_specific": {"severity": "MODERATE"},
    "references": [{"type": "WEB", "url": "https://nvd.nist.gov/vuln/detail/CVE-2026-53493"}],
}

# 仅有无前缀 CVSS v2 向量（OSV/NVD 的常态形态）
V_V2ONLY = {
    "id": "GO-v2-only",
    "summary": "legacy advisory with only a bare CVSS v2 vector",
    "aliases": [],
    "severity": [{"type": "CVSS_V2", "score": "AV:N/AC:L/Au:N/C:P/I:P/A:P"}],
    "affected": [{
        "package": {"name": "example/legacy", "ecosystem": "Go"},
        "ranges": [{"type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "1.2.3"}]}],
    }],
    "database_specific": {"severity": "HIGH"},
}

# 完全没有向量与文本等级，只能按中危兜底
V_NOINFO = {
    "id": "GO-noinfo",
    "summary": "advisory without any severity information",
    "affected": [{
        "package": {"name": "example/unknown", "ecosystem": "Go"},
        "ranges": [{"type": "SEMVER",
                    "events": [{"introduced": "0"}, {"fixed": "9.9.9"}]}],
    }],
}

VULNS = {v["id"]: v for v in
         (V_LODASH, V_LODASH_DUP, V_SPRING, V_PRE, V_CONTAINERD, V_V2ONLY, V_NOINFO)}

# 包级批量查询的应答索引：(生态, 包名, 版本) -> [公告编号]
BATCH_INDEX = {
    ("npm", "lodash", "4.17.20"): ["GHSA-35jh-r3h4-6jhm", "GHSA-r5fr-rjxr-66jc"],
    ("Maven", "org.springframework:spring-webmvc", "5.3.39"): ["GHSA-spring-branches"],
    ("npm", "acme-lib", "2.4.0"): ["GHSA-pre-release"],
    ("Go", "github.com/containerd/containerd/v2", "2.4.0"): ["GHSA-pg57-6jwg-q645"],
    ("Go", "example/legacy", "1.0.0"): ["GO-v2-only"],
    ("Go", "example/unknown", "1.0.0"): ["GO-noinfo"],
    ("npm", "left-pad", "1.3.0"): [],
}


def dep(eco, name, version, manifest="pkg.json", **kw):
    """构造与 manifests.parse 输出同形的依赖记录。"""
    d = {
        "ecosystem": eco, "name": name, "version": version, "raw": version,
        "version_kind": "exact", "manifest": manifest, "manifests": [manifest],
        "module": "", "scope": "compile", "indirect": False, "coord": None,
    }
    d.update(kw)
    return d


class FakeHttp:
    """替换 vulndb.Http：按夹具索引应答，并记录每次请求以便断言"真的没联网"。"""
    calls: list = []

    def __init__(self, *a, **k):
        pass

    def json(self, url, payload=None, method="POST"):
        FakeHttp.calls.append((method, url))
        if url == vulndb.OSV_BATCH_URL:
            results = []
            for q in payload.get("queries") or []:
                p = q.get("package") or {}
                ids = BATCH_INDEX.get((p.get("ecosystem"), p.get("name"),
                                       q.get("version")), [])
                results.append({"vulns": [{"id": i} for i in ids]})
            return {"results": results}
        if url.startswith(vulndb.OSV_VULN_URL):
            vid = url[len(vulndb.OSV_VULN_URL):]
            if vid in VULNS:
                return VULNS[vid]
        raise AssertionError(f"夹具未覆盖的请求: {method} {url}")


def run_analyze(deps, cache_path, offline=False):
    """以 Mock HTTP 跑一遍 analyze（调用方负责清零 FakeHttp.calls）。"""
    real_http = vulndb.Http
    vulndb.Http = FakeHttp
    try:
        return vulndb.analyze(deps, cache_path, offline=offline)
    finally:
        vulndb.Http = real_http


# ================================================================ 用例
print("=" * 68)
print("  依赖漏洞库（SCA）· 离线核心测试")
print("=" * 68)

section("\n[1] 版本比较与预发布识别")
check("数字段按数值比较（2.10 > 2.9）", vulndb.cmp_version("2.10.0", "2.9.9") > 0)
check("补丁位比较（4.17.21 > 4.17.20）", vulndb.cmp_version("4.17.21", "4.17.20") > 0)
check("缺段视为 0（1.2 == 1.2.0）", vulndb.cmp_version("1.2", "1.2.0") == 0)
check("候选版低于正式版（6.2.0.CR1 < 6.2.0）", vulndb.cmp_version("6.2.0.CR1", "6.2.0") < 0)
check("相同版本为 0", vulndb.cmp_version("1.0.0", "1.0.0") == 0)
check("识别候选版 6.2.0.CR1", vulndb.is_prerelease("6.2.0.CR1"))
check("识别预发布 1.0.0-rc1", vulndb.is_prerelease("1.0.0-rc1"))
check("正式版 2.4.1 非预发布", not vulndb.is_prerelease("2.4.1"))

section("\n[2] 区间归属判定")
rng_fixed = {"type": "ECOSYSTEM",
             "events": [{"introduced": "4.17.11"}, {"fixed": "4.17.21"}]}
ivs = vulndb.range_intervals(rng_fixed)
check("introduced+fixed 生成单个左闭右开区间", len(ivs) == 1 and ivs[0].get("fix") == "4.17.21")
check("区间内版本命中", vulndb.in_interval("4.17.20", ivs[0]))
check("修复版本本身不命中（fixed 不含）", not vulndb.in_interval("4.17.21", ivs[0]))
check("区间前版本不命中", not vulndb.in_interval("4.17.10", ivs[0]))

rng_last = {"type": "ECOSYSTEM",
            "events": [{"introduced": "5.3.0"}, {"last_affected": "5.3.39"}]}
ivs2 = vulndb.range_intervals(rng_last)
check("last_affected 为闭端且无修复版本",
      len(ivs2) == 1 and not ivs2[0].get("fix"), f"fix={ivs2[0].get('fix')!r}")
check("last_affected 版本本身命中", vulndb.in_interval("5.3.39", ivs2[0]))
check("last_affected 之后不命中", not vulndb.in_interval("5.3.40", ivs2[0]))

section("\n[3] 修复跨度分级")
check("同版本线（4.17.20→4.17.21）", vulndb.fix_kind_of("4.17.20", "4.17.21") == "same-branch")
check("升次版本线（2.7→2.14.0）", vulndb.fix_kind_of("2.7", "2.14.0") == "minor-up")
check("跨主版本（5.3.39→6.2.7）", vulndb.fix_kind_of("5.3.39", "6.2.7") == "major-up")
check("同版本不动（1.0.0→1.0.0）", vulndb.fix_kind_of("1.0.0", "1.0.0") == "same-branch")

section("\n[4] CVSS 评分（v3 值均为 NVD 实证）")
V3_CASES = [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # 经典满分前
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0),  # log4shell
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:H/A:H", 7.2),   # 2026 docker 实测
    ("CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N", 6.8),   # 2026 moby 实测
    ("CVSS:3.1/AV:L/AC:H/PR:L/UI:R/S:C/C:N/I:L/A:H", 6.1),   # 2026 docker 实测
    ("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),   # v3.0 同分
]
for vec, want in V3_CASES:
    score, tag = cvss.base_score(vec)
    check(f"{vec.split('/', 1)[1][:40]}… = {want}", score == want and tag == "CVSS_V3",
          f"实际 {score}/{tag}")
check("v3 前缀向量可被 is_cvss_vector 识别",
      cvss.is_cvss_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))

section("\n[5] CVSS v2 评分（OSV/NVD 常见无前缀形态）")
V2_CASES = [
    ("AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5),
    ("AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0),
    ("CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P", 7.5),
]
for vec, want in V2_CASES:
    score, tag = cvss.base_score(vec)
    check(f"{vec[:36]}… = {want}", score == want and tag == "CVSS_V2",
          f"实际 {score}/{tag}")
check("无前缀 v2 向量可被 is_cvss_vector 识别",
      cvss.is_cvss_vector("AV:N/AC:L/Au:N/C:P/I:P/A:P"))
check("v3 形态不会被误判为 v2",
      not cvss.is_v2_vector("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"))
check("非向量文本不误判", not cvss.is_cvss_vector("not a vector")
      and cvss.base_score("not a vector") == (None, ""))

section("\n[6] 等级归一")
check("9.8 -> critical", cvss.score_to_severity(9.8) == "critical")
check("7.2 -> high", cvss.score_to_severity(7.2) == "high")
check("6.1 -> medium", cvss.score_to_severity(6.1) == "medium")
check("3.7 -> low", cvss.score_to_severity(3.7) == "low")
check("文本 MODERATE -> medium", cvss.text_to_severity("MODERATE") == "medium")
check("文本 IMPORTANT -> high（红帽口径）", cvss.text_to_severity("IMPORTANT") == "high")

section("\n[7] 修复版本推导（区间归属判定）")
fix = vulndb.resolve_fix(V_LODASH, "lodash", "4.17.20")
check("命中区间自带修复版本", fix["fixed"] == "4.17.21" and fix["has_fix"],
      f"fixed={fix['fixed']}")
check("同版本线升级", fix["fix_kind"] == "same-branch")

fix2 = vulndb.resolve_fix(V_SPRING, "org.springframework:spring-webmvc", "5.3.39")
check("last_affected 分支不被误报为可原线修复", fix2["fixed"] == "6.2.7",
      f"fixed={fix2['fixed'] or '—'}")
check("跨主版本升级且标记 has_fix", fix2["fix_kind"] == "major-up" and fix2["has_fix"])

fix3 = vulndb.resolve_fix(V_PRE, "acme-lib", "2.4.0")
check("命中分支只有候选版时改推更高正式版", fix3["fixed"] == "3.1.0",
      f"fixed={fix3['fixed']}")
check("规避预发布后的跨度为跨主版本", fix3["fix_kind"] == "major-up")

fix4 = vulndb.resolve_fix(V_CONTAINERD, "github.com/containerd/containerd/v2", "2.4.0")
check("Go 模块同线升级 2.4.0 -> 2.4.1", fix4["fixed"] == "2.4.1"
      and fix4["fix_kind"] == "same-branch")

section("\n[8] 修复命令生成")
check("npm 命令", vulndb.fix_command(dep("npm", "lodash", "4.17.20"),
                                     "4.17.21") == "npm install lodash@4.17.21")
check("go 命令", vulndb.fix_command(dep("go", "github.com/containerd/containerd/v2",
                                        "2.4.0"), "2.4.1")
      == "go get github.com/containerd/containerd/v2@2.4.1")
check("maven 给出修改 pom 的指引而非命令行",
      "pom.xml" in (vulndb.fix_command(dep("maven", "org.springframework:spring-webmvc",
                                           "5.3.39"), "6.2.7") or ""))

section("\n[9] 别名去重（并查集）")
sev = vulndb.severity_of(V_LODASH)
f1 = vulndb.build_finding(V_LODASH, dep("npm", "lodash", "4.17.20"))
f2 = vulndb.build_finding(V_LODASH_DUP, dep("npm", "lodash", "4.17.20"))
check("两条公告都被识别为 critical", f1["severity"] == f2["severity"] == "critical")
merged, dropped = vulndb.dedupe_by_alias([f1, f2])
check("互为别名的公告合并为 1 条", len(merged) == 1 and dropped == 1)
check("保留信息最全者（引用更多）",
      merged[0]["vuln_id"] == "GHSA-35jh-r3h4-6jhm", str(len(merged[0]["references"])) + " 条引用")
check("被合并者编号进入 also_ids",
      "GHSA-r5fr-rjxr-66jc" in merged[0]["also_ids"], str(merged[0]["also_ids"]))

section("\n[10] 等级来源优先级")
sev_v2 = vulndb.severity_of(V_V2ONLY)
check("无前缀 CVSS_V2 向量可算分", sev_v2["cvss"] == 7.5
      and sev_v2["severity_source"] == "CVSS_V2", str(sev_v2))
sev_db = vulndb.severity_of(V_CONTAINERD)
check("无向量时回退数据库文本等级", sev_db["severity"] == "medium"
      and sev_db["severity_source"] == "database", str(sev_db))
sev_no = vulndb.severity_of(V_NOINFO)
check("完全无信息按中危兜底并标注", sev_no["severity"] == "medium"
      and sev_no["severity_source"] == "default", str(sev_no))

section("\n[11] 可查询依赖筛选")
qs, skipped = vulndb.collect_queryable([
    dep("npm", "lodash", "4.17.20"),
    dep("npm", "lodash", "4.17.20"),                       # 重复
    dep("maven", "org.x:y", "", version_kind="unresolved"),  # 版本未解析
    dep("pypi", "Flask_Login", "0.5.0"),                   # 名称归一化
])
check("未解析版本被跳过", skipped["unresolved"] == 1)
check("重复依赖被跳过", skipped["duplicate"] == 1)
check("PyPI 名称归一（下划线转连字符并小写）",
      len(qs) == 2 and any(it["osv_name"] == "flask-login" for it in qs),
      "/".join(it["osv_name"] for it in qs))

section("\n[12] analyze() 端到端（Mock HTTP + 临时缓存）")
DEPS = [
    dep("npm", "lodash", "4.17.20", manifest="package-lock.json"),
    dep("maven", "org.springframework:spring-webmvc", "5.3.39", manifest="pom.xml"),
    dep("go", "github.com/containerd/containerd/v2", "2.4.0", manifest="go.mod"),
    dep("npm", "left-pad", "1.3.0", manifest="package.json"),
    dep("maven", "org.zizao:internal-parent", "", version_kind="unresolved",
        manifest="pom.xml"),
]
tmp = tempfile.mkdtemp(prefix="vulntest-")
try:
    cache_path = os.path.join(tmp, "cache.json")
    FakeHttp.calls = []                      # 显式清零：三次运行共用同一个计数
    res = run_analyze(DEPS, cache_path)
    s = res["summary"]
    check("未解析依赖被跳过并统计", s["unresolved"] == 1, str(s["unresolved"]))
    check("查询了 4 个可定位版本", s["queried"] == 4, str(s["queried"]))
    check("两条重复公告合并为 1", s["duplicate_advisories"] == 1, str(s["duplicate_advisories"]))
    check("去重后共 3 条漏洞", s["vuln_total"] == 3, str(s["vuln_total"]))
    check("涉及 3 个依赖包", s["vuln_packages"] == 3, str(s["vuln_packages"]))
    check("等级计数与明细一致", s["critical"] == 1 and res["by_severity"]["critical"] == 1,
          f"critical={s['critical']}")
    check("全部可修复", s["fixable"] == 3 and s["no_fix"] == 0)
    check("跨度计数：同线 2 + 跨主版本 1",
          s["easy_fix"] == 2 and s["major_up"] == 1 and s["minor_up"] == 0,
          f"easy={s['easy_fix']} major={s['major_up']}")

    by_pkg = {f["package"]: f for f in res["findings"]}
    lo = by_pkg.get("lodash")
    check("lodash 定级 critical（CVSS 9.8）",
          lo and lo["severity"] == "critical" and lo["cvss"] == 9.8,
          f"cvss={lo and lo['cvss']}")
    check("lodash 建议升 4.17.21（同线）",
          lo and lo["fixed"] == "4.17.21" and lo["fix_kind"] == "same-branch")
    check("lodash 保留合并来源",
          lo and "GHSA-r5fr-rjxr-66jc" in lo["also_ids"], str(lo and lo["also_ids"]))
    sp = by_pkg.get("org.springframework:spring-webmvc")
    check("spring-webmvc 5.3.39 推升 6.2.7 且不遮掩跨主版本",
          sp and sp["fixed"] == "6.2.7" and sp["fix_kind"] == "major-up")
    co = by_pkg.get("github.com/containerd/containerd/v2")
    check("containerd 建议同线升 2.4.1 且命令正确",
          co and co["fixed"] == "2.4.1" and co["command"]
          == "go get github.com/containerd/containerd/v2@2.4.1")
    check("结果按严重程度降序",
          [cvss.rank(f["severity"]) for f in res["findings"]]
          == sorted(cvss.rank(f["severity"]) for f in res["findings"]))
    check("无漏洞包（left-pad）不产生结果", "left-pad" not in by_pkg)
    calls_first = len(FakeHttp.calls)
    check("首次运行全部走网络", calls_first > 0, f"{calls_first} 次请求")

    # ---- 第二遍：命中缓存，不应再发起任何网络请求 ----
    res2 = run_analyze(DEPS, cache_path)
    check("第二遍命中包级与公告缓存（零请求）",
          len(FakeHttp.calls) == calls_first and res2["cache_hits"] > 0,
          f"cache_hits={res2['cache_hits']} 新增请求={len(FakeHttp.calls) - calls_first}")
    check("缓存路径结果与首遍一致", res2["summary"]["vuln_total"] == 3)

    # ---- 离线模式：共用同一份缓存，模拟"断网后重开"的生产场景 ----
    res3 = run_analyze(DEPS, cache_path, offline=True)
    check("离线模式不发起任何请求", len(FakeHttp.calls) == calls_first,
          f"新增请求={len(FakeHttp.calls) - calls_first}")
    check("离线模式靠缓存得到完整结果",
          res3["summary"]["vuln_total"] == 3 and res3["summary"]["queried"] == 4,
          f"漏洞={res3['summary']['vuln_total']} 查询={res3['summary']['queried']}")
    check("离线模式在结果中标注离线状态",
          res3.get("offline") is True and res3["online"] is False,
          f"offline={res3.get('offline')} online={res3.get('online')}")
finally:
    shutil.rmtree(tmp, ignore_errors=True)

print("\n" + "=" * 68)
print(f"  结果：\033[32m{len(PASS)} 项通过\033[0m" +
      (f"，\033[31m{len(FAIL)} 项失败\033[0m" if FAIL else "，全部通过 ✓"))
if FAIL:
    for f in FAIL:
        print("   - 失败：", f)
print("=" * 68)
sys.exit(1 if FAIL else 0)
