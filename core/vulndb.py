# -*- coding: utf-8 -*-
"""依赖漏洞库（SCA）：用 OSV.dev 数据源匹配依赖的已知漏洞。

架构取舍（ADR）
---------------
**数据源：OSV.dev 在线 API + 本地磁盘缓存**，而不是下载各生态的离线数据库归档。

- 选 OSV 的理由：版本区间匹配由 OSV 服务端完成，我们不需要为每个生态实现一遍
  semver / PEP440 / Maven 版本序的比较语义——那是最容易产生**假阴性**的地方，
  一旦算错，用户会以为"没漏洞"而实际有。OSV 的返回即权威判定。
- 不下载 `all.zip` 的理由：npm 的归档已达数百 MB，Maven 更大；且仍需自行实现区间
  比较。收益（离线）可以由缓存拿到，成本却高得多。
- 缓存策略：包级结果 TTL 默认 24 小时，漏洞详情 TTL 默认 7 天（公告基本只增不改）。
  这样重复扫描几乎不产生网络请求，断网时也能用上一次的数据，并如实告知数据龄期
  （`data_age`），不会把陈旧数据伪装成实时结果。

**已知边界**（对外说明时必须保留）
- 只覆盖能确定版本的依赖：`version_kind=unresolved` 的依赖不参与查询，会单独计数。
- `version_kind=floor`（从 `^1.2.3` 这类区间取的下界）可能产生假阳性，结果里带标记。
- 只覆盖直接依赖（除非仓库里有 lockfile 或依赖树文件）。
- 不做可达性分析：漏洞是否真被调用需要人工确认，本工具只做"存在已知漏洞"的事实陈述。
"""
from __future__ import annotations

import json
import os
import re
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed

from . import cvss
from .manifests import OSV_ECOSYSTEM

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
OSV_BATCH_SIZE = 1000                 # OSV 单次 querybatch 的查询数上限
DEFAULT_PKG_TTL = 24 * 3600           # 包级结果缓存 24 小时
DEFAULT_VULN_TTL = 7 * 24 * 3600      # 漏洞详情缓存 7 天
MAX_VULN_CACHE = 4000
MAX_PKG_CACHE = 20000
MAX_FINDINGS = 4000                   # 单次分析的结果条数上限
CACHE_SCHEMA = 1


# ============================================================== 版本比较
# 生态无关的启发式版本序：切分成数字段与字母段后逐段比较。
# 它要处理的真实形态包括 npm 的 1.2.3-beta.1、Maven 的 5.2.20.RELEASE、
# Go 的 v1.3.1、PEP440 的 1.2.3rc1 —— 没有一种通用规范能同时覆盖，因此：
#   * 数值段按整数比
#   * 字母段按"预发布等级"比（rc < release）
#   * 缺段视为 0（1.0 == 1.0.0）；若缺的是字母段则视为正式版（1.0 > 1.0-rc1）
_QUAL_RANK = {
    "dev": -6, "alpha": -5, "a": -5, "beta": -4, "b": -4,
    "milestone": -3, "m": -3, "snapshot": -3,
    "pre": -2, "preview": -2, "rc": -2, "cr": -2,
    "": 0, "release": 0, "final": 0, "ga": 0,
    "sp": 1, "post": 1, "rev": 1, "r": 1,
}


def _tokens(version: str):
    v = (version or "").strip().lower()
    if len(v) > 1 and v[0] == "v" and v[1].isdigit():
        v = v[1:]
    v = v.split("+")[0]                     # 去掉 build metadata
    return re.findall(r"\d+|[a-z]+", v)


def cmp_version(a: str, b: str) -> int:
    """返回 -1 / 0 / 1。无法比较时退化为字符串比较。"""
    ta, tb = _tokens(a), _tokens(b)
    if not ta or not tb:
        return (a > b) - (a < b)
    n = max(len(ta), len(tb))
    for i in range(n):
        x = ta[i] if i < len(ta) else None
        y = tb[i] if i < len(tb) else None
        if x is None and y is None:
            return 0
        if x is None:
            if y.isdigit():
                yv = int(y)
                if yv == 0:
                    continue           # 尾部补零视为相等
                return -1
            return 1               # x 是正式版，y 是预发布标记
        if y is None:
            if x.isdigit():
                if int(x) == 0:
                    continue
                return 1
            return -1
        xd, yd = x.isdigit(), y.isdigit()
        if xd and yd:
            xi, yi = int(x), int(y)
            if xi != yi:
                return 1 if xi > yi else -1
        elif not xd and not yd:
            rx = _QUAL_RANK.get(x, None)
            ry = _QUAL_RANK.get(y, None)
            if rx is not None and ry is not None:
                if rx != ry:
                    return 1 if rx > ry else -1
            elif x != y:
                return 1 if x > y else -1
        else:
            return 1 if xd else -1     # 数字段 > 字母段
    return 0


# ============================================== OSV 区间语义（introduced/fixed）
def range_intervals(range_obj: dict):
    """把 OSV 的 events 列表切成区间：[{lo, hi, inclusive, fix}]。

    OSV 语义：events 顺序敏感，`introduced` 开启区间，`fixed` 结束区间（不含），
    `last_affected` 结束区间（含，表示该分支"最后受影响的版本"、即没有修复版本）。
    `introduced: "0"` 表示从最早版本开始。
    """
    out, cur = [], None
    for ev in range_obj.get("events") or []:
        if "introduced" in ev:
            if cur is not None:
                out.append({"lo": cur, "hi": None, "inclusive": False, "fix": ""})
            cur = ev["introduced"]
        elif "fixed" in ev:
            out.append({"lo": cur if cur is not None else "0",
                        "hi": ev["fixed"], "inclusive": False, "fix": ev["fixed"]})
            cur = None
        elif "last_affected" in ev:
            out.append({"lo": cur if cur is not None else "0",
                        "hi": ev["last_affected"], "inclusive": True, "fix": ""})
            cur = None
    if cur is not None:
        out.append({"lo": cur, "hi": None, "inclusive": False, "fix": ""})
    return out


def in_interval(version: str, iv: dict) -> bool:
    lo, hi = iv.get("lo") or "0", iv.get("hi")
    if lo and lo != "0" and cmp_version(version, lo) < 0:
        return False
    if hi:
        c = cmp_version(version, hi)
        return c <= 0 if iv.get("inclusive") else c < 0
    return True


def branch_of(version: str) -> str:
    """取版本的前两段作为"版本线"标识（5.3.17 -> 5.3、2.7 -> 2.7）。"""
    t = _tokens(version)
    return ".".join(t[:2]) if t else ""


def major_of(version: str) -> str:
    t = _tokens(version)
    return t[0] if t and t[0].isdigit() else ""


_PRERELEASE = {"alpha", "a", "beta", "b", "rc", "cr", "m", "milestone",
               "snapshot", "pre", "preview", "dev", "next", "canary"}


def is_prerelease(version: str) -> bool:
    """是否预发布版本（alpha/beta/rc/snapshot…）。

    修复建议必须避开预发布版：把用户从 6.0.18.Final 建议升到 6.2.0.CR1 是坏建议，
    生产环境不该引入候选发布版。
    """
    return any(t in _PRERELEASE for t in _tokens(version))


def fix_kind_of(current: str, fixed: str) -> str:
    """修复版本相对当前版本的升级跨度 —— 直接决定"改动风险有多大"。

    只分"同分支 / 跨分支"太粗：2.7 升到 2.14 同为 2.x，与 5.3 升到 6.x 的风险
    完全不同，却都会被标成"跨大版本"。因此按主版本切分：
      same-branch 同一主次版本线内（如 5.3.17 -> 5.3.18）
      minor-up    同主版本的更高次版本线（如 2.7 -> 2.14、1.9.4 -> 1.11.0）
      major-up    跨主版本（如 5.3.17 -> 6.2.17）
    """
    if not fixed:
        return "none"
    if branch_of(current) == branch_of(fixed):
        return "same-branch"
    if major_of(current) and major_of(current) == major_of(fixed):
        return "minor-up"
    return "major-up"


# ================================================================ 修复建议
_FIX_CMD = {
    "maven": "修改 pom.xml 中 {name} 的 <version> 为 {fixed}（或执行 mvn versions:use-latest-versions -Dincludes={name}）",
    "npm": "npm install {name}@{fixed}",
    "pypi": 'pip install "{name}>={fixed}"',
    "go": "go get {name}@{fixed}",
    "rubygems": "bundle update {name}（并确保 Gemfile.lock 落到 {fixed} 及以上）",
    "packagist": "composer require {name}:{fixed}",
    "crates.io": "cargo update -p {name} --precise {fixed}",
    "nuget": "dotnet add package {name} --version {fixed}",
    "pub": "flutter pub add {name}:{fixed}",
    "hex": '修改 mix.exs 中 {name} 的版本约束到 "~> {fixed}"',
}


def resolve_fix(vuln: dict, name: str, version: str) -> dict:
    """推导该依赖的最优修复版本。

    这里必须做"区间归属判定"，而不能简单取所有 fixed 的最小值。实测案例：
    Spring Framework 某公告同时给 spring-webmvc 的 5.3.x 分支标了 last_affected
    5.3.39（该分支没有修复版本），又给 6.2.x / 7.0.x 标了 fixed。若只看 fixed 最小值，
    会误导用户以为"升到 6.2.17 就行"，却漏掉"5.3 分支根本没有修复版本"这一事实。
    """
    hit_fixes, all_fixes = [], []
    unfixed_in_range = False
    matched_range = False
    explicit_match = False

    for aff in vuln.get("affected") or []:
        pkg = (aff.get("package") or {}).get("name")
        if pkg and name and pkg != name:
            continue                       # 同一公告可能覆盖多个包，只看本包
        if version in (aff.get("versions") or []):
            explicit_match = True
        for rng in aff.get("ranges") or []:
            ivs = range_intervals(rng)
            for iv in ivs:
                if iv.get("fix"):
                    all_fixes.append(iv["fix"])
                if in_interval(version, iv):
                    matched_range = True
                    if iv.get("fix"):
                        hit_fixes.append(iv["fix"])
                    else:
                        unfixed_in_range = True

    cur_branch = branch_of(version)
    uniq = sorted(set(all_fixes), key=_SortKey)
    higher = [v for v in uniq if cmp_version(v, version) > 0]

    def _pick(cands):
        """在候选里挑最优修复版本：优先正式版，其次版本号最低（改动跨度最小）。"""
        if not cands:
            return ""
        stable = [v for v in cands if not is_prerelease(v)]
        return min(stable or list(cands), key=_SortKey)

    def _result(fixed):
        return {"fixed": fixed, "fix_kind": fix_kind_of(version, fixed),
                "fixed_all": uniq[:6], "has_fix": bool(fixed), "branch": branch_of(version)}

    # ① 命中区间自带修复版本 —— 最可信
    if hit_fixes:
        best = _pick(hit_fixes)
        if is_prerelease(best):          # 数据只给了预发布版，改挑更高的正式版
            alt = _pick([v for v in higher if not is_prerelease(v)])
            if alt:
                best = alt
        return _result(best)
    # ② 命中区间明确"无修复"（last_affected）：只能往更高版本线升
    if matched_range and unfixed_in_range:
        return _result(_pick(higher))
    # ③ 通过显式 versions 列表命中：在同包所有修复版本里取最小的高于当前版本者
    if explicit_match or matched_range:
        return _result(_pick(higher))
    return _result("")


class _SortKey:
    """给 sorted() 用的比较键：把一个版本映射成可比较元组。"""

    __slots__ = ("v",)

    def __init__(self, v):
        self.v = v

    def __lt__(self, other):
        return cmp_version(self.v, other.v) < 0

    def __eq__(self, other):
        return cmp_version(self.v, other.v) == 0

    def __hash__(self):
        return hash(self.v)


def fix_command(dep: dict, fixed: str) -> str:
    """生成可复制的升级命令（按生态）。没有对应生态模板时返回空串。"""
    if not fixed:
        return ""
    tmpl = _FIX_CMD.get(dep["ecosystem"])
    return tmpl.format(name=dep["name"], fixed=fixed) if tmpl else ""


def fix_advice(dep: dict, info: dict) -> str:
    """生成中文修复建议正文（不含命令，命令由 fix_command 单独提供）。"""
    cur = dep["version"]
    kind = info.get("fix_kind")
    if not info.get("has_fix") or kind == "none":
        return (f"官方尚未针对 {cur} 所在的 {info.get('branch') or '-'} 版本线发布修复版本。"
                f"建议：① 评估升级到更高主版本（可能涉及不兼容改动，需完整回归）；"
                f"② 若无法升级，确认该组件是否真正被调用，并在网关 / WAF 层做针对性拦截；"
                f"③ 持续关注上游公告，及时跟进修复版本。")
    fixed = info["fixed"]
    span = {
        "same-branch": f"升级到 {fixed} 或更高版本（同一版本线内，兼容性风险低）",
        "minor-up": f"升级到 {fixed} 或更高版本（同主版本的更高次版本线，需回归测试）",
        "major-up": f"{cur} 所在版本线（{info.get('branch') or '-'}）已无修复版本，"
                    f"需升级到 {fixed} 或更高版本（跨主版本，不兼容风险高）",
    }.get(kind, f"升级到 {fixed} 或更高版本")
    warn = "。注意：官方标注的修复版本为预发布版，生产环境建议采用对应的正式版本" \
        if is_prerelease(fixed) else ""
    return span + warn + "。"


# ============================================================== 严重等级
def severity_of(vuln: dict) -> dict:
    """归一化严重等级：优先自己算 CVSS，其次用数据库文本等级。"""
    vector, score, vtype = "", None, ""
    # 1) CVSS 向量（优先 v3，其次 v2；v4 未实现）
    candidates = []
    for sev in vuln.get("severity") or []:
        t = str(sev.get("type") or "").upper()
        s = str(sev.get("score") or "")
        if not s:
            continue
        if cvss.is_cvss_vector(s):
            candidates.append((t, s))
        elif t in ("CVSS_V3", "CVSS_V2") and re.match(r"^\d", s):
            candidates.append((t, s))
    for want in ("CVSS_V3", "CVSS_V2"):
        for t, s in candidates:
            if t == want or s.lower().startswith("cvss:3" if want == "CVSS_V3" else "cvss:2"):
                value, tag = cvss.base_score(s)
                if value is None:
                    continue
                score, vector, vtype = value, s, tag
                break
        if score is not None:
            break
    if score is not None:
        return {"severity": cvss.score_to_severity(score), "cvss": score,
                "cvss_vector": vector, "severity_source": vtype}

    # 2) 数据库文本等级：database_specific.severity（GHSA/OSV 常见）
    db = vuln.get("database_specific") or {}
    for key in ("severity", "cvss_severity"):
        s = cvss.text_to_severity(db.get(key))
        if s:
            return {"severity": s, "cvss": None, "cvss_vector": "", "severity_source": "database"}
    for aff in vuln.get("affected") or []:
        eco = aff.get("ecosystem_specific") or {}
        s = cvss.text_to_severity(eco.get("severity"))
        if s:
            return {"severity": s, "cvss": None, "cvss_vector": "",
                    "severity_source": "ecosystem"}
    # 3) 兜底：无法定级时按中危处理并标注低可信
    return {"severity": "medium", "cvss": None, "cvss_vector": "",
            "severity_source": "default"}


# ============================================================== HTTP 通道
class Http:
    """带通道回落与重试的极简 HTTP 客户端。

    通道顺序：环境代理（若配置）优先，失败则改直连；反之亦然。企业内网常需代理，
    而本机开发环境通常直连，两者都要能work。
    记录首次成功的通道，后续复用，避免每次都试两遍。
    """

    def __init__(self, timeout: float = 20.0, retries: int = 2):
        self.timeout = timeout
        self.retries = retries
        proxy_env = any(os.environ.get(k) for k in
                        ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"))
        env_aware = urllib.request.build_opener()
        direct = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        self._openers = [env_aware, direct] if proxy_env else [direct, env_aware]
        self._preferred = 0
        self.requests = 0
        self.failures = 0
        self.last_error = ""

    def _order(self):
        first = self._openers[self._preferred]
        return [first] + [o for o in self._openers if o is not first]

    def json(self, url: str, payload=None, method="POST"):
        body = json.dumps(payload).encode("utf-8") if payload is not None else None
        headers = {"Content-Type": "application/json", "Accept": "application/json",
                   "User-Agent": "audit-tool/1.4 (+osv-client)"}
        last = None
        for attempt in range(self.retries + 1):
            for idx, op in enumerate(self._order()):
                try:
                    req = urllib.request.Request(url, body, headers, method=method)
                    with op.open(req, timeout=self.timeout) as resp:
                        raw = resp.read()
                    self.requests += 1
                    return json.loads(raw.decode("utf-8"))
                except urllib.error.HTTPError as exc:
                    last = exc
                    self.requests += 1
                    if exc.code in (429, 500, 502, 503, 504) and attempt < self.retries:
                        break                      # 可重试，换下一轮
                    if exc.code in (400, 404):
                        self.failures += 1
                        raise
                except Exception as exc:           # noqa: BLE001  网络/解析错误
                    last = exc
                    self.requests += 1
            if attempt < self.retries:
                time.sleep(0.8 * (attempt + 1))
        self.failures += 1
        self.last_error = f"{type(last).__name__}: {last}"
        raise last if last else RuntimeError("OSV 请求失败")


# ============================================================== 本地缓存
class VulnCache:
    """磁盘缓存：包级查询结果 + 漏洞详情，均带 TTL。

    分两级缓存是因为它们的变化率差两个数量级：同一依赖的命中集合会随新公告变化
    （24 小时），而单条公告的正文几乎不变（7 天）。分级后重复扫描的请求数趋近于 0。
    """

    def __init__(self, path: str, pkg_ttl: int = DEFAULT_PKG_TTL,
                 vuln_ttl: int = DEFAULT_VULN_TTL):
        self.path = path
        self.pkg_ttl = pkg_ttl
        self.vuln_ttl = vuln_ttl
        self.pkg: dict = {}
        self.vuln: dict = {}
        self.lock = threading.Lock()
        self.dirty = False
        self.saved_at = 0.0
        self.load()

    # ------------------------------------------------------------ 读写
    def load(self) -> None:
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (OSError, ValueError):
            return
        if data.get("schema") != CACHE_SCHEMA:
            return
        self.pkg = data.get("pkg") or {}
        self.vuln = data.get("vuln") or {}
        self.saved_at = float(data.get("saved") or 0)

    def save(self) -> None:
        with self.lock:
            if not self.dirty:
                return
            self.prune()
            payload = {"schema": CACHE_SCHEMA, "saved": time.time(),
                       "pkg": self.pkg, "vuln": self.vuln}
            os.makedirs(os.path.dirname(self.path), exist_ok=True)
            tmp = self.path + ".tmp"
            try:
                with open(tmp, "w", encoding="utf-8") as f:
                    json.dump(payload, f, ensure_ascii=False, separators=(",", ":"))
                os.replace(tmp, self.path)         # 原子替换，避免半截文件
                self.dirty = False
            except OSError:
                try:
                    os.remove(tmp)
                except OSError:
                    pass

    def prune(self) -> None:
        """超量时按时间戳淘汰最旧条目。"""
        if len(self.vuln) > MAX_VULN_CACHE:
            keep = sorted(self.vuln.items(), key=lambda kv: kv[1].get("t", 0),
                          reverse=True)[:MAX_VULN_CACHE]
            self.vuln = dict(keep)
        if len(self.pkg) > MAX_PKG_CACHE:
            keep = sorted(self.pkg.items(), key=lambda kv: kv[1].get("t", 0),
                          reverse=True)[:MAX_PKG_CACHE]
            self.pkg = dict(keep)

    # ------------------------------------------------------------ 访问
    @staticmethod
    def key(ecosystem: str, name: str, version: str) -> str:
        return f"{ecosystem}|{name}|{version}"

    def get_pkg(self, key: str):
        rec = self.pkg.get(key)
        if not rec:
            return None
        if time.time() - rec.get("t", 0) > self.pkg_ttl:
            return None
        return rec.get("v") or []

    def put_pkg(self, key: str, ids) -> None:
        with self.lock:
            self.pkg[key] = {"t": time.time(), "v": list(ids)}
            self.dirty = True

    def get_vuln(self, vid: str):
        rec = self.vuln.get(vid)
        if not rec:
            return None
        if time.time() - rec.get("t", 0) > self.vuln_ttl:
            return None
        return rec.get("d")

    def put_vuln(self, vid: str, obj: dict) -> None:
        with self.lock:
            self.vuln[vid] = {"t": time.time(), "d": obj}
            self.dirty = True

    def stats(self) -> dict:
        ages = [r.get("t", 0) for r in self.pkg.values()]
        return {
            "path": self.path,
            "packages": len(self.pkg),
            "vulns": len(self.vuln),
            "saved_at": self.saved_at,
            "oldest_entry_age": (time.time() - min(ages)) if ages else None,
            "pkg_ttl": self.pkg_ttl,
            "vuln_ttl": self.vuln_ttl,
        }


# ============================================================== 结果组装
def _trim_details(text: str, limit: int = 1400) -> str:
    if not text:
        return ""
    text = re.sub(r"\r\n?", "\n", text).strip()
    return text if len(text) <= limit else text[:limit].rstrip() + " …（详见公告原文）"


def _pick_refs(vuln: dict, limit: int = 6):
    refs, seen = [], set()
    for r in vuln.get("references") or []:
        url = r.get("url")
        if not url or url in seen:
            continue
        seen.add(url)
        refs.append({"url": url, "type": r.get("type", "")})
    priority = {"ADVISORY": 0, "FIX": 1, "ARTICLE": 2, "REPORT": 3, "WEB": 4, "PACKAGE": 6}
    refs.sort(key=lambda r: priority.get(r["type"], 5))
    return refs[:limit]


def build_finding(vuln: dict, dep: dict) -> dict:
    """把一条 OSV 记录与一个依赖合成一条可展示、可导出的结果。"""
    sev = severity_of(vuln)
    fix = resolve_fix(vuln, dep["name"], dep["version"])
    db = vuln.get("database_specific") or {}
    aliases = [str(a) for a in (vuln.get("aliases") or [])]
    cve = next((a for a in aliases if a.upper().startswith("CVE-")), "")
    return {
        "vuln_id": vuln.get("id", ""),
        "cve": cve,
        "aliases": aliases[:6],
        "also_ids": [],          # 由 dedupe_by_alias 填充：指向同一漏洞的其它公告编号
        "title": (vuln.get("summary") or "").strip() or vuln.get("id", ""),
        "details": _trim_details(vuln.get("details", "")),
        "severity": sev["severity"],
        "cvss": sev["cvss"],
        "cvss_vector": sev["cvss_vector"],
        "severity_source": sev["severity_source"],
        "cwe": (db.get("cwe_ids") or [])[:4],
        "published": vuln.get("published", ""),
        "modified": vuln.get("modified", ""),
        # 受影响的依赖
        "ecosystem": dep["ecosystem"],
        "package": dep["name"],
        "version": dep["version"],
        "version_kind": dep["version_kind"],
        "manifest": dep["manifest"],
        "manifests": dep.get("manifests", [dep["manifest"]]),
        "module": dep.get("module", ""),
        "scope": dep.get("scope", "compile"),
        "indirect": dep.get("indirect", False),
        # 修复信息
        "fixed": fix["fixed"],
        "fix_kind": fix["fix_kind"],
        "fixed_all": fix["fixed_all"],
        "has_fix": fix["has_fix"],
        "advice": fix_advice(dep, fix),
        "command": fix_command(dep, fix["fixed"]),
        "references": _pick_refs(vuln),
    }


def _richness(f: dict):
    """判定"同一漏洞的多个公告里哪个信息更全"（越大越优）。"""
    return (-cvss.rank(f["severity"]), f["cvss"] or 0.0,
            1 if f["severity_source"].startswith("CVSS") else 0,
            1 if f["has_fix"] else 0, len(f["references"]),
            1 if f["cve"] else 0, len(f["details"]))


def dedupe_by_alias(findings: list[dict]):
    """按别名合并重复公告（并查集）。

    为什么必须做：OSV 里同一漏洞常有多条公告互为别名。实测 lodash 的
    GHSA-35jh-r3h4-6jhm 的 aliases 就含 GHSA-r5fr-rjxr-66jc，两者都带
    CVE-2021-23337。不去重会让用户看到"同一个 CVE 报了两遍"，漏洞总数虚高，
    按依赖聚合的计数也不可信。合并规则：保留信息最全的一条，把其余编号并入
    `also_ids`，并统计丢弃数以便透明说明。
    """
    parent: dict = {}

    def find(x):
        parent.setdefault(x, x)
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    def union(a, b):
        ra, rb = find(a), find(b)
        if ra != rb:
            parent[rb] = ra

    for f in findings:
        ids = [f["vuln_id"]] + list(f["aliases"])
        for other in ids[1:]:
            union(ids[0], other)

    groups: dict = {}
    for f in findings:
        key = (f["ecosystem"], f["package"], f["version"], find(f["vuln_id"]))
        cur = groups.get(key)
        if cur is None:
            f["also_ids"] = []
            groups[key] = f
        elif _richness(f) > _richness(cur):
            f["also_ids"] = sorted(set(cur.get("also_ids", []) + [cur["vuln_id"]]
                                       + [a for a in cur["aliases"] if a != f["vuln_id"]]))
            f["aliases"] = sorted(set(f["aliases"]) | set(cur["aliases"]))
            groups[key] = f
        else:
            cur["also_ids"] = sorted(set(cur.get("also_ids", []) + [f["vuln_id"]]
                                         + [a for a in f["aliases"] if a != cur["vuln_id"]]))
            cur["aliases"] = sorted(set(cur["aliases"]) | set(f["aliases"]))
    kept = list(groups.values())
    return kept, len(findings) - len(kept)


def _rollup(findings: list[dict]) -> list[dict]:
    """按 (生态, 包, 版本) 聚合，供界面按依赖维度展示。"""
    groups: dict = {}
    for f in findings:
        key = (f["ecosystem"], f["package"], f["version"])
        g = groups.get(key)
        if g is None:
            groups[key] = g = {
                "ecosystem": f["ecosystem"], "name": f["package"], "version": f["version"],
                "version_kind": f["version_kind"], "manifest": f["manifest"],
                "manifests": f["manifests"], "scope": f["scope"],
                "indirect": f["indirect"], "count": 0,
                "worst": f["severity"], "worst_cvss": f["cvss"] or 0.0,
                "top": f["vuln_id"], "fixed": "", "fixable": 0, "no_fix": 0,
                "vulns": [],
            }
        g["count"] += 1
        if cvss.rank(f["severity"]) < cvss.rank(g["worst"]):
            g["worst"] = f["severity"]
            g["top"] = f["vuln_id"]
        if (f["cvss"] or 0) > (g["worst_cvss"] or 0):
            g["worst_cvss"] = f["cvss"]
        if f["has_fix"]:
            g["fixable"] += 1
            if not g["fixed"] or cmp_version(f["fixed"], g["fixed"]) > 0:
                g["fixed"] = f["fixed"]
        else:
            g["no_fix"] += 1
        g["vulns"].append(f["vuln_id"])
    out = list(groups.values())
    out.sort(key=lambda g: (cvss.rank(g["worst"]), -(g["worst_cvss"] or 0), g["name"]))
    return out


# ============================================================== 主流程
def collect_queryable(deps: list[dict]):
    """挑出可查询的依赖，并给出被跳过者的原因统计。"""
    queryable, skipped = [], {"unresolved": 0, "no_ecosystem": 0, "duplicate": 0}
    seen = set()
    for d in deps:
        if d.get("version_kind") == "unresolved" or not d.get("version"):
            skipped["unresolved"] += 1
            continue
        if d.get("ecosystem") not in OSV_ECOSYSTEM:
            skipped["no_ecosystem"] += 1
            continue
        name = d["name"]
        if d["ecosystem"] == "pypi":
            name = re.sub(r"[-_.]+", "-", name).lower()
        key = (OSV_ECOSYSTEM[d["ecosystem"]], name, d["version"])
        if key in seen:
            skipped["duplicate"] += 1
            continue
        seen.add(key)
        queryable.append({"dep": d, "osv_eco": OSV_ECOSYSTEM[d["ecosystem"]],
                          "osv_name": name, "key": key})
    return queryable, skipped


def analyze(deps: list[dict], cache_path: str, *, pkg_ttl: int = DEFAULT_PKG_TTL,
            vuln_ttl: int = DEFAULT_VULN_TTL, timeout: float = 20.0,
            workers: int = 6, offline: bool = False, refresh: bool = False,
            progress=None) -> dict:
    """扫描依赖的已知漏洞，返回结构化的结果集。

    progress: 可选回调 (phase:str, done:int, total:int)，用于把进度回传给界面。
    """
    t0 = time.time()
    cache = VulnCache(cache_path, pkg_ttl, vuln_ttl)
    http = Http(timeout=timeout)
    result = {
        "source": "OSV.dev",
        "source_url": "https://osv.dev",
        "online": False,
        "offline": bool(offline),
        "error": "",
        "deps_total": len(deps),
        "queried": 0,
        "cache_hits": 0,
        "skipped": {},
        "unique_vulns": 0,
        "findings": [],
        "packages": [],
        "by_severity": {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0},
        "summary": {},
        "cache": {},
        "elapsed": 0.0,
    }

    queryable, skipped = collect_queryable(deps)
    result["skipped"] = skipped
    result["cache"] = cache.stats()

    if not queryable:
        result["elapsed"] = round(time.time() - t0, 2)
        result["summary"] = {"vuln_total": 0, "vuln_packages": 0, "fixable": 0, "no_fix": 0,
                             "queried": 0, "unresolved": skipped["unresolved"]}
        cache.save()
        return result

    # ---------------- 第 1 步：包级查询（缓存优先，其余批量走 OSV）----------------
    if progress:
        progress("vulndb-query", 0, len(queryable))
    pending, ids_by_key = [], {}
    for item in queryable:
        cached = None if refresh else cache.get_pkg(VulnCache.key(*item["key"]))
        if cached is None:
            pending.append(item)
        else:
            ids_by_key[item["key"]] = cached
            result["cache_hits"] += 1

    net_error = ""
    if pending and not offline:
        for start in range(0, len(pending), OSV_BATCH_SIZE):
            chunk = pending[start:start + OSV_BATCH_SIZE]
            payload = {"queries": [{"package": {"name": it["osv_name"],
                                                "ecosystem": it["osv_eco"]},
                                    "version": it["dep"]["version"]} for it in chunk]}
            try:
                resp = http.json(OSV_BATCH_URL, payload)
            except Exception as exc:               # noqa: BLE001
                net_error = f"{type(exc).__name__}: {exc}"
                break
            for it, res in zip(chunk, resp.get("results") or []):
                ids = [v.get("id") for v in (res.get("vulns") or []) if v.get("id")]
                ids_by_key[it["key"]] = ids
                cache.put_pkg(VulnCache.key(*it["key"]), ids)
            if progress:
                progress("vulndb-query", min(start + len(chunk), len(pending)), len(pending))
        result["online"] = not net_error
    elif offline:
        net_error = "离线模式：未发起网络请求"
    result["error"] = net_error

    result["queried"] = len(ids_by_key)
    all_ids = sorted({vid for ids in ids_by_key.values() for vid in ids})
    result["unique_vulns"] = len(all_ids)

    if not all_ids:
        result["elapsed"] = round(time.time() - t0, 2)
        result["summary"] = {"vuln_total": 0, "vuln_packages": 0, "fixable": 0, "no_fix": 0,
                            "queried": result["queried"],
                            "unresolved": skipped["unresolved"]}
        cache.save()
        result["cache"] = cache.stats()
        return result

    # ---------------- 第 2 步：拉取漏洞详情（缓存优先，其余并发）----------------
    details: dict = {}
    missing = []
    for vid in all_ids:
        cached = None if refresh else cache.get_vuln(vid)
        if cached is None:
            missing.append(vid)
        else:
            details[vid] = cached

    if missing and not offline:
        if progress:
            progress("vulndb-detail", 0, len(missing))
        done = 0
        def fetch(vid):
            try:
                return vid, http.json(OSV_VULN_URL + urllib.parse.quote(vid, safe=""),
                                      method="GET")
            except Exception:                      # noqa: BLE001
                return vid, None
        with ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(fetch, vid) for vid in missing]
            for fut in as_completed(futures):
                vid, obj = fut.result()
                done += 1
                if obj:
                    details[vid] = obj
                    cache.put_vuln(vid, obj)
                if progress and done % 5 == 0:
                    progress("vulndb-detail", done, len(missing))
        if progress:
            progress("vulndb-detail", len(missing), len(missing))

    # ---------------- 第 3 步：组装结果 ----------------
    findings = []
    for it in queryable:
        dep = it["dep"]
        for vid in ids_by_key.get(it["key"], []):
            vuln = details.get(vid)
            if not vuln:
                continue
            findings.append(build_finding(vuln, dep))
            if len(findings) >= MAX_FINDINGS:
                break
        if len(findings) >= MAX_FINDINGS:
            break

    findings.sort(key=lambda f: (cvss.rank(f["severity"]), -(f["cvss"] or 0),
                                 f["package"], f["vuln_id"]))
    # 别名去重：同一漏洞的多条公告只保留信息最全的一条
    findings, dropped = dedupe_by_alias(findings)
    findings.sort(key=lambda f: (cvss.rank(f["severity"]), -(f["cvss"] or 0),
                                 f["package"], f["vuln_id"]))
    for f in findings:
        result["by_severity"][f["severity"]] = result["by_severity"].get(f["severity"], 0) + 1

    packages = _rollup(findings)
    result["findings"] = findings
    result["packages"] = packages
    result["summary"] = {
        "vuln_total": len(findings),
        "vuln_packages": len(packages),
        "critical": result["by_severity"].get("critical", 0),
        "high": result["by_severity"].get("high", 0),
        "fixable": sum(1 for f in findings if f["has_fix"]),
        "no_fix": sum(1 for f in findings if not f["has_fix"]),
        "easy_fix": sum(1 for f in findings if f["fix_kind"] == "same-branch"),
        "minor_up": sum(1 for f in findings if f["fix_kind"] == "minor-up"),
        "major_up": sum(1 for f in findings if f["fix_kind"] == "major-up"),
        "duplicate_advisories": dropped,
        "unresolved": skipped["unresolved"],
        "queried": result["queried"],
        "floored": sum(1 for d in deps if d.get("version_kind") == "floor"),
        "truncated": len(findings) >= MAX_FINDINGS,
    }
    result["elapsed"] = round(time.time() - t0, 2)
    cache.save()
    result["cache"] = cache.stats()
    return result
