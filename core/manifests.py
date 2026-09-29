# -*- coding: utf-8 -*-
"""依赖清单解析：把各生态的清单文件统一成可比对、可查询的依赖记录。

设计要点
--------
1. **统一模型**：所有生态统一产出同一个 Dep 字典，下游（漏洞匹配 / 报告导出 /
   界面）只认这一种结构，新增生态不需要改下游。

2. **版本可信度分级**（`version_kind`）—— 这是本模块最重要的概念：
   - `exact`  锁定文件或精确声明（package-lock.json / go.mod / pom.xml 显式版本）
   - `floor`  从语义化区间取"下界"（`^4.17.0` -> `4.17.0`）。
              下界会比真实安装版本更旧，因此**可能产生假阳性**：
              项目实际装的是 4.17.21（无漏洞），声明区间下界 4.17.0 却有漏洞。
              下游必须把这个标记透出给用户，不能当作确定结论。
   - `unresolved` 版本由父 POM 管理但本地无法解析，或用了变量/区间无法定位。
              这种依赖**不参与漏洞查询**，但要在清单里可见，否则用户会以为"漏扫了"。

3. **不解析传递依赖**：pom.xml / package.json 只声明直接依赖。真实攻击面包含传递
   依赖，需配合 `mvn dependency:tree` / lockfile 才能得到完整清单。本模块会在有
   lockfile 时优先采用 lockfile（含传递依赖），这是有意的取舍。
"""
from __future__ import annotations

import json
import os
import re
import xml.etree.ElementTree as ET

from .textio import read_text

MAX_DEPS = 3000                     # 依赖条目上限，防止 lockfile 把内存吃满

# 内部生态标识 -> OSV 生态标识（OSV 的命名是大小写敏感的）
OSV_ECOSYSTEM = {
    "go": "Go",
    "npm": "npm",
    "pypi": "PyPI",
    "maven": "Maven",
    "gradle": "Maven",
    "rubygems": "RubyGems",
    "packagist": "Packagist",
    "crates.io": "crates.io",
    "nuget": "NuGet",
    "pub": "Pub",
    "hex": "Hex",
    "cocoapods": "CocoaPods",
    "swift": "SwiftURL",
}

ECO_LABEL = {
    "go": "Go Modules",
    "npm": "npm / Node",
    "pypi": "Python (PyPI)",
    "maven": "Maven",
    "gradle": "Gradle",
    "rubygems": "RubyGems",
    "packagist": "Composer / PHP",
    "crates.io": "Rust / crates.io",
    "nuget": ".NET / NuGet",
    "pub": "Dart / Pub",
    "hex": "Elixir / Hex",
    "cocoapods": "CocoaPods / iOS",
    "swift": "SwiftPM",
}

# 清单文件名 -> 处理函数注册（按 basename 精确匹配）
MANIFEST_NAMES = {
    "pom.xml", "build.gradle", "build.gradle.kts", "libs.versions.toml",
    "gradle.lockfile",
    "package.json", "package-lock.json", "npm-shrinkwrap.json", "yarn.lock",
    "requirements.txt", "requirements-dev.txt", "requirements-prod.txt",
    "pyproject.toml", "pipfile", "pipfile.lock", "poetry.lock",
    "go.mod",
    "gemfile", "gemfile.lock",
    "composer.json", "composer.lock",
    "cargo.toml", "cargo.lock",
    "packages.config", "packages.lock.json",
    "pubspec.yaml", "pubspec.lock",
    "mix.lock",
    "podfile.lock",
    "package.swift",
}


def _base(path: str) -> str:
    return os.path.basename(path).lower()


def _mk(ecosystem, name, version, manifest, *, raw=None, kind="exact",
        module="", scope="compile", indirect=False, coord="", note=""):
    """构造一条标准依赖记录。"""
    return {
        "ecosystem": ecosystem,
        "name": (name or "").strip(),
        "version": (version or "").strip(),
        "raw": (raw if raw is not None else version or "").strip(),
        "version_kind": kind if version else "unresolved",
        "version_note": note,
        "manifest": manifest,
        "module": module or "",
        "scope": scope,
        "indirect": bool(indirect),
        "coord": coord or "",
    }


# =============================================================== 版本区间处理
_NPM_PSEUDO = ("workspace:", "file:", "link:", "http:", "https:", "git+",
               "git:", "github:", "npm:", "portal:", "catalog:")
_NPM_UNBOUNDED = ("", "*", "x", "X", "latest", "next", "beta", "alpha")


def npm_floor(spec: str):
    """把 npm 版本区间取下界，返回 (版本, kind)。

    只取下界是刻意的简化：真正的区间满足关系需要完整 semver 实现，而"取声明下界
    去查漏洞"会偏保守（可能多报）。因此结果标记为 floor，由界面提示用户复核。
    """
    if not spec:
        return None, "unresolved"
    s = str(spec).strip()
    low = s.lower()
    if any(p in low for p in _NPM_PSEUDO):
        return None, "unresolved"
    if s in _NPM_UNBOUNDED or low in ("latest", "next"):
        return None, "unresolved"
    s = s.split("||")[0].strip()                    # 多区间只取第一段
    s = re.sub(r"^[\s^~>=<]+", "", s).strip()
    s = s.lstrip("vV")
    m = re.match(r"^(\d+)(?:\.(\d+|[xX*]))?(?:\.(\d+|[xX*]))?", s)
    if not m:
        return None, "unresolved"
    parts = [m.group(1), m.group(2) or "0", m.group(3) or "0"]
    norm = ".".join(p if p.isdigit() else "0" for p in parts)
    # 原样精确版本（4.17.15）算 exact；带区间前缀/通配的算 floor
    exact = bool(re.fullmatch(r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.\-]+)?", s))
    return norm + (s[len(norm):] if exact else ""), ("exact" if exact else "floor")


def strip_v(version: str) -> str:
    """去除 Go 模块版本的 v 前缀（OSV 侧不带 v）。"""
    return re.sub(r"^v(?=\d)", "", (version or "").strip())


def _pypi_name(name: str) -> str:
    """PEP 503 归一化。"""
    return re.sub(r"[-_.]+", "-", (name or "").strip()).lower()


def _req_line_spec(line: str):
    """解析 requirements.txt 单行 -> (name, spec, kind)。"""
    line = line.strip()
    if not line or line.startswith("#"):
        return None
    line = line.split(" #")[0].strip()
    if not line or line.startswith("-"):            # -r / -e / --hash 等指令行
        return None
    line = re.sub(r"\[[^\]]*\]", "", line)          # 去掉 extras
    line = line.split(";")[0].strip()               # 去掉环境标记
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._\-]*)\s*(==|===|>=|<=|~=|!=|>|<)?\s*(.*)$", line)
    if not m:
        return None
    name, op, ver = m.group(1), m.group(2) or "", (m.group(3) or "").strip()
    if not ver:
        return _pypi_name(name), "", "unresolved"
    ver = ver.split(",")[0].strip()                 # `>=1.0,<2.0` 取下界
    kind = "exact" if op in ("==", "===") else "floor"
    return _pypi_name(name), ver, kind


# ================================================================ Maven (pom.xml)
_POM_NS = "{http://maven.apache.org/POM/4.0.0}"


def _tag(el) -> str:
    return el.tag.split("}")[-1] if isinstance(el.tag, str) else ""


def _child(el, name):
    if el is None:
        return None
    for c in el:
        if _tag(c) == name:
            return c
    return None


def _children(el, name):
    return [] if el is None else [c for c in el if _tag(c) == name]


def _text(el) -> str:
    return (el.text or "").strip() if el is not None and el.text else ""


def _path(el, *names):
    cur = el
    for n in names:
        cur = _child(cur, n)
        if cur is None:
            return None
    return cur


def _pom_parse(abs_path: str):
    """解析单个 pom.xml，返回原始事实（不做跨 POM 解析）。"""
    content, _ = read_text(abs_path)
    if not content:
        return None
    try:
        root = ET.fromstring(content)
    except ET.ParseError:
        return None
    if _tag(root) != "project":
        return None

    parent = _path(root, "parent")
    props_el = _child(root, "properties")
    props = {}
    for p in (list(props_el) if props_el is not None else []):
        props[_tag(p)] = _text(p)

    group = _text(_child(root, "groupId")) or _text(_child(parent, "groupId"))
    artifact = _text(_child(root, "artifactId"))
    version = _text(_child(root, "version")) or _text(_child(parent, "version"))
    packaging = _text(_child(root, "packaging")) or "jar"
    rel_path = _text(_child(parent, "relativePath")) if parent is not None else None

    props.setdefault("project.version", version)
    props.setdefault("project.groupId", group)
    props.setdefault("project.artifactId", artifact)
    props.setdefault("project.parent.version", _text(_child(parent, "version")))
    props.setdefault("project.parent.groupId", _text(_child(parent, "groupId")))
    props.setdefault("pom.version", version)
    props.setdefault("pom.groupId", group)

    def collect_deps(node):
        out = []
        for d in _children(node, "dependency"):
            g = _text(_child(d, "groupId"))
            a = _text(_child(d, "artifactId"))
            out.append({
                "groupId": g, "artifactId": a,
                "version": _text(_child(d, "version")),
                "scope": _text(_child(d, "scope")) or "compile",
                "optional": _text(_child(d, "optional")).lower() == "true",
                "coord": f"{g}:{a}" if g and a else a,
            })
        return out

    return {
        "path": abs_path,
        "coord": f"{group}:{artifact}" if group and artifact else artifact,
        "group": group, "artifact": artifact, "version": version,
        "packaging": packaging,
        "parent_coord": (f"{_text(_child(parent, 'groupId'))}:"
                         f"{_text(_child(parent, 'artifactId'))}") if parent is not None else "",
        "parent_version": _text(_child(parent, "version")) if parent is not None else "",
        "relative_path": rel_path,
        "props": props,
        "deps": collect_deps(_child(root, "dependencies")),
        "managed": {d["coord"]: d["version"] for d in collect_deps(
            _child(_path(root, "dependencyManagement"), "dependencies"))},
    }


def _resolve_props(value: str, props: dict, depth: int = 5) -> str:
    """反复替换 ${...}，最多 depth 轮。"""
    if not value or "${" not in value:
        return value
    for _ in range(depth):
        changed = False

        def sub(m):
            nonlocal changed
            key = m.group(1)
            if key in props and props[key] is not None:
                changed = True
                return props[key]
            return m.group(0)

        value = re.sub(r"\$\{([^}]+)\}", sub, value)
        if not changed:
            break
    return value


def _pom_parse_all(poms: list[str]):
    """两阶段解析：先全部读成事实，再按父子链解析版本。"""
    facts = {}
    for p in poms:
        f = _pom_parse(p)
        if f:
            facts[os.path.normpath(p)] = f
    by_coord = {}
    for f in facts.values():
        if f["coord"]:
            by_coord.setdefault(f["coord"], f)

    def parent_of(f, seen=None):
        seen = seen if seen is not None else set()
        if not f["parent_coord"] or f["parent_coord"] in seen:
            return None
        seen.add(f["parent_coord"])
        # 优先按 relativePath 找同仓 POM，其次按坐标索引
        if f.get("relative_path") is not None:
            rp = f["relative_path"] or "../pom.xml"
            cand = os.path.normpath(os.path.join(os.path.dirname(f["path"]), rp))
            if cand in facts:
                return facts[cand]
            if os.path.isdir(cand):
                cand = os.path.normpath(os.path.join(cand, "pom.xml"))
                if cand in facts:
                    return facts[cand]
        return by_coord.get(f["parent_coord"])

    def chain_of(f):
        """自身 -> 父 -> 祖父……（有环保护）。"""
        chain, cur, seen = [], f, set()
        while cur is not None and id(cur) not in seen:
            seen.add(id(cur))
            chain.append(cur)
            cur = parent_of(cur)
        return chain

    def external_parent(f):
        """返回父链上"第一个在源码库里找不到的父 POM"坐标（没有则空串）。

        多模块 Java 项目普遍继承公司内部父 POM（如 com.x:platform-dependencies），
        该父 POM 不在仓库里，其 <properties> 与 <dependencyManagement> 自然拿不到。
        把这一根因明确回传给用户，比只显示"版本未解析"有用得多。
        """
        cur = f
        for _ in range(8):
            nxt = parent_of(cur)
            if nxt is None:
                return cur["parent_coord"] or ""
            cur = nxt
        return cur["parent_coord"] or ""

    def merged_props(f):
        """父链属性逐层合并（子覆盖父），并对属性值自身再解引用。"""
        props = {}
        for node in reversed(chain_of(f)):        # 祖先在前，后代覆盖
            layer = dict(node["props"])
            for k, v in layer.items():
                if v:
                    layer[k] = _resolve_props(v, {**props, **layer})
            props.update(layer)
        props["project.version"] = f["version"]
        return props

    out = []
    for f in facts.values():
        props = merged_props(f)
        managed = {}
        for node in chain_of(f):                  # 近的亲优先，子不覆盖父已有项
            for k, v in node["managed"].items():
                managed.setdefault(k, v)
        ext = external_parent(f)
        for d in f["deps"]:
            if not d["artifactId"]:
                continue
            coord = d["coord"]
            if not coord or ":" not in coord:
                g = d["groupId"] or f["group"]
                coord = f"{g}:{d['artifactId']}" if g else d["artifactId"]
            raw = d["version"] or managed.get(coord, "")
            ver = _resolve_props(raw, props) if raw else ""
            note = ""
            if not ver or "${" in ver:
                ver = ""
                if not raw:
                    note = f"版本由父 POM 的 dependencyManagement 提供，源码内未找到"
                else:
                    note = f"属性 {raw} 未在本仓库任何 POM 中定义"
                if ext:
                    note += f"；根父 POM {ext} 不在源码库中（需执行 mvn dependency:tree 才能得到确定版本）"
            out.append(_mk("maven", coord, ver, _rel(f["path"]),
                           raw=raw or "(未声明)", kind="exact" if ver else "unresolved",
                           module=f["coord"], scope=d["scope"], coord=coord, note=note))
    return out


def _rel(abs_path: str, root_hint: str = "") -> str:
    """把绝对路径转成展示用相对路径（由调用方通过 _REL 映射覆盖）。"""
    return _REL.get(os.path.normpath(abs_path), os.path.basename(abs_path))


_REL: dict = {}          # 绝对路径 -> 相对路径（parse() 开始时填充）


# ================================================================= Gradle
_GRADLE_DEP_RE = re.compile(
    r"(?:^|\s)(implementation|api|compileOnly|compileOnlyApi|runtimeOnly|compile|"
    r"testImplementation|testCompileOnly|testRuntimeOnly|annotationProcessor|kapt|"
    r"developmentOnly|providedRuntime|classpath)\s*[\(\s]['\"]([^'\"]+)['\"]"
)
_GRADLE_MAP_RE = re.compile(
    r"(?:^|\s)(\w+)\s+group:\s*['\"]([^'\"]+)['\"]\s*,\s*name:\s*['\"]([^'\"]+)['\"]"
    r"(?:\s*,\s*version:\s*['\"]([^'\"]+)['\"])?"
)
_GRADLE_VAR_RE = re.compile(r"""(?:ext\.)?([A-Za-z_]\w*)\s*=\s*['"]([^'"]+)['"]""")
_GRADLE_VAL_RE = re.compile(r"""(?:val|var|const val)\s+([A-Za-z_]\w*)\s*=\s*["']([^"']+)["']""")


def _gradle_parse(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    variables = {}
    for m in _GRADLE_VAR_RE.finditer(content):
        variables[m.group(1)] = m.group(2)
    for m in _GRADLE_VAL_RE.finditer(content):
        variables[m.group(1)] = m.group(2)

    def resolve(v: str):
        if not v:
            return ""
        if "$" not in v:
            return v
        out = re.sub(r"\$\{?([A-Za-z_]\w*)\}?", lambda m: variables.get(m.group(1), m.group(0)), v)
        return "" if "$" in out else out

    rel = _rel(abs_path)
    found = []
    for m in _GRADLE_MAP_RE.finditer(content):
        cfg, g, a, v = m.group(1), m.group(2), m.group(3), m.group(4)
        ver = resolve(v or "")
        found.append(_mk("maven", f"{g}:{a}", ver, rel, raw=v or "${未声明}",
                         kind="exact" if ver else "unresolved",
                         scope=_gradle_scope(cfg), coord=f"{g}:{a}"))
    for m in _GRADLE_DEP_RE.finditer(content):
        cfg, coords = m.group(1), m.group(2).strip()
        if coords.startswith("project(") or ":" not in coords:
            continue
        parts = coords.split(":")
        if len(parts) < 2:
            continue
        g, a = parts[0], parts[1]
        ver_raw = parts[2] if len(parts) > 2 else ""
        ver = resolve(ver_raw)
        found.append(_mk("maven", f"{g}:{a}", ver, rel,
                         raw=ver_raw or "${未声明}",
                         kind="exact" if ver else "unresolved",
                         scope=_gradle_scope(cfg), coord=f"{g}:{a}"))
    return found


def _gradle_scope(cfg: str) -> str:
    c = cfg.lower()
    if c.startswith("test"):
        return "test"
    if c in ("compileonly", "compileonlyapi", "annotationprocessor", "kapt"):
        return "provided"
    if c in ("runtimeonly", "developmentonly"):
        return "runtime"
    return "compile"


# =========================================================== Gradle 版本目录
def _version_catalog(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    versions, libs, section = {}, {}, ""
    for raw in content.split("\n"):
        line = raw.split("#")[0].strip()
        if not line:
            continue
        if line.startswith("["):
            section = line.strip("[]").strip()
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*"([^"]*)"', line)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        if section == "versions":
            versions[key] = val
        elif section == "libraries":
            libs[key] = val
    out = []
    for _, spec in libs.items():
        parts = [p.strip() for p in spec.split(":")]
        if len(parts) < 2:
            continue
        ver = parts[2] if len(parts) > 2 else ""
        ver = re.sub(r"\$\{?([A-Za-z0-9_.\-]+)\}?", lambda m: versions.get(m.group(1), m.group(0)), ver)
        if "$" in ver:
            ver = ""
        out.append(_mk("maven", f"{parts[0]}:{parts[1]}", ver, rel,
                       raw=spec, kind="exact" if ver else "unresolved",
                       coord=f"{parts[0]}:{parts[1]}"))
    return out


# ====================================================================== npm
def _package_json(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return []
    rel = _rel(abs_path)
    module = data.get("name", "") or ""
    out = []
    for section, scope, ind in (("dependencies", "compile", False),
                                ("devDependencies", "test", True),
                                ("optionalDependencies", "optional", False),
                                ("peerDependencies", "peer", False)):
        for name, spec in (data.get(section) or {}).items():
            ver, kind = npm_floor(str(spec))
            out.append(_mk("npm", name, ver or "", rel, raw=str(spec),
                           kind=kind, module=module, scope=scope, indirect=ind))
    return out


def _package_lock(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return []
    rel = _rel(abs_path)
    out = []
    pkgs = data.get("packages")
    if isinstance(pkgs, dict):                       # lockfileVersion 2 / 3
        for path, meta in pkgs.items():
            if not path or not isinstance(meta, dict):
                continue
            name = meta.get("name") or path.split("node_modules/")[-1]
            ver = meta.get("version")
            if not name or not ver:
                continue
            out.append(_mk("npm", name, ver, rel, raw=str(ver), kind="exact",
                           scope="test" if meta.get("dev") else "compile",
                           indirect=("node_modules/" in path),
                           module=meta.get("name", "")))
    else:                                            # lockfileVersion 1
        def walk(node, depth=0):
            for name, meta in (node or {}).items():
                if not isinstance(meta, dict):
                    continue
                ver = meta.get("version")
                if ver:
                    out.append(_mk("npm", name, ver, rel, raw=str(ver), kind="exact",
                                   scope="test" if meta.get("dev") else "compile",
                                   indirect=depth > 0))
                walk(meta.get("dependencies"), depth + 1)
        walk(data.get("dependencies"))
    return out


# =================================================================== Python
def _toml_lite(text: str) -> dict:
    """极简 TOML 读取：只处理 [section] 与 key = 值（含多行数组）。

    Python 3.9/3.10 没有标准库 tomllib，而本项目坚持零第三方依赖，故对
    pyproject.toml 只做"够用"的解析：不追求 TOML 完整性，只取依赖声明。
    """
    data: dict = {}
    section = ""
    lines = text.split("\n")
    i = 0
    while i < len(lines):
        raw = lines[i]
        line = raw.split("#")[0].rstrip() if not raw.strip().startswith("#") else ""
        i += 1
        s = line.strip()
        if not s:
            continue
        m = re.match(r"^\[([^\]]+)\]$", s)
        if m:
            section = m.group(1).strip()
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+|"[^"]+")\s*=\s*(.*)$', s)
        if not m:
            continue
        key, val = m.group(1).strip('"'), m.group(2).strip()
        if val.startswith("[") and not val.endswith("]"):     # 多行数组
            buf = val
            while i < len(lines) and not buf.rstrip().endswith("]"):
                buf += "\n" + lines[i].split("#")[0]
                i += 1
            val = buf
        data.setdefault(section, {})[key] = val
    return data


def _toml_array(val: str):
    return [x.strip().strip('"').strip("'") for x in val.strip().strip("[]").split(",") if x.strip()]


def _toml_str(val: str) -> str:
    return val.strip().strip('"').strip("'")


def _pyproject(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    out = []
    # 优先用标准库 tomllib（3.11+），缺失时退回极简解析
    try:
        import tomllib
        data = tomllib.loads(content)
    except Exception:  # noqa: BLE001
        data = None
    entries = []          # (name, spec, scope)
    if isinstance(data, dict):
        proj = data.get("project") or {}
        for spec in proj.get("dependencies") or []:
            entries.append((str(spec), "compile"))
        for spec in (proj.get("optional-dependencies") or {}).get("dev") or []:
            entries.append((str(spec), "test"))
        poetry = ((data.get("tool") or {}).get("poetry") or {})
        for sec, scope in (("dependencies", "compile"),
                           ("dev-dependencies", "test")):
            for name, v in (poetry.get(sec) or {}).items():
                if name.lower() == "python":
                    continue
                spec = v if isinstance(v, str) else (v or {}).get("version", "")
                entries.append((f"{name}{spec if str(spec).startswith(('=', '<', '>', '~', '^', '!')) else '==' + str(spec)}",
                                scope) if spec else (name, scope))
    else:
        raw = _toml_lite(content)
        proj = raw.get("project", {})
        for spec in _toml_array(proj.get("dependencies", "[]")):
            entries.append((spec, "compile"))
        opt = raw.get("project.optional-dependencies", {})
        for spec in _toml_array(opt.get("dev", "[]")):
            entries.append((spec, "test"))
        poetry = raw.get("tool.poetry.dependencies", {})
        for name, v in poetry.items():
            if name.lower() == "python":
                continue
            spec = _toml_str(v)
            entries.append((f"{name}=={spec}" if spec else name, "compile"))
        for name, v in raw.get("tool.poetry.dev-dependencies", {}).items():
            entries.append((f"{name}=={_toml_str(v) or ''}", "test"))
    for spec, scope in entries:
        parsed = _req_line_spec(spec.replace(" ", "") if " " in spec and "=" not in spec else spec)
        if not parsed:
            continue
        name, ver, kind = parsed
        out.append(_mk("pypi", name, ver, rel, raw=spec, kind=kind, scope=scope))
    return out


def _requirements(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    out = []
    for raw in content.split("\n"):
        parsed = _req_line_spec(raw)
        if not parsed:
            continue
        name, ver, kind = parsed
        out.append(_mk("pypi", name, ver, rel, raw=raw.strip(), kind=kind,
                       scope="test" if "dev" in _base(abs_path) else "compile"))
    return out


def _pipfile(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    data = _toml_lite(content)
    out = []
    for section, scope in (("packages", "compile"), ("dev-packages", "test")):
        for name, val in (data.get(section) or {}).items():
            ver = _toml_str(val)
            ver = re.sub(r"^[=<>~^]+", "", ver)
            out.append(_mk("pypi", _pypi_name(name), ver, rel, raw=_toml_str(val),
                           kind="exact" if ver else "unresolved", scope=scope))
    return out


def _pipfile_lock(abs_path: str):
    """Pipfile.lock 是 JSON，含精确锁定版本（含传递依赖）。"""
    content, _ = read_text(abs_path)
    if not content:
        return []
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return []
    rel = _rel(abs_path)
    out = []
    for section, scope in (("default", "compile"), ("develop", "test")):
        for name, meta in (data.get(section) or {}).items():
            if not isinstance(meta, dict):
                continue
            ver = str(meta.get("version") or "").lstrip("=")
            out.append(_mk("pypi", _pypi_name(name), ver, rel,
                           raw=str(meta.get("version") or ""),
                           kind="exact" if ver else "unresolved", scope=scope))
    return out


# ====================================================================== Go
def _go_mod(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    out = []
    module = ""
    in_req = False
    for raw in content.split("\n"):
        line = raw.strip()
        if line.startswith("module "):
            module = line[len("module "):].strip()
            continue
        if line.startswith("require ("):
            in_req = True
            continue
        if in_req and line == ")":
            in_req = False
            continue
        target = None
        if in_req and line and not line.startswith("//"):
            target = line
        elif line.startswith("require ") and "(" not in line:
            target = line[len("require "):]
        if not target:
            continue
        target = target.split("//")[0].strip()
        parts = target.split()
        if len(parts) < 2:
            continue
        ver = strip_v(parts[1])
        out.append(_mk("go", parts[0], ver, rel, raw=target, kind="exact",
                       module=module, indirect="// indirect" in raw,
                       scope="compile"))
    return out


# ==================================================================== RubyGem
_GEM_SPEC_RE = re.compile(r"^ {4}([A-Za-z0-9_.\-]+) \(([^)]+)\)")


def _gemfile_lock(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    out, in_specs = [], False
    for raw in content.split("\n"):
        if raw.startswith("GEM"):
            in_specs = False
            continue
        if raw.strip() == "specs:":
            in_specs = True
            continue
        if in_specs:
            m = _GEM_SPEC_RE.match(raw)
            if m:
                out.append(_mk("rubygems", m.group(1), m.group(2), rel,
                               raw=f"{m.group(1)} ({m.group(2)})", kind="exact"))
    return out


def _gemfile(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    out = []
    for m in re.finditer(r"""^\s*gem\s+['"]([^'"]+)['"](?:\s*,\s*['"]([^'"]+)['"])?""",
                         content, re.M):
        name, spec = m.group(1), m.group(2) or ""
        ver = re.sub(r"^[~><=!=\s]+", "", spec).split(",")[0].strip()
        out.append(_mk("rubygems", name, ver, rel, raw=spec or "(未锁定)",
                       kind="exact" if ver else "unresolved"))
    return out


# ================================================================== Composer
def _composer_lock(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return []
    rel = _rel(abs_path)
    out = []
    for section, scope in (("packages", "compile"), ("packages-dev", "test")):
        for p in data.get(section) or []:
            name, ver = p.get("name"), p.get("version")
            if not name or not ver:
                continue
            out.append(_mk("packagist", name, ver.lstrip("v"), rel, raw=str(ver),
                           kind="exact", scope=scope))
    return out


def _composer_json(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    try:
        data = json.loads(content)
    except (ValueError, TypeError):
        return []
    rel = _rel(abs_path)
    out = []
    for section, scope in (("require", "compile"), ("require-dev", "test")):
        for name, spec in (data.get(section) or {}).items():
            if name == "php" or "/" not in name:
                continue
            ver = re.sub(r"^[\^~>=<v\s]+", "", str(spec)).strip()
            out.append(_mk("packagist", name, ver, rel, raw=str(spec),
                           kind="exact" if ver else "unresolved", scope=scope))
    return out


# ====================================================================== Rust
_CARGO_LOCK_RE = re.compile(
    r'\[\[package\]\]\s*\nname\s*=\s*"([^"]+)"\s*\nversion\s*=\s*"([^"]+)"', re.M)


def _cargo_lock(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    return [_mk("crates.io", m.group(1), m.group(2), rel,
                raw=f'{m.group(1)} {m.group(2)}', kind="exact")
            for m in _CARGO_LOCK_RE.finditer(content)]


def _cargo_toml(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    out, section = [], ""
    for raw in content.split("\n"):
        line = raw.split("#")[0].strip()
        if not line:
            continue
        if line.startswith("["):
            section = line.strip("[]").strip()
            continue
        if not re.match(r"^\[?(dependencies|dev-dependencies|build-dependencies)", section):
            continue
        m = re.match(r'^([A-Za-z0-9_.\-]+)\s*=\s*(?:"([^"]*)"|\{[^}]*version\s*=\s*"([^"]+)")',
                     line)
        if not m:
            continue
        name = m.group(1)
        spec = m.group(2) or m.group(3) or ""
        ver = re.sub(r"^[\^~>=<\s]+", "", spec).strip()
        out.append(_mk("crates.io", name, ver, rel, raw=spec,
                       kind="exact" if ver else "unresolved",
                       scope="test" if "dev" in section else "compile"))
    return out


# ====================================================================== .NET
_CS_RE = re.compile(
    r"<PackageReference\s+[^>]*Include\s*=\s*[\"']([^\"']+)[\"'][^>]*?"
    r"(?:Version\s*=\s*[\"']([^\"']+)[\"'])?", re.I)
_PKGCFG_RE = re.compile(r"<package\s+[^>]*id\s*=\s*[\"']([^\"']+)[\"'][^>]*?"
                        r"version\s*=\s*[\"']([^\"']+)[\"']", re.I)


def _csproj(abs_path: str):
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    out = []
    for m in _CS_RE.finditer(content):
        name, ver = m.group(1), m.group(2) or ""
        if not ver:      # <Version> 子节点写法
            tail = content[m.end():m.end() + 300]
            vm = re.search(r"<Version>([^<]+)</Version>", tail)
            ver = vm.group(1).strip() if vm else ""
        out.append(_mk("nuget", name, ver, rel, raw=ver or "(由 Directory.Packages.props 管理)",
                       kind="exact" if ver else "unresolved"))
    for m in _PKGCFG_RE.finditer(content):
        out.append(_mk("nuget", m.group(1), m.group(2), rel, kind="exact"))
    return out


# =========================================================== 依赖树文件摄取
# 关键取舍：pom.xml / package.json 的可达版本受"父 POM 是否在仓库里""依赖是否被
# BOM 管理""声明的是区间还是精确值"三重限制。项目只要能构建，就有一条更可靠的路：
#   mvn dependency:tree -DoutputFile=deps.txt -Dscope=compile
#   gradle dependencies > deps.txt
# 其输出是**解析后的精确版本 + 传递依赖**。这里做内容嗅探摄取它。
# 为避免把普通文本误判成依赖树，要求：文件名像依赖清单 + 至少 3 行合法坐标。
_TREE_HINT_RE = re.compile(r"(?i)(depend|deps|tree|libs|modules)")
_TREE_EXT = (".txt", ".log", ".out", ".tree")


def _tree_coord(line: str):
    """把一行依赖树文本解析成 (coord, version, scope)，失败返回 None。"""
    s = re.sub(r"^(?:[|+\\\-\s]{1,8})(?=[A-Za-z_@])", "", line).strip()
    if not s or ":" not in s:
        return None
    parts = [p.strip() for p in s.split(":")]
    parts = [p for p in parts if p]
    if len(parts) == 3:                     # g:a:version        （tgf 扁平格式）
        g, a, ver, scope = parts[0], parts[1], parts[2], ""
    elif len(parts) >= 4:                   # g:a:type:version[:scope]
        g, a, ver, scope = parts[0], parts[1], parts[3], (parts[4] if len(parts) > 4 else "")
    else:
        return None
    if not re.match(r"^\d", ver):           # 版本必须以数字开头（挡住 project : module 之类）
        return None
    if not re.match(r"^[A-Za-z_@]", g):
        return None
    return f"{g}:{a}", ver, scope


def _dep_tree(abs_path: str):
    content, _ = read_text(abs_path)
    if not content or len(content) > 512 * 1024:
        return []
    rel = _rel(abs_path)
    out = []
    for raw in content.split("\n"):
        parsed = _tree_coord(raw)
        if not parsed:
            continue
        coord, ver, scope = parsed
        out.append(_mk("maven", coord, ver, rel, raw=raw.strip(), kind="exact",
                       scope=scope or "compile", coord=coord,
                       note="来自依赖树文件（含传递依赖，版本已解析）"))
    return out if len(out) >= 3 else []


# ============================================================== 调度与去重
# =============================================================== 扩展生态
# 以下解析器遵循模块统一约定：只产出标准 Dep 记录（_mk），单个文件解析失败
# 静默跳过（parse 的调度层兜底），不阻塞其他清单。

def _poetry_lock(abs_path: str):
    """poetry.lock：[[package]] 数组，锁定精确版本（含传递依赖）。"""
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    out = []
    try:
        import tomllib
        for pkg in tomllib.loads(content).get("package") or []:
            name, ver = (pkg.get("name") or "").strip(), (pkg.get("version") or "").strip()
            if name and ver:
                cat = (pkg.get("category") or "main").lower()
                out.append(_mk("pypi", name, ver, rel, kind="exact",
                               scope="test" if cat == "dev" else "compile",
                               indirect=cat == "dev"))
    except Exception:                          # noqa: BLE001  tomllib 缺失/坏档时退回正则
        for m in re.finditer(r"\[\[package\]\](.*?)(?=\[\[package\]\]|\Z)", content, re.S):
            blk = m.group(1)
            nm = re.search(r'^\s*name\s*=\s*"([^"]+)"', blk, re.M)
            vr = re.search(r'^\s*version\s*=\s*"([^"]+)"', blk, re.M)
            if nm and vr:
                out.append(_mk("pypi", nm.group(1), vr.group(1), rel, kind="exact"))
    return out


def _yarn_lock(abs_path: str):
    """yarn.lock：v1（version "x"）与 Berry（version: x）两种格式，含传递依赖。"""
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    out, name = [], None
    for raw in content.split("\n"):
        line = raw.rstrip()
        if not line or line.startswith("#"):
            continue
        if not line[0].isspace():              # 条目头："pkg@range", pkg@range:
            head = line.rstrip(":").strip().strip('"').split(",")[0].strip()
            idx = head.rfind("@")              # scoped 包取最后一个 @，@scope/pkg@1.0.0
            name = head[:idx] if idx > 0 else None
            continue
        s = line.strip()
        if name is None:
            continue
        m = re.match(r'^version\s*"([^"]+)"', s) or re.match(r'^version:\s*"?([^"\s]+)"?', s)
        if m and m.group(1):
            out.append(_mk("npm", name, m.group(1), rel, kind="exact", indirect=True))
            name = None                        # 每个条目只取一次 version
    return out


def _pubspec_lock(abs_path: str):
    """pubspec.lock（Dart）：packages: 下 name -> dependency/version 三行结构。"""
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    out, cur, dep, ver = [], None, "", ""

    def flush():
        if cur and ver:
            out.append(_mk("pub", cur, ver, rel, kind="exact",
                           scope="test" if dep == "direct dev" else "compile",
                           indirect=dep == "transitive"))

    for raw in content.split("\n"):
        line = raw.rstrip()
        if not line or line.lstrip().startswith("#"):
            continue
        if not line[0].isspace():
            cur = None
            continue
        indent = len(line) - len(line.lstrip())
        s = line.strip()
        if indent == 2 and s.endswith(":"):
            flush()
            cur, dep, ver = s[:-1].strip().strip('"'), "", ""
        elif cur:
            if s.startswith("dependency:"):
                dep = s.split(":", 1)[1].strip().strip('"')
            elif s.startswith("version:"):
                ver = s.split(":", 1)[1].strip().strip('"')
    flush()
    return out


_PUB_SPEC_RE = re.compile(r"^[\^~><=]*\s*\d")


def _pubspec(abs_path: str):
    """pubspec.yaml（Dart）：直接依赖声明，区间取下界（floor 语义）。"""
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    out, section = [], ""
    for raw in content.split("\n"):
        line = raw.split("#")[0].rstrip()
        if not line.strip():
            continue
        if not line[0].isspace():
            section = line.split(":", 1)[0].strip()
            continue
        if section not in ("dependencies", "dev_dependencies"):
            continue
        indent = len(line) - len(line.lstrip())
        s = line.strip()
        if indent != 2 or ":" not in s:
            continue
        name, val = s.split(":", 1)
        name, val = name.strip(), val.strip()
        if not name or name == "flutter":      # SDK 框架本体不参与漏洞匹配
            continue
        scope = "test" if section == "dev_dependencies" else "compile"
        if _PUB_SPEC_RE.match(val):
            kind = "floor" if val[:1] in "^~<>" else "exact"
            m = re.match(r"[\^~><=]*\s*(\d[^\s,]*)", val)
            out.append(_mk("pub", name, m.group(1) if m else "", rel,
                           raw=val, kind=kind, scope=scope,
                           note="区间下界，实际安装版本可能更新" if kind == "floor" else ""))
        else:
            out.append(_mk("pub", name, "", rel, raw=val, kind="unresolved",
                           scope=scope, note="sdk/git/path 依赖，版本需由 pubspec.lock 提供"))
    return out


_MIX_RE = re.compile(r'"([^"]+)"\s*:\s*\{\s*:\s*hex\s*,\s*:\s*\w+\s*,\s*"([^"]+)"')


def _mix_lock(abs_path: str):
    """mix.lock（Elixir/Hex）：每行一个 \"pkg\": {:hex, :pkg, \"version\", ...}。"""
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    return [_mk("hex", m.group(1), m.group(2), rel, kind="exact")
            for m in _MIX_RE.finditer(content)]


_POD_RE = re.compile(r"^(.*?)\s*\(([^)]+)\)\s*$")


def _pod_lock(abs_path: str):
    """Podfile.lock（CocoaPods）：PODS: 段的 - Name (version)，子规格归并到主包。"""
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    out, section = [], ""
    for raw in content.split("\n"):
        line = raw.rstrip()
        if not line.strip():
            continue
        if not line[0].isspace():
            section = line.strip()
            continue
        if section != "PODS:" or not line.strip().startswith("- "):
            continue
        m = _POD_RE.match(line.strip()[2:].strip())
        if not m:
            continue
        full, ver = m.group(1).strip(), m.group(2).strip().split()[0]
        base = full.split("/")[0]              # Firebase/Core -> Firebase（子规格归主包）
        out.append(_mk("cocoapods", base, ver, rel, raw=f"{full} ({ver})", kind="exact",
                       note=f"子规格 {full}" if full != base else ""))
    return out


def _nuget_lock(abs_path: str):
    """packages.lock.json（.NET）：每个 TFM 一组 Direct/Transitive 依赖。"""
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    try:
        data = json.loads(content)
    except ValueError:
        return []
    out = []
    for _tfm, packages in (data.get("dependencies") or {}).items():
        for name, info in (packages or {}).items():
            ver = (info or {}).get("resolved") or ""
            if not ver:
                continue
            typ = ((info or {}).get("type") or "").lower()
            out.append(_mk("nuget", name, ver, rel, kind="exact", indirect=typ != "direct",
                           note="Central Transitive 管理" if "central" in typ else ""))
    return out


def _gradle_lockfile(abs_path: str):
    """gradle.lockfile：group:artifact:version=配置列表（Gradle 依赖锁定）。"""
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    out = []
    for raw in content.split("\n"):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        coords, _, confs = line.partition("=")
        seg = coords.split(":")
        if len(seg) < 3:
            continue
        g, a, v = seg[0].strip(), seg[1].strip(), seg[2].strip()
        if not v or not re.match(r"^[\d\[].", v):
            continue
        out.append(_mk("maven", f"{g}:{a}", v, rel, kind="exact", coord=f"{g}:{a}",
                       scope="test" if "test" in confs.lower() else "compile"))
    return out


_SWIFT_VER_RE = re.compile(
    r'(?:from|exact)\s*:\s*"([\d][^"]*)"|\.exact\(\s*"([\d][^"]*)"\s*\)')
_SWIFT_URL_RE = re.compile(r'url:\s*"([^"]+)"')


def _package_swift(abs_path: str):
    """Package.swift（SwiftPM）：.package(url:...) 声明。

    OSV 的 SwiftURL 生态以仓库 URL 为包名，故 name 存完整 URL，
    coord 存短名（仓库最后一段）供界面展示。
    """
    content, _ = read_text(abs_path)
    if not content:
        return []
    rel = _rel(abs_path)
    out = []
    for m in re.finditer(r"\.package\(([^)]*)\)", content, re.S):
        args = m.group(1)
        mu = _SWIFT_URL_RE.search(args)
        if not mu:
            continue
        url = mu.group(1)
        short = url.rstrip("/").split("/")[-1]
        if short.endswith(".git"):
            short = short[:-4]
        mv = _SWIFT_VER_RE.search(args)
        if mv:
            ver = mv.group(1) or mv.group(2) or ""
            # exact 判定：匹配文本以 exact 开头，或走的是 .exact("x") 备选分支
            kind = "exact" if (mv.group(0).startswith("exact") or mv.group(2)) else "floor"
            out.append(_mk("swift", url, ver, rel, raw=args.strip()[:120], kind=kind,
                           coord=short,
                           note="区间下界，实际解析版本可能更新" if kind == "floor" else ""))
        else:
            out.append(_mk("swift", url, "", rel, raw=args.strip()[:120],
                           kind="unresolved", coord=short,
                           note="revision/branch/本地路径依赖，无固定版本"))
    return out


def _kind_of(name: str, path: str) -> str | None:
    low = name.lower()
    if low == "pom.xml":
        return "pom"
    if low in ("build.gradle", "build.gradle.kts"):
        return "gradle"
    if low == "libs.versions.toml":
        return "catalog"
    if low == "package.json":
        return "pkgjson"
    if low in ("package-lock.json", "npm-shrinkwrap.json"):
        return "pkglock"
    if low == "yarn.lock":
        return "yarnlock"
    if low == "poetry.lock":
        return "poetrylock"
    if low.startswith("requirements") and low.endswith(".txt"):
        return "requirements"
    if low == "pyproject.toml":
        return "pyproject"
    if low == "pipfile":
        return "pipfile"
    if low == "pipfile.lock":
        return "pipfilelock"
    if low == "go.mod":
        return "gomod"
    if low == "gemfile.lock":
        return "gemlock"
    if low == "gemfile":
        return "gemfile"
    if low == "composer.lock":
        return "composerlock"
    if low == "composer.json":
        return "composerjson"
    if low == "cargo.lock":
        return "cargolock"
    if low == "cargo.toml":
        return "cargotoml"
    if low.endswith(".csproj") or low == "packages.config":
        return "nuget"
    if low == "packages.lock.json":
        return "nulock"
    if low == "gradle.lockfile":
        return "gradlelock"
    if low == "pubspec.yaml":
        return "pubspec"
    if low == "pubspec.lock":
        return "publock"
    if low == "mix.lock":
        return "mixlock"
    if low == "podfile.lock":
        return "podlock"
    if low == "package.swift":
        return "packageswift"
    return None


def is_manifest(path: str) -> bool:
    base = _base(path)
    return base in MANIFEST_NAMES or base.endswith(".csproj")


def parse(files, cap: int = MAX_DEPS):
    """解析全部清单文件，返回 (deps, meta)。

    files: 具备 .rel / .abs 属性的对象序列（引擎的 FileEntry）。
    deps  : 去重后的依赖记录列表（按生态 + 名称 + 版本排序）。
    meta  : 解析概况，供界面与报告展示"哪些清单被读到 / 有没有截断"。
    """
    global _REL
    _REL = {}
    for f in files:
        _REL[os.path.normpath(getattr(f, "abs", ""))] = getattr(f, "rel", "")

    groups: dict = {}
    poms = []
    trees = []
    for f in files:
        rel, abs_path = getattr(f, "rel", ""), getattr(f, "abs", "")
        kind = _kind_of(_base(rel), rel)
        if not kind:
            # 依赖树文件：靠文件名提示 + 内容嗅探识别，不参与常规清单调度
            low = _base(rel)
            if low.endswith(_TREE_EXT) and _TREE_HINT_RE.search(low):
                trees.append(abs_path)
            continue
        groups.setdefault(kind, []).append(abs_path)
        if kind == "pom":
            poms.append(abs_path)

    found = []
    kinds_seen = {}
    for kind, paths in groups.items():
        kinds_seen[kind] = len(paths)
        for p in paths:
            try:
                if kind == "pom":
                    continue                      # pom 走两阶段统一解析
                elif kind == "gradle":
                    found += _gradle_parse(p)
                elif kind == "catalog":
                    found += _version_catalog(p)
                elif kind == "pkgjson":
                    found += _package_json(p)
                elif kind == "pkglock":
                    found += _package_lock(p)
                elif kind == "requirements":
                    found += _requirements(p)
                elif kind == "pyproject":
                    found += _pyproject(p)
                elif kind == "pipfile":
                    found += _pipfile(p)
                elif kind == "pipfilelock":
                    found += _pipfile_lock(p)
                elif kind == "gomod":
                    found += _go_mod(p)
                elif kind == "gemlock":
                    found += _gemfile_lock(p)
                elif kind == "gemfile":
                    found += _gemfile(p)
                elif kind == "composerlock":
                    found += _composer_lock(p)
                elif kind == "composerjson":
                    found += _composer_json(p)
                elif kind == "cargolock":
                    found += _cargo_lock(p)
                elif kind == "cargotoml":
                    found += _cargo_toml(p)
                elif kind == "nuget":
                    found += _csproj(p)
                elif kind == "poetrylock":
                    found += _poetry_lock(p)
                elif kind == "yarnlock":
                    found += _yarn_lock(p)
                elif kind == "pubspec":
                    found += _pubspec(p)
                elif kind == "publock":
                    found += _pubspec_lock(p)
                elif kind == "mixlock":
                    found += _mix_lock(p)
                elif kind == "podlock":
                    found += _pod_lock(p)
                elif kind == "nulock":
                    found += _nuget_lock(p)
                elif kind == "gradlelock":
                    found += _gradle_lockfile(p)
                elif kind == "packageswift":
                    found += _package_swift(p)
            except Exception:                     # noqa: BLE001  单个清单失败不影响整体
                continue
    if poms:
        try:
            found += _pom_parse_all(poms)
        except Exception:                          # noqa: BLE001
            pass
    for t in trees:
        try:
            got = _dep_tree(t)
        except Exception:                          # noqa: BLE001
            got = []
        if got:
            found += got
            kinds_seen["depsTree"] = kinds_seen.get("depsTree", 0) + 1

    # ---- 去重：同生态同名同版本合并，保留全部出现位置 ----
    merged: dict = {}
    for d in found:
        if not d["name"]:
            continue
        key = (d["ecosystem"], d["name"], d["version"], d["version_kind"])
        rec = merged.get(key)
        if rec is None:
            rec = dict(d)
            rec["manifests"] = [d["manifest"]]
            rec["scopes"] = [d["scope"]] if d["scope"] else []
            merged[key] = rec
        else:
            if d["manifest"] not in rec["manifests"]:
                rec["manifests"].append(d["manifest"])
            if d["scope"] and d["scope"] not in rec["scopes"]:
                rec["scopes"].append(d["scope"])
            rec["indirect"] = rec["indirect"] and d["indirect"]

    deps = list(merged.values())

    # ---- 精确版本优先：同一生态下若有 exact 记录，则丢弃同包的 floor 记录 ----
    # 典型场景：仓库里既有 package-lock.json（精确、含传递依赖）又有 package.json
    # （区间声明）。两条都送去查漏洞会重复报同一条，且 floor 还更容易假阳性。
    exact_names = {(d["ecosystem"], d["name"]) for d in deps
                   if d["version_kind"] == "exact"}
    if exact_names:
        deps = [d for d in deps
                if d["version_kind"] != "floor"
                or (d["ecosystem"], d["name"]) not in exact_names]

    truncated = len(deps) > cap
    if truncated:
        # 截断时优先保留可直接比对的（exact），再按生态/名称排序
        order = {"exact": 0, "floor": 1, "unresolved": 2}
        deps.sort(key=lambda d: (order.get(d["version_kind"], 3),
                                 d["ecosystem"], d["name"], d["version"]))
        deps = deps[:cap]
    for d in deps:
        scopes = d.get("scopes") or ["compile"]
        d["manifest"] = d["manifests"][0]
        # 作用域取"最生产"的那个：同一依赖只要有一处用于生产，就不能按测试代码弱化
        d["scope"] = next((s for s in ("compile", "runtime", "provided", "optional",
                                       "peer", "test") if s in scopes), scopes[0])
        # indirect：解析器标记的传递依赖（go.mod // indirect、lockfile 嵌套），
        # 或所有出现位置都落在测试作用域
        d["indirect"] = bool(d.get("indirect")) or all(
            s in ("test", "dev") for s in scopes)
        d.pop("scopes", None)
    deps.sort(key=lambda d: (d["ecosystem"], d["name"], d["version"]))

    by_eco = {}
    for d in deps:
        by_eco[d["ecosystem"]] = by_eco.get(d["ecosystem"], 0) + 1
    unresolved = sum(1 for d in deps if d["version_kind"] == "unresolved")
    floored = sum(1 for d in deps if d["version_kind"] == "floor")
    meta = {
        "manifests": sum(kinds_seen.values()),
        "by_manifest_kind": kinds_seen,
        "by_ecosystem": by_eco,
        "unresolved": unresolved,
        "floored": floored,
        "truncated": truncated,
        "total": len(deps),
    }
    return deps, meta
