# -*- coding: utf-8 -*-
"""
源代码静态审计平台 —— 服务端入口

仅依赖 Python 3.9+ 标准库，无需安装任何第三方包。
启动：python app.py [--root 待审计目录] [--port 8770] [--host 127.0.0.1]
"""
from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import mimetypes
import os
import platform
import posixpath
import re
import secrets
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core import (AuditEngine, CATEGORY_META, DEFAULT_EXCLUDES, LANG_EXT,
                  RULES, SEVERITY_META, SEVERITY_ORDER, detect_language, read_text)
from core import reporter, vulndb, projects
from core.manifests import ECO_LABEL, OSV_ECOSYSTEM, is_manifest
# 工具元信息（名称 / 版本 / 反馈邮箱 / 最低 Python 版本）统一取自 core/meta.py，
# 保证服务端、报告导出、自检脚本三处永远一致
from core.meta import (FEEDBACK_EMAIL, FEEDBACK_SUBJECT_PREFIX, FEEDBACK_TITLE,
                       MIN_PYTHON, MIN_PYTHON_STR, PYTHON_DOWNLOAD_URL,
                       RECOMMENDED_PYTHON, TOOL_NAME, TOOL_NAME_EN, TOOL_VERSION)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WEB_DIR = os.path.join(BASE_DIR, "web")
REPORT_DIR = os.path.join(BASE_DIR, "reports")

# 漏洞库缓存目录（独立于 reports/workspaces，便于单独清理与备份）
VULNDB_DIR = os.path.join(BASE_DIR, "vulndb")
VULNDB_CACHE = os.path.join(VULNDB_DIR, "cache.json")

# 审计项目目录：每次扫描独立建档（唯一 ID），结果/配置相互隔离
PROJECTS_DIR = projects.PROJECTS_DIR

# 服务端默认排除：基础排除项 + 审计工具自身目录 + 报告输出目录
SERVER_EXCLUDES = list(DEFAULT_EXCLUDES) + [os.path.basename(BASE_DIR), "reports",
                                            "workspaces", "vulndb", "projects"]

# ---------------------------------------------------------------- 上传工作区
# 浏览器原生目录选择器不会给出绝对路径，因此「网页选目录」必须把文件上传到服务器，
# 由服务器在 workspaces/<id>/<名称> 下建立一份副本再扫描。
WORKSPACE_DIR = os.path.join(BASE_DIR, "workspaces")
MAX_UPLOAD_FILES = 8000                       # 单次上传文件数上限
MAX_UPLOAD_FILE = 12 * 1024 * 1024            # 单文件上限 12MB
MAX_UPLOAD_TOTAL = 400 * 1024 * 1024          # 单次上传总量上限 400MB
MAX_WORKSPACES = 6                            # 保留最近 N 个工作区
WS_REGISTRY: dict = {}                        # ws_id -> {root, name, files, bytes, created}

# 服务器端兜底过滤：即便前端漏掉，也不落盘明显无审计价值的二进制/压缩包
UPLOAD_BLOCK_EXT = {
    ".png", ".jpg", ".jpeg", ".gif", ".bmp", ".ico", ".webp", ".svgz", ".tiff",
    ".mp3", ".mp4", ".avi", ".mov", ".mkv", ".wav", ".flac", ".webm",
    ".zip", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar", ".war", ".apk",
    ".exe", ".dll", ".so", ".dylib", ".bin", ".o", ".a", ".lib", ".class", ".pyc",
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".db", ".sqlite", ".pack", ".idx",
}

EXPORT_FORMATS = {
    "html": ("HTML 网页报告", "html"),
    "docx": ("Word 文档 (.docx)", "docx"),
    "md": ("Markdown 文档", "md"),
    "csv": ("CSV 表格", "csv"),
    "json": ("JSON 数据", "json"),
}

# 结果分组维度
GROUP_KEYS = {
    "severity": lambda f: f["severity"],
    "category": lambda f: f["category"],
    "scope": lambda f: f.get("scope", "production"),
    "file": lambda f: f["file"],
    "rule": lambda f: f["rule_id"],
}
SCOPE_CN = {"production": "生产代码", "test": "测试 / 示例代码", "doc": "文档"}

# 全局状态
STATE = {
    "root": None,          # 当前审计根目录
    "target": None,        # {root, name, kind} —— kind: path(服务器目录) / upload(网页上传)
    "engine": None,        # 最近一次完成的引擎
    "project_id": "",      # 当前扫描所属项目（每次扫描新建，见 core/projects.py）
    "running": False,
    "lock": threading.Lock(),
    "task": None,
    "progress": None,
    # ---- 依赖漏洞库（SCA）----
    "vulns": None,          # 最近一次漏洞分析结果（与 engine.vulns 同一对象）
    "vuln_running": False,
    "vuln_progress": None,  # {phase, done, total}
    "vuln_error": "",
    "vuln_opts": {"enabled": True, "ttl": vulndb.DEFAULT_PKG_TTL,
                  "offline": False, "analyzed_at": 0.0, "engine_id": None},
}

# 漏洞结果分组维度
VULN_GROUP_KEYS = ("package", "severity", "ecosystem", "fix", "manifest", "cvss")
FIX_LABEL = {
    "same-branch": "同版本线内可修复",
    "minor-up": "需升到更高次版本线",
    "major-up": "需跨主版本升级",
    "none": "暂无修复版本",
}
_FIX_ORDER = {"same-branch": 0, "minor-up": 1, "major-up": 2, "none": 3}

# 文件树缓存：{root: (时间戳, 树)}，避免每次刷新页面都重新遍历磁盘
_TREE_CACHE: dict = {}
_TREE_TTL = 20.0


# ============================================================== 工具函数
def ok(data):
    return {"code": 0, "message": "success", "data": data}


def fail(msg, code=1):
    return {"code": code, "message": msg, "data": None}


def safe_join(root: str, rel: str) -> str | None:
    """把相对路径安全地拼到 root 下，阻止路径穿越。"""
    rel = urllib.parse.unquote(rel or "").replace("\\", "/").lstrip("/")
    rel = posixpath.normpath(rel)
    if rel in (".", "") or rel.startswith("../"):
        return None
    target = os.path.abspath(os.path.join(root, rel.replace("/", os.sep)))
    root_abs = os.path.abspath(root)
    if target != root_abs and not target.startswith(root_abs + os.sep):
        return None
    return target


# ---------------------------------------------------------------- 工作区
def _safe_folder_name(name: str) -> str:
    """把上传来源的文件夹名净化成安全的目录名。"""
    name = (name or "").strip().replace("\\", "/").split("/")[-1]
    name = re.sub(r'[<>:"/\\|?*\x00-\x1f]+', "_", name).strip(" .")
    return (name or "uploaded")[:64]


def ws_root(ws_id: str) -> str | None:
    """解析工作区根目录；服务重启后注册表丢失时回退到目录探测。"""
    if not ws_id or not re.fullmatch(r"[A-Za-z0-9_-]{6,64}", ws_id):
        return None
    rec = WS_REGISTRY.get(ws_id)
    if rec and os.path.isdir(rec["root"]):
        return rec["root"]
    base = os.path.join(WORKSPACE_DIR, ws_id)
    if not os.path.isdir(base):
        return None
    subs = [os.path.join(base, d) for d in sorted(os.listdir(base))
            if os.path.isdir(os.path.join(base, d))]
    return subs[0] if subs else base


def create_workspace(folder: str) -> dict:
    """新建一个上传工作区，返回 {ws, root, name}。"""
    os.makedirs(WORKSPACE_DIR, exist_ok=True)
    prune_workspaces()
    name = _safe_folder_name(folder)
    ws_id = time.strftime("%Y%m%d-%H%M%S") + "-" + secrets.token_hex(3)
    root = os.path.join(WORKSPACE_DIR, ws_id, name)
    os.makedirs(root, exist_ok=True)
    WS_REGISTRY[ws_id] = {"root": root, "name": name, "files": 0, "bytes": 0,
                          "created": time.time()}
    return {"ws": ws_id, "root": root, "name": name}


def prune_workspaces(keep: int = MAX_WORKSPACES) -> None:
    """只保留最近创建的 N 个工作区，避免磁盘无限增长。"""
    if not os.path.isdir(WORKSPACE_DIR):
        return
    entries = []
    for d in os.listdir(WORKSPACE_DIR):
        p = os.path.join(WORKSPACE_DIR, d)
        if os.path.isdir(p):
            try:
                entries.append((os.path.getmtime(p), d))
            except OSError:
                continue
    entries.sort(reverse=True)
    for _, name in entries[keep:]:
        shutil.rmtree(os.path.join(WORKSPACE_DIR, name), ignore_errors=True)
        WS_REGISTRY.pop(name, None)


# ------------------------------------------------- 服务器端原生目录对话框
try:
    import tkinter  # noqa: F401
    HAS_TK = True
except Exception:                                        # noqa: BLE001
    HAS_TK = False

_BROWSE_SCRIPT = (
    "import sys\n"
    "import tkinter as tk\n"
    "from tkinter import filedialog\n"
    "r = tk.Tk()\n"
    "r.withdraw()\n"
    "r.attributes('-topmost', True)\n"
    "r.update()\n"
    "p = filedialog.askdirectory(title='选择待审计的代码目录', initialdir=sys.argv[1])\n"
    "try:\n"
    "    r.destroy()\n"
    "except Exception:\n"
    "    pass\n"
    "sys.stdout.write(p or '')\n"
)


def browse_folder(initial: str) -> tuple[str, str]:
    """弹出操作系统原生目录对话框，返回 (路径, 错误信息)。

    在独立子进程中运行 Tk（主进程可能是无 tkinter 的解释器，且 Tk 不适合在
    工作线程中创建），并强制子进程以 UTF-8 输出，避免中文路径被误码。
    """
    if not HAS_TK:
        return "", ("当前 Python 解释器未包含 tkinter，无法弹出系统目录对话框。"
                    "请改为手工填写路径，或用自带 tkinter 的官方 Python 启动本工具。")
    if not os.path.isdir(initial or ""):
        initial = os.path.expanduser("~")
    env = dict(os.environ)
    env["PYTHONIOENCODING"] = "utf-8"
    env["PYTHONUTF8"] = "1"
    try:
        proc = subprocess.run([sys.executable, "-c", _BROWSE_SCRIPT, initial],
                              capture_output=True, timeout=600, env=env)
    except subprocess.TimeoutExpired:
        return "", "目录选择等待超时，请重试。"
    except Exception as exc:                             # noqa: BLE001
        return "", f"无法启动目录对话框：{exc}"
    out = proc.stdout.decode("utf-8", "replace").strip()
    if not out and proc.returncode != 0:
        err = proc.stderr.decode("utf-8", "replace").strip().splitlines()
        return "", "目录对话框启动失败：" + (err[-1] if err else "未知错误")
    return out, ""


# ==================================================== 运行环境自检（可移植性）
# 目标：让「拷到别的电脑上能不能直接跑」这件事有据可查——把 Python 版本、操作系统、
# 目录可写性、端口可用性、联网能力等影响可移植性的因素一次性列清楚，
# 既通过 `python app.py --check-env` 在装之前自证，也通过 `GET /api/env`
# 在界面「关于与反馈」面板里展示并一键复制给维护者。
_NET_CACHE: dict = {"at": 0.0, "ok": None}      # 联网探测结果缓存，避免面板反复阻塞
_NET_TTL = 60.0


def probe_network(host: str = "osv.dev", port: int = 443,
                  timeout: float = 2.5, force: bool = False) -> bool:
    """探测能否访问漏洞库站点（TLS 端口连通性即可，不发送实际请求）。

    结果缓存 60 秒；失败不抛异常，只返回 False —— 离线环境同样可以正常使用
    （SCA 退化为只读本地缓存），因此这不是「硬性检查项」。
    """
    now = time.time()
    if not force and _NET_CACHE["ok"] is not None and now - _NET_CACHE["at"] < _NET_TTL:
        return bool(_NET_CACHE["ok"])
    okflag = False
    try:
        with socket.create_connection((host, port), timeout=timeout):
            okflag = True
    except Exception:                                    # noqa: BLE001
        okflag = False
    _NET_CACHE.update({"at": now, "ok": okflag})
    return okflag


def _dir_writable(path: str) -> bool:
    """目录是否可写：不存在则尝试创建，再写入并删除一个探测文件实测。"""
    try:
        os.makedirs(path, exist_ok=True)
        probe = os.path.join(path, ".write-probe-" + secrets.token_hex(4))
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.remove(probe)
        return True
    except Exception:                                    # noqa: BLE001
        return False


def _cache_size(path: str) -> int:
    try:
        return os.path.getsize(path)
    except OSError:
        return 0


def env_report(check_network: bool = True, port: int = 0) -> dict:
    """汇总运行环境与可移植性相关的全部信息（供 CLI 自检与 /api/env 复用）。"""
    py_ver = "%d.%d.%d" % sys.version_info[:3]
    py_ok = tuple(sys.version_info[:2]) >= MIN_PYTHON
    port = int(port or STATE.get("port") or 8770)
    port_busy = port_occupied("127.0.0.1", port)

    dirs = {
        "工具目录": BASE_DIR,
        "报告目录": REPORT_DIR,
        "上传工作区": WORKSPACE_DIR,
        "项目档案": PROJECTS_DIR,
        "漏洞库缓存": VULNDB_DIR,
    }
    writable = {name: _dir_writable(p) for name, p in dirs.items()}
    all_writable = all(writable.values())

    online = probe_network(force=True) if check_network else False
    cache_bytes = _cache_size(VULNDB_CACHE)
    offline_opt = bool(STATE["vuln_opts"].get("offline"))

    checks = []

    def _chk(key, label, ok, detail, fatal=True):
        checks.append({"key": key, "label": label, "ok": bool(ok),
                       "detail": detail, "fatal": bool(fatal)})

    _chk("python", f"Python 版本 ≥ {MIN_PYTHON_STR}", py_ok,
         f"当前 {py_ver}（{sys.implementation.name}）；推荐 {RECOMMENDED_PYTHON}"
         + ("" if py_ok else f"；请升级：{PYTHON_DOWNLOAD_URL}"))
    _chk("stdlib", "标准库依赖齐全（零第三方包）", True,
         f"规则 {len(RULES)} 条 / 清单格式 {len(OSV_ECOSYSTEM)} 种，全部由标准库实现，无需 pip install")
    _chk("writable", "工具目录可写（报告 / 归档 / 缓存）", all_writable,
         ("全部可写：" + "、".join(dirs)) if all_writable
         else "不可写：" + "、".join(n for n, v in writable.items() if not v)
              + " —— 请把工具放到有写权限的目录（避免 Program Files 等受保护位置）")
    _chk("port", f"默认端口 {port} 可用", not port_busy,
         "端口空闲" if not port_busy
         else "已被占用，启动时会自动顺延到下一个空闲端口（不影响使用）", fatal=False)
    _chk("tkinter", "网页目录浏览器可用（不依赖 tkinter）", True,
         "已内置；系统原生对话框" + ("可用（可选快捷方式）" if HAS_TK else "不可用（已自动隐藏，不影响选目录）"),
         fatal=False)
    _chk("network", "可访问 OSV.dev（在线依赖漏洞库）", online,
         "在线可用，SCA 数据实时更新" if online
         else "不可达：SCA 将只读本地缓存，静态扫描与其余功能不受影响（非硬性依赖）",
         fatal=False)

    warn = [c for c in checks if not c["ok"] and not c["fatal"]]
    fail = [c for c in checks if not c["ok"] and c["fatal"]]
    summary = {
        "ok": sum(1 for c in checks if c["ok"]),
        "warn": len(warn), "fail": len(fail), "total": len(checks),
        "ready": not fail,
        "verdict": "环境就绪，可直接运行" if not fail
                   else "存在阻断项，请先按提示处理",
    }

    return {
        "tool": TOOL_NAME,
        "tool_en": TOOL_NAME_EN,
        "version": TOOL_VERSION,
        "feedback": {
            "email": FEEDBACK_EMAIL,
            "title": FEEDBACK_TITLE,
            "subject_prefix": FEEDBACK_SUBJECT_PREFIX,
        },
        "requirements": {
            "os": "Windows 7 SP1+ / 主流 Linux 发行版 / macOS 10.13+",
            "python": f">= {MIN_PYTHON_STR}",
            "python_recommended": RECOMMENDED_PYTHON,
            "third_party": "无（零 pip 依赖）",
            "optional": "tkinter（仅系统原生对话框快捷方式）、联网（仅在线 SCA）",
            "download": PYTHON_DOWNLOAD_URL,
        },
        "python": {
            "version": py_ver,
            "full": sys.version.replace("\n", " "),
            "implementation": sys.implementation.name,
            "executable": sys.executable,
            "ok": py_ok,
            "required": MIN_PYTHON_STR,
            "recommended": RECOMMENDED_PYTHON,
        },
        "system": {
            "os": platform.system(),
            "os_release": platform.release(),
            "os_version": platform.version(),
            "machine": platform.machine(),
            "platform": sys.platform,
            "frozen": bool(getattr(sys, "frozen", False)),
        },
        "encoding": {
            "stdout": getattr(sys.stdout, "encoding", "") or "",
            "filesystem": sys.getfilesystemencoding(),
            "default": sys.getdefaultencoding(),
            "utf8_mode": bool(getattr(sys.flags, "utf8_mode", 0)),
        },
        "paths": {
            "base_dir": BASE_DIR,
            "cwd": os.getcwd(),
            "audit_root": STATE.get("root") or "",
            "dirs": dirs,
        },
        "writable": {**writable, "all": all_writable},
        "features": {
            "rules": len(RULES),
            "manifest_ecosystems": len(OSV_ECOSYSTEM),
            "tkinter": HAS_TK,
            "web_dir_browser": True,
            "network": online,
            "vulndb_enabled": bool(STATE["vuln_opts"].get("enabled")),
            "vulndb_offline": offline_opt,
            "vulndb_cache_bytes": cache_bytes,
            "vulndb_cache_present": cache_bytes > 0,
        },
        "checks": checks,
        "summary": summary,
    }


def print_env_report(rep: dict) -> None:
    """把环境自检结果打印成人类可读的控制台报告。

    状态标记刻意使用 ASCII（OK / ! / X）：控制台输出可能被重定向到 GBK 终端或
    管道，非 ASCII 的勾叉字符会乱码，而 ASCII 标记在任何编码下都能正确显示。
    """
    def mark(c):
        return "OK" if c["ok"] else ("!" if not c["fatal"] else "X")

    print("=" * 68)
    print(f"  {TOOL_NAME} v{TOOL_VERSION} —— 运行环境自检")
    print("=" * 68)
    for c in rep["checks"]:
        print(f"  [{mark(c)}] {c['label']}")
        print(f"        {c['detail']}")
    p = rep["paths"]
    print("-" * 68)
    print(f"  工具目录   : {p['base_dir']}")
    print(f"  工作目录   : {p['cwd']}")
    print(f"  解释器     : {rep['python']['executable']}")
    print(f"  操作系统   : {rep['system']['os']} {rep['system']['os_release']}"
          f"（{rep['system']['machine']}）")
    print(f"  终端编码   : {rep['encoding']['stdout'] or '未知'} / 文件系统 {rep['encoding']['filesystem']}")
    print("-" * 68)
    s = rep["summary"]
    icon = "OK" if s["ready"] else "X"
    print(f"  [{icon}] {s['verdict']}：{s['ok']}/{s['total']} 项通过"
          + (f"，{s['warn']} 项提示" if s["warn"] else "")
          + (f"，{s['fail']} 项阻断" if s["fail"] else ""))
    print("=" * 68)
    print(f"  可移植性：整个工具目录（含 projects/ 与 vulndb/）复制到任意装有")
    print(f"  Python {MIN_PYTHON_STR}+ 的电脑即可直接运行，无需安装任何第三方包。")
    print("=" * 68)
    print(f"  {FEEDBACK_TITLE}：{FEEDBACK_EMAIL}")
    print("=" * 68)


# 隐藏目录中仍需扫描的例外（GitHub 工作流常含部署配置风险）
KEPT_DOT_DIRS = {".github"}


def _keep_dir(d: str) -> bool:
    return d not in SERVER_EXCLUDES and (not d.startswith(".git") or d in KEPT_DOT_DIRS) \
        and (not d.startswith(".") or d in KEPT_DOT_DIRS)


# ------------------------------------------- 网页目录浏览器（零 tkinter 依赖）
# 「选择审计目录」不再要求 Python 解释器自带 tkinter：由网页逐层浏览服务器文件
# 系统，服务端只负责「列举子目录 + 统计可审计源码文件数」，全部为标准库调用，
# Windows / Linux / macOS 通用。tkinter 若存在，系统原生对话框仍作为可选快捷方式
# 保留（见 /api/browse），二者互不影响。
DIR_LIST_MAX = 800          # 单层返回的子目录上限（超大目录不拖垮前端）
DIR_ENRICH_MAX = 150        # 子目录逐项统计（源码数/是否含下级）的条目上限
DIR_WALK_MAX = 30000        # 递归统计源码文件时最多访问的条目数（有界，保证响应速度）
DIR_WALK_SEC = 3.0          # 递归统计的时间上限（秒）
_DRIVE_LETTERS = "ACDEFGHIJKLMNOPQRSTUVWXYZB"


def _same_path(a: str, b: str) -> bool:
    try:
        return os.path.normcase(os.path.abspath(a)) == os.path.normcase(os.path.abspath(b))
    except Exception:                                    # noqa: BLE001
        return False


def list_roots() -> list:
    """可浏览的起始位置：Windows 各盘符 / POSIX 根目录，另附用户主目录。"""
    out = []
    if os.name == "nt":
        for ch in _DRIVE_LETTERS:
            drive = ch + ":\\"
            try:
                if os.path.isdir(drive):
                    out.append({"name": ch + ":", "path": drive})
            except OSError:                              # 无介质的光驱/软驱等
                continue
    else:
        out.append({"name": "/", "path": "/"})
    home = os.path.expanduser("~")
    if os.path.isdir(home) and not any(_same_path(r["path"], home) for r in out):
        out.append({"name": "用户主目录", "path": home})
    return out


def _crumbs(path: str) -> list:
    """从根到当前目录的逐级可点击路径。

    显式按盘符/分隔符拆分，避免 os.path.dirname 在盘符根（C:\\）与其缩写（C:）
    之间来回跳导致出现重复层级。
    """
    p = os.path.abspath(path)
    drive, tail = os.path.splitdrive(p)
    norm = tail.replace("\\", os.sep).replace("/", os.sep)
    parts = [x for x in norm.split(os.sep) if x]
    if drive:
        cur = drive + os.sep
        items = [{"name": drive, "path": cur}]
    else:
        cur = os.sep
        items = [{"name": os.sep, "path": os.sep}]
    for part in parts:
        cur = os.path.join(cur, part)
        items.append({"name": part, "path": cur})
    return items


def _walk_sources(root: str, deadline: float) -> tuple:
    """有界递归统计可审计源码文件数，返回 (数量, 是否因上限提前停止)。"""
    n, visited, partial = 0, 0, False
    stack = [root]
    while stack and not partial:
        cur = stack.pop()
        try:
            with os.scandir(cur) as it:
                for e in it:
                    visited += 1
                    if visited >= DIR_WALK_MAX or time.time() > deadline:
                        partial = True
                        break
                    try:
                        if e.is_dir(follow_symlinks=False):
                            if _keep_dir(e.name):
                                stack.append(e.path)
                        elif e.is_file(follow_symlinks=False) and detect_language(e.name):
                            n += 1
                    except OSError:
                        continue
        except OSError:                                  # 无权限的子目录直接跳过
            continue
    return n, partial


def dir_list(path: str) -> dict:
    """列举 path 下的子目录概况；path 为空时只返回起始位置候选。

    只读操作：不做任何写入，也不跟随符号链接（避免环路）。
    """
    roots = list_roots()
    if not (path or "").strip():
        return {"path": "", "name": "", "parent": "", "crumbs": [], "roots": roots,
                "sep": os.sep, "dirs": [], "self": None, "truncated": False}

    path = os.path.abspath(os.path.expanduser(path.strip()))
    if not os.path.isdir(path):
        raise NotADirectoryError(path)

    n_src = n_manifest = n_hidden = 0
    subdirs = []
    with os.scandir(path) as it:                         # 权限错误交由路由层转 403
        for e in it:
            try:
                if e.is_dir(follow_symlinks=False):
                    if _keep_dir(e.name):
                        subdirs.append(e.name)
                    else:
                        n_hidden += 1                # 扫描时会被跳过的目录，仅计数不列出
                elif e.is_file(follow_symlinks=False):
                    if detect_language(e.name):
                        n_src += 1
                    if is_manifest(e.name):
                        n_manifest += 1
            except OSError:
                continue

    subdirs.sort(key=lambda s: s.lower())
    truncated = len(subdirs) > DIR_LIST_MAX
    shown = subdirs[:DIR_LIST_MAX]
    enrich = len(shown) <= DIR_ENRICH_MAX

    dirs = []
    for name in shown:
        item = {"name": name, "path": os.path.join(path, name),
                "n_src": None, "n_sub": None, "has_manifest": False}
        if enrich:                                       # 大目录只列名，避免 N 次 scandir
            try:
                with os.scandir(item["path"]) as sub:
                    cnt = sub_n = 0
                    manifest = False
                    for e in sub:
                        try:
                            if e.is_dir(follow_symlinks=False):
                                if _keep_dir(e.name):
                                    sub_n += 1
                            elif e.is_file(follow_symlinks=False):
                                if detect_language(e.name):
                                    cnt += 1
                                if is_manifest(e.name):
                                    manifest = True
                        except OSError:
                            continue
                item["n_src"], item["n_sub"], item["has_manifest"] = cnt, sub_n, manifest
            except OSError:
                pass
        dirs.append(item)

    stripped = path.rstrip(os.sep)
    crumbs = _crumbs(path)
    parent = crumbs[-2]["path"] if len(crumbs) > 1 else ""
    total, partial = _walk_sources(path, time.time() + DIR_WALK_SEC)
    return {
        "path": path,
        "name": os.path.basename(stripped) or path,
        "parent": parent,
        "crumbs": crumbs,
        "roots": roots,
        "sep": os.sep,
        "dirs": dirs,
        "self": {"n_src": n_src, "n_src_total": total, "partial": partial,
                 "n_manifest": n_manifest, "n_sub": len(subdirs), "n_hidden": n_hidden},
        "truncated": truncated,
    }


def build_tree(root: str, file_meta: dict | None = None):
    """构建文件树（只含源代码/配置文件，跳过二进制与大目录）。"""
    file_meta = file_meta or {}
    tree = {"name": os.path.basename(root) or root, "path": "", "type": "dir", "children": []}
    node_map = {"": tree}

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = sorted(d for d in dirnames if _keep_dir(d))
        rel_dir = os.path.relpath(dirpath, root).replace("\\", "/")
        if rel_dir == ".":
            rel_dir = ""
        parent = node_map.get(rel_dir)
        if parent is None:
            continue
        for d in dirnames:
            rel_d = f"{rel_dir}/{d}" if rel_dir else d
            node = {"name": d, "path": rel_d, "type": "dir", "children": []}
            node_map[rel_d] = node
            parent["children"].append(node)
        for fn in sorted(filenames):
            ext = os.path.splitext(fn)[1].lower()
            lang = detect_language(fn)
            if lang is None and ext not in (".md", ".json", ".txt", ".mod", ".sum", ".lock", ".golden", ".txtar"):
                continue
            rel_f = f"{rel_dir}/{fn}" if rel_dir else fn
            try:
                size = os.path.getsize(os.path.join(dirpath, fn))
            except OSError:
                size = 0
            meta = file_meta.get(rel_f, {})
            parent["children"].append({
                "name": fn, "path": rel_f, "type": "file",
                "lang": lang or ext.lstrip("."), "size": size,
                "issues": meta.get("total", 0), "worst": meta.get("worst"),
            })

    # 目录聚合：自下而上累计子节点的命中数与最严重等级
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}

    def rollup(n):
        n["children"] = [c for c in n["children"] if c["type"] == "file" or rollup(c)]
        n["children"].sort(key=lambda c: (c["type"] != "dir", c["name"].lower()))
        total, worst, files = 0, None, 0
        for c in n["children"]:
            total += c.get("issues", 0) or 0
            files += 1 if c["type"] == "file" else (c.get("files") or 0)
            w = c.get("worst")
            if w and (worst is None or order[w] < order[worst]):
                worst = w
        n["issues"], n["worst"], n["files"] = total, worst, files
        return bool(n["children"]) or n.get("path") == ""

    rollup(tree)
    return tree


def cached_tree(root: str, file_meta: dict, refresh: bool = False):
    """带短 TTL 的文件树缓存，扫描结束后自动失效。"""
    hit = _TREE_CACHE.get(root)
    now = time.time()
    if not refresh and hit and now - hit[0] < _TREE_TTL:
        base = hit[1]
    else:
        base = build_tree(root)
        _TREE_CACHE[root] = (now, base)

    # 拷贝并注入命中信息（不污染缓存结构）；目录的子树统计自下而上重算
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}

    def inject(node):
        if node["type"] == "file":
            meta = file_meta.get(node["path"]) or {}
            return {**node, "issues": meta.get("total", 0), "worst": meta.get("worst"),
                    "files": 1, "dirs": 0}
        kids = [inject(c) for c in node["children"]]
        total, worst, files, dirs = 0, None, 0, 0
        for k in kids:
            total += k.get("issues", 0) or 0
            files += k.get("files", 0) or 0
            if k["type"] == "dir":
                dirs += 1 + (k.get("dirs", 0) or 0)
            w = k.get("worst")
            if w and (worst is None or order[w] < order[worst]):
                worst = w
        return {**node, "children": kids, "issues": total, "worst": worst,
                "files": files, "dirs": dirs}

    return inject(base)


def invalidate_tree():
    _TREE_CACHE.clear()


def export_report(fmt: str, name: str = "", eng=None, **opts) -> tuple[str, bytes, str]:
    """生成报告，返回 (文件名, 内容, MIME)。eng 缺省用当前引擎（历史项目传项目视图）。"""
    eng = eng or STATE["engine"]
    if eng is None:
        raise RuntimeError("尚未执行扫描，无法导出报告")
    stamp = time.strftime("%Y%m%d-%H%M%S")
    stem = f"{name}-审计报告-{stamp}" if name else f"audit-report-{stamp}"
    stem = "".join(c for c in stem if c not in '\\/:*?"<>|').strip() or f"audit-report-{stamp}"

    if fmt == "json":
        return f"{stem}.json", reporter.to_json(eng).encode("utf-8"), "application/json; charset=utf-8"
    if fmt == "csv":
        return f"{stem}.csv", reporter.to_csv(eng).encode("utf-8-sig"), "text/csv; charset=utf-8"
    if fmt == "md":
        return f"{stem}.md", reporter.to_markdown(eng).encode("utf-8"), "text/markdown; charset=utf-8"
    if fmt == "docx":
        detail = opts.get("detail") or "full"
        if detail not in ("full", "summary"):
            detail = "full"
        try:
            max_findings = max(0, int(opts.get("max") or 0))
        except (TypeError, ValueError):
            max_findings = 0
        data = reporter.to_docx(eng, detail=detail, max_findings=max_findings)
        return (f"{stem}.docx", data,
                "application/vnd.openxmlformats-officedocument.wordprocessingml.document")
    return f"{stem}.html", reporter.to_html(eng).encode("utf-8"), "text/html; charset=utf-8"


class ProjectView:
    """历史项目的只读引擎视图：暴露 reporter / 接口处理所需的引擎子集。

    summary() / findings / deps / deps_meta / vulns 来自持久化快照；
    files 在审计根目录仍存在时惰性重建（仅 walk 不扫描），供源码检视与报告用。
    """

    def __init__(self, pid: str, snapshot: dict):
        self.pid = pid
        meta = snapshot.get("meta") or {}
        self.meta = meta
        self.target = meta.get("target") or {}
        self.findings = snapshot.get("findings") or []
        self.deps = snapshot.get("deps") or []
        self.deps_meta = snapshot.get("deps_meta") or {}
        self.vulns = snapshot.get("vulns")
        self._summary = snapshot.get("summary") or {}
        self._summary.setdefault("total", len(self.findings))
        self.root = meta.get("root") or ""
        self._files = None                       # 惰性：首次访问才 walk

    def summary(self):
        return self._summary

    def file_meta(self):
        """按文件聚合命中数（与 AuditEngine.file_meta 同一逻辑，供文件树展示）。"""
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

    @property
    def files(self):
        if self._files is None:
            self._files = []
            if self.root and os.path.isdir(self.root):
                try:
                    eng = AuditEngine(self.root)
                    eng.walk()
                    self._files = eng.files
                except Exception:                 # noqa: BLE001  根目录被移走时源码检视降级
                    self._files = []
        return self._files

    @property
    def total_lines(self):
        return self._summary.get("lines_total", 0)

    @property
    def elapsed(self):
        return self._summary.get("elapsed", 0)


def _project_param(qs):
    """从查询串取项目 ID；缺省/非法返回 None。"""
    pid = (qs.get("project", [""])[0] or "").strip()
    if not pid or pid == STATE.get("project_id"):
        return None                               # 当前项目走内存，保证实时性
    snap = projects.load(pid)
    return ProjectView(pid, snap) if snap else None


def snapshot_engine(eng, pid: str) -> dict:
    """把引擎当前结果组装为项目快照（result.json 的内容）。"""
    meta = projects.load_meta(pid) or {}
    meta.setdefault("id", pid)
    meta["target"] = STATE.get("target") or meta.get("target") or {}
    return {
        "meta": meta,
        "summary": eng.summary(),
        "findings": eng.findings,
        "deps": getattr(eng, "deps", None) or [],
        "deps_meta": getattr(eng, "deps_meta", {}) or {},
        "vulns": getattr(eng, "vulns", None),
    }


def save_project_snapshot(pid: str, eng, *, status: str = "", error: str = "") -> bool:
    """落盘项目快照；status 为空时由快照内容自动判定（完成/部分完成/中断）。"""
    if not pid:
        return False
    try:
        snap = snapshot_engine(eng, pid)
        if error:
            snap["error"] = error
            snap["meta"]["status"] = "error"
        return projects.save_result(pid, snap, status=status, error=error)
    except Exception:                             # noqa: BLE001  建档失败不影响扫描主流程
        traceback.print_exc()
        return False


def sort_findings(items, sort_key: str):
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    if sort_key == "file":
        return sorted(items, key=lambda f: (f["file"], f["line"]))
    if sort_key == "rule":
        return sorted(items, key=lambda f: (f["rule_id"], f["file"], f["line"]))
    if sort_key == "score":
        return sorted(items, key=lambda f: (-f["score"], f["file"], f["line"]))
    if sort_key == "severity":
        return sorted(items, key=lambda f: (order[f["severity"]], -f["score"], f["file"], f["line"]))
    # 默认 risk：等级 → 风险分 → 文件 → 行号
    return sorted(items, key=lambda f: (order[f["severity"]], -f["score"], f["file"], f["line"]))


def filter_findings(eng, qs):
    """按查询串过滤审计结果，返回 (items, 过滤条件摘要)。"""
    sev = (qs.get("severity", ["all"])[0] or "all")
    cat = (qs.get("category", ["all"])[0] or "all")
    scope = (qs.get("scope", ["all"])[0] or "all")
    kw = (qs.get("keyword", [""])[0] or "").strip().lower()
    items = eng.findings
    if sev != "all":
        items = [x for x in items if x["severity"] == sev]
    if cat != "all":
        items = [x for x in items if x["category"] == cat]
    if scope == "production":
        items = [x for x in items if x.get("scope", "production") == "production"]
    elif scope != "all":
        items = [x for x in items if x.get("scope") == scope]
    if kw:
        items = [x for x in items
                 if kw in (x["title"] + x["file"] + x["rule_id"] + x["category_label"]).lower()]
    return items, {"severity": sev, "category": cat, "scope": scope, "keyword": kw}


def group_of(items, by: str):
    """按维度聚合，返回带排序的分组列表。"""
    order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
    if by not in GROUP_KEYS:
        return []
    keyfn = GROUP_KEYS[by]
    buckets: dict = {}
    for f in items:
        k = keyfn(f)
        b = buckets.get(k)
        if b is None:
            label, sub = k, ""
            if by == "severity":
                label, sub = f["severity_label"], ""
            elif by == "category":
                label, sub = f["category_label"], ""
            elif by == "scope":
                label, sub = SCOPE_CN.get(k, k), ""
            elif by == "file":
                label = os.path.basename(k) or k
                sub = os.path.dirname(k)
            elif by == "rule":
                label, sub = k, f["title"]
            buckets[k] = {"key": k, "label": label, "sub": sub, "count": 0,
                          "worst": None, "weight": 0.0,
                          "by_severity": {s: 0 for s in SEVERITY_ORDER}}
        b = buckets[k]
        b["count"] += 1
        b["weight"] = round(b["weight"] + f["score"], 2)
        b["by_severity"][f["severity"]] += 1
        if b["worst"] is None or order[f["severity"]] < order[b["worst"]]:
            b["worst"] = f["severity"]

    groups = list(buckets.values())
    if by == "severity":
        groups.sort(key=lambda g: order.get(g["key"], 99))
    elif by == "scope":
        groups.sort(key=lambda g: {"production": 0, "test": 1, "doc": 2}.get(g["key"], 9))
    else:
        groups.sort(key=lambda g: (-g["count"], g["key"]))
    return groups


# ============================================================ 依赖漏洞库
def vuln_status() -> dict:
    """漏洞库的当前状态，供界面与 /api/meta 展示。"""
    opts = STATE["vuln_opts"]
    res = STATE.get("vulns")
    cache = {}
    try:
        cache = vulndb.VulnCache(VULNDB_CACHE, opts["ttl"], vulndb.DEFAULT_VULN_TTL).stats()
        cache.pop("path", None)
    except Exception:                             # noqa: BLE001
        cache = {}
    return {
        "source": "OSV.dev",
        "source_url": "https://osv.dev",
        "enabled": bool(opts["enabled"]),
        "offline": bool(opts["offline"]),
        "running": STATE["vuln_running"],
        "progress": STATE.get("vuln_progress"),
        "error": STATE.get("vuln_error") or "",
        "ttl_hours": round(opts["ttl"] / 3600, 1),
        "analyzed_at": opts.get("analyzed_at") or 0,
        "analyzed_at_text": (time.strftime("%Y-%m-%d %H:%M:%S",
                                           time.localtime(opts["analyzed_at"]))
                             if opts.get("analyzed_at") else ""),
        "data_age": (round(time.time() - opts["analyzed_at"])
                     if opts.get("analyzed_at") else None),
        "cache": cache,
        "ecosystems": {k: v for k, v in OSV_ECOSYSTEM.items()},
        "group_dims": [{"key": k, "label": v} for k, v in (
            ("package", "按依赖包"), ("severity", "按严重程度"), ("ecosystem", "按生态"),
            ("fix", "按修复可行性"), ("manifest", "按清单文件"), ("cvss", "按 CVSS 档位"))],
        "fix_label": FIX_LABEL,
        "summary": (res or {}).get("summary") or {},
    }


def start_vuln_analysis(engine) -> bool:
    """为已完成规则扫描的引擎启动依赖漏洞分析（独立线程，不阻塞结果展示）。"""
    opts = STATE["vuln_opts"]
    if not opts["enabled"]:
        return False
    if STATE["vuln_running"]:
        return False
    if not getattr(engine, "deps", None):
        STATE["vulns"] = None
        engine.vulns = None
        STATE["vuln_progress"] = {"phase": "empty", "done": 0, "total": 0}
        return False

    STATE["vuln_running"] = True
    STATE["vuln_error"] = ""
    STATE["vuln_progress"] = {"phase": "pending", "done": 0, "total": len(engine.deps)}
    engine_id = id(engine)

    def on_progress(phase, done, total):
        STATE["vuln_progress"] = {"phase": phase, "done": done, "total": total}

    def worker():
        try:
            res = vulndb.analyze(
                engine.deps, VULNDB_CACHE,
                pkg_ttl=opts["ttl"], vuln_ttl=vulndb.DEFAULT_VULN_TTL,
                offline=bool(opts["offline"]), progress=on_progress)
            if STATE["vuln_opts"].get("engine_id") not in (None, engine_id) and \
                    STATE["engine"] is not engine:
                return                            # 期间已切换目标，丢弃过期结果
            engine.vulns = res
            STATE["vulns"] = res
            STATE["vuln_opts"]["analyzed_at"] = time.time()
            STATE["vuln_opts"]["engine_id"] = engine_id
            save_project_snapshot(STATE.get("project_id") or "", engine)   # 漏洞结果补写进项目快照
            s = res.get("summary") or {}
            print(f"[+] 依赖漏洞分析完成：查询 {res['queried']} 个依赖 / "
                  f"{s.get('vuln_total', 0)} 条漏洞 / 受影响依赖 {s.get('vuln_packages', 0)} 个 / "
                  f"耗时 {res['elapsed']}s" + (f" / 数据源错误：{res['error']}" if res["error"] else ""))
        except Exception as exc:                  # noqa: BLE001
            traceback.print_exc()
            STATE["vuln_error"] = f"{type(exc).__name__}: {exc}"
            engine.vulns = {"error": STATE["vuln_error"], "findings": [], "packages": [],
                            "summary": {}, "by_severity": {}, "skipped": {},
                            "online": False, "source": "OSV.dev", "elapsed": 0.0}
            STATE["vulns"] = engine.vulns
            # 把「依赖分析失败」写进项目档案：静态扫描本身是完整的，故该项目在
            # 扫描历史里标记为「部分完成」（partial）而非失败，并保留失败原因。
            if STATE["engine"] is engine:
                save_project_snapshot(STATE.get("project_id") or "", engine)
        finally:
            STATE["vuln_running"] = False
            STATE["vuln_progress"] = {"phase": "done", "done": 1, "total": 1}

    threading.Thread(target=worker, daemon=True).start()
    return True


def filter_vulns(res: dict, qs: dict):
    """对漏洞结果做筛选，返回 (items, 条件摘要)。"""
    items = (res or {}).get("findings") or []
    sev = (qs.get("severity", ["all"])[0] or "all")
    fix = (qs.get("fix", ["all"])[0] or "all")
    scope = (qs.get("scope", ["all"])[0] or "all")
    eco = (qs.get("ecosystem", ["all"])[0] or "all")
    kw = (qs.get("keyword", [""])[0] or "").strip().lower()
    if sev != "all":
        items = [x for x in items if x["severity"] == sev]
    if eco != "all":
        items = [x for x in items if x["ecosystem"] == eco]
    if fix == "fixable":
        items = [x for x in items if x["has_fix"]]
    elif fix == "easy":
        items = [x for x in items if x["fix_kind"] == "same-branch"]
    elif fix == "cross":
        items = [x for x in items if x["fix_kind"] in ("minor-up", "major-up")]
    elif fix == "none":
        items = [x for x in items if not x["has_fix"]]
    if scope == "prod":
        items = [x for x in items if not x["indirect"] and x["scope"] in ("compile", "runtime")]
    elif scope == "dev":
        items = [x for x in items if x["indirect"] or x["scope"] == "test"]
    if kw:
        items = [x for x in items if kw in (
            x["package"] + x["vuln_id"] + x["cve"] + x["title"] + x["manifest"]
            + " ".join(x.get("aliases") or [])).lower()]
    return items, {"severity": sev, "fix": fix, "scope": scope,
                   "ecosystem": eco, "keyword": kw}


def group_vulns(items, by: str):
    """按维度聚合漏洞结果。"""
    if by not in VULN_GROUP_KEYS:
        return []
    eco_label = dict(ECO_LABEL)
    buckets: dict = {}
    for f in items:
        if by == "package":
            k = f"{f['ecosystem']}|{f['package']}@{f['version']}"
            label, sub = f"{f['package']}@{f['version']}", eco_label.get(f["ecosystem"], f["ecosystem"])
        elif by == "severity":
            k = f["severity"]
            label, sub = SEVERITY_META.get(k, {}).get("label", k), ""
        elif by == "ecosystem":
            k = f["ecosystem"]
            label, sub = eco_label.get(k, k), ""
        elif by == "fix":
            k = f["fix_kind"]
            label, sub = FIX_LABEL.get(k, k), ""
        elif by == "manifest":
            k = f["manifest"]
            label, sub = os.path.basename(k) or k, os.path.dirname(k)
        else:                                     # cvss
            s = f["cvss"]
            k = "未评级" if s is None else ("9.0+ 严重" if s >= 9 else
                                        "7.0-8.9 高危" if s >= 7 else
                                        "4.0-6.9 中危" if s >= 4 else "0.1-3.9 低危")
            label, sub = k, ""
        b = buckets.get(k)
        if b is None:
            buckets[k] = b = {"key": k, "label": label, "sub": sub, "count": 0,
                              "worst": None, "max_cvss": 0.0,
                              "by_severity": {s: 0 for s in SEVERITY_ORDER}}
        b["count"] += 1
        b["by_severity"][f["severity"]] += 1
        if b["worst"] is None or SEVERITY_ORDER.index(f["severity"]) < \
                SEVERITY_ORDER.index(b["worst"]):
            b["worst"] = f["severity"]
        b["max_cvss"] = max(b["max_cvss"], f["cvss"] or 0.0)
    groups = list(buckets.values())
    if by == "severity":
        groups.sort(key=lambda g: SEVERITY_ORDER.index(g["key"]))
    elif by == "fix":
        groups.sort(key=lambda g: _FIX_ORDER.get(g["key"], 9))
    elif by == "cvss":
        groups.sort(key=lambda g: -g["max_cvss"])
    else:
        groups.sort(key=lambda g: (SEVERITY_ORDER.index(g["worst"]), -g["max_cvss"], g["label"]))
    return groups


# ============================================================== 请求处理
class Handler(BaseHTTPRequestHandler):
    server_version = "CodeAudit/1.1"
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        if os.environ.get("AUDIT_DEBUG"):
            sys.stderr.write("[%s] %s\n" % (self.log_date_time_string(), fmt % args))

    # ---------------------------------------------------------- 响应助手
    def _send(self, status, body: bytes, ctype="application/json; charset=utf-8",
              extra=None, allow_gzip=True):
        headers = dict(extra or {})
        if (allow_gzip and len(body) >= 860 and status == 200
                and "gzip" in (self.headers.get("Accept-Encoding") or "").lower()
                and "Content-Encoding" not in headers):
            body = gzip.compress(body, 6)
            headers["Content-Encoding"] = "gzip"
            headers["Vary"] = "Accept-Encoding"
        self.send_response(status)
        if status == 304 or self.command == "HEAD":
            for k, v in headers.items():
                self.send_header(k, v)
            self.end_headers()
            return
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        for k, v in headers.items():
            self.send_header(k, v)
        self.end_headers()
        try:
            self.wfile.write(body)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def _json(self, payload, status=200):
        self._send(status, json.dumps(payload, ensure_ascii=False,
                                      separators=(",", ":")).encode("utf-8"))

    def _read_body(self):
        try:
            n = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            n = 0
        if n <= 0:
            return {}
        try:
            return json.loads(self.rfile.read(n).decode("utf-8"))
        except Exception:
            return {}

    # -------------------------------------------------------------- GET
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)
        try:
            if path in ("/", "/index.html"):
                return self._serve_static("index.html", no_cache=True)
            if path.startswith("/static/"):
                return self._serve_static(path[len("/static/"):])
            if path == "/api/meta":
                return self._json(ok({
                    "tool": TOOL_NAME,
                    "version": TOOL_VERSION,
                    "severities": SEVERITY_ORDER,
                    "severity_meta": SEVERITY_META,
                    "categories": CATEGORY_META,
                    "languages": LANG_EXT,
                    "rule_count": len(RULES),
                    "formats": [{"key": k, "label": v[0]} for k, v in EXPORT_FORMATS.items()],
                    # 反馈入口：界面「关于与反馈」面板直接读取此处，避免前端硬编码邮箱
                    "feedback": {
                        "email": FEEDBACK_EMAIL,
                        "title": FEEDBACK_TITLE,
                        "subject_prefix": FEEDBACK_SUBJECT_PREFIX,
                    },
                    "env": {
                        "python": "%d.%d.%d" % sys.version_info[:3],
                        "python_required": MIN_PYTHON_STR,
                        "os": platform.system() + " " + platform.release(),
                        "third_party": "无",
                    },
                    "group_dims": [
                        {"key": "severity", "label": "按严重程度"},
                        {"key": "category", "label": "按漏洞类型"},
                        {"key": "file", "label": "按所在文件"},
                        {"key": "rule", "label": "按规则"},
                        {"key": "scope", "label": "按作用域"},
                    ],
                    "rules": [{
                        "id": r["id"], "title": r["title"], "severity": r["severity"],
                        "category": r["category"], "cwe": r["cwe"],
                        "languages": r["languages"], "confidence": r["confidence"],
                        "description": r.get("description", ""),
                        "remediation": r.get("remediation", ""),
                    } for r in RULES],
                    "root": STATE["root"],
                    "target": STATE["target"],
                    "project_id": STATE.get("project_id") or "",
                    "browse": HAS_TK,                 # 可选：系统原生对话框（需 tkinter）
                    "web_dir": True,                  # 内置：网页目录浏览器（零依赖，始终可用）
                    "skip_dirs": sorted(DEFAULT_EXCLUDES),
                    "vulndb": {**vuln_status(), "cache": {k: v for k, v in
                                                          (vuln_status().get("cache") or {}).items()
                                                          if k in ("packages", "vulns")}},
                    "eco_label": ECO_LABEL,
                    "limits": {
                        "max_files": MAX_UPLOAD_FILES,
                        "max_file": MAX_UPLOAD_FILE,
                        "max_total": MAX_UPLOAD_TOTAL,
                    },
                }))
            if path == "/api/env":
                # 运行环境自检：供「关于与反馈」面板展示与一键复制诊断信息
                # ?net=0 可跳过联网探测（面板首屏快速渲染用）
                want_net = qs.get("net", ["0"])[0] != "0"
                return self._json(ok(env_report(check_network=want_net)))
            if path == "/api/tree":
                pv = _project_param(qs)
                root = pv.root if pv else STATE["root"]
                if not root:
                    return self._json(fail("尚未指定审计目录"), 400)
                if pv and not os.path.isdir(root):
                    return self._json(fail("该项目的审计源目录已不存在，无法检视源码（结果数据仍可查看与导出）"), 410)
                eng = pv if pv else STATE["engine"]
                meta = eng.file_meta() if eng else {}
                refresh = qs.get("refresh", ["0"])[0] == "1"
                return self._json(ok(cached_tree(root, meta, refresh)))
            if path == "/api/dir":
                q = (qs.get("path", [""])[0] or "")
                try:
                    return self._json(ok(dir_list(q)))
                except PermissionError:
                    return self._json(fail("没有权限读取该目录：" + q), 403)
                except NotADirectoryError:
                    return self._json(fail("目录不存在或不是文件夹：" + q), 404)
                except OSError as exc:
                    return self._json(fail("无法读取该目录：" + str(exc)), 500)
            if path == "/api/file":
                return self._api_file(qs)
            if path == "/api/progress":
                eng = STATE["engine"]
                if STATE["running"] and STATE.get("progress") is not None:
                    return self._json(ok(STATE["progress"]))
                if eng is None:
                    return self._json(ok({"phase": "idle", "done": False}))
                return self._json(ok({"phase": "done", "done": True,
                                      "current": len(eng.files), "total": len(eng.files),
                                      "elapsed": eng.elapsed}))
            if path == "/api/result":
                return self._api_result(qs)
            if path == "/api/deps":
                pv = _project_param(qs)
                eng = pv or STATE["engine"]
                deps = eng.deps if eng else []
                meta = getattr(eng, "deps_meta", {}) if eng else {}
                vulns_res = pv.vulns if pv else STATE.get("vulns")
                eco = {}
                for d in deps:
                    k = d.get("ecosystem", "other")
                    eco[k] = eco.get(k, 0) + 1
                # 每个依赖挂上漏洞计数，让界面在依赖清单里直接标红
                vmap = {}
                for f in ((vulns_res or {}).get("findings") or []):
                    vmap[(f["ecosystem"], f["package"], f["version"])] = \
                        vmap.get((f["ecosystem"], f["package"], f["version"]), 0) + 1
                for d in deps:
                    d["vuln_count"] = vmap.get((d.get("ecosystem"), d.get("name"),
                                                d.get("version")), 0)
                return self._json(ok({
                    "deps": deps, "total": len(deps), "by_ecosystem": eco,
                    "eco_label": ECO_LABEL, "meta": meta,
                    "vuln": (vulns_res or {}).get("summary") or {},
                    "project_id": pv.pid if pv else STATE.get("project_id") or "",
                }))
            if path == "/api/vulns":
                return self._api_vulns(qs)
            if path == "/api/projects":
                items = projects.list_all()
                return self._json(ok({
                    "projects": items,
                    "current": STATE.get("project_id") or "",
                    "totals": projects.aggregate(items),
                    "statuses": projects.STATUS_LABEL,
                }))
            if path == "/api/project":
                pid = (qs.get("id", [""])[0] or "").strip()
                snap = projects.load(pid) if pid else None
                if snap is None:
                    return self._json(fail("项目不存在：" + pid), 404)
                return self._json(ok({"project": snap}))
            if path == "/api/project/detail":
                # 「扫描历史」二级详情页的数据源：一次请求返回该次扫描的完整信息
                pid = (qs.get("id", [""])[0] or "").strip()
                if not pid:
                    return self._json(fail("缺少项目 ID"), 400)
                try:
                    top = max(1, min(500, int(qs.get("top", ["60"])[0])))
                except ValueError:
                    top = 60
                d = projects.detail(pid, top_findings=top, rule_count=len(RULES))
                if d is None:
                    return self._json(fail("项目不存在：" + pid), 404)
                d["live"] = pid == (STATE.get("project_id") or "")   # 是否为当前工作台项目
                return self._json(ok(d))
            if path == "/api/vulndb/status":
                return self._json(ok(vuln_status()))
            if path == "/api/export":
                return self._api_export(qs)
            if path == "/api/reports":
                items = []
                if os.path.isdir(REPORT_DIR):
                    for fn in sorted(os.listdir(REPORT_DIR), reverse=True):
                        fp = os.path.join(REPORT_DIR, fn)
                        if not os.path.isfile(fp):        # 跳过子目录（如截图归档 shots/）
                            continue
                        try:
                            items.append({
                                "name": fn, "size": os.path.getsize(fp),
                                "time": time.strftime("%Y-%m-%d %H:%M:%S",
                                                      time.localtime(os.path.getmtime(fp))),
                            })
                        except OSError:
                            continue
                return self._json(ok({"reports": items[:80]}))
            if path.startswith("/reports/"):
                return self._serve_report(path[len("/reports/"):])
            return self._json(fail("接口不存在"), 404)
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            return self._json(fail(f"服务端异常：{exc}"), 500)

    # ------------------------------------------------------------- POST
    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        qs = urllib.parse.parse_qs(parsed.query)
        try:
            if parsed.path == "/api/scan":
                return self._api_scan(self._read_body())
            if parsed.path == "/api/target":
                return self._api_target(self._read_body())
            if parsed.path == "/api/upload/init":
                return self._api_upload_init(self._read_body())
            if parsed.path == "/api/upload/file":
                return self._api_upload_file(qs)
            if parsed.path == "/api/upload/done":
                return self._api_upload_done(self._read_body())
            if parsed.path == "/api/browse":
                return self._api_browse(self._read_body())
            if parsed.path == "/api/vulndb/update":
                return self._api_vulndb_update(self._read_body())
            if parsed.path == "/api/project/delete":
                pid = (self._read_body() or {}).get("id") or ""
                if not pid:
                    return self._json(fail("缺少项目 ID"), 400)
                if pid == STATE.get("project_id"):
                    return self._json(fail("当前项目正在使用中，请先开始一次新扫描后再删除"), 409)
                return self._json(ok({"deleted": projects.delete(pid)}))
            return self._json(fail("接口不存在"), 404)
        except Exception as exc:  # noqa: BLE001
            traceback.print_exc()
            return self._json(fail(f"服务端异常：{exc}"), 500)

    do_HEAD = do_GET

    # ---------------------------------------------------------- 静态文件
    def _serve_static(self, rel, no_cache=False):
        target = safe_join(WEB_DIR, rel)
        if not target or not os.path.isfile(target):
            return self._json(fail("静态资源不存在"), 404)
        with open(target, "rb") as f:
            raw = f.read()
        etag = '"' + hashlib.md5(raw[:4096] + str(len(raw)).encode()).hexdigest()[:16] + '"'
        if self.headers.get("If-None-Match") == etag:
            return self._send(304, b"", "text/plain", {"ETag": etag}, allow_gzip=False)
        ctype = mimetypes.guess_type(target)[0] or "application/octet-stream"
        if ctype.startswith("text/") or ctype in ("application/javascript", "application/json"):
            ctype += "; charset=utf-8"
        # 内容未变时走 304，避免重复下载；HTML 入口不缓存，保证改版即时生效
        cache = "no-cache, must-revalidate"
        return self._send(200, raw, ctype,
                          {"ETag": etag, "Cache-Control": cache}, allow_gzip=True)

    def _serve_report(self, rel):
        target = safe_join(REPORT_DIR, rel)
        if not target or not os.path.isfile(target):
            return self._json(fail("报告不存在"), 404)
        ctype = mimetypes.guess_type(target)[0] or "application/octet-stream"
        if ctype.startswith("text/"):
            ctype += "; charset=utf-8"
        with open(target, "rb") as f:
            return self._send(200, f.read(), ctype)

    # ------------------------------------------------------------ 文件接口
    def _api_file(self, qs):
        pv = _project_param(qs)
        root = (pv.root if pv else None) or STATE["root"]
        rel = qs.get("path", [""])[0]
        target = safe_join(root, rel)
        if not target or not os.path.isfile(target):
            return self._json(fail("文件不存在或路径非法"), 404)
        try:
            size = os.path.getsize(target)
            if size > 3 * 1024 * 1024:
                return self._json(fail("文件过大（>3MB），不支持在线预览"), 413)
        except OSError:
            return self._json(fail("文件读取失败"), 500)
        content, enc = read_text(target)
        if content is None:
            return self._json(fail("二进制文件，不支持在线预览"), 415)
        rel_norm = os.path.relpath(target, root).replace("\\", "/")
        findings = []
        eng = pv or STATE["engine"]
        if eng:
            findings = [f for f in eng.findings if f["file"] == rel_norm]
        return self._json(ok({
            "path": rel_norm,
            "lang": detect_language(target) or "text",
            "encoding": enc,
            "size": size,
            "lines": content.count("\n") + 1,
            "content": content,
            "findings": findings,
        }))

    # ------------------------------------------------------------ 结果接口
    def _api_result(self, qs):
        eng = _project_param(qs) or STATE["engine"]
        if eng is None:
            return self._json(fail("尚未执行扫描"), 404)
        items, _filters = filter_findings(eng, qs)
        by = (qs.get("group_by", [""])[0] or "").strip()
        gkey = (qs.get("group_key", [""])[0] or "").strip()
        sort_key = (qs.get("sort", ["risk"])[0] or "risk").strip()
        summary = eng.summary()

        payload = {
            "summary": summary,
            "total_filtered": len(items),
            "sort": sort_key,
        }

        if by in GROUP_KEYS:
            payload["group_by"] = by
            if not gkey:
                # 只返回分组概览
                payload["groups"] = group_of(items, by)
                return self._json(ok(payload))
            items = [x for x in items if GROUP_KEYS[by](x) == gkey]
            payload["group_key"] = gkey
            payload["total_in_group"] = len(items)
            payload["total_filtered"] = len(items)

        items = sort_findings(items, sort_key)
        try:
            offset = max(0, int(qs.get("offset", ["0"])[0] or 0))
        except ValueError:
            offset = 0
        try:
            limit = min(1000, max(1, int(qs.get("limit", ["80"])[0] or 80)))
        except ValueError:
            limit = 80
        payload.update({
            "offset": offset, "limit": limit,
            "findings": items[offset:offset + limit],
            "has_more": offset + limit < len(items),
        })
        return self._json(ok(payload))

    # ---------------------------------------------------- 依赖漏洞库接口
    def _api_vulns(self, qs):
        """漏洞结果查询：筛选 + 排序 + 分页 + 分组。"""
        pv = _project_param(qs)
        eng = pv or STATE["engine"]
        res = pv.vulns if pv else STATE.get("vulns")
        if res is None:
            status = vuln_status()
            if eng is None:
                return self._json(fail("尚未执行扫描"), 404)
            return self._json(ok({
                "ready": False, "running": status["running"], "status": status,
                "findings": [], "packages": [], "groups": [], "summary": {},
                "by_severity": {}, "skipped": {}, "total": 0, "total_filtered": 0,
                "error": STATE.get("vuln_error") or "",
                "deps_meta": getattr(eng, "deps_meta", {}),
            }))

        items, _filters = filter_vulns(res, qs)
        by = (qs.get("group_by", [""])[0] or "").strip()
        sort_key = (qs.get("sort", ["severity"])[0] or "severity").strip()
        payload = {
            "ready": True,
            "status": vuln_status(),
            "summary": res.get("summary") or {},
            "by_severity": res.get("by_severity") or {},
            "skipped": res.get("skipped") or {},
            "online": res.get("online"),
            "error": res.get("error") or "",
            "elapsed": res.get("elapsed"),
            "total": len(res.get("findings") or []),
            "total_filtered": len(items),
            "deps_meta": getattr(eng, "deps_meta", {}),
            "project_id": pv.pid if pv else STATE.get("project_id") or "",
            "fix_label": FIX_LABEL,
            "eco_label": ECO_LABEL,
        }

        if by in VULN_GROUP_KEYS:
            payload["group_by"] = by
            gkey = (qs.get("group_key", [""])[0] or "").strip()
            if not gkey:
                payload["groups"] = group_vulns(items, by)
                return self._json(ok(payload))
            payload["group_key"] = gkey
            payload["total_in_group"] = len(items)

        if sort_key == "package":
            items = sorted(items, key=lambda f: (f["ecosystem"], f["package"], f["version"]))
        elif sort_key == "cvss":
            items = sorted(items, key=lambda f: (-(f["cvss"] or 0), f["package"]))
        elif sort_key == "fix":
            items = sorted(items, key=lambda f: (_FIX_ORDER.get(f["fix_kind"], 9),
                                                SEVERITY_ORDER.index(f["severity"])))
        else:                                     # 默认按严重程度
            items = sorted(items, key=lambda f: (SEVERITY_ORDER.index(f["severity"]),
                                                 -(f["cvss"] or 0), f["package"], f["vuln_id"]))
        try:
            offset = max(0, int(qs.get("offset", ["0"])[0] or 0))
        except ValueError:
            offset = 0
        try:
            limit = min(1000, max(1, int(qs.get("limit", ["80"])[0] or 80)))
        except ValueError:
            limit = 80
        payload.update({
            "sort": sort_key, "offset": offset, "limit": limit,
            "findings": items[offset:offset + limit],
            "packages": res.get("packages") or [],
            "has_more": offset + limit < len(items),
        })
        return self._json(ok(payload))

    def _api_vulndb_update(self, body):
        """重新分析依赖漏洞（可强制刷新缓存 / 切换离线模式）。"""
        eng = STATE["engine"]
        if eng is None:
            return self._json(fail("尚未执行扫描，无法分析依赖"), 400)
        if STATE["running"]:
            return self._json(fail("规则扫描进行中，请稍后再试"), 409)
        if STATE["vuln_running"]:
            return self._json(fail("依赖漏洞分析正在进行中"), 409)
        opts = STATE["vuln_opts"]
        if "ttl_hours" in body:
            try:
                hours = float(body["ttl_hours"])
                opts["ttl"] = max(0, int(hours * 3600))
            except (TypeError, ValueError):
                pass
        if "offline" in body:
            opts["offline"] = bool(body["offline"])
        if "enabled" in body:
            opts["enabled"] = bool(body["enabled"])
        refresh = bool(body.get("refresh"))
        if refresh:
            # 清掉包级缓存，强制重新联网查询（漏洞详情仍复用，公告正文极少变动）
            try:
                cache = vulndb.VulnCache(VULNDB_CACHE, opts["ttl"], vulndb.DEFAULT_VULN_TTL)
                with cache.lock:
                    cache.pkg.clear()
                    cache.dirty = True
                cache.save()
            except Exception:                     # noqa: BLE001
                pass
        if not opts["enabled"]:
            STATE["vulns"] = None
            eng.vulns = None
            return self._json(ok({"started": False, "enabled": False}))
        started = start_vuln_analysis(eng)
        return self._json(ok({"started": started, "refresh": refresh,
                              "offline": opts["offline"], "status": vuln_status()}))

    # ------------------------------------------------------------ 导出接口
    def _api_export(self, qs):
        fmt = (qs.get("format", ["html"])[0] or "html").lower()
        if fmt not in EXPORT_FORMATS:
            return self._json(fail("不支持的导出格式"), 400)
        name = (qs.get("name", [""])[0] or "").strip()
        detail = (qs.get("detail", ["full"])[0] or "full").strip()
        mx = (qs.get("max", ["0"])[0] or "0").strip()
        eng = _project_param(qs)
        fname, body, ctype = export_report(fmt, name, eng=eng, detail=detail, max=mx)
        os.makedirs(REPORT_DIR, exist_ok=True)
        with open(os.path.join(REPORT_DIR, fname), "wb") as fh:
            fh.write(body)
        q = urllib.parse.quote(fname)
        return self._send(200, body, ctype, {
            "Content-Disposition": f"attachment; filename=\"{q}\"; filename*=UTF-8''{q}",
            "X-Report-File": urllib.parse.quote(fname),
        }, allow_gzip=False)

    # ------------------------------------------------------------ 扫描接口
    def _api_scan(self, body):
        with STATE["lock"]:
            if STATE["running"]:
                return self._json(fail("已有扫描任务正在执行中"), 409)

            root = body.get("root") or STATE["root"]
            if not root or not os.path.isdir(root):
                return self._json(fail(f"目录不存在：{root}"), 400)
            root = os.path.abspath(root)

            excludes = body.get("excludes")
            if isinstance(excludes, str):
                excludes = [x.strip() for x in excludes.split(",") if x.strip()]
            if not excludes:
                excludes = SERVER_EXCLUDES

            severities = body.get("severities") or SEVERITY_ORDER
            categories = body.get("categories") or list(CATEGORY_META)

            engine = AuditEngine(root, excludes=excludes, severities=severities,
                                 categories=categories)
            # ---- 项目建档：每次扫描都是独立项目，结果/配置物理隔离 ----
            pid = projects.new_id()
            target = {
                "root": root,
                "name": body.get("label") or os.path.basename(root.rstrip(os.sep)) or root,
                "kind": body.get("kind") or "path",
            }
            projects.create({
                "id": pid,
                "version": TOOL_VERSION,
                "target": target,
                "root": root,
                "created_at": time.time(),
                "excludes": excludes,
                "severities": severities,
                "categories": categories,
                "vulndb_enabled": bool(STATE["vuln_opts"]["enabled"]),
            })
            STATE["root"] = root
            STATE["target"] = target
            STATE["project_id"] = pid
            STATE["engine"] = engine
            STATE["running"] = True
            STATE["progress"] = {"phase": "starting", "done": False,
                                 "current": 0, "total": 0, "file": ""}
            invalidate_tree()

            def worker():
                try:
                    engine.scan()
                    print(f"[+] 扫描完成：{len(engine.files)} 文件 / "
                          f"{engine.total_lines:,} 行 / {len(engine.findings)} 项 / "
                          f"耗时 {engine.elapsed}s")
                    # 先落盘项目快照、再释放"运行中"：进度一旦置 done，界面与自检
                    # 就会立即读取结果，若快照未写完会出现"done 但快照缺失"的竞态。
                    save_project_snapshot(pid, engine)          # 状态由快照内容判定
                    STATE["running"] = False
                    STATE["progress"] = dict(engine.progress)
                    invalidate_tree()
                    STATE["vuln_opts"]["engine_id"] = id(engine)
                    start_vuln_analysis(engine)
                except Exception as exc:  # noqa: BLE001
                    traceback.print_exc()
                    engine.progress.update({"phase": "error", "done": True, "error": str(exc)})
                    # 失败也要在扫描历史里留下可追溯的记录：已扫到文件时保留
                    # 部分快照（status=error），否则只改元数据状态。
                    if getattr(engine, "files", None):
                        save_project_snapshot(pid, engine, status="error", error=str(exc))
                    else:
                        projects.mark_status(pid, "error", error=str(exc))
                    STATE["running"] = False
                    invalidate_tree()

            def watch():
                while STATE["running"]:
                    STATE["progress"] = dict(engine.progress)
                    time.sleep(0.2)
                STATE["progress"] = dict(engine.progress)

            STATE["task"] = threading.Thread(target=worker, daemon=True)
            STATE["task"].start()
            threading.Thread(target=watch, daemon=True).start()

        return self._json(ok({"started": True, "root": root, "rule_count": len(RULES),
                              "project_id": pid}))

    # ------------------------------------------------------- 上传接口
    def _api_target(self, body):
        """只切换审计目录、不触发扫描（用于「仅上传」等场景）。

        切换后清空上一次的引擎与结果，避免界面出现「目录已换、结果还是旧的」的错位。
        """
        root = (body.get("root") or "").strip()
        if not root or not os.path.isdir(root):
            return self._json(fail(f"目录不存在：{root}"), 400)
        root = os.path.abspath(root)
        with STATE["lock"]:
            if STATE["running"]:
                return self._json(fail("扫描进行中，暂不能切换审计目录"), 409)
            STATE["root"] = root
            STATE["target"] = {
                "root": root,
                "name": body.get("label") or os.path.basename(root.rstrip(os.sep)) or root,
                "kind": body.get("kind") or "path",
            }
            STATE["engine"] = None
            STATE["progress"] = None
            STATE["vulns"] = None
            STATE["vuln_error"] = ""
            STATE["vuln_progress"] = None
            STATE["vuln_opts"]["analyzed_at"] = 0.0
            STATE["vuln_opts"]["engine_id"] = None
            invalidate_tree()
        return self._json(ok(STATE["target"]))

    def _content_length(self) -> int:
        try:
            return max(0, int(self.headers.get("Content-Length") or 0))
        except ValueError:
            return 0

    def _drain(self, n: int) -> None:
        """读完并丢弃剩余请求体，保证长连接不错位。"""
        left = n
        while left > 0:
            chunk = self.rfile.read(min(262144, left))
            if not chunk:
                break
            left -= len(chunk)

    def _api_upload_init(self, body):
        info = create_workspace(body.get("folder") or "")
        return self._json(ok(info))

    def _api_upload_file(self, qs):
        """接收单个文件（原始字节流，路径通过查询串传递）。

        采用「一个请求一个文件」而非 multipart，可边收边落盘，
        避免把整个目录一次性读进内存，也无需手写 multipart 解析。
        """
        ws_id = (qs.get("ws", [""])[0] or "").strip()
        root = ws_root(ws_id)
        if not root:
            return self._json(fail("上传会话无效或已过期，请重新选择文件夹"), 400)

        rel = urllib.parse.unquote(qs.get("path", [""])[0] or "")
        target = safe_join(root, rel)
        if not target:
            return self._json(fail(f"非法文件路径：{rel}"), 400)

        n = self._content_length()
        if n <= 0:
            return self._json(fail(f"文件内容为空：{rel}"), 400)

        rec = WS_REGISTRY.setdefault(ws_id, {"root": root, "files": 0, "bytes": 0,
                                             "created": time.time()})
        if rec["files"] >= MAX_UPLOAD_FILES:
            self._drain(n)
            return self._json(fail(f"文件数超过上限 {MAX_UPLOAD_FILES} 个"), 413)
        if n > MAX_UPLOAD_FILE:
            self._drain(n)
            return self._json(
                fail(f"文件超过单文件上限 {MAX_UPLOAD_FILE // 1048576}MB：{rel}"), 413)
        if rec["bytes"] + n > MAX_UPLOAD_TOTAL:
            self._drain(n)
            return self._json(
                fail(f"上传总量超过上限 {MAX_UPLOAD_TOTAL // 1048576}MB"), 413)
        if os.path.splitext(target)[1].lower() in UPLOAD_BLOCK_EXT:
            self._drain(n)
            return self._json(ok({"path": rel, "skipped": True, "reason": "二进制/压缩文件"}))

        os.makedirs(os.path.dirname(target), exist_ok=True)
        written = 0
        try:
            with open(target, "wb") as fh:
                while written < n:
                    chunk = self.rfile.read(min(262144, n - written))
                    if not chunk:
                        break
                    fh.write(chunk)
                    written += len(chunk)
        except OSError as exc:
            return self._json(fail(f"写入失败：{exc}"), 500)

        rec["files"] += 1
        rec["bytes"] += written
        return self._json(ok({"path": rel, "size": written}))

    def _api_upload_done(self, body):
        ws_id = (body.get("ws") or "").strip()
        root = ws_root(ws_id)
        if not root:
            return self._json(fail("上传会话无效或已过期，请重新选择文件夹"), 400)
        rec = WS_REGISTRY.get(ws_id, {})
        name = os.path.basename(root.rstrip(os.sep)) or "uploaded"
        return self._json(ok({
            "ws": ws_id, "root": root, "name": name,
            "files": rec.get("files", 0), "bytes": rec.get("bytes", 0),
        }))

    def _api_browse(self, body):
        initial = body.get("initial") or STATE["root"] or os.path.expanduser("~")
        path, err = browse_folder(os.path.abspath(initial))
        if err:
            return self._json(fail(err), 501 if not HAS_TK else 500)
        return self._json(ok({"path": path, "cancelled": not path}))


# ---------------------------------------------------------------- 启动辅助
# 本机可能配置了 HTTP_PROXY，探测 127.0.0.1 必须显式绕过代理，否则会连到代理而非本机服务
_LOCAL_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def port_occupied(host: str, port: int, timeout: float = 0.4) -> bool:
    """检测端口是否已被监听。"""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex((host, port)) == 0


def probe_running(host: str, port: int, timeout: float = 1.5):
    """探测端口上是否运行着本平台；是则返回其 /api/meta 数据，否则返回 None。"""
    try:
        req = urllib.request.Request(f"http://{host}:{port}/api/meta",
                                     headers={"Accept": "application/json"})
        with _LOCAL_OPENER.open(req, timeout=timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8", "replace"))
    except Exception:                                   # noqa: BLE001
        return None
    data = payload.get("data") if isinstance(payload, dict) else None
    if isinstance(data, dict) and data.get("tool") == TOOL_NAME:
        return data
    return None


def find_free_port(host: str, start: int, tries: int = 20):
    """从 start 起顺延寻找第一个空闲端口，找不到返回 None。"""
    for p in range(start, start + tries):
        if not port_occupied(host, p):
            return p
    return None


def main():
    # 控制台编码兜底：输出被重定向到非 UTF-8 终端时，个别字符编码失败不应导致中断
    for _stream in (sys.stdout, sys.stderr):
        try:
            _stream.reconfigure(errors="replace")
        except Exception:                                # noqa: BLE001
            pass

    ap = argparse.ArgumentParser(
        description=f"{TOOL_NAME} v{TOOL_VERSION}（零第三方依赖，仅需 Python {MIN_PYTHON_STR}+）",
        epilog=f"问题反馈与建议：{FEEDBACK_EMAIL}",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    ap.add_argument("--root", default=os.path.dirname(BASE_DIR),
                    help="待审计的代码目录（默认上一级目录）")
    ap.add_argument("--port", type=int, default=8770)
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--open", action="store_true", help="启动后自动打开浏览器")
    ap.add_argument("--check-env", "--doctor", dest="check_env", action="store_true",
                    help="只做运行环境自检（Python 版本 / 目录可写性 / 端口 / 联网）并退出，"
                         "不启动服务——拷到新电脑后先跑一次即可确认能否直接用")
    ap.add_argument("--no-reuse", action="store_true",
                    help="端口已被本平台占用时不复用，直接退出")
    ap.add_argument("--strict-port", action="store_true",
                    help="端口被其他程序占用时不自动顺延端口，直接退出")
    ap.add_argument("--no-vulndb", action="store_true",
                    help="不启用依赖漏洞库（跳过 OSV 查询，纯离线规则扫描）")
    ap.add_argument("--offline", action="store_true",
                    help="漏洞库离线模式：只读本地缓存，不发起任何网络请求")
    ap.add_argument("--vulndb-ttl", type=float, default=24.0,
                    help="依赖查询结果缓存有效期（小时，默认 24；0 表示每次都重新查询）")
    args = ap.parse_args()

    # ---- 环境自检模式：先于一切初始化，任何机器上都能直接跑，不依赖目录存在 ----
    if args.check_env:
        rep = env_report(check_network=True, port=args.port)
        print_env_report(rep)
        return 0 if rep["summary"]["ready"] else 1

    # 漏洞库运行参数：命令行 > 环境变量 > 默认值
    STATE["vuln_opts"]["enabled"] = not args.no_vulndb
    STATE["vuln_opts"]["offline"] = bool(args.offline)
    STATE["vuln_opts"]["ttl"] = max(0, int(args.vulndb_ttl * 3600))

    root = os.path.abspath(args.root)
    if not os.path.isdir(root):
        print(f"[!] 目录不存在：{root}")
        return 1

    port = args.port
    if port_occupied(args.host, port):
        # 情况一：端口上跑的就是本平台 —— 直接复用，不再重复启动
        info = None if args.no_reuse else probe_running(args.host, port)
        if info:
            url = f"http://{args.host}:{port}/"
            print("=" * 68)
            print(f"  {TOOL_NAME} v{info.get('version', TOOL_VERSION)} 已在运行")
            print("=" * 68)
            print(f"  访问地址   : {url}")
            print(f"  审计根目录 : {info.get('root') or '（未知）'}")
            print(f"  规则总数   : {info.get('rule_count', len(RULES))} 条")
            print(f"  运行环境   : Python {sys.version.split()[0]} · {platform.system()} {platform.release()}")
            print(f"  问题反馈   : {FEEDBACK_EMAIL}")
            print("=" * 68)
            print("  端口已被本平台占用，无需重复启动，已为你打开浏览器。")
            print(f"  如需另起一个实例，请改用其他端口，例如：--port {port + 1}")
            print("=" * 68)
            if args.open:
                # 复用场景下进程随后即退出，必须同步打开，定时器来不及触发
                try:
                    webbrowser.open(url)
                except Exception:                        # noqa: BLE001
                    pass
            return 0

        # 情况二：端口被别的程序占用 —— 顺延端口（除非显式要求严格）
        if args.strict_port:
            print(f"[!] 端口 {port} 已被其他程序占用（--strict-port 已启用，退出）。")
            return 1
        alt = find_free_port(args.host, port + 1)
        if alt is None:
            print(f"[!] 端口 {port} 被占用，且后续 20 个端口均不可用，请手动指定 --port。")
            return 1
        print(f"[!] 提示：端口 {port} 已被其他程序占用，已自动改用 {alt}。")
        port = alt

    STATE["root"] = root
    STATE["port"] = port          # 供 /api/env 自检与端口冲突提示复用
    STATE["target"] = {"root": root, "name": os.path.basename(root.rstrip(os.sep)) or root,
                       "kind": "path"}
    os.makedirs(REPORT_DIR, exist_ok=True)
    prune_workspaces()

    try:
        srv = ThreadingHTTPServer((args.host, port), Handler)
    except OSError as exc:
        print(f"[!] 无法监听 {args.host}:{port} —— {exc}")
        print("    请关闭占用该端口的程序，或用 --port 指定其他端口。")
        return 1
    srv.daemon_threads = True
    url = f"http://{args.host}:{port}/"
    print("=" * 68)
    print(f"  {TOOL_NAME} v{TOOL_VERSION}")
    print("=" * 68)
    print(f"  审计根目录 : {root}")
    print(f"  规则总数   : {len(RULES)} 条")
    print(f"  依赖漏洞库 : " + ("未启用（--no-vulndb）" if not STATE['vuln_opts']['enabled']
                                else f"OSV.dev / 缓存 {STATE['vuln_opts']['ttl'] // 3600}h"
                                     + ("（离线模式）" if STATE['vuln_opts']['offline'] else "")))
    print(f"  导出格式   : {' / '.join(EXPORT_FORMATS)}")
    print(f"  运行环境   : Python {sys.version.split()[0]} · {platform.system()} {platform.release()}"
          f" · {'已含 tkinter（可选）' if HAS_TK else '无 tkinter（不影响使用）'}")
    print(f"  访问地址   : {url}")
    print("  停止服务   : Ctrl + C（或双击同目录的 stop.bat）")
    print("=" * 68)
    print(f"  问题反馈与建议 : {FEEDBACK_EMAIL}")
    print(f"  环境自检       : python app.py --check-env")
    print("=" * 68)
    if args.open:
        threading.Timer(0.8, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] 服务已停止")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
