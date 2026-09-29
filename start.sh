#!/usr/bin/env bash
# 源代码静态审计平台 - Linux / macOS 启动器
#
# 依赖项：只需本机已安装 Python 3.9 或更高版本，无需 pip install 任何第三方包。
# 迁移：整个 audit-tool 目录可直接拷贝到其他电脑运行（路径全部相对化）。
# 指定解释器：导出环境变量 AUDIT_PYTHON=/usr/bin/python3 可跳过自动探测。
# 环境自检：./start.sh --check-env
# 问题反馈：wangwangdui214@qq.com
#
# 用法：./start.sh           启动服务（就绪后自动打开浏览器；Ctrl+C 停止）
#       ./start.sh --check-env  只做环境自检，不启动服务
set -u
cd "$(dirname "$0")"

HERE="$(pwd)"
MODE=""
if [ "${1:-}" = "--check-env" ] || [ "${1:-}" = "check" ]; then
  MODE="1"
fi

# ==================== 一、定位 Python 解释器（要求 3.9+） ====================
PY=""

# 0) 环境变量显式指定（优先级最高）
if [ -n "${AUDIT_PYTHON:-}" ] && [ -x "${AUDIT_PYTHON}" ]; then
  PY="${AUDIT_PYTHON}"
fi

# 1) PATH 中的 python3.x / python3 / python，按版本由高到低尝试
if [ -z "$PY" ]; then
  for c in python3.14 python3.13 python3.12 python3.11 python3.10 python3.9 \
           python3 python; do
    if command -v "$c" >/dev/null 2>&1; then
      if "$c" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 9) else 1)' \
           >/dev/null 2>&1; then
        PY="$(command -v "$c")"
        break
      fi
    fi
  done
fi

# 2) 常见安装位置（发行版包管理器 / Homebrew / pyenv / 官方安装包）
if [ -z "$PY" ]; then
  for c in /usr/bin/python3 /usr/local/bin/python3 /opt/homebrew/bin/python3 \
           "$HOME/.pyenv/shims/python3" \
           /Library/Frameworks/Python.framework/Versions/Current/bin/python3; do
    if [ -x "$c" ]; then
      if "$c" -c 'import sys; sys.exit(0 if sys.version_info[:2] >= (3, 9) else 1)' \
           >/dev/null 2>&1; then
        PY="$c"
        break
      fi
    fi
  done
fi

if [ -z "$PY" ]; then
  echo "[错误] 未找到 Python 3.9+ 解释器。"
  echo "       本工具零第三方依赖，但需要本机已安装 Python 3.9 或更高版本。"
  echo "       · macOS:  brew install python3"
  echo "       · Ubuntu: sudo apt install python3"
  echo "       · CentOS: sudo yum install python3"
  echo "       或从 https://www.python.org/downloads/ 下载安装。"
  if [ -n "${AUDIT_PYTHON:-}" ]; then
    echo "       （已设置 AUDIT_PYTHON=${AUDIT_PYTHON}，但该路径不可执行）"
  else
    echo "       若已安装仍报错，可指定解释器：export AUDIT_PYTHON=/path/to/python3"
  fi
  exit 1
fi

# ==================== 二、环境自检模式 ====================
if [ -n "$MODE" ]; then
  echo "解释器：$PY"
  echo
  exec "$PY" "$HERE/app.py" --check-env
fi

# ==================== 三、启动审计平台 ====================
echo "解释器：$PY"
echo "正在启动源代码静态审计平台，请稍候…"
echo "（服务就绪后会自动打开浏览器；Ctrl+C 停止服务）"
echo

exec "$PY" "$HERE/app.py" --root "$(dirname "$HERE")" --port 8770 --open
