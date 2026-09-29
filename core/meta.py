# -*- coding: utf-8 -*-
"""工具元信息的唯一真源（Single Source of Truth）。

工具名、版本号、反馈邮箱集中在此定义，供服务端（app.py）、报告导出
（core/reporter.py）与自检脚本（selftest.py）共同引用，避免各处硬编码
导致版本号漂移、反馈入口漏配。

本模块**只含常量与一个极轻量的版本判定函数**，不 import 任何其它模块，
因此可以被任意模块安全导入而不引入循环依赖。
"""
from __future__ import annotations

import sys

# ------------------------------------------------------------------ 基础标识
TOOL_NAME = "源代码静态审计平台"
TOOL_NAME_EN = "Source Code Security Audit Console"
TOOL_VERSION = "1.8.0"

# ------------------------------------------------------------------ 反馈与沟通
# 用户提交问题与建议的统一收件邮箱（界面「关于与反馈」、导出报告页脚均引用此值）
FEEDBACK_EMAIL = "wangwangdui214@qq.com"
FEEDBACK_TITLE = "问题反馈与建议"
# 邮件主题前缀，便于收件端按版本归档检索
FEEDBACK_SUBJECT_PREFIX = f"[{TOOL_NAME}]"

# ------------------------------------------------------------------ 环境要求
# 运行所需的最低 Python 版本（元组形式，便于比较；全部依赖均为标准库）
MIN_PYTHON = (3, 9)
MIN_PYTHON_STR = "3.9"
# 经验证运行良好的版本区间（仅用于文档与自检提示，不构成硬性限制）
RECOMMENDED_PYTHON = "3.10 – 3.13"
# 官方下载页（启动器在未找到解释器时打印）
PYTHON_DOWNLOAD_URL = "https://www.python.org/downloads/"


def python_ok(version_info=None) -> bool:
    """判断给定（或当前）Python 版本是否满足最低要求。"""
    return tuple((version_info or sys.version_info)[:2]) >= MIN_PYTHON


def full_version() -> str:
    """形如 `1.8.0` 的版本号（供界面与报告展示）。"""
    return TOOL_VERSION
