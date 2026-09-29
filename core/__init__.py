# -*- coding: utf-8 -*-
"""核心包：规则库、扫描引擎、报告导出。"""
# 元信息常量先于子模块导入，保证任何子模块都能 `from .meta import ...` 而不触发循环导入
from .meta import (FEEDBACK_EMAIL, FEEDBACK_SUBJECT_PREFIX, FEEDBACK_TITLE,
                   MIN_PYTHON, MIN_PYTHON_STR, PYTHON_DOWNLOAD_URL,
                   RECOMMENDED_PYTHON, TOOL_NAME, TOOL_NAME_EN, TOOL_VERSION)

from .engine import AuditEngine, detect_language, read_text
from .rules import (CATEGORY_META, DEFAULT_EXCLUDES, LANG_EXT, RULES,
                    SEVERITY_META, SEVERITY_ORDER)

__all__ = [
    "AuditEngine", "detect_language", "read_text",
    "RULES", "SEVERITY_META", "SEVERITY_ORDER", "CATEGORY_META",
    "LANG_EXT", "DEFAULT_EXCLUDES",
    # 元信息
    "TOOL_NAME", "TOOL_NAME_EN", "TOOL_VERSION",
    "FEEDBACK_EMAIL", "FEEDBACK_TITLE", "FEEDBACK_SUBJECT_PREFIX",
    "MIN_PYTHON", "MIN_PYTHON_STR", "RECOMMENDED_PYTHON", "PYTHON_DOWNLOAD_URL",
]
