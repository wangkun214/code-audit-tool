# -*- coding: utf-8 -*-
"""
零依赖 DOCX（OOXML / Word 2007+）生成器。

不依赖 python-docx / lxml，只用标准库 zipfile 手写 OOXML，
以延续整个审计平台「无需 pip install」的设计原则。

面向审计报告场景提供：
  * 标题层级（Heading 1-4，带大纲级别，可在 Word 导航窗格中展开）
  * 表格（表头底纹、斑马纹、列宽控制、重复表头行）
  * 代码块（行号栏 + 等宽字体 + 底纹，命中行红色高亮）
  * 分布条形图（用单元格底纹绘制，无需图表部件）
  * 页眉 / 页脚（含 PAGE / NUMPAGES 域，自动页码）
  * 中文排版（w:eastAsia 显式指定，避免字体回退错乱）
"""
from __future__ import annotations

import io
import os
import re
import zipfile
from datetime import datetime

# ------------------------------------------------------------------ 常量
FONT_CJK = "宋体"            # 正文中文
FONT_HEAD = "微软雅黑"        # 标题中文
FONT_LATIN = "Segoe UI"      # 正文西文
FONT_CODE = "Consolas"       # 代码
FONT_CODE_CJK = "宋体"

COLOR_BRAND = "1F3A5F"
COLOR_TEXT = "1F2937"
COLOR_MUTED = "6B7280"
COLOR_LINE = "D8DEE7"
COLOR_HEAD_FILL = "EEF2F8"
COLOR_ZEBRA = "F8FAFC"
COLOR_CODE_FILL = "F4F6F9"
COLOR_CODE_HIT = "FCE7E7"
COLOR_TABLE_BORDER = "C9D3E0"

# A4 纵向：11906 x 16838 twips；页边距 1134 twips（2cm）
PAGE_W = 11906
PAGE_H = 16838
MARGIN = 1134
CONTENT_W = PAGE_W - MARGIN * 2          # 9638 twips 正文可用宽

SEVERITY_COLOR = {
    "critical": "B91C1C",
    "high": "DC2626",
    "medium": "D97706",
    "low": "0284C7",
    "info": "64748B",
}

_ILLEGAL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def _esc(text) -> str:
    """XML 文本转义（& < > 必须转义；引号在属性中另行处理）。"""
    s = _ILLEGAL.sub("", str(text if text is not None else ""))
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def _esc_attr(text) -> str:
    return _esc(text).replace('"', "&quot;").replace("'", "&apos;")


def _t(text) -> str:
    """生成一个 w:t 节点，保留空格。"""
    return f'<w:t xml:space="preserve">{_esc(text)}</w:t>'


def _rpr(bold=False, italic=False, size=None, color=None, mono=False,
         underline=False, fill=None, cjk=None) -> str:
    """构造 w:rPr 片段。size 为半磅值（21 = 10.5pt）。

    子元素严格按 OOXML CT_RPr 的 schema 顺序排列：
      rFonts → b/bCs → i/iCs → color → sz/szCs → u → shd
    """
    if mono:
        fonts = (f'<w:rFonts w:ascii="{FONT_CODE}" w:hAnsi="{FONT_CODE}" '
                 f'w:eastAsia="{cjk or FONT_CODE_CJK}" w:cs="{FONT_CODE}"/>')
    else:
        fonts = (f'<w:rFonts w:ascii="{FONT_LATIN}" w:hAnsi="{FONT_LATIN}" '
                 f'w:eastAsia="{cjk or FONT_CJK}" w:cs="{FONT_LATIN}"/>')
    p = [fonts]
    if bold:
        p.append("<w:b/><w:bCs/>")
    if italic:
        p.append("<w:i/><w:iCs/>")
    if color:
        p.append(f'<w:color w:val="{color}"/>')
    if size:
        p.append(f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/>')
    if underline:
        p.append('<w:u w:val="single"/>')
    if fill:
        p.append(f'<w:shd w:val="clear" w:color="auto" w:fill="{fill}"/>')
    return "<w:rPr>" + "".join(p) + "</w:rPr>"


def _run(text, **kw) -> str:
    return f"<w:r>{_rpr(**kw)}{_t(text)}</w:r>"


def _field(instr: str, placeholder: str = "1", size=18, color=COLOR_MUTED) -> str:
    """插入一个 Word 域（如 PAGE / NUMPAGES）。"""
    rpr = _rpr(size=size, color=color)
    return (
        f'<w:r>{rpr}<w:fldChar w:fldCharType="begin"/></w:r>'
        f'<w:r>{rpr}<w:instrText xml:space="preserve"> {instr} </w:instrText></w:r>'
        f'<w:r>{rpr}<w:fldChar w:fldCharType="separate"/></w:r>'
        f'<w:r>{rpr}{_t(placeholder)}</w:r>'
        f'<w:r>{rpr}<w:fldChar w:fldCharType="end"/></w:r>'
    )


class DocxBuilder:
    """极简 Word 文档构建器：按顺序追加块级元素，最后打包为 .docx。"""

    def __init__(self, header_text: str = "", footer_left: str = ""):
        self.body: list[str] = []
        self.header_text = header_text
        self.footer_left = footer_left
        self.title = header_text or "审计报告"

    # ------------------------------------------------------------ 基础块
    def _p(self, inner: str, ppr: str = "") -> None:
        self.body.append(f"<w:p>{ppr}{inner}</w:p>")

    def _ppr(self, style=None, align=None, spacing=None, indent=None,
             border=None, fill=None, keep_next=False, page_break_before=False,
             context=None) -> str:
        parts = []
        if style:
            parts.append(f'<w:pStyle w:val="{style}"/>')
        if keep_next:
            parts.append("<w:keepNext/><w:keepLines/>")
        if page_break_before:
            parts.append('<w:pageBreakBefore/>')
        if border:
            parts.append(border)
        if fill:
            parts.append(f'<w:shd w:val="clear" w:color="auto" w:fill="{fill}"/>')
        if spacing:
            parts.append(spacing)
        if indent:
            parts.append(indent)
        if context:
            parts.append(context)
        if align:
            parts.append(f'<w:jc w:val="{align}"/>')
        return "<w:pPr>" + "".join(parts) + "</w:pPr>" if parts else ""

    @staticmethod
    def _spacing(before=0, after=120, line=None, rule="auto") -> str:
        s = f'<w:spacing w:before="{before}" w:after="{after}"'
        if line:
            s += f' w:line="{line}" w:lineRule="{rule}"'
        return s + "/>"

    # ------------------------------------------------------------ 标题
    def add_heading(self, text, level: int = 1, color: str = COLOR_BRAND) -> None:
        sizes = {1: 32, 2: 26, 3: 23, 4: 21}
        before = {1: 360, 2: 300, 3: 240, 4: 200}
        after = {1: 180, 2: 140, 3: 120, 4: 100}
        lv = max(1, min(4, int(level)))
        border = None
        if lv == 1:
            border = ('<w:pBdr><w:bottom w:val="single" w:sz="12" w:space="6" '
                      f'w:color="{COLOR_BRAND}"/></w:pBdr>')
        ppr = self._ppr(style=f"Heading{lv}", spacing=self._spacing(before[lv], after[lv]),
                        border=border, keep_next=True)
        run = (f'<w:r>{_rpr(bold=True, size=sizes[lv], color=color, cjk=FONT_HEAD)}'
               f'{_t(text)}</w:r>')
        self._p(run, ppr)

    def add_title(self, text, sub: str = "") -> None:
        ppr = self._ppr(align="center", spacing=self._spacing(0, 120))
        self._p(f'<w:r>{_rpr(bold=True, size=48, color=COLOR_BRAND, cjk=FONT_HEAD)}'
                f'{_t(text)}</w:r>', ppr)
        if sub:
            ppr2 = self._ppr(align="center", spacing=self._spacing(0, 240))
            self._p(f'<w:r>{_rpr(size=21, color=COLOR_MUTED)}{_t(sub)}</w:r>', ppr2)

    # ------------------------------------------------------------ 段落
    def add_paragraph(self, text, size=21, bold=False, color=COLOR_TEXT,
                      align=None, before=0, after=110, indent_left=None,
                      mono=False, fill=None) -> None:
        ind = f'<w:ind w:left="{indent_left}"/>' if indent_left else None
        ppr = self._ppr(align=align, spacing=self._spacing(before, after),
                        indent=ind, fill=fill)
        self._p(_run(text, size=size, bold=bold, color=color, mono=mono), ppr)

    def add_bullet(self, text, level: int = 0, marker: str = "●", size=21) -> None:
        """无编号部件的项目符号：手工标记 + 悬挂缩进（渲染稳定）。"""
        left = 240 + level * 340
        ppr = self._ppr(spacing=self._spacing(0, 70),
                        indent=f'<w:ind w:left="{left + 260}" w:hanging="260"/>')
        runs = (_run(marker + " ", size=size, color=COLOR_BRAND) +
                _run(text, size=size))
        self._p(runs, ppr)

    def add_ordered(self, idx: int, text, size=21) -> None:
        ppr = self._ppr(spacing=self._spacing(0, 70),
                        indent='<w:ind w:left="440" w:hanging="340"/>')
        self._p(_run(f"{idx}. ", size=size, bold=True, color=COLOR_BRAND) +
                _run(text, size=size), ppr)

    def add_kv_line(self, key: str, value: str, size=21) -> None:
        ppr = self._ppr(spacing=self._spacing(0, 80),
                        indent='<w:ind w:left="300" w:hanging="300"/>')
        self._p(_run("· ", size=size, color=COLOR_MUTED) +
                _run(f"{key}：", size=size, bold=True) +
                _run(value, size=size), ppr)

    def add_note(self, text, fill="FFFBEB", color="92400E", size=19) -> None:
        border = ('<w:pBdr><w:left w:val="single" w:sz="18" w:space="6" '
                  f'w:color="{color}"/></w:pBdr>')
        ppr = self._ppr(spacing=self._spacing(60, 110), fill=fill, border=border,
                        indent='<w:ind w:left="200" w:right="200"/>')
        self._p(_run(text, size=size, color=color), ppr)

    def add_divider(self) -> None:
        ppr = self._ppr(spacing=self._spacing(60, 60),
                        border=f'<w:pBdr><w:bottom w:val="single" w:sz="6" '
                               f'w:space="1" w:color="{COLOR_LINE}"/></w:pBdr>')
        self._p("", ppr)

    def add_page_break(self) -> None:
        self._p('<w:r><w:br w:type="page"/></w:r>')

    def add_spacer(self, height_twips=200) -> None:
        ppr = self._ppr(spacing=self._spacing(0, 0, line=height_twips, rule="exact"))
        self._p("", ppr)

    # ------------------------------------------------------------ 代码块
    def add_code_block(self, lines, start_no: int = 1, hit_lines=(), max_len=180) -> None:
        """代码块：行号栏 + 等宽字体 + 底纹；命中行以浅红底纹加粗。"""
        hits = set(hit_lines or ())
        if not lines:
            return
        total = len(lines)
        for i, raw in enumerate(lines):
            no = start_no + i
            text = str(raw).replace("\t", "    ")
            if len(text) > max_len:
                text = text[:max_len] + " …"
            is_hit = no in hits
            fill = COLOR_CODE_HIT if is_hit else COLOR_CODE_FILL
            first, last = i == 0, i == total - 1
            edge = "8" if (first or last) else "0"
            # w:pBdr 子元素顺序固定为 top → left → bottom → right
            side_color = "B91C1C" if is_hit else "C9D3E0"
            border = ('<w:pBdr>'
                      f'<w:top w:val="single" w:sz="{edge}" w:space="0" w:color="C9D3E0"/>'
                      f'<w:left w:val="single" w:sz="12" w:space="4" w:color="{side_color}"/>'
                      f'<w:bottom w:val="single" w:sz="{edge}" w:space="0" w:color="C9D3E0"/>'
                      '</w:pBdr>')
            ppr = self._ppr(spacing=self._spacing(0, 0, line=240, rule="auto"),
                            fill=fill, border=border, keep_next=not last,
                            indent='<w:ind w:left="120" w:right="120"/>')
            gutter = f"{no:>5} │ "
            code_color = "B91C1C" if is_hit else "1F2937"
            self._p(
                f'<w:r>{_rpr(size=16, mono=True, color="9AA6B8", fill=fill)}'
                f'{_t(gutter)}</w:r>'
                f'<w:r>{_rpr(size=16, mono=True, bold=is_hit, fill=fill, color=code_color)}'
                f'{_t(text)}</w:r>',
                ppr)
        self.add_spacer(120)

    # ------------------------------------------------------------ 表格
    def add_table(self, headers, rows, widths=None, zebra=True,
                  header_fill=COLOR_HEAD_FILL, font_size=19,
                  align_right=(), mono_cols=(), empty_text="—") -> None:
        """通用表格。widths 为各列 twips 宽度列表，缺省均分正文宽度。"""
        ncol = len(headers)
        if not widths:
            widths = [CONTENT_W // ncol] * ncol
        else:
            widths = list(widths) + [CONTENT_W // ncol] * (ncol - len(widths))
            widths = widths[:ncol]

        def cell(content, w, *, fill=None, bold=False, right=False,
                 mono=False, size=font_size, color=COLOR_TEXT, span=None):
            # tcPr 子元素顺序：tcW → gridSpan → shd → tcMar → vAlign
            tcpr = [f'<w:tcW w:w="{w}" w:type="dxa"/>']
            if span:
                tcpr.append(f'<w:gridSpan w:val="{span}"/>')
            if fill:
                tcpr.append(f'<w:shd w:val="clear" w:color="auto" w:fill="{fill}"/>')
            tcpr.append('<w:tcMar>'
                        '<w:top w:w="50" w:type="dxa"/><w:bottom w:w="50" w:type="dxa"/>'
                        '<w:left w:w="90" w:type="dxa"/><w:right w:w="90" w:type="dxa"/>'
                        '</w:tcMar>')
            tcpr.append('<w:vAlign w:val="center"/>')
            jc = '<w:jc w:val="right"/>' if right else ""
            ppr = (f'<w:pPr><w:spacing w:before="0" w:after="0" '
                   f'w:line="240" w:lineRule="auto"/>{jc}</w:pPr>')
            text = str(content) if content not in (None, "") else empty_text
            return (f'<w:tc><w:tcPr>{"".join(tcpr)}</w:tcPr>'
                    f'<w:p>{ppr}{_run(text, size=size, bold=bold, mono=mono, color=color)}'
                    f'</w:p></w:tc>')

        borders = (
            '<w:tblBorders>'
            + "".join(f'<w:{s} w:val="single" w:sz="4" w:space="0" w:color="{COLOR_TABLE_BORDER}"/>'
                      for s in ("top", "left", "bottom", "right", "insideH", "insideV"))
            + '</w:tblBorders>'
        )
        # tblPr 子元素顺序：tblW → tblBorders → tblLayout → tblCellMar
        out = [
            '<w:tbl><w:tblPr>'
            f'<w:tblW w:w="{sum(widths)}" w:type="dxa"/>'
            f'{borders}'
            '<w:tblLayout w:type="fixed"/>'
            f'<w:tblCellMar><w:left w:w="90" w:type="dxa"/><w:right w:w="90" w:type="dxa"/></w:tblCellMar>'
            '</w:tblPr>'
            '<w:tblGrid>' + "".join(f'<w:gridCol w:w="{w}"/>' for w in widths) + '</w:tblGrid>'
        ]
        # 表头行（跨页重复）
        out.append('<w:tr><w:trPr><w:tblHeader/></w:trPr>'
                   + "".join(cell(h, widths[i], fill=header_fill, bold=True, size=font_size)
                             for i, h in enumerate(headers))
                   + '</w:tr>')
        for ri, row in enumerate(rows):
            fill = COLOR_ZEBRA if (zebra and ri % 2 == 1) else None
            tcs = []
            for ci in range(ncol):
                val = row[ci] if ci < len(row) else ""
                tcs.append(cell(val, widths[ci], fill=fill,
                                right=ci in align_right, mono=ci in mono_cols))
            out.append('<w:tr>' + "".join(tcs) + '</w:tr>')
        out.append('</w:tbl>')
        self.body.append("".join(out))
        self.add_spacer(160)

    # ------------------------------------------------- 分布条形图（底纹实现）
    def add_bar_chart(self, items, bar_cells: int = 22, label_w: int = 2200,
                      value_w: int = 1000) -> None:
        """用单元格底纹绘制横向条形图，避免引入图表部件。

        items: [(标签, 数值, 颜色HEX), ...]
        """
        if not items:
            return
        label_w = 2200
        value_w = 1000
        bar_total = CONTENT_W - label_w - value_w   # 6438
        cell_w = max(1, bar_total // bar_cells)
        peak = max((v for _, v, _ in items), default=0) or 1

        def tc(w, content="", *, fill=None, borders="none", jc=None, size=17,
               bold=False, color=COLOR_TEXT):
            if borders == "none":
                bd = ('<w:tcBorders>'
                      + "".join(f'<w:{s} w:val="nil"/>' for s in
                                ("top", "left", "bottom", "right"))
                      + '</w:tcBorders>')
            else:
                bd = ('<w:tcBorders>'
                      + "".join(f'<w:{s} w:val="single" w:sz="4" w:space="0" '
                                f'w:color="{COLOR_TABLE_BORDER}"/>'
                                for s in ("top", "left", "bottom", "right"))
                      + '</w:tcBorders>')
            # tcPr 顺序：tcW → tcBorders → shd → tcMar → vAlign
            tcpr = [f'<w:tcW w:w="{w}" w:type="dxa"/>', bd]
            if fill:
                tcpr.append(f'<w:shd w:val="clear" w:color="auto" w:fill="{fill}"/>')
            tcpr.append('<w:tcMar><w:top w:w="20" w:type="dxa"/><w:bottom w:w="20" w:type="dxa"/>'
                        '<w:left w:w="60" w:type="dxa"/><w:right w:w="60" w:type="dxa"/></w:tcMar>')
            tcpr.append('<w:vAlign w:val="center"/>')
            jcs = f'<w:jc w:val="{jc}"/>' if jc else ""
            ppr = (f'<w:pPr><w:spacing w:before="0" w:after="0" w:line="240" '
                   f'w:lineRule="auto"/>{jcs}</w:pPr>')
            return (f'<w:tc><w:tcPr>{"".join(tcpr)}</w:tcPr>'
                    f'<w:p>{ppr}{_run(content, size=size, bold=bold, color=color)}</w:p></w:tc>')

        widths = [label_w, value_w] + [cell_w] * bar_cells
        out = ['<w:tbl><w:tblPr>'
               f'<w:tblW w:w="{sum(widths)}" w:type="dxa"/>'
               '<w:tblBorders>'
               + "".join(f'<w:{s} w:val="nil"/>' for s in
                         ("top", "left", "bottom", "right", "insideH", "insideV"))
               + '</w:tblBorders>'
               '<w:tblLayout w:type="fixed"/></w:tblPr>'
               '<w:tblGrid>' + "".join(f'<w:gridCol w:w="{w}"/>' for w in widths) + '</w:tblGrid>']
        for label, val, color in items:
            filled = int(round(val / peak * bar_cells)) if val else 0
            tcs = [tc(label_w, label, borders="box", size=18),
                   tc(value_w, str(val), borders="box", jc="right", size=18, bold=True, color=color)]
            for i in range(bar_cells):
                tcs.append(tc(cell_w, "", fill=color if i < filled else "F1F4F8"))
            out.append('<w:tr>' + "".join(tcs) + '</w:tr>')
        out.append('</w:tbl>')
        self.body.append("".join(out))
        self.add_spacer(160)

    # ------------------------------------------------------------ 打包
    def _header_xml(self) -> str:
        ppr = ('<w:pPr><w:pBdr><w:bottom w:val="single" w:sz="4" w:space="2" '
               f'w:color="{COLOR_LINE}"/></w:pBdr>'
               '<w:jc w:val="right"/></w:pPr>')
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:hdr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                f'<w:p>{ppr}{_run(self.header_text, size=17, color=COLOR_MUTED)}</w:p>'
                '</w:hdr>')

    def _footer_xml(self) -> str:
        ppr = '<w:pPr><w:jc w:val="center"/></w:pPr>'
        left = f'{_run(self.footer_left + "　", size=17, color=COLOR_MUTED)}' if self.footer_left else ""
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:ftr xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                f'<w:p>{ppr}{left}'
                f'{_run("第 ", size=17, color=COLOR_MUTED)}'
                f'{_field("PAGE")}'
                f'{_run(" 页 / 共 ", size=17, color=COLOR_MUTED)}'
                f'{_field("NUMPAGES")}'
                f'{_run(" 页", size=17, color=COLOR_MUTED)}'
                '</w:p></w:ftr>')

    def _styles_xml(self) -> str:
        def style(sid, name, level, size, before, after, color=COLOR_BRAND, bold=True):
            # pPr 顺序：keepNext → keepLines → spacing → outlineLvl
            return (
                f'<w:style w:type="paragraph" w:styleId="{sid}"><w:name w:val="{name}"/>'
                '<w:basedOn w:val="Normal"/><w:qFormat/>'
                '<w:pPr><w:keepNext/><w:keepLines/>'
                f'<w:spacing w:before="{before}" w:after="{after}" w:line="300" w:lineRule="auto"/>'
                f'<w:outlineLvl w:val="{level}"/></w:pPr>'
                f'<w:rPr><w:rFonts w:ascii="{FONT_LATIN}" w:hAnsi="{FONT_LATIN}" '
                f'w:eastAsia="{FONT_HEAD}" w:cs="{FONT_LATIN}"/>'
                f'{"<w:b/><w:bCs/>" if bold else ""}<w:color w:val="{color}"/>'
                f'<w:sz w:val="{size}"/><w:szCs w:val="{size}"/></w:rPr></w:style>'
            )

        return (
            '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
            '<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
            '<w:docDefaults><w:rPrDefault><w:rPr>'
            f'<w:rFonts w:ascii="{FONT_LATIN}" w:hAnsi="{FONT_LATIN}" '
            f'w:eastAsia="{FONT_CJK}" w:cs="{FONT_LATIN}"/>'
            '<w:sz w:val="21"/><w:szCs w:val="21"/>'
            '<w:lang w:val="en-US" w:eastAsia="zh-CN"/>'
            '</w:rPr></w:rPrDefault>'
            '<w:pPrDefault><w:pPr><w:spacing w:after="110" w:line="300" '
            'w:lineRule="auto"/></w:pPr></w:pPrDefault></w:docDefaults>'
            '<w:style w:type="paragraph" w:default="1" w:styleId="Normal">'
            '<w:name w:val="Normal"/><w:qFormat/>'
            '<w:pPr><w:spacing w:after="110" w:line="300" w:lineRule="auto"/></w:pPr>'
            '</w:style>'
            + style("Heading1", "heading 1", 0, 32, 360, 180)
            + style("Heading2", "heading 2", 1, 26, 300, 140)
            + style("Heading3", "heading 3", 2, 23, 240, 120, color="243B55")
            + style("Heading4", "heading 4", 3, 21, 200, 100, color="334155")
            + '<w:style w:type="character" w:styleId="CodeChar"><w:name w:val="Code Char"/>'
            f'<w:rPr><w:rFonts w:ascii="{FONT_CODE}" w:hAnsi="{FONT_CODE}" '
            f'w:eastAsia="{FONT_CODE_CJK}"/><w:sz w:val="17"/></w:rPr></w:style>'
            '</w:styles>'
        )

    def _settings_xml(self) -> str:
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:settings xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">'
                '<w:zoom w:percent="100"/>'
                '<w:defaultTabStop w:val="420"/>'
                '<w:compat><w:compatSetting w:name="compatibilityMode" '
                'w:uri="http://schemas.microsoft.com/office/word" w:val="15"/></w:compat>'
                '<w:themeFontLang w:val="en-US" w:eastAsia="zh-CN"/>'
                '</w:settings>')

    def _document_xml(self) -> str:
        sect = ('<w:sectPr>'
                '<w:headerReference w:type="default" r:id="rId3"/>'
                '<w:footerReference w:type="default" r:id="rId4"/>'
                f'<w:pgSz w:w="{PAGE_W}" w:h="{PAGE_H}"/>'
                f'<w:pgMar w:top="{MARGIN}" w:right="{MARGIN}" w:bottom="{MARGIN}" '
                f'w:left="{MARGIN}" w:header="720" w:footer="720" w:gutter="0"/>'
                '<w:cols w:space="425"/><w:docGrid w:type="lines" w:linePitch="312"/>'
                '</w:sectPr>')
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<w:document '
                'xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main" '
                'xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships" '
                'xmlns:wp="http://schemas.openxmlformats.org/drawingml/2006/wordprocessingDrawing">'
                '<w:body>' + "".join(self.body) + sect + '</w:body></w:document>')

    def _content_types(self) -> str:
        over = {
            "/word/document.xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml",
            "/word/styles.xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml",
            "/word/settings.xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.settings+xml",
            "/word/header1.xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.header+xml",
            "/word/footer1.xml": "application/vnd.openxmlformats-officedocument.wordprocessingml.footer+xml",
            "/docProps/core.xml": "application/vnd.openxmlformats-package.core-properties+xml",
            "/docProps/app.xml": "application/vnd.openxmlformats-officedocument.extended-properties+xml",
        }
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                '<Default Extension="xml" ContentType="application/xml"/>'
                + "".join(f'<Override PartName="{k}" ContentType="{v}"/>' for k, v in over.items())
                + '</Types>')

    R = "http://schemas.openxmlformats.org/officeDocument/2006/relationships"
    PR = "http://schemas.openxmlformats.org/package/2006/relationships"

    def _rels_root(self) -> str:
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                f'<Relationships xmlns="{self.PR}">'
                f'<Relationship Id="rId1" Type="{self.R}/officeDocument" Target="word/document.xml"/>'
                f'<Relationship Id="rId2" Type="http://schemas.openxmlformats.org/package/2006/relationships/metadata/core-properties" Target="docProps/core.xml"/>'
                f'<Relationship Id="rId3" Type="{self.R}/extended-properties" Target="docProps/app.xml"/>'
                '</Relationships>')

    def _rels_doc(self) -> str:
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                f'<Relationships xmlns="{self.PR}">'
                f'<Relationship Id="rId1" Type="{self.R}/styles" Target="styles.xml"/>'
                f'<Relationship Id="rId2" Type="{self.R}/settings" Target="settings.xml"/>'
                f'<Relationship Id="rId3" Type="{self.R}/header" Target="header1.xml"/>'
                f'<Relationship Id="rId4" Type="{self.R}/footer" Target="footer1.xml"/>'
                '</Relationships>')

    def _core_xml(self) -> str:
        now = datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<cp:coreProperties '
                'xmlns:cp="http://schemas.openxmlformats.org/package/2006/metadata/core-properties" '
                'xmlns:dc="http://purl.org/dc/elements/1.1/" '
                'xmlns:dcterms="http://purl.org/dc/terms/" '
                'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">'
                f'<dc:title>{_esc(self.title)}</dc:title>'
                '<dc:creator>源代码静态审计平台</dc:creator>'
                '<cp:lastModifiedBy>源代码静态审计平台</cp:lastModifiedBy>'
                f'<dcterms:created xsi:type="dcterms:W3CDTF">{now}</dcterms:created>'
                f'<dcterms:modified xsi:type="dcterms:W3CDTF">{now}</dcterms:modified>'
                '</cp:coreProperties>')

    def _app_xml(self) -> str:
        return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>'
                '<Properties xmlns="http://schemas.openxmlformats.org/officeDocument/2006/extended-properties" '
                'xmlns:vt="http://schemas.openxmlformats.org/officeDocument/2006/docPropsVTypes">'
                '<Application>源代码静态审计平台</Application>'
                '<AppVersion>1.1</AppVersion>'
                '</Properties>')

    def _parts(self) -> dict:
        return {
            "[Content_Types].xml": self._content_types(),
            "_rels/.rels": self._rels_root(),
            "docProps/core.xml": self._core_xml(),
            "docProps/app.xml": self._app_xml(),
            "word/document.xml": self._document_xml(),
            "word/_rels/document.xml.rels": self._rels_doc(),
            "word/styles.xml": self._styles_xml(),
            "word/settings.xml": self._settings_xml(),
            "word/header1.xml": self._header_xml(),
            "word/footer1.xml": self._footer_xml(),
        }

    def _write(self, fp) -> None:
        with zipfile.ZipFile(fp, "w", zipfile.ZIP_DEFLATED, compresslevel=6) as z:
            for name, data in self._parts().items():
                z.writestr(name, data.encode("utf-8"))

    def save(self, path: str) -> int:
        """写入磁盘，返回文件字节数。"""
        with open(path, "wb") as fh:
            self._write(fh)
        return os.path.getsize(path)

    def to_bytes(self) -> bytes:
        """输出为内存字节流，供 HTTP 直接下发。"""
        buf = io.BytesIO()
        self._write(buf)
        return buf.getvalue()
