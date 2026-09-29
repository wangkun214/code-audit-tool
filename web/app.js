/* =============================================================
   源代码静态审计平台 · 前端逻辑 v1.1
   文件树 / 源码检视 / 安全看板 / 分组审计结果 / 报告导出
   ============================================================= */
(function () {
  'use strict';

  /* ------------------------------------------------------------ 常量 */
  const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info'];
  const SEV_COLOR = {
    critical: '#a4161a', high: '#e03131', medium: '#e8850c',
    low: '#1c7ed6', info: '#6b7280',
  };
  const SCOPE_CN = { production: '生产代码', test: '测试 / 示例代码', doc: '文档' };
  const PAGE_SIZE = 60;          // 平铺列表每页条数
  const GROUP_PAGE = 40;         // 分组内每页条数
  const HIGHLIGHT_MAX = 2500;    // 超过该行数不再做语法高亮（性能保护）
  const RENDER_MAX = 40000;      // 超过该行数只渲染前 N 行
  const RING_C = 339.292;        // 2πr，r = 54

  /* ------------------------------------------------------------ 状态 */
  const S = {
    meta: null,
    target: null,           // 当前审计目标 {name, root, kind: 'path'|'upload'}
    pick: null,             // 浏览器原生选择器选中的文件夹（待上传）
    pickBusy: false,
    browseBusy: false,
    dirData: null,          // 网页目录浏览器当前目录数据
    dirBusy: false,
    tree: null,
    fileIndex: {},          // path -> 文件节点
    dirIndex: {},           // path -> 目录节点（惰性渲染时查子节点）
    collapsed: new Set(),   // 已折叠的目录路径
    summary: null,
    currentFile: null,
    currentFindings: [],    // 当前文件的风险行
    hitCursor: -1,
    wrap: false,
    scanning: false,
    pollTimer: null,
    depLoaded: false,
    deps: [],
    depEco: 'all',
    depKw: '',
    ruleSev: 'all',
    ruleKw: '',
    centerTab: 'code',
    observer: null,
  };

  /* ---- 审计项目隔离：当前查看的项目 ID（空 = 最近一次扫描的实时数据） ---- */
  let VIEW_PID = '';
  function withProj(path) {
    if (!VIEW_PID) return path;
    return path + (path.includes('?') ? '&' : '?') + 'project=' + encodeURIComponent(VIEW_PID);
  }

  /* 项目列表加载器：真实实现在 bindTopbar() 内（依赖其局部状态），
     init() 恢复会话时也要调用，故提升为模块级引用；真实实现加载后覆盖此占位。 */
  let loadProjList = async () => {};

  /* 把某历史项目载入工作台（真实实现在 bindTopbar() 内，扫描历史详情页要调用） */
  let openProjectRef = async () => {};

  const F = {
    sev: 'all', cat: 'all', scope: 'all', keyword: '',    groupBy: '', sort: 'risk',
    items: [], offset: 0, total: 0, hasMore: false,
    groups: [], openKey: null,
    groupItems: [], groupOffset: 0, groupTotal: 0, groupHasMore: false,
    loading: false,
    reqId: 0,
  };

  /* ------------------------------------------------------------ 工具 */
  const $ = (id) => document.getElementById(id);
  const qsa = (sel, root) => Array.prototype.slice.call((root || document).querySelectorAll(sel));

  function escapeHtml(s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, (c) => (
      { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]
    ));
  }

  function debounce(fn, ms) {
    let t = null;
    return function () {
      const args = arguments;
      clearTimeout(t);
      t = setTimeout(() => fn.apply(null, args), ms);
    };
  }

  function fmtNum(n) {
    return (n == null ? 0 : n).toLocaleString('zh-CN');
  }

  function sevLabel(sev) {
    const m = (S.meta && S.meta.severity_meta) || {};
    return (m[sev] || {}).label || sev;
  }

  function catLabel(cat) {
    const m = (S.meta && S.meta.categories) || {};
    return m[cat] || cat;
  }

  async function api(path, opts) {
    // 容错：fetch 的 body 只接受字符串 / Blob / FormData 等，直接传对象会被转成
    // 字符串 "[object Object]"（且不带 Content-Type），服务端解析不出任何字段。
    // 这里统一把普通对象序列化为 JSON，避免调用方漏写 stringify 造成静默失败。
    let o = opts;
    const b = o && o.body;
    if (b && typeof b === 'object'
        && !(b instanceof FormData) && !(b instanceof Blob)
        && !(b instanceof ArrayBuffer) && !(b instanceof URLSearchParams)
        && !(b instanceof ReadableStream)) {
      o = Object.assign({}, o, {
        headers: Object.assign({ 'Content-Type': 'application/json' }, o.headers || {}),
        body: JSON.stringify(b),
      });
    }
    const res = await fetch(path, o);
    let data;
    try {
      data = await res.json();
    } catch (e) {
      throw new Error('响应解析失败（HTTP ' + res.status + '）');
    }
    if (data.code !== 0) throw new Error(data.message || '请求失败');
    return data.data;
  }

  let toastTimer = null;
  function toast(msg, kind, ms) {
    const t = $('toast');
    t.textContent = msg;
    t.className = 'toast show' + (kind ? ' ' + kind : '');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { t.className = 'toast'; }, ms || 2600);
  }

  function setStatus(text, kind, meta) {
    $('statusText').textContent = text;
    $('statusDot').className = 'status-dot' + (kind ? ' ' + kind : '');
    if (meta !== undefined) $('statusMeta').textContent = meta;
  }

  function copyText(text) {
    const done = () => toast('已复制：' + (text.length > 40 ? text.slice(0, 40) + '…' : text), 'ok', 1800);
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(text).then(done, () => fallback());
    } else fallback();
    function fallback() {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;opacity:0';
      document.body.appendChild(ta);
      ta.select();
      try { document.execCommand('copy'); done(); } catch (e) { toast('复制失败，请手动选择', 'err'); }
      document.body.removeChild(ta);
    }
  }

  /* ============================================================ 扫描 */
  function startScan(opts) {
    if (S.scanning) return;
    opts = opts || {};
    const explicit = (opts.root || '').trim();
    if (!explicit && !S.target) {
      openTarget();
      toast('请先选择待审计的代码目录', 'err');
      return;
    }
    S.scanning = true;
    const btn = $('btnScan');
    btn.disabled = true;
    btn.classList.add('scanning');
    $('btnScanText').textContent = '扫描中…';
    $('progressWrap').classList.add('show');
    $('progressWrap').classList.remove('error');
    setProgress({ phase: 'starting', current: 0, total: 0, file: '' });
    setStatus('正在启动扫描任务…', 'busy');

    const t = S.target || {};
    api('/api/scan', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        root: explicit || undefined,
        label: opts.label || t.name || '',
        kind: opts.kind || t.kind || 'path',
      }),
    }).then((data) => {
      // 每次扫描都会新建独立项目，记录其 ID，之后所有结果请求都指向该项目
      VIEW_PID = (data && data.project_id) || '';
      poll();
    }).catch((e) => {
      toast('扫描启动失败：' + e.message, 'err', 4500);
      setStatus('扫描启动失败', 'err');
      finishScan();
    });
  }

  function setProgress(p) {
    const phaseMap = {
      starting: '初始化', walking: '遍历文件', scanning: '静态扫描',
      done: '扫描完成', error: '扫描出错', idle: '就绪', pending: '待启动',
    };
    $('progPhase').textContent = phaseMap[p.phase] || p.phase || '-';
    $('progFile').textContent = p.file || '';
    $('progCount').textContent = p.total ? (fmtNum(p.current) + ' / ' + fmtNum(p.total)) : '';
    const pct = p.phase === 'done' ? 100 : (p.total ? Math.round((p.current / p.total) * 100) : 4);
    $('progBar').style.width = pct + '%';
    if (p.phase === 'error') $('progressWrap').classList.add('error');
  }

  function poll() {
    api('/api/progress').then((p) => {
      setProgress(p);
      if (p.phase === 'scanning' && p.total) {
        setStatus('正在扫描 ' + fmtNum(p.current) + '/' + fmtNum(p.total) + ' 个文件…', 'busy');
      }
      if (p.done) {
        if (p.phase === 'error') {
          toast('扫描出错：' + (p.error || '未知错误'), 'err', 5200);
          setStatus('扫描中止', 'err');
        }
        finishScan();
        return refreshAll();
      }
      S.pollTimer = setTimeout(poll, 320);
    }).catch(() => { S.pollTimer = setTimeout(poll, 600); });
  }

  function finishScan() {
    S.scanning = false;
    clearTimeout(S.pollTimer);
    const btn = $('btnScan');
    btn.disabled = false;
    btn.classList.remove('scanning');
    $('btnScanText').textContent = '重新扫描';
    setTimeout(() => $('progressWrap').classList.remove('show'), 1600);
  }

  /* ============================================================ 总览刷新 */
  async function refreshAll() {
    try {
      await Promise.all([loadSummary(), loadTree(true)]);
      S.depLoaded = false;
      $('btnDeps').disabled = false;
      $('btnExport').disabled = false;
      await loadFindings(true);
      renderBoard();
      if (isNarrow()) setPane('findings');   // 窄屏：扫描完成直接展示结果
      const s = S.summary || {};
      setStatus('扫描完成', 'ok',
        fmtNum(s.files_total) + ' 个文件 · ' + fmtNum(s.lines_total) + ' 行 · ' +
        fmtNum(s.total) + ' 项风险 · 耗时 ' + s.elapsed + 's');
      toast('扫描完成，共发现 ' + fmtNum(s.total) + ' 项风险', 'ok', 3200);
      // 规则扫描结束即开始依赖漏洞分析：分析在服务端独立线程中跑，这里轮询它的进度
      $('kpiVulns').textContent = '…';
      startVulnPoll();
    } catch (e) {
      toast('加载结果失败：' + e.message, 'err', 4500);
    }
  }

  async function loadSummary() {
    const data = await api(withProj('/api/result?limit=1'));
    S.summary = data.summary;
    renderKpis();
  }

  function renderKpis() {
    const s = S.summary;
    if (!s) return;

    // 风险指数环
    const idx = s.risk_index || 0;
    $('kpiRisk').textContent = idx;
    const ring = $('ringFg');
    ring.style.stroke = idx >= 60 ? SEV_COLOR.high
      : idx >= 40 ? SEV_COLOR.medium
        : idx >= 20 ? '#2563eb' : '#0f9d58';
    ring.style.strokeDashoffset = String(RING_C * (1 - Math.min(100, idx) / 100));

    let verdict, note;
    if (!s.total) { verdict = '未命中风险项'; note = '当前规则集未在代码库中发现可疑模式'; }
    else if (idx < 15) { verdict = '风险很低'; note = '命中项以低危为主，建议例行修复'; }
    else if (idx < 30) { verdict = '风险较低'; note = '存在少量中危项，纳入迭代计划整改'; }
    else if (idx < 50) { verdict = '风险中等'; note = '建议优先处理严重与高危项'; }
    else if (idx < 70) { verdict = '风险偏高'; note = '存在较多高危命中，需尽快安排整改'; }
    else { verdict = '风险很高'; note = '建议立即处置严重与高危项并复扫验证'; }
    $('riskVerdict').textContent = verdict;
    $('riskNote').textContent = note + '　·　加权风险分 ' + (s.severity_weight || 0);

    // 分级卡片
    const maxSev = Math.max(1, ...SEV_ORDER.map((k) => s.by_severity[k] || 0));
    SEV_ORDER.forEach((k) => {
      const el = $('kpi-' + k);
      if (el) el.textContent = fmtNum(s.by_severity[k] || 0);
      const card = document.querySelector('.sev-card[data-sev="' + k + '"]');
      if (card) card.querySelector('.bar').style.width =
        ((s.by_severity[k] || 0) / maxSev * 100) + '%';
    });

    $('kpiFiles').textContent = fmtNum(s.files_total);
    $('kpiLines').textContent = fmtNum(s.lines_total);
    $('kpiHitFiles').textContent = fmtNum(s.files_with_findings);
    $('kpiSuppressed').textContent = fmtNum(s.suppressed);
    $('fileCount').textContent = fmtNum(s.files_total) + ' 个文件';
    syncSevCards();
  }

  function syncSevCards() {
    qsa('.sev-card').forEach((c) => c.classList.toggle('on', c.dataset.sev === F.sev));
  }

  /* ============================================================ 审计目录树
     交互约定
       · 单击目录行（含箭头与名称）  → 下拉展开 / 收起该目录
       · 双击目录行                  → 递归展开整棵子树（已全展开时递归收起）
       · 单击文件行                  → 打开源码（配合「自动定位」展开并高亮）
       · 悬停行 / 箭头               → 高亮反馈，title 提示完整路径与操作方式
       · 键盘 ↑ ↓ 移动，→ 展开或进入子项，← 收起或退回父目录，
              Enter / Space 激活，Home / End 首末，Esc 取消焦点
     层级可辨
       · 每级缩进 15px，并在父级箭头正下方绘制竖向引导线 + 横向连接短线
       · 目录名深色加粗、文件名浅色 + 语言色图标，二者视觉可区分
       · 当前打开文件的整条祖先路径点亮（.onpath），一眼看出所处层级
     性能
       · 折叠状态的目录不生成子节点 DOM（惰性渲染），首屏节点由 2500+ 降至百级
       · 展开动画使用 grid-template-rows 0fr↔1fr 过渡，无 JS 布局抖动
     ============================================================ */
  const TREE_LS_KEY = 'audit-tree-state';
  const TREE_STAGGER_CAP = 8;       // 入场错峰动画的最大序号
  const TREE_JUSTOPEN_MS = 620;     // justopen 标记存活时长（≈ 动画总时长）
  const TREE_CLICK_DELAY = 160;     // 单击延迟，用于区分单击与双击

  const reduceMotion = (() => {
    try { return !!window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches; }
    catch (e) { return false; }
  })();

  let treePersistTimer = null;
  let treeClickTimer = null;

  function fmtSize(bytes) {
    const n = Number(bytes) || 0;
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(n < 10240 ? 1 : 0) + ' KB';
    return (n / 1048576).toFixed(1) + ' MB';
  }

  async function loadTree(refresh) {
    S.tree = await api(withProj('/api/tree' + (refresh ? '?refresh=1' : '')));
    indexTree();
    restoreTreeState();
    renderTree();
  }

  function indexTree() {
    const files = {}, dirs = {};
    const walk = (n) => {
      if (n.type === 'dir') dirs[n.path] = n; else files[n.path] = n;
      (n.children || []).forEach(walk);
    };
    walk(S.tree);
    S.fileIndex = files;
    S.dirIndex = dirs;
  }

  /* ---------------------------------------------- 展开状态（含持久化） */
  function treeStateKey() {
    return 'v1:' + ((S.meta && S.meta.root) || '');
  }

  function restoreTreeState() {
    let saved = null;
    try { saved = JSON.parse(localStorage.getItem(TREE_LS_KEY) || 'null'); } catch (e) { saved = null; }
    if (saved && saved.key === treeStateKey() && Array.isArray(saved.collapsed)) {
      S.collapsed = new Set(saved.collapsed);
      const sel = $('treeDepth');
      const v = saved.depth == null ? null : String(saved.depth);
      if (v && Array.prototype.some.call(sel.options, (o) => o.value === v)) sel.value = v;
      return;
    }
    S.collapsed = new Set();
    applyDepth(treeDepthValue(), false);   // 首次访问：按「展开层级」预设折叠
  }

  function persistTreeState() {
    clearTimeout(treePersistTimer);
    treePersistTimer = setTimeout(() => {
      try {
        localStorage.setItem(TREE_LS_KEY, JSON.stringify({
          key: treeStateKey(),
          depth: treeDepthValue(),
          collapsed: Array.from(S.collapsed),
        }));
      } catch (e) { /* 隐私模式等存储不可用时静默忽略 */ }
    }, 400);
  }

  function treeDepthValue() {
    const v = $('treeDepth').value;
    return v === 'all' ? 'all' : Number(v);
  }

  /** 展开到第 depth 层：depth=0 全部折叠，'all' 全部展开 */
  function applyDepth(depth, doRender) {
    S.collapsed = new Set();
    if (depth !== 'all') {
      const walk = (n, lv) => {
        if (n.type !== 'dir') return;
        if (lv >= depth && n.path) S.collapsed.add(n.path);
        (n.children || []).forEach((c) => walk(c, lv + 1));
      };
      walk(S.tree, 0);
    }
    if (doRender) { renderTree(); persistTreeState(); }
  }

  /* ---------------------------------------------------------- 渲染 */
  function renderTree() {
    const host = $('tree');
    if (!S.tree) { host.innerHTML = '<div class="empty">暂无数据</div>'; return; }
    const kw = ($('fileSearch').value || '').trim().toLowerCase();
    const onlyIssues = $('onlyIssues').checked;
    const filtering = !!kw || onlyIssues;

    const nodes = S.tree.children || [];
    const shown = filtering ? pruneNodes(nodes, kw, onlyIssues) : nodes;
    const body = shown.length
      ? renderNodes(shown, 1, filtering, kw)
      : '<div class="empty">' + (filtering
        ? '没有匹配的文件<br>试试减少筛选条件或清空搜索词'
        : '当前目录下没有可审计的源码文件') + '</div>';

    host.innerHTML = rootBarHtml() + body;
    if (filtering) host.dataset.filtering = '1'; else delete host.dataset.filtering;
  }

  function rootBarHtml() {
    const r = S.tree;
    return '<div class="tree-root" title="审计根目录：' + escapeHtml(r.name) + '">' +
      '<span class="ico">⌸</span><b>' + escapeHtml(r.name) + '</b>' +
      '<span>' + fmtNum(r.files || 0) + ' 文件 · ' + fmtNum(r.dirs || 0) + ' 目录</span></div>';
  }

  /** 过滤：目录自身命中时保留整棵子树，否则只保留命中后代 */
  function pruneNodes(nodes, kw, onlyIssues) {
    const out = [];
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      if (n.type === 'file') {
        if (onlyIssues && !n.issues) continue;
        if (kw && n.path.toLowerCase().indexOf(kw) < 0) continue;
        out.push(n);
      } else {
        const selfHit = !!kw && n.path.toLowerCase().indexOf(kw) >= 0;
        const kids = pruneNodes(n.children || [], selfHit ? '' : kw, onlyIssues);
        if (!kids.length) continue;
        if (onlyIssues && !n.issues) continue;
        out.push({ name: n.name, path: n.path, type: 'dir', lang: n.lang,
                   size: 0, issues: n.issues, worst: n.worst,
                   files: n.files, dirs: n.dirs, children: kids });
      }
    }
    return out;
  }

  function renderNodes(nodes, lv, forceOpen, kw) {
    let out = '';
    for (let i = 0; i < nodes.length; i++) {
      const n = nodes[i];
      const style = ' style="--lv:' + lv + ';--i:' + Math.min(i, TREE_STAGGER_CAP) + '"';
      if (n.type === 'dir') {
        const open = forceOpen ? true : !S.collapsed.has(n.path);
        out += '<div class="tnode' + (open ? ' open' : '') + '" data-type="dir" data-path="' +
          escapeHtml(n.path) + '" data-lv="' + lv + '"' + style + '>' +
          dirRowHtml(n, open, kw) +
          '<div class="tchildren"><div class="tinner"' + (open ? ' data-loaded="1"' : '') + '>' +
          (open ? renderNodes(n.children || [], lv + 1, forceOpen, kw) : '') +
          '</div></div></div>';
      } else {
        out += '<div class="tnode" data-type="file" data-path="' + escapeHtml(n.path) +
          '" data-lv="' + lv + '"' + style + '>' + fileRowHtml(n, kw) + '</div>';
      }
    }
    return out;
  }

  function dirRowHtml(n, open, kw) {
    const tip = escapeHtml(n.path) + '\n单击：展开 / 收起　双击：展开整棵子树\n' +
      '子树含 ' + fmtNum(n.files) + ' 个文件 · ' + fmtNum(n.dirs) + ' 个子目录';
    return '<div class="trow" data-dir="1" role="treeitem" tabindex="-1" aria-expanded="' +
      (open ? 'true' : 'false') + '" title="' + tip + '">' +
      '<span class="tchev"></span>' +
      '<span class="tname">' + hlText(n.name, kw) + '</span>' +
      '<span class="tinfo">' + fmtNum(n.files) + ' 文件</span>' +
      (n.issues ? badge(n.issues, n.worst) : '') + '</div>';
  }

  function fileRowHtml(n, kw) {
    return '<div class="trow lang-' + escapeHtml(n.lang || '') + '" data-file="' +
      escapeHtml(n.path) + '" role="treeitem" tabindex="-1" title="' +
      escapeHtml(n.path) + '\n单击：打开源码">' +
      '<span class="tchev"></span>' +
      '<span class="tico">' + iconFor(n.lang) + '</span>' +
      '<span class="tname">' + hlText(n.name, kw) + '</span>' +
      '<span class="tinfo">' + fmtSize(n.size) + '</span>' +
      (n.issues ? badge(n.issues, n.worst) : '') + '</div>';
  }

  /** 命中关键词高亮（仅用于文件树内搜索） */
  function hlText(text, kw) {
    const s = String(text == null ? '' : text);
    if (!kw) return escapeHtml(s);
    const i = s.toLowerCase().indexOf(kw);
    if (i < 0) return escapeHtml(s);
    return escapeHtml(s.slice(0, i)) + '<mark>' + escapeHtml(s.slice(i, i + kw.length)) +
      '</mark>' + escapeHtml(s.slice(i + kw.length));
  }

  function badge(count, worst) {
    const color = SEV_COLOR[worst] || SEV_COLOR.info;
    return '<span class="dot" style="background:' + color + '"></span>' +
      '<span class="tcnt" style="background:' + color + '">' + count + '</span>';
  }

  function iconFor(lang) {
    const m = {
      go: '◆', yaml: '≡', yml: '≡', dockerfile: '▣', terraform: '⬢',
      javascript: '⬡', typescript: '⬡', python: '◈', shell: '❯',
      json: '{}', rego: '⬟', java: '☕', markdown: '≣', sql: '⛁', ruby: '◉',
    };
    return m[lang] || '·';
  }

  /* --------------------------------------------------- 展开 / 收起 */
  /** 惰性渲染：目录首次展开时才生成子节点 DOM */
  function ensureChildren(el) {
    const inner = el.querySelector(':scope > .tchildren > .tinner');
    if (!inner || inner.dataset.loaded === '1') return inner;
    const node = S.dirIndex[el.dataset.path];
    const lv = (parseInt(el.dataset.lv, 10) || 1) + 1;
    inner.innerHTML = (node && node.children && node.children.length)
      ? renderNodes(node.children, lv, false, '') : '';
    inner.dataset.loaded = '1';
    return inner;
  }

  function setOpen(el, open, animate) {
    if (!el || el.classList.contains('open') === open) return;
    if (open) {
      ensureChildren(el);
      el.classList.add('open');
      if (animate !== false && !reduceMotion) {
        el.classList.add('justopen');
        setTimeout(() => el.classList.remove('justopen'), TREE_JUSTOPEN_MS);
      }
      if (el.dataset.path) S.collapsed.delete(el.dataset.path);
    } else {
      el.classList.remove('open');
      if (el.dataset.path) S.collapsed.add(el.dataset.path);
    }
    const row = el.querySelector(':scope > .trow');
    if (row) row.setAttribute('aria-expanded', open ? 'true' : 'false');
  }

  function setSubtreeOpen(el, open) {
    const walk = (n) => {
      if (n.dataset.type !== 'dir') return;
      if (open) ensureChildren(n);
      n.classList.toggle('open', open);
      const p = n.dataset.path;
      if (p) { if (open) S.collapsed.delete(p); else S.collapsed.add(p); }
      const row = n.querySelector(':scope > .trow');
      if (row) row.setAttribute('aria-expanded', open ? 'true' : 'false');
      qsa(':scope > .tchildren > .tinner > .tnode', n).forEach(walk);
    };
    walk(el);
    if (open && !reduceMotion) {
      el.classList.add('justopen');
      setTimeout(() => el.classList.remove('justopen'), TREE_JUSTOPEN_MS);
    }
  }

  function parentDirNode(node) {
    const inner = node && node.parentElement;
    const wrap = inner && inner.parentElement;
    const parent = wrap && wrap.parentElement;
    return parent && parent.classList && parent.classList.contains('tnode') ? parent : null;
  }

  function expandToFile(path) {
    const parts = String(path || '').split('/');
    if (parts.length < 2) return;
    let acc = '';
    for (let i = 0; i < parts.length - 1; i++) {
      acc = acc ? acc + '/' + parts[i] : parts[i];
      S.collapsed.delete(acc);
      const el = document.querySelector('.tnode[data-path="' + CSS.escape(acc) + '"]');
      if (!el) break;              // 尚未渲染（更上层未展开）→ 停止下钻
      setOpen(el, true, false);    // 逐级展开，展开时惰性渲染下一层
    }
  }

  /** 统计目录节点总数（用于「展开全部」时给出规模提示） */
  function countDirs(nodes) {
    let count = 0;
    const walk = (n) => {
      if (n.type !== 'dir') return;
      count++;
      (n.children || []).forEach(walk);
    };
    nodes.forEach(walk);
    return count;
  }

  function setAllCollapsed(collapsed) {
    if (!S.tree) return;
    const walk = (n) => {
      if (n.type !== 'dir') return;
      if (n.path) { if (collapsed) S.collapsed.add(n.path); else S.collapsed.delete(n.path); }
      (n.children || []).forEach(walk);
    };
    (S.tree.children || []).forEach(walk);
    renderTree();
    persistTreeState();
    if (collapsed) toast('已折叠全部目录，仅保留顶层');
    else toast('已展开全部目录（' + fmtNum(countDirs(S.tree.children || [])) + ' 个目录节点）');
  }

  /* ---------------------------------------------------- 选中与定位 */
  function markActiveFile(path) {
    qsa('.trow.active').forEach((e) => e.classList.remove('active'));
    qsa('.tnode.onpath').forEach((e) => e.classList.remove('onpath'));
    const el = document.querySelector('.trow[data-file="' + CSS.escape(path) + '"]');
    if (!el) return;
    el.classList.add('active');
    // 点亮整条祖先路径，便于辨认该文件所处的层级
    let p = parentDirNode(el.parentElement);
    while (p) { p.classList.add('onpath'); p = parentDirNode(p); }
    // 用视口坐标换算滚动位置：嵌套的定位容器会让 offsetTop 失真
    const box = $('tree');
    const rb = el.getBoundingClientRect();
    const bb = box.getBoundingClientRect();
    const relTop = rb.top - bb.top;
    const h = box.clientHeight;
    if (relTop < 0 || relTop > h - 34) {
      box.scrollTop += relTop - h / 2 + rb.height / 2;
    }
  }

  /* ---------------------------------------------------- 键盘导航 */
  /** 折叠目录的子节点仍保留在 DOM 中（便于瞬时重开），导航时必须排除 */
  function isRowVisible(el) {
    if (!el) return false;
    if (typeof el.checkVisibility === 'function') {
      return el.checkVisibility({ visibilityProperty: true, opacityProperty: false,
                                  contentVisibilityAuto: false });
    }
    return getComputedStyle(el).visibility !== 'hidden';
  }

  function visibleRows() { return qsa('.trow', $('tree')).filter(isRowVisible); }

  function focusRow(row) {
    if (!row) return;
    qsa('.trow.kfocus', $('tree')).forEach((r) => r.classList.remove('kfocus'));
    row.classList.add('kfocus');
    try { row.focus({ preventScroll: true }); } catch (e) { row.focus(); }
    row.scrollIntoView({ block: 'nearest' });
  }

  function onTreeKey(e) {
    const rows = visibleRows();
    if (!rows.length) return;
    const idx = rows.findIndex((r) => r.classList.contains('kfocus'));
    const cur = idx >= 0 ? rows[idx] : null;
    const isDir = (r) => !!r && r.dataset.dir !== undefined;

    switch (e.key) {
      case 'ArrowDown':
        e.preventDefault();
        focusRow(rows[Math.min(rows.length - 1, idx + 1)]);
        break;
      case 'ArrowUp':
        e.preventDefault();
        focusRow(rows[Math.max(0, idx - 1)]);
        break;
      case 'ArrowRight': {
        e.preventDefault();
        if (!cur) { focusRow(rows[0]); break; }
        const node = cur.parentElement;
        if (isDir(cur) && !node.classList.contains('open')) {
          setOpen(node, true); persistTreeState();
        } else if (rows[idx + 1]) {
          focusRow(rows[idx + 1]);            // 进入第一个子项
        }
        break;
      }
      case 'ArrowLeft': {
        e.preventDefault();
        if (!cur) break;
        const node = cur.parentElement;
        if (isDir(cur) && node.classList.contains('open')) {
          setOpen(node, false); persistTreeState();
        } else {
          const up = parentDirNode(node);
          if (up) focusRow(up.querySelector(':scope > .trow'));
        }
        break;
      }
      case 'Enter':
      case ' ': {
        e.preventDefault();
        if (!cur) { focusRow(rows[0]); break; }
        if (cur.dataset.file !== undefined) openFile(cur.dataset.file);
        else { const node = cur.parentElement; setOpen(node, !node.classList.contains('open')); persistTreeState(); }
        break;
      }
      case 'Home': e.preventDefault(); focusRow(rows[0]); break;
      case 'End': e.preventDefault(); focusRow(rows[rows.length - 1]); break;
      case 'Escape': qsa('.trow.kfocus').forEach((r) => r.classList.remove('kfocus')); break;
      default: break;
    }
  }

  /* ---------------------------------------------------- 事件绑定 */
  function bindTree() {
    const host = $('tree');

    // 单击：目录 → 展开 / 收起；文件 → 打开源码
    // 延迟 160ms 执行，使双击（展开整棵子树）不会产生两次切换的闪烁
    host.addEventListener('click', (e) => {
      const row = e.target.closest('.trow');
      if (!row) return;
      qsa('.trow.kfocus', host).forEach((r) => r.classList.remove('kfocus'));
      if (row.dataset.file !== undefined) { openFile(row.dataset.file); return; }
      clearTimeout(treeClickTimer);
      treeClickTimer = setTimeout(() => {
        const node = row.parentElement;
        if (!node || node.dataset.type !== 'dir') return;
        setOpen(node, !node.classList.contains('open'));
        persistTreeState();
      }, TREE_CLICK_DELAY);
    });

    // 双击目录：递归展开整棵子树；已完全展开时递归收起
    host.addEventListener('dblclick', (e) => {
      const row = e.target.closest('.trow');
      if (!row || row.dataset.file !== undefined) return;
      clearTimeout(treeClickTimer);          // 取消单击的展开/收起，避免二次切换闪烁
      const node = row.parentElement;
      if (!node) return;
      const open = node.classList.contains('open');
      const anyClosed = !!node.querySelector('.tnode[data-type="dir"]:not(.open)');
      const target = !open || anyClosed;     // 未展开 / 仍有折叠后代 → 展开全部
      setSubtreeOpen(node, target);
      persistTreeState();
      const name = node.dataset.path.split('/').pop();
      toast(target ? '已展开「' + name + '」整棵子树' : '已收起「' + name + '」下的子目录');
    });

    host.addEventListener('keydown', onTreeKey);

    // 展开层级预设
    $('treeDepth').addEventListener('change', (e) => {
      if (!S.tree) { e.target.value = '2'; return; }
      const v = e.target.value;
      applyDepth(v === 'all' ? 'all' : Number(v), true);
      toast('目录树：' + e.target.options[e.target.selectedIndex].textContent);
    });
  }

  /* ============================================================ 源码检视 */
  const KW = {
    go: ['package', 'import', 'func', 'var', 'const', 'type', 'struct', 'interface', 'map', 'chan',
      'go', 'defer', 'select', 'range', 'return', 'if', 'else', 'for', 'switch', 'case', 'default',
      'break', 'continue', 'fallthrough', 'goto', 'nil', 'true', 'false', 'string', 'int', 'int64',
      'int32', 'uint', 'uint64', 'byte', 'rune', 'bool', 'float64', 'float32', 'error', 'make',
      'new', 'len', 'cap', 'append', 'copy', 'delete', 'panic', 'recover'],
    python: ['def', 'class', 'import', 'from', 'as', 'return', 'if', 'elif', 'else', 'for', 'while',
      'try', 'except', 'finally', 'with', 'lambda', 'yield', 'global', 'nonlocal', 'pass', 'break',
      'continue', 'raise', 'assert', 'del', 'in', 'is', 'not', 'and', 'or', 'None', 'True', 'False',
      'self', 'async', 'await'],
    javascript: ['function', 'var', 'let', 'const', 'return', 'if', 'else', 'for', 'while', 'do',
      'switch', 'case', 'default', 'break', 'continue', 'new', 'this', 'class', 'extends', 'super',
      'try', 'catch', 'finally', 'throw', 'typeof', 'instanceof', 'in', 'of', 'async', 'await',
      'yield', 'import', 'export', 'from', 'null', 'undefined', 'true', 'false', 'delete', 'void'],
    typescript: ['function', 'var', 'let', 'const', 'return', 'if', 'else', 'for', 'while', 'switch',
      'interface', 'type', 'enum', 'class', 'extends', 'implements', 'public', 'private', 'protected',
      'readonly', 'async', 'await', 'import', 'export', 'from', 'new', 'this', 'null', 'undefined'],
    java: ['package', 'import', 'public', 'private', 'protected', 'class', 'interface', 'enum',
      'extends', 'implements', 'static', 'final', 'void', 'new', 'return', 'if', 'else', 'for',
      'while', 'do', 'switch', 'case', 'default', 'break', 'continue', 'try', 'catch', 'finally',
      'throw', 'throws', 'this', 'super', 'null', 'true', 'false', 'String', 'abstract',
      'synchronized', 'volatile', 'instanceof'],
    shell: ['if', 'then', 'else', 'elif', 'fi', 'for', 'while', 'do', 'done', 'case', 'esac',
      'function', 'return', 'export', 'local', 'echo', 'exit', 'set', 'unset', 'source'],
  };
  const HASH_COMMENT = new Set(['python', 'shell', 'yaml', 'yml', 'ruby', 'toml',
    'dockerfile', 'rego', 'text', 'json']);

  function highlightLine(line, lang) {
    const kw = KW[lang] || KW.javascript;
    const hash = HASH_COMMENT.has(lang);
    const re = hash
      ? /("(?:\\.|[^"\\])*"?|'(?:\\.|[^'\\])*'?|`[^`]*`?)|(#.*)|(\b\d+(?:\.\d+)?\b)|(\b[A-Za-z_]\w*\b)|(\s+)|([\s\S])/g
      : /("(?:\\.|[^"\\])*"?|'(?:\\.|[^'\\])*'?|`[^`]*`?)|(\/\/.*|\/\*[\s\S]*?\*\/)|(\b\d+(?:\.\d+)?\b)|(\b[A-Za-z_]\w*\b)|(\s+)|([\s\S])/g;
    let out = '', m;
    while ((m = re.exec(line)) !== null) {
      if (m[1]) out += '<span class="tk-str">' + escapeHtml(m[1]) + '</span>';
      else if (m[2]) out += '<span class="tk-com">' + escapeHtml(m[2]) + '</span>';
      else if (m[3]) out += '<span class="tk-num">' + escapeHtml(m[3]) + '</span>';
      else if (m[4]) {
        const w = m[4];
        if (kw.indexOf(w) >= 0) out += '<span class="tk-kw">' + escapeHtml(w) + '</span>';
        else if (line.charAt(re.lastIndex) === '(') out += '<span class="tk-fn">' + escapeHtml(w) + '</span>';
        else out += escapeHtml(w);
      } else out += escapeHtml(m[0]);
    }
    return out;
  }

  async function openFile(path, focusLine) {
    if (!path) return;
    if ($('autoExpand').checked) expandToFile(path);
    markActiveFile(path);
    S.currentFile = path;

    const viewer = $('viewer');
    $('viewMeta').textContent = '加载中…';
    $('btnCopyPath').disabled = true;
    viewer.innerHTML = '<div class="empty">加载中…</div>';

    let data;
    try {
      data = await api(withProj('/api/file?path=' + encodeURIComponent(path)));
    } catch (e) {
      viewer.innerHTML = '<div class="empty">' + escapeHtml(e.message) + '</div>';
      $('viewMeta').textContent = '';
      return;
    }
    if (S.currentFile !== path) return;   // 竞态保护
    if (isNarrow()) setPane('center');    // 窄屏：自动切到源码分栏

    S.currentFindings = (data.findings || []).slice().sort((a, b) => a.line - b.line);
    S.hitCursor = -1;
    const hitMap = {};
    S.currentFindings.forEach((f) => { hitMap[f.line] = f; });

    let lines = data.content.split('\n');
    let notice = '';
    if (lines.length > RENDER_MAX) {
      notice = '文件共 ' + fmtNum(lines.length) + ' 行，已截断渲染前 ' +
        fmtNum(RENDER_MAX) + ' 行以保证流畅度。';
      lines = lines.slice(0, RENDER_MAX);
    }
    const doHighlight = lines.length <= HIGHLIGHT_MAX;
    if (!doHighlight) {
      notice += (notice ? ' ' : '') + '文件较大（' + fmtNum(lines.length) +
        ' 行），已关闭语法高亮以提升滚动性能。';
    }

    const buf = [];
    for (let i = 0; i < lines.length; i++) {
      const ln = i + 1;
      const f = hitMap[ln];
      const txt = lines[i] === '' ? '&nbsp;' : (doHighlight ? highlightLine(lines[i], data.lang) : escapeHtml(lines[i]));
      buf.push('<div class="cl' + (f ? ' hit' : '') + '" id="L' + ln + '"' +
        (f ? ' data-fid="' + escapeHtml(f.id) + '"' : '') + '>' +
        '<span class="lno">' + ln + '</span><span class="ct">' + txt + '</span></div>');
    }
    viewer.innerHTML = (notice ? '<div class="notice">' + notice + '</div>' : '') +
      '<div class="code-table">' + buf.join('') + '</div>';

    $('viewPath').textContent = path;
    $('viewMeta').textContent = fmtNum(data.lines) + ' 行 · ' +
      (data.size / 1024).toFixed(1) + ' KB · ' + (data.encoding || 'utf-8') +
      (S.currentFindings.length ? ' · ' + S.currentFindings.length + ' 处风险' : ' · 无风险命中');
    $('btnCopyPath').disabled = false;
    $('btnPrevHit').disabled = S.currentFindings.length < 1;
    $('btnNextHit').disabled = S.currentFindings.length < 1;

    if (focusLine) {
      jumpTo(focusLine);
      const i = S.currentFindings.findIndex((f) => f.line === focusLine);
      S.hitCursor = i;
    } else {
      viewer.scrollTop = 0;
    }
  }

  function jumpTo(line) {
    const el = $('viewer').querySelector('#L' + line);
    if (!el) return;
    // 远距离瞬时定位、近距离平滑滚动：兼顾「精准到达」与「不迷失上下文」
    const box = $('viewer');
    const top = el.offsetTop;
    const far = Math.abs(top - box.scrollTop) > box.clientHeight * 1.5;
    el.scrollIntoView({ block: 'center', behavior: far ? 'auto' : 'smooth' });
    el.classList.remove('flash');
    void el.offsetWidth;
    el.classList.add('flash');
  }

  function stepHit(delta) {
    const list = S.currentFindings;
    if (!list.length) return;
    S.hitCursor = (S.hitCursor + delta + list.length) % list.length;
    const f = list[S.hitCursor];
    jumpTo(f.line);
    toast('第 ' + (S.hitCursor + 1) + '/' + list.length + ' 处：' +
      f.severity_label + ' · ' + f.rule_id, 'ok', 1600);
  }

  /* ============================================================ 安全看板 */
  function renderBoard() {
    const s = S.summary;
    const host = $('board');
    if (!s) return;
    if (!s.total) {
      host.innerHTML = '<div class="empty">未命中风险项，无需整改项</div>';
      return;
    }
    const total = s.total;
    const C = 2 * Math.PI * 55;

    // --- 环形图 ---
    let acc = 0;
    const arcs = SEV_ORDER.map((k) => {
      const v = s.by_severity[k] || 0;
      if (!v) return '';
      const len = v / total * C;
      const seg = '<circle cx="66" cy="66" r="55" stroke="' + SEV_COLOR[k] +
        '" stroke-dasharray="' + len.toFixed(2) + ' ' + (C - len).toFixed(2) +
        '" stroke-dashoffset="' + (-acc).toFixed(2) + '"></circle>';
      acc += len;
      return seg;
    }).join('');

    const legend = SEV_ORDER.map((k) => {
      const v = s.by_severity[k] || 0;
      return '<div class="legend-row" data-sev="' + k + '">' +
        '<i style="background:' + SEV_COLOR[k] + '"></i>' + sevLabel(k) +
        '<b>' + fmtNum(v) + '</b>' +
        '<span class="pct">' + (v / total * 100).toFixed(1) + '%</span></div>';
    }).join('');

    // --- 类型分布 ---
    const cats = Object.keys(s.by_category)
      .map((k) => [k, s.by_category[k]])
      .filter((x) => x[1] > 0)
      .sort((a, b) => b[1] - a[1]);
    const catPeak = cats.length ? cats[0][1] : 1;
    const catBars = cats.map(([k, v]) => barRow(catLabel(k), v, v / catPeak * 100, '#2563eb')).join('');

    // --- 高频规则 TOP ---
    const ruleRanks = (s.top_rules || []).slice(0, 10).map((t, i) =>
      '<div class="rank-row" data-rule="' + escapeHtml(t.rule_id) + '">' +
      '<span class="n">' + (i + 1) + '</span>' +
      '<span class="p"><span class="rid">' + escapeHtml(t.rule_id) + '</span> ' +
      escapeHtml(t.title || t.category_label || '') + '</span>' +
      '<span class="c" style="color:' + (SEV_COLOR[t.severity] || '#333') + '">' +
      fmtNum(t.count) + '</span></div>').join('');

    // --- 热点文件 TOP ---
    const fileRanks = (s.top_files || []).slice(0, 12).map((t, i) =>
      '<div class="rank-row" data-file="' + escapeHtml(t.file) + '" title="' + escapeHtml(t.file) + '">' +
      '<span class="n">' + (i + 1) + '</span>' +
      '<span class="p">' + escapeHtml(t.file) + '</span>' +
      '<span class="c" style="color:' + (SEV_COLOR[t.worst] || '#333') + '">' +
      fmtNum(t.count) + '</span></div>').join('');

    // --- 语言分布 ---
    const langs = Object.keys(s.lang_stat || {}).slice(0, 12);
    const langItems = langs.map((k) =>
      '<div class="kv-item"><b>' + fmtNum(s.lang_stat[k]) + '</b><span>' +
      escapeHtml(S.langName(k)) + '</span></div>').join('');

    // --- 作用域 ---
    const sc = s.by_scope || {};
    const scopeItems = ['production', 'test', 'doc'].map((k) =>
      '<div class="kv-item"><b>' + fmtNum(sc[k] || 0) + '</b><span>' +
      SCOPE_CN[k] + '</span></div>').join('');

    host.innerHTML =
      '<div class="board-grid">' +
      '<div class="card"><h3>风险等级分布<em>共 ' + fmtNum(total) + ' 项</em></h3>' +
      '<div class="donut-wrap">' +
      '<svg class="donut" viewBox="0 0 132 132">' +
      '<circle cx="66" cy="66" r="55" stroke="#eef2f8"></circle>' + arcs + '</svg>' +
      '<div class="donut-legend">' + legend + '</div></div></div>' +

      '<div class="card"><h3>漏洞类型分布<em>共 ' + cats.length + ' 类</em></h3>' +
      '<div class="bar-list">' + (catBars || '<div class="empty">暂无数据</div>') + '</div></div>' +

      '<div class="card"><h3>高频规则 TOP10<em>点击筛选</em></h3>' +
      '<div class="rank-list">' + (ruleRanks || '<div class="empty">暂无数据</div>') + '</div></div>' +

      '<div class="card"><h3>风险热点文件 TOP12<em>点击打开源码</em></h3>' +
      '<div class="rank-list">' + (fileRanks || '<div class="empty">暂无数据</div>') + '</div></div>' +

      '<div class="card"><h3>作用域分布<em>按整改优先级</em></h3>' +
      '<div class="kv-grid">' + scopeItems + '</div>' +
      '<p class="legend-row" style="cursor:default;margin-top:9px;color:#8794a7;font-size:10.5px;' +
      'line-height:1.6;display:block">测试 / 示例代码命中自动下调一级，文档命中降为「提示」，' +
      '均可通过右侧筛选排除。</p></div>' +

      '<div class="card"><h3>代码语言分布<em>按文件数</em></h3>' +
      '<div class="kv-grid">' + (langItems || '<div class="empty">暂无数据</div>') + '</div></div>' +

      '<div class="card span2"><h3>扫描摘要</h3><div class="kv-grid">' +
      '<div class="kv-item"><b>' + fmtNum(s.files_total) + '</b><span>扫描文件数</span></div>' +
      '<div class="kv-item"><b>' + fmtNum(s.lines_total) + '</b><span>代码总行数</span></div>' +
      '<div class="kv-item"><b>' + fmtNum(s.files_with_findings) + '</b><span>命中文件数</span></div>' +
      '<div class="kv-item"><b>' + fmtNum(s.suppressed) + '</b><span>上下文降噪</span></div>' +
      '<div class="kv-item"><b>' + s.elapsed + 's</b><span>引擎耗时</span></div>' +
      '<div class="kv-item"><b>' + fmtNum(s.deps_count) + '</b><span>依赖项</span></div>' +
      '<div class="kv-item"><b>' + fmtNum(S.meta ? S.meta.rule_count : 0) + '</b><span>内置规则</span></div>' +
      '<div class="kv-item"><b>' + escapeHtml((s.scanned_at || '').slice(11)) + '</b><span>扫描时间</span></div>' +
      '</div></div>' +
      '</div>';

    // 图表交互
    qsa('.legend-row[data-sev]', host).forEach((r) => r.addEventListener('click', () => {
      setSevFilter(r.dataset.sev === F.sev ? 'all' : r.dataset.sev);
    }));
    qsa('.rank-row[data-rule]', host).forEach((r) => r.addEventListener('click', () => {
      $('findSearch').value = r.dataset.rule;
      $('findSearchClear').hidden = false;
      F.keyword = r.dataset.rule.toLowerCase();
      switchTab('findings');
      loadFindings(true);
    }));
    qsa('.rank-row[data-file]', host).forEach((r) => r.addEventListener('click', () => {
      switchTab('code');
      openFile(r.dataset.file);
    }));
    // 动画：条形宽度延迟应用
    requestAnimationFrame(() => qsa('.bar-row .fill', host).forEach((el) => {
      el.style.width = el.dataset.w + '%';
    }));
  }

  function barRow(label, value, pct, color) {
    return '<div class="bar-row"><span class="lab" title="' + escapeHtml(label) + '">' +
      escapeHtml(label) + '</span><span class="track">' +
      '<span class="fill" data-w="' + pct.toFixed(1) + '" style="background:' + color + '"></span>' +
      '</span><span class="val">' + fmtNum(value) + '</span></div>';
  }

  S.langName = function (k) {
    const m = {
      go: 'Go', yaml: 'YAML', yml: 'YAML', json: 'JSON', markdown: 'Markdown',
      javascript: 'JavaScript', typescript: 'TypeScript', python: 'Python',
      shell: 'Shell', dockerfile: 'Dockerfile', terraform: 'Terraform',
      rego: 'Rego', java: 'Java', ruby: 'Ruby', sql: 'SQL', text: '纯文本',
    };
    return m[k] || k;
  };

  function switchTab(which) {
    const panes = { code: 'tabCode', board: 'tabBoard', deps: 'tabDeps' };
    if (panes[which]) {
      $('centerTabs').querySelectorAll('button').forEach((b) =>
        b.classList.toggle('on', b.dataset.tab === which));
      Object.keys(panes).forEach((k) => $(panes[k]).classList.toggle('on', k === which));
      S.centerTab = which;
      if (which === 'deps') {
        // 打开标签页即拉一次；若后台仍在分析则启动轮询等待
        loadVulns(true);
        api('/api/vulndb/status').then((st) => {
          paintVulnHeader(st);
          if (st.running) startVulnPoll();
        }).catch(() => {});
      }
      return;
    }
    if (which === 'findings') $('findings').scrollTop = 0;
  }

  /* ============================================================ 审计结果 */
  function filterQuery() {
    return {
      severity: F.sev, category: F.cat, scope: F.scope,
      keyword: F.keyword, sort: F.sort,
    };
  }

  function filterIsActive() {
    return F.sev !== 'all' || F.cat !== 'all' || F.scope !== 'all' || !!F.keyword;
  }

  function renderFilterSummary(total) {
    const parts = [];
    if (F.sev !== 'all') parts.push(sevLabel(F.sev));
    if (F.cat !== 'all') parts.push(catLabel(F.cat));
    if (F.scope !== 'all') parts.push(SCOPE_CN[F.scope] || F.scope);
    if (F.keyword) parts.push('“' + F.keyword + '”');
    $('filterSummary').textContent = filterIsActive()
      ? '筛选后 ' + fmtNum(total) + ' 项（' + parts.join(' · ') + '）'
      : '';
  }

  async function loadFindings(reset) {
    if (reset) {
      F.offset = 0;
      F.items = [];
      F.groups = [];
      F.openKey = null;
      F.groupItems = [];
    }
    F.loading = true;
    const rid = ++F.reqId;
    const findingsHost = $('findings');
    if (reset) findingsHost.innerHTML = '<div class="empty">加载中…</div>';

    try {
      if (F.groupBy) {
        const q = new URLSearchParams(Object.assign(filterQuery(), { group_by: F.groupBy }));
        const data = await api(withProj('/api/result?' + q.toString()));
        if (rid !== F.reqId) return;
        F.groups = data.groups || [];
        F.total = data.total_filtered;
        renderGroups();
      } else {
        const q = new URLSearchParams(Object.assign(filterQuery(), {
          limit: PAGE_SIZE, offset: F.offset,
        }));
        const data = await api(withProj('/api/result?' + q.toString()));
        if (rid !== F.reqId) return;
        F.items = F.items.concat(data.findings || []);
        F.total = data.total_filtered;
        F.hasMore = !!data.has_more;
        renderFlat(reset);
      }
      renderFilterSummary(F.total);
      $('findingCount').textContent = fmtNum(F.total) + ' 项';
      $('mCount').textContent = fmtNum(F.total);
      setStatusMeta();
    } catch (e) {
      if (rid === F.reqId) {
        findingsHost.innerHTML = '<div class="empty">加载失败：' + escapeHtml(e.message) + '</div>';
      }
    } finally {
      if (rid === F.reqId) F.loading = false;
    }
  }

  function setStatusMeta() {
    if (!S.summary) return;
    setStatus(S.scanning ? '正在扫描…' : '扫描完成',
      S.scanning ? 'busy' : 'ok',
      fmtNum(S.summary.files_total) + ' 文件 · ' + fmtNum(S.summary.lines_total) + ' 行 · ' +
      fmtNum(S.summary.total) + ' 项风险 · 风险指数 ' + S.summary.risk_index);
  }

  /* ---- 平铺列表 ---- */
  function renderFlat(reset) {
    const host = $('findings');
    if (!F.items.length) {
      host.innerHTML = '<div class="empty">没有符合当前筛选条件的审计结果' +
        (filterIsActive() ? '<br><br>试试清除筛选条件' : '') + '</div>';
      return;
    }
    if (reset) host.innerHTML = '';
    const moreBtn = $('loadMore');
    if (moreBtn) moreBtn.remove();

    const startIdx = reset ? 0 : host.querySelectorAll('.fcard').length;
    const html = F.items.slice(startIdx).map((f, i) => findingCard(f, startIdx + i)).join('');
    host.insertAdjacentHTML('beforeend', html);

    if (F.hasMore) {
      const btn = document.createElement('button');
      btn.id = 'loadMore';
      btn.className = 'load-more';
      btn.textContent = '加载更多（已显示 ' + F.items.length + ' / ' + F.total + ' 项）';
      btn.addEventListener('click', () => {
        if (F.loading) return;
        F.offset = F.items.length;
        loadFindings(false);
      });
      host.appendChild(btn);
      observeLoadMore(btn);
    } else if (F.items.length > PAGE_SIZE) {
      const div = document.createElement('div');
      div.className = 'empty';
      div.textContent = '已显示全部 ' + F.items.length + ' 项';
      host.appendChild(div);
    }
    bindCards(host);
  }

  function observeLoadMore(btn) {
    if (S.observer) S.observer.disconnect();
    if (!('IntersectionObserver' in window)) return;
    S.observer = new IntersectionObserver((ents) => {
      ents.forEach((en) => {
        if (en.isIntersecting && !F.loading && F.hasMore) {
          S.observer.disconnect();
          F.offset = F.items.length;
          loadFindings(false);
        }
      });
    }, { root: $('findings'), rootMargin: '320px' });
    S.observer.observe(btn);
  }

  /* ---- 分组列表 ---- */
  function renderGroups() {
    const host = $('findings');
    if (!F.groups.length) {
      host.innerHTML = '<div class="empty">没有符合当前筛选条件的审计结果</div>';
      return;
    }
    host.innerHTML = F.groups.map((g) => {
      const open = F.openKey === g.key;
      const mini = SEV_ORDER.map((k) => {
        const v = (g.by_severity || {})[k] || 0;
        return '<i style="background:' + (v ? SEV_COLOR[k] : '#e2e8f0') + '"></i>';
      }).join('');
      const badgeHtml = F.groupBy === 'severity'
        ? '<span class="fbadge" style="background:' + (SEV_COLOR[g.key] || '#6b7280') + '">' +
          escapeHtml(g.label) + '</span>'
        : '<span class="fbadge" style="background:' + (SEV_COLOR[g.worst] || '#6b7280') + '">' +
          (F.groupBy === 'file' ? '文件' : '组') + '</span>';
      return '<div class="group' + (open ? '' : ' collapsed') + '" data-key="' + escapeHtml(g.key) + '">' +
        '<div class="group-head">' +
        '<span class="caret">▼</span>' + badgeHtml +
        '<span class="g-label">' + escapeHtml(g.label) + '</span>' +
        '<span class="g-sub" title="' + escapeHtml(g.sub || '') + '">' + escapeHtml(g.sub || '') + '</span>' +
        '<span class="g-mini" title="等级分布">' + mini + '</span>' +
        '<span class="g-count" style="background:' + (SEV_COLOR[g.worst] || '#6b7280') + '">' +
        fmtNum(g.count) + '</span></div>' +
        '<div class="group-body">' + (open ? '<div class="empty">加载中…</div>' : '') + '</div></div>';
    }).join('');

    qsa('.group-head', host).forEach((h) => {
      h.addEventListener('click', () => toggleGroup(h.parentElement));
    });
    if (F.openKey) loadGroupItems(F.openKey, true);
  }

  function toggleGroup(g) {
    const key = g.dataset.key;
    const body = g.querySelector('.group-body');
    if (g.classList.contains('collapsed')) {
      g.classList.remove('collapsed');
      if (key === F.openKey) return;
      F.openKey = key;
      qsa('.group').forEach((x) => { if (x !== g) x.classList.add('collapsed'); });
      loadGroupItems(key, true);
    } else {
      g.classList.add('collapsed');
      if (F.openKey === key) F.openKey = null;
    }
  }

  async function loadGroupItems(key, reset) {
    if (reset) { F.groupItems = []; F.groupOffset = 0; }
    const g = document.querySelector('.group[data-key="' + CSS.escape(key) + '"]');
    if (!g) return;
    const body = g.querySelector('.group-body');
    const rid = ++F.reqId;
    if (reset) body.innerHTML = '<div class="empty">加载中…</div>';

    const q = new URLSearchParams(Object.assign(filterQuery(), {
      group_by: F.groupBy, group_key: key,
      limit: GROUP_PAGE, offset: F.groupOffset,
    }));
    try {
      const data = await api(withProj('/api/result?' + q.toString()));
      if (rid !== F.reqId) return;
      const items = data.findings || [];
      F.groupItems = F.groupItems.concat(items);
      F.groupTotal = data.total_in_group != null ? data.total_in_group : data.total_filtered;
      F.groupHasMore = !!data.has_more;
      if (reset) body.innerHTML = '';
      const html = items.map((f, i) => findingCard(f, F.groupItems.length - items.length + i)).join('');
      body.insertAdjacentHTML('beforeend', html);
      const old = body.querySelector('.load-more');
      if (old) old.remove();
      if (F.groupHasMore) {
        const btn = document.createElement('button');
        btn.className = 'load-more';
        btn.textContent = '在本组中加载更多（已显示 ' + F.groupItems.length + ' / ' + F.groupTotal + ' 项）';
        btn.addEventListener('click', () => {
          F.groupOffset = F.groupItems.length;
          loadGroupItems(key, false);
        });
        body.appendChild(btn);
      }
      bindCards(body);
    } catch (e) {
      body.innerHTML = '<div class="empty">加载失败：' + escapeHtml(e.message) + '</div>';
    }
  }

  /* ---- 卡片 ---- */
  function findingCard(f, idx) {
    const snip = (f.snippet || []).map((l) =>
      '<div class="cl' + (l.hit ? ' hit' : '') + '"><span class="lno">' + l.n + '</span>' +
      '<span class="ct">' + (escapeHtml(l.text) || '&nbsp;') + '</span></div>').join('');
    return '<div class="fcard sev-' + f.severity + '" data-idx="' + idx + '">' +
      '<div class="fcard-head">' +
      '<span class="fbadge">' + escapeHtml(f.severity_label) + '</span>' +
      '<div class="fcard-mid">' +
      '<div class="fcard-title">' + escapeHtml(f.title) + '</div>' +
      '<div class="fcard-loc" title="' + escapeHtml(f.file) + '">' +
      escapeHtml(f.file) + ':' + f.line + ':' + f.column + '</div>' +
      '</div><span class="fscore" title="风险分">' + f.score + '</span>' +
      '</div>' +
      '<div class="fcard-body">' +
      '<div class="fmeta">' +
      '<span>规则 ' + escapeHtml(f.rule_id) + '</span>' +
      '<span>' + escapeHtml(f.category_label) + '</span>' +
      '<span>' + escapeHtml(f.cwe) + '</span>' +
      '<span>置信度 ' + escapeHtml(f.confidence) + '</span>' +
      '<span>' + escapeHtml(S.langName(f.lang)) + '</span>' +
      (f.scope && f.scope !== 'production'
        ? '<span class="scope-tag">' + (SCOPE_CN[f.scope] || f.scope) + '</span>' : '') +
      '</div>' +
      (f.scope_note ? '<p class="fnote">⚠ ' + escapeHtml(f.scope_note) + '</p>' : '') +
      '<div class="fsnippet">' + snip + '</div>' +
      '<div class="fblock-title">风险说明</div>' +
      '<p class="fblock-text">' + escapeHtml(f.description) + '</p>' +
      '<div class="fblock-title fix">修复建议</div>' +
      '<pre class="fblock-text">' + escapeHtml(f.remediation) + '</pre>' +
      '<div class="factions">' +
      '<button class="fjump" data-file="' + escapeHtml(f.file) + '" data-line="' + f.line + '">' +
      '📍 定位到源码 ' + f.line + ' 行</button>' +
      '<button class="fcopy" data-copy="' + escapeHtml(f.file + ':' + f.line + ':' + f.column) + '">' +
      '复制定位</button>' +
      '</div></div></div>';
  }

  function bindCards(root) {
    qsa('.fcard-head', root).forEach((h) => {
      if (h.dataset.bound) return;
      h.dataset.bound = '1';
      h.addEventListener('click', () => h.parentElement.classList.toggle('open'));
    });
    qsa('.fjump', root).forEach((b) => {
      if (b.dataset.bound) return;
      b.dataset.bound = '1';
      b.addEventListener('click', (ev) => {
        ev.stopPropagation();
        switchTab('code');
        openFile(b.dataset.file, parseInt(b.dataset.line, 10));
      });
    });
    qsa('.fcopy', root).forEach((b) => {
      if (b.dataset.bound) return;
      b.dataset.bound = '1';
      b.addEventListener('click', (ev) => { ev.stopPropagation(); copyText(b.dataset.copy); });
    });
  }

  /* ---- 筛选绑定 ---- */
  function setSevFilter(sev) {
    F.sev = sev;
    qsa('#sevChips button').forEach((b) => b.classList.toggle('on', b.dataset.sev === sev));
    syncSevCards();
    loadFindings(true);
  }

  function bindFilters() {
    $('sevChips').addEventListener('click', (e) => {
      const b = e.target.closest('button');
      if (b) setSevFilter(b.dataset.sev);
    });

    $('sevCards').addEventListener('click', (e) => {
      const c = e.target.closest('.sev-card');
      if (!c) return;
      setSevFilter(F.sev === c.dataset.sev ? 'all' : c.dataset.sev);
    });

    $('catFilter').addEventListener('change', (e) => { F.cat = e.target.value; loadFindings(true); });
    $('groupBy').addEventListener('change', (e) => { F.groupBy = e.target.value; loadFindings(true); });
    $('sortBy').addEventListener('change', (e) => { F.sort = e.target.value; loadFindings(true); });
    $('onlyProd').addEventListener('change', (e) => {
      F.scope = e.target.checked ? 'production' : 'all';
      loadFindings(true);
    });

    const findSearch = $('findSearch');
    findSearch.addEventListener('input', debounce(() => {
      F.keyword = findSearch.value.trim();
      $('findSearchClear').hidden = !findSearch.value;
      loadFindings(true);
    }, 280));
    $('findSearchClear').addEventListener('click', () => {
      findSearch.value = ''; F.keyword = ''; $('findSearchClear').hidden = true; loadFindings(true);
    });

    const fileSearch = $('fileSearch');
    fileSearch.addEventListener('input', debounce(() => {
      $('fileSearchClear').hidden = !fileSearch.value;
      renderTree();
    }, 160));
    $('fileSearchClear').addEventListener('click', () => {
      fileSearch.value = ''; $('fileSearchClear').hidden = true; renderTree();
    });
    $('onlyIssues').addEventListener('change', renderTree);
    $('btnExpandAll').addEventListener('click', () => setAllCollapsed(false));
    $('btnCollapseAll').addEventListener('click', () => setAllCollapsed(true));
    $('btnCollapseAllGroups').addEventListener('click', () => {
      qsa('.group').forEach((g) => g.classList.add('collapsed'));
      F.openKey = null;
    });
  }

  /* ============================================================ 弹窗 */
  function openModal(id) { $(id).classList.add('show'); }
  function closeModals() { qsa('.modal.show').forEach((m) => m.classList.remove('show')); }

  function showRules() {
    const list = (S.meta && S.meta.rules) || [];
    $('ruleCount').textContent = '（共 ' + list.length + ' 条）';
    renderRuleList();
    openModal('modalRules');
  }

  function renderRuleList() {
    const list = (S.meta && S.meta.rules) || [];
    const kw = S.ruleKw;
    const sev = S.ruleSev;
    const filtered = list.filter((r) => {
      if (sev !== 'all' && r.severity !== sev) return false;
      if (!kw) return true;
      const hay = (r.id + r.title + r.cwe + r.category + r.languages.join(' ')).toLowerCase();
      return hay.indexOf(kw) >= 0;
    });
    if (!filtered.length) {
      $('ruleList').innerHTML = '<div class="empty">没有匹配的规则</div>';
      return;
    }
    const byCat = {};
    filtered.forEach((r) => { (byCat[r.category] = byCat[r.category] || []).push(r); });
    let html = '';
    Object.keys(byCat).forEach((cat) => {
      const arr = byCat[cat];
      html += '<div class="cat-head">' + escapeHtml(catLabel(cat)) +
        '（' + arr.length + ' 条）</div>';
      arr.forEach((r) => {
        html += '<div class="rule-item"><h4>' +
          '<span class="rule-tag sev-' + r.severity + '">' + sevLabel(r.severity) + '</span>' +
          escapeHtml(r.title) + '</h4>' +
          '<div class="rule-meta"><span>编号 ' + escapeHtml(r.id) + '</span>' +
          '<span>' + escapeHtml(r.cwe) + '</span>' +
          '<span>适用 ' + escapeHtml((r.languages || []).join(' / ')) + '</span>' +
          '<span>置信度 ' + escapeHtml(r.confidence) + '</span></div>' +
          (r.description ? '<p class="desc">' + escapeHtml(r.description) + '</p>' : '') +
          '</div>';
      });
    });
    $('ruleList').innerHTML = html;
  }

  /* ===================== 关于与反馈（含运行环境诊断） ===================== */
  // 反馈入口的三处挂载点（顶栏按钮 / 窄屏更多菜单 / 状态栏）共用下面的实现：
  // 邮箱取自服务端 /api/meta.feedback，不在此硬编码，换邮箱只需改 core/meta.py。
  let ABOUT_ENV = null;
  let ABOUT_ENV_LOADING = false;

  function feedbackInfo() {
    const f = (S.meta && S.meta.feedback) || {};
    return {
      email: f.email || '',
      title: f.title || '问题反馈与建议',
      prefix: f.subject_prefix || '',
    };
  }

  /** 生成可粘贴的诊断信息：版本 / 系统 / Python / 目录可写性 / 自检结论 */
  function diagText(env) {
    const f = feedbackInfo();
    const m = S.meta || {};
    const e = env || ABOUT_ENV || {};
    const py = e.python || {};
    const sys = e.system || {};
    const enc = e.encoding || {};
    const fe = e.features || {};
    const wr = e.writable || {};
    const L = [];
    L.push('===== ' + (m.tool || '源代码静态审计平台') + ' 问题反馈 =====');
    L.push('工具版本 : v' + (m.version || '?'));
    L.push('操作系统 : ' + (sys.os || '?') + ' ' + (sys.os_release || '')
           + '（' + (sys.machine || '') + '）');
    L.push('Python   : ' + (py.version || '?') + '（' + (py.implementation || '?') + '）'
           + '　要求 ≥ ' + (py.required || '3.9'));
    L.push('解释器   : ' + (py.executable || '?'));
    L.push('工具目录 : ' + ((e.paths || {}).base_dir || '?'));
    L.push('终端编码 : ' + (enc.stdout || '?') + ' / 文件系统 ' + (enc.filesystem || '?'));
    L.push('规则总数 : ' + (fe.rules != null ? fe.rules : (m.rule_count || '?')) + ' 条');
    L.push('依赖漏洞 : ' + (fe.vulndb_enabled
      ? (fe.vulndb_offline ? '已启用（离线只读缓存）' : '已启用（在线 OSV.dev）')
      : '未启用') + ' · ' + (fe.network ? '可联网' : '不可联网'));
    L.push('目录可写 : ' + (wr.all ? '是' : '否（' + Object.keys(wr)
      .filter(function (k) { return k !== 'all' && !wr[k]; }).join('、') + '）'));
    L.push('环境自检 : ' + (((e.summary || {}).verdict) || '未执行'));
    L.push('');
    L.push('问题描述：（请描述现象，例如：扫描某目录后，规则 XXX 对文件 YYY 报了 ZZZ，实际不成立）');
    L.push('复现步骤：');
    L.push('  1. ');
    L.push('  2. ');
    L.push('');
    L.push('（反馈邮箱：' + f.email + '）');
    return L.join('\n');
  }

  async function loadAboutEnv(force) {
    if (ABOUT_ENV && !force) return ABOUT_ENV;
    if (ABOUT_ENV_LOADING) return ABOUT_ENV;
    ABOUT_ENV_LOADING = true;
    try {
      // net=1：顺带探测能否访问 OSV.dev，结果仅供诊断展示
      ABOUT_ENV = await api('/api/env?net=1');
    } catch (e) {
      ABOUT_ENV = null;
    } finally {
      ABOUT_ENV_LOADING = false;
    }
    return ABOUT_ENV;
  }

  function renderAboutEnv(env) {
    const box = $('aboutEnv');
    const chk = $('aboutChecks');
    if (!env) {
      box.innerHTML = '<div class="empty-mini">运行环境读取失败（/api/env 接口不可用）'
        + '—— 可直接把本页截图与问题描述发送至反馈邮箱。</div>';
      chk.innerHTML = '';
      return;
    }
    const py = env.python || {}, sys = env.system || {}, fe = env.features || {};
    const req = env.requirements || {}, wr = env.writable || {};
    const rows = [
      ['工具版本', 'v' + (env.version || '?')],
      ['操作系统', (sys.os || '?') + ' ' + (sys.os_release || '') + ' · ' + (sys.machine || '')],
      ['Python', (py.version || '?') + '（要求 ≥ ' + (py.required || '3.9')
        + '，推荐 ' + (py.recommended || '3.10 – 3.13') + '）'],
      ['第三方依赖', req.third_party || '无（零 pip 依赖）'],
      ['可选组件', req.optional || '—'],
      ['规则 / 清单', (fe.rules || 0) + ' 条规则 · ' + (fe.manifest_ecosystems || 0) + ' 种依赖清单'],
      ['依赖漏洞库', fe.vulndb_enabled
        ? (fe.vulndb_offline ? '已启用（离线只读缓存）' : '已启用（在线 OSV.dev）') : '未启用'],
      ['目录可写', wr.all ? '全部可写' : '存在不可写目录，建议更换工具存放位置'],
    ];
    box.innerHTML = rows.map(function (r) {
      return '<div class="env-row"><span>' + escapeHtml(r[0]) + '</span>'
        + '<b>' + escapeHtml(String(r[1])) + '</b></div>';
    }).join('');
    const checks = env.checks || [];
    chk.innerHTML = checks.map(function (c) {
      const cls = c.ok ? 'ok' : (c.fatal ? 'bad' : 'warn');
      return '<div class="env-check ' + cls + '">'
        + '<i aria-hidden="true">' + (c.ok ? '✓' : (c.fatal ? '✗' : '!')) + '</i>'
        + '<span>' + escapeHtml(c.label) + '</span>'
        + '<em>' + escapeHtml(c.detail) + '</em></div>';
    }).join('');
  }

  async function showAbout() {
    const f = feedbackInfo();
    const m = S.meta || {};
    const req = (m.env || {}).python_required || '3.9';
    $('aboutName').textContent = m.tool || '源代码静态审计平台';
    $('aboutVersion').textContent = 'v' + (m.version || '?')
      + ' · 仅需 Python ' + req + '+ · 无需 pip install';
    $('aboutEmail').textContent = f.email || '—';
    setMailto(null);
    openModal('modalAbout');
    renderAboutEnv(ABOUT_ENV);
    const env = await loadAboutEnv();
    if (!$('modalAbout').classList.contains('show')) return;   // 用户已关闭，无需重绘
    renderAboutEnv(env);
    setMailto(env);
  }

  /** 写入 mailto 链接（主题 + 正文预填诊断信息），无邮箱时降级为提示 */
  function setMailto(env) {
    const f = feedbackInfo();
    const a = $('aboutMail');
    if (!f.email) { a.href = '#'; return; }
    const body = diagText(env);
    // mailto 正文长度有限（多数客户端约 2000 字符），超长时截断并改用「复制诊断信息」
    const safe = body.length > 1600 ? body.slice(0, 1600) + '\n…（完整诊断信息请点「复制诊断信息」）' : body;
    a.href = 'mailto:' + f.email
      + '?subject=' + encodeURIComponent(f.prefix + ' 问题反馈')
      + '&body=' + encodeURIComponent(safe);
  }

  async function showDeps() {
    openModal('modalDeps');
    if (S.depLoaded) return;
    $('depList').innerHTML = '<div class="empty">加载中…</div>';
    try {
      const data = await api(withProj('/api/deps'));
      S.deps = data.deps || [];
      S.depVulnSummary = data.vuln || {};
      S.depVulnMeta = data.meta || {};
      $('depCount').textContent = '（共 ' + S.deps.length + ' 项）';
      const eco = data.eco_label || { go: 'Go Modules', npm: 'npm', pypi: 'PyPI' };
      const chips = $('depEcoChips');
      const ecoKeys = Object.keys(data.by_ecosystem || {});
      chips.innerHTML = '<button class="on" data-eco="all">全部 ' + S.deps.length + '</button>' +
        ecoKeys.map((k) => '<button data-eco="' + escapeHtml(k) + '">' +
          escapeHtml(eco[k] || k) + ' ' + data.by_ecosystem[k] + '</button>').join('');
      chips.addEventListener('click', (e) => {
        const b = e.target.closest('button');
        if (!b) return;
        S.depEco = b.dataset.eco;
        qsa('button', chips).forEach((x) => x.classList.toggle('on', x === b));
        renderDepList(eco);
      });
      S.depLoaded = true;
      renderDepList(eco);
    } catch (e) {
      $('depList').innerHTML = '<div class="empty">' + escapeHtml(e.message) + '</div>';
    }
  }

  function renderDepList(eco) {
    const list = S.deps.filter((d) => {
      if (S.depEco !== 'all' && d.ecosystem !== S.depEco) return false;
      if (S.depKw && d.name.toLowerCase().indexOf(S.depKw) < 0) return false;
      return true;
    });
    const vmeta = (S.depVulnMeta || {});
    const vsum = (S.depVulnSummary || {});
    const head = '<p class="rule-meta" style="margin:0 0 10px">'
      + '共 ' + S.deps.length + ' 项依赖；其中 <b>' + fmtNum(vsum.vuln_packages || 0)
      + '</b> 项存在已知漏洞（<b>' + fmtNum(vsum.vuln_total || 0) + '</b> 条公告）。'
      + (vsum.unresolved ? '另有 ' + vsum.unresolved + ' 项版本无法解析，未纳入比对。' : '')
      + '　→ 切到中栏「依赖风险」标签查看漏洞明细与修复建议。'
      + '（显示 ' + list.length + ' / ' + S.deps.length + ' 项）</p>';
    const vkCls = { exact: '', floor: 't-floor', unresolved: 't-none' };
    $('depList').innerHTML = list.length
      ? head + '<div class="dep-grid">' + list.map((d) => {
        const n = d.vuln_count || 0;
        const vk = (d.version_kind && d.version_kind !== 'exact')
          ? '<span class="tag-mini ' + vkCls[d.version_kind] + '" title="'
            + escapeHtml(VK_CN[d.version_kind] || '') + '">' + escapeHtml(VK_CN[d.version_kind] || '') + '</span>'
          : '';
        return '<div class="dep-item' + (n ? ' has-vuln' : '') + '" title="'
          + escapeHtml((d.manifests || [d.manifest || '']).join('  ·  ')) + '">'
          + (n ? '<i class="vuln-flag" title="存在 ' + n + ' 条已知漏洞">' + n + '</i>' : '')
          + '<code>' + escapeHtml(d.name) + '</code>'
          + '<span>' + escapeHtml(d.version || '—') + ' · '
          + escapeHtml(eco[d.ecosystem] || d.ecosystem || '')
          + (d.indirect ? ' · 间接' : '') + '</span>' + vk + '</div>';
      }).join('') + '</div>'
      : '<div class="empty">没有匹配的依赖项</div>';
  }

  /* ==================================================== 依赖漏洞库（SCA）
     结果来自服务端 OSV.dev 匹配。设计要点：
     ① 分析在独立线程里跑，界面先用「分析中…」占位，不阻塞规则扫描结果；
     ② 修复建议按"升级跨度"分级（同版本线 / 升次版本线 / 跨主版本 / 无修复），
        这是用户判断"改起来有多大风险"的依据；
     ③ 版本可信度不遮掩：区间下界推出的版本会明确标注，避免把推定值当结论。
     ================================================================ */
  const V = { sev: 'all', fix: 'all', kw: '', sort: 'severity', group: '' };
  const VULN = { data: null, timer: null, loading: false };

  const VULN_SEV_CN = { critical: '严重', high: '高危', medium: '中危', low: '低危', info: '提示' };
  const FIX_TAG = {
    'same-branch': ['t-easy', '同版本线可修复'],
    'minor-up': ['t-minor', '需升次版本线'],
    'major-up': ['t-major', '需跨主版本'],
    none: ['t-none', '暂无修复版本'],
  };
  const VK_CN = { exact: '精确', floor: '区间下界（推定）', unresolved: '未解析' };
  const VULN_PHASE = {
    pending: '正在准备依赖漏洞分析…',
    'vulndb-query': '正在向 OSV.dev 查询依赖…',
    'vulndb-detail': '正在拉取漏洞公告详情…',
    empty: '未解析到可查询的依赖',
    done: '分析完成',
  };

  function fmtAge(sec) {
    if (sec == null) return '';
    if (sec < 90) return sec + ' 秒前';
    if (sec < 3600) return Math.round(sec / 60) + ' 分钟前';
    if (sec < 86400) return Math.round(sec / 3600) + ' 小时前';
    return Math.round(sec / 86400) + ' 天前';
  }

  function vaultnPhaseText(pr) {
    if (!pr) return '正在分析依赖漏洞…';
    const base = VULN_PHASE[pr.phase] || '正在分析依赖漏洞…';
    if (pr.total > 1 && pr.done > 0 && pr.phase !== 'done') {
      return base + '（' + pr.done + ' / ' + pr.total + '）';
    }
    return base;
  }

  function paintVulnHeader(st) {
    st = st || {};
    const s = st.summary || {};
    const total = s.vuln_total || 0;
    const src = $('vulnSrc');
    if (!st.enabled) {
      src.className = 'vuln-src off'; src.textContent = '依赖漏洞库已关闭';
    } else if (st.running) {
      src.className = 'vuln-src'; src.textContent = '分析中…';
    } else if (st.error && !st.analyzed_at) {
      src.className = 'vuln-src err'; src.textContent = '漏洞库不可用';
    } else if (st.analyzed_at) {
      src.className = 'vuln-src'; src.textContent = '依赖漏洞库 · OSV.dev';
    } else {
      src.className = 'vuln-src off'; src.textContent = '尚未分析依赖漏洞';
    }

    const bits = [];
    if (st.analyzed_at_text) bits.push('更新于 ' + st.analyzed_at_text);
    if (st.data_age != null && st.data_age > 5) bits.push('数据龄期 ' + fmtAge(st.data_age));
    if (s.queried) bits.push('已查询 ' + s.queried + ' 个依赖');
    if (st.cache && st.cache.vulns) bits.push('本地公告缓存 ' + st.cache.vulns + ' 条');
    if (st.offline) bits.push('离线模式（不联网）');
    if (st.error) bits.push('⚠ ' + st.error);
    $('vulnMeta').textContent = bits.join(' · ');

    const kpi = $('kpiVulns');
    if (st.running) kpi.textContent = '…';
    else if (!st.analyzed_at) kpi.textContent = '--';
    else kpi.textContent = fmtNum(total);
    $('statVuln').classList.toggle('on-alert', (s.critical || 0) > 0);
    $('vulnDot').hidden = total <= 0;
    const badge = $('depsBadge');
    badge.hidden = total <= 0;
    badge.textContent = total > 999 ? '999+' : String(total);
    if (document.activeElement !== $('vulnOffline')) $('vulnOffline').checked = !!st.offline;
  }

  function vulnQuery() {
    const p = new URLSearchParams();
    p.set('severity', V.sev); p.set('fix', V.fix);
    if (V.kw) p.set('keyword', V.kw);
    p.set('sort', V.sort);
    if (V.group) p.set('group_by', V.group);
    p.set('limit', '200');
    return p.toString();
  }

  async function loadVulns(showLoading) {
    const body = $('vulnBody');
    VULN.loading = true;
    if (showLoading) body.innerHTML = '<div class="vuln-progress"><i class="spin"></i>正在读取依赖漏洞结果…</div>';
    try {
      const d = await api(withProj('/api/vulns?' + vulnQuery()));
      VULN.data = d;
      renderVulns(d);
    } catch (e) {
      body.innerHTML = '<div class="empty">加载失败：' + escapeHtml(e.message) + '</div>';
    } finally {
      VULN.loading = false;
    }
  }

  function vulnCard(f) {
    const sev = f.severity;
    const tag = FIX_TAG[f.fix_kind] || FIX_TAG.none;
    const cvss = (f.cvss != null)
      ? '<span class="vuln-cvss c-' + sev + '" title="' + escapeHtml(f.cvss_vector || 'CVSS 向量') + '">'
        + f.cvss + '</span>' : '';
    const vk = (f.version_kind && f.version_kind !== 'exact')
      ? ' <span class="tag-mini t-floor" title="该版本由声明区间下界推得，实际安装版本可能更新（可能误报）">'
        + escapeHtml(VK_CN[f.version_kind] || f.version_kind) + '</span>' : '';
    const aliases = (f.also_ids || []).length
      ? ' <span class="vuln-aliases">（同一漏洞另有公告：'
        + escapeHtml((f.also_ids || []).slice(0, 3).join('、')) + '）</span>' : '';
    const ref = (f.references || []).length
      ? '<div class="vuln-links">参考：<a href="' + escapeHtml(f.references[0].url)
        + '" target="_blank" rel="noopener noreferrer">' + escapeHtml(f.references[0].url) + '</a></div>' : '';
    const fixedTxt = f.fixed
      ? '<span class="vuln-arrow">→</span><span class="vuln-fixed">' + escapeHtml(f.fixed) + '</span>'
      : '<span class="vuln-arrow">→</span><span class="vuln-fixed none">该版本线无修复版本</span>';
    return '<article class="vuln-card sev-' + sev + '">'
      + '<div class="vuln-card-head">'
      + '<span class="badge sev-' + sev + '">' + (VULN_SEV_CN[sev] || sev) + '</span>'
      + cvss
      + '<span class="vuln-id">' + escapeHtml(f.vuln_id) + (f.cve ? ' · ' + escapeHtml(f.cve) : '') + '</span>'
      + '<span class="tag-mini ' + tag[0] + '">' + tag[1] + '</span>'
      + '<h4>' + escapeHtml(f.title) + aliases + '</h4>'
      + '</div>'
      + '<div class="vuln-line"><span class="key">受影响依赖</span>'
      + '<span class="vuln-dep">' + escapeHtml(f.package) + '<span class="ver">@'
      + escapeHtml(f.version) + '</span></span>' + vk + fixedTxt + '</div>'
      + '<div class="vuln-line"><span class="key">来源清单</span><code>'
      + escapeHtml(f.manifest) + '</code>'
      + (f.indirect ? '<span class="tag-mini">间接依赖</span>' : '')
      + (f.scope && f.scope !== 'compile' ? '<span class="tag-mini">' + escapeHtml(f.scope) + '</span>' : '')
      + (f.cwe && f.cwe.length ? '<span class="tag-mini">' + escapeHtml(f.cwe.slice(0, 2).join(' / ')) + '</span>' : '')
      + '</div>'
      + '<div class="vuln-advice' + (f.has_fix ? '' : ' no-fix') + '">'
      + escapeHtml(f.advice)
      + (f.command ? '<br><span class="cmd">' + escapeHtml(f.command) + '</span>' : '')
      + '</div>'
      + ref
      + '</article>';
  }

  function vulnGroups(groups) {
    return groups.map((g) => {
      const cls = g.worst ? ' sev-' + g.worst : '';
      const chips = VULN_SEV_CN[g.worst]
        ? '<span class="badge sev-' + g.worst + '">' + VULN_SEV_CN[g.worst] + '</span>' : '';
      return '<div class="vuln-group" data-key="' + escapeHtml(g.key) + '">'
        + '<div class="vuln-group-head">'
        + '<span class="g-caret">▸</span>' + chips
        + '<span class="g-label">' + escapeHtml(g.label) + '</span>'
        + (g.sub ? '<span class="g-sub">' + escapeHtml(g.sub) + '</span>' : '')
        + '<span class="g-count">' + g.count + ' 条'
        + (g.max_cvss ? ' · 最高 ' + g.max_cvss : '') + '</span>'
        + '</div><div class="vuln-group-items" data-key="' + escapeHtml(g.key) + '"></div></div>';
    }).join('');
  }

  function renderVulns(d) {
    const body = $('vulnBody');
    const st = (d.status || {});
    paintVulnHeader(st);

    if (!d.ready) {
      body.innerHTML = st.running
        ? '<div class="vuln-progress"><i class="spin"></i>' + escapeHtml(vaultnPhaseText(st.progress)) + '</div>'
        : '<div class="empty">' + (d.error
          ? '依赖漏洞分析未完成：' + escapeHtml(d.error)
          : '尚未分析依赖漏洞。点击右上角「更新漏洞库」开始。') + '</div>';
      return;
    }

    const s = d.summary || {};
    const dm = d.deps_meta || {};
    const sk = d.skipped || {};
    const sum = '<div class="vuln-summary">'
      + '<div class="vuln-sum-item' + ((s.critical || 0) > 0 ? ' alert' : '') + '"><b>'
      + fmtNum(s.critical) + '</b><span>严重</span></div>'
      + '<div class="vuln-sum-item' + ((s.high || 0) > 0 ? ' warn' : '') + '"><b>'
      + fmtNum(s.high) + '</b><span>高危</span></div>'
      + '<div class="vuln-sum-item"><b>' + fmtNum(s.vuln_packages) + '</b><span>受影响依赖</span></div>'
      + '<div class="vuln-sum-item ok"><b>' + fmtNum(s.easy_fix) + '</b><span>同版本线可修复</span></div>'
      + '<div class="vuln-sum-item"><b>' + fmtNum((s.minor_up || 0) + (s.major_up || 0))
      + '</b><span>需升级版本线</span></div>'
      + '<div class="vuln-sum-item"><b>' + fmtNum(s.no_fix) + '</b><span>暂无修复版本</span></div>'
      + '<div class="vuln-sum-item"><b>' + fmtNum(s.queried) + '</b><span>已查询依赖</span></div>'
      + '</div>';

    const notes = [];
    if (d.error && !d.online) {
      notes.push('本次未能成功联网（' + escapeHtml(d.error) + '），结果基于本地缓存或为空，'
        + '建议检查网络 / 代理后点击「更新漏洞库」重试。');
    }
    if (sk.unresolved) {
      notes.push('有 ' + sk.unresolved + ' 个依赖的版本由外部父 POM / BOM 管理，源码内无法解析，'
        + '未纳入漏洞比对。执行 <code>mvn dependency:tree -DoutputFile=deps.txt</code> 后重新扫描可获得精确版本。');
    }
    if (s.duplicate_advisories) {
      notes.push('已按漏洞别名合并 ' + s.duplicate_advisories + ' 条重复公告（同一漏洞常被多个数据库重复收录）。');
    }
    if (s.truncated) notes.push('结果超过上限，仅展示前 ' + 200 + ' 条，请用筛选缩小范围。');
    const noteHtml = notes.length
      ? '<div class="vuln-note">' + notes.map((n) => '• ' + n).join('<br>') + '</div>' : '';

    // 严重程度快捷筛选 chips
    const bySev = d.by_severity || {};
    const chips = $('vulnSevChips');
    chips.innerHTML = '<button class="' + (V.sev === 'all' ? 'on' : '') + '" data-sev="all">全部 '
      + fmtNum(d.total) + '</button>'
      + Object.keys(VULN_SEV_CN).map((k) => {
        const n = bySev[k] || 0;
        return '<button class="' + (V.sev === k ? 'on' : '') + '" data-sev="' + k + '"'
          + (n ? '' : ' disabled') + '>' + VULN_SEV_CN[k] + ' ' + n + '</button>';
      }).join('');

    let list = '';
    if (!d.total_filtered) {
      list = '<div class="empty">' + (d.total
        ? '当前筛选条件下没有匹配的漏洞'
        : '未发现已知漏洞 🎉　已查询 ' + fmtNum(s.queried) + ' 个依赖') + '</div>';
    } else if (V.group && (d.groups || []).length) {
      list = vulnGroups(d.groups);
    } else {
      list = d.findings.map(vulnCard).join('');
      if (d.has_more) list += '<div class="empty">（仅显示前 ' + d.findings.length + ' 条，共 '
        + d.total_filtered + ' 条，请用筛选缩小范围）</div>';
    }

    body.innerHTML = sum + noteHtml + list;
    body.scrollTop = 0;

    // 分组懒加载明细
    qsa('.vuln-group-head', body).forEach((head) => {
      head.addEventListener('click', async () => {
        const g = head.parentElement;
        const key = g.dataset.key;
        const open = g.classList.toggle('open');
        const box = qsa('.vuln-group-items', g)[0];
        if (!open || box.dataset.loaded === '1') return;
        box.innerHTML = '<div class="empty">加载中…</div>';
        try {
          const more = await api(withProj('/api/vulns?' + vulnQuery() + '&group_key=' + encodeURIComponent(key) + '&limit=200'));
          box.innerHTML = (more.findings || []).map(vulnCard).join('')
            || '<div class="empty">该分组下没有明细</div>';
          box.dataset.loaded = '1';
        } catch (e) {
          box.innerHTML = '<div class="empty">加载失败：' + escapeHtml(e.message) + '</div>';
        }
      });
    });
  }

  function stopVulnPoll() {
    if (VULN.timer) { clearInterval(VULN.timer); VULN.timer = null; }
  }

  function startVulnPoll() {
    stopVulnPoll();
    let ticks = 0;
    const tick = async () => {
      ticks += 1;
      let st = null;
      try { st = await api('/api/vulndb/status'); } catch (e) { st = null; }
      if (st) {
        paintVulnHeader(st);
        if (!st.running && (st.analyzed_at || st.error || st.summary.vuln_total != null)) {
          stopVulnPoll();
          if (st.analyzed_at || st.error) await loadVulns(false);
          return;
        }
        if (S.centerTab === 'deps') {
          $('vulnBody').innerHTML = '<div class="vuln-progress"><i class="spin"></i>'
            + escapeHtml(vaultnPhaseText(st.progress)) + '</div>';
        }
      }
      if (ticks >= 240) stopVulnPoll();
    };
    tick();
    VULN.timer = setInterval(tick, 1200);
  }

  async function updateVulnDb(force) {
    const btn = $('btnVulnRefresh');
    btn.disabled = true;
    btn.textContent = '更新中…';
    try {
      const r = await api('/api/vulndb/update', {
        method: 'POST',
        body: { refresh: !!force, offline: $('vulnOffline').checked },
      });
      if (r.enabled === false) {
        toast('依赖漏洞库已关闭', 'warn');
        paintVulnHeader(await api('/api/vulndb/status'));
      } else {
        toast(force ? '已清空缓存，正在重新查询漏洞库…' : '正在重新分析依赖漏洞…', 'ok');
        if (S.centerTab === 'deps') {
          $('vulnBody').innerHTML = '<div class="vuln-progress"><i class="spin"></i>正在分析依赖漏洞…</div>';
        }
        startVulnPoll();
      }
    } catch (e) {
      toast('更新失败：' + e.message, 'err', 4200);
    } finally {
      btn.disabled = false;
      btn.textContent = '更新漏洞库';
    }
  }

  function bindVuln() {
    $('statVuln').addEventListener('click', () => switchTab('deps'));
    $('btnVulnRefresh').addEventListener('click', () => updateVulnDb(true));
    $('vulnOffline').addEventListener('change', () => updateVulnDb(false));
    $('vulnFix').addEventListener('change', (e) => { V.fix = e.target.value; loadVulns(true); });
    $('vulnSort').addEventListener('change', (e) => { V.sort = e.target.value; loadVulns(true); });
    $('vulnGroup').addEventListener('change', (e) => { V.group = e.target.value; loadVulns(true); });
    $('vulnSevChips').addEventListener('click', (e) => {
      const b = e.target.closest('button');
      if (!b || b.disabled) return;
      V.sev = b.dataset.sev;
      qsa('button', $('vulnSevChips')).forEach((x) => x.classList.toggle('on', x === b));
      loadVulns(true);
    });
    const search = $('vulnSearch');
    const clear = $('vulnSearchClear');
    const run = debounce(() => {
      V.kw = search.value.trim().toLowerCase();
      clear.hidden = !search.value;
      loadVulns(true);
    }, 220);
    search.addEventListener('input', run);
    clear.addEventListener('click', () => {
      search.value = ''; clear.hidden = true; V.kw = ''; loadVulns(true);
    });
  }

  async function showReports() {
    openModal('modalReports');
    $('reportList').innerHTML = '<div class="empty">加载中…</div>';
    try {
      const data = await api('/api/reports');
      const items = data.reports || [];
      $('reportList').innerHTML = items.length
        ? items.map((r) =>
          '<div class="report-item"><span class="rmeta">' + escapeHtml(r.time) + '</span>' +
          '<span class="rname">' + escapeHtml(r.name) + '</span>' +
          '<span class="rmeta">' + (r.size / 1024).toFixed(1) + ' KB</span>' +
          '<a href="/reports/' + encodeURIComponent(r.name) + '" download>下载</a></div>').join('')
        : '<div class="empty">还没有生成过报告</div>';
    } catch (e) {
      $('reportList').innerHTML = '<div class="empty">' + escapeHtml(e.message) + '</div>';
    }
  }

  /* ====================================================== 拖拽文件夹上传 */
  function bindDropZone() {
    const zone = $('pickZone');
    const stop = (e) => { e.preventDefault(); e.stopPropagation(); };
    ['dragenter', 'dragover'].forEach((ev) => zone.addEventListener(ev, (e) => {
      stop(e);
      zone.classList.add('drag');
    }));
    zone.addEventListener('dragleave', (e) => {
      stop(e);
      if (zone.contains(e.relatedTarget)) return;
      zone.classList.remove('drag');
    });
    zone.addEventListener('drop', async (e) => {
      stop(e);
      zone.classList.remove('drag');
      const items = e.dataTransfer && e.dataTransfer.items;
      if (!items || !items.length) return;
      S.pickBusy = true;
      setPickZone('正在读取拖入的文件夹…', true);
      try {
        const entries = [];
        for (let i = 0; i < items.length; i++) {
          const en = items[i].webkitGetAsEntry && items[i].webkitGetAsEntry();
          if (en) entries.push(en);
        }
        if (!entries.length) {
          toast('当前浏览器不支持读取拖入的文件夹，请改用点击选择', 'err', 4200);
          return;
        }
        const L = uploadLimits(), skip = skipDirs();
        const files = [];
        let skipped = 0, bytes = 0, capped = false, rootName = '';

        const takeFile = (entry, rel) => new Promise((res) => {
          entry.file((f) => {
            if (skip.has(f.name) || BIN_EXT.has(extOf(f.name))) { skipped++; return res(); }
            if (files.length >= L.maxFiles) { skipped++; capped = true; return res(); }
            if (!f.size || f.size > L.maxFile || bytes + f.size > L.maxTotal) { skipped++; return res(); }
            bytes += f.size;
            files.push({ rel: rel, file: f });
            res();
          }, () => res());
        });

        const readDir = async (dir, prefix, depth) => {
          if (depth > 24) return;
          const reader = dir.createReader();
          for (;;) {
            const batch = await new Promise((res) => reader.readEntries(res, () => res([])));
            if (!batch.length) break;
            for (const en of batch) {
              const rel = prefix ? prefix + '/' + en.name : en.name;
              if (en.isDirectory) {
                if (skip.has(en.name) || (en.name.charAt(0) === '.' && en.name !== '.github')) {
                  skipped++;
                  continue;
                }
                await readDir(en, rel, depth + 1);
              } else {
                await takeFile(en, rel);
              }
            }
          }
        };

        for (const en of entries) {
          if (en.isDirectory) {
            if (!rootName) rootName = en.name;
            await readDir(en, '', 0);
          } else {
            await takeFile(en, en.name);
          }
        }
        commitPick({ name: rootName || '拖入的文件夹', files: files,
                     skipped: skipped, bytes: bytes, capped: capped });
      } catch (err) {
        toast('读取拖入内容失败：' + err.message, 'err', 4500);
      } finally {
        S.pickBusy = false;
        $('pickZone').classList.remove('busy');
      }
    });
  }

  /* ============================================================ 导出 */
  function bindTopbar() {
    $('btnScan').addEventListener('click', () => startScan());

    /* ---------- 审计目标选择器 ---------- */
    $('btnTarget').addEventListener('click', openTarget);
    $('targetTabs').addEventListener('click', (e) => {
      const b = e.target.closest('button');
      if (b) switchTargetTab(b.dataset.ttab);
    });
    $('pickZone').addEventListener('click', pickFolder);
    $('pickZone').addEventListener('keydown', (e) => {
      if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); pickFolder(); }
    });
    $('dirPicker').addEventListener('change', (e) => {
      const fl = e.target.files;
      if (fl && fl.length) commitPick(collectFromInput(fl));
      e.target.value = '';                     // 允许重复选择同一文件夹
    });
    $('btnUploadScan').addEventListener('click', () => uploadPick(true));
    $('btnUploadOnly').addEventListener('click', () => uploadPick(false));
    $('btnClearPick').addEventListener('click', clearPick);
    $('btnBrowseDir').addEventListener('click', openDirBrowser);
    $('btnBrowse').addEventListener('click', browseServer);
    $('btnUseServer').addEventListener('click', () => useServerPath(true));
    $('dbUp').addEventListener('click', () => {
      if (S.dirData && S.dirData.parent) loadDir(S.dirData.parent); else loadDir('');
    });
    $('dbCancel').addEventListener('click', closeDirBrowser);
    $('dbPick').addEventListener('click', () => pickDir(false));
    $('dbPickScan').addEventListener('click', () => pickDir(true));
    const dbJump = (e) => {
      const t = e.target.closest('[data-goto]');
      if (!t) return;
      if (e.type === 'keydown') {
        if (!t.classList.contains('db-row')) return;
        if (e.key !== 'Enter' && e.key !== ' ') return;
        e.preventDefault();
      }
      loadDir(t.dataset.goto);
    };
    $('dbList').addEventListener('click', dbJump);
    $('dbList').addEventListener('keydown', dbJump);
    $('dbRoots').addEventListener('click', dbJump);
    $('dbCrumbs').addEventListener('click', dbJump);
    $('serverPath').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') useServerPath(true);
    });
    bindDropZone();

    /* ---------- 窄屏「更多」菜单 ---------- */
    const more = $('moreDrop');
    $('btnMore').addEventListener('click', (e) => {
      e.stopPropagation();
      more.classList.toggle('open');
    });
    document.addEventListener('click', () => more.classList.remove('open'));
    $('moreMenu').addEventListener('click', (e) => {
      const a = e.target.closest('a');
      if (!a) return;
      e.preventDefault();
      more.classList.remove('open');
      const act = a.dataset.act;
      if (act === 'rules') showRules();
      else if (act === 'deps') { if ($('btnDeps').disabled) toast('请先完成一次扫描', 'err'); else showDeps(); }
      else if (act === 'reports') showReports();
      else if (act === 'target') openTarget();
      else if (act === 'about') showAbout();
    });

    /* ---------- 窄屏分栏切换 ---------- */
    $('paneSwitch').addEventListener('click', (e) => {
      const b = e.target.closest('button');
      if (b) setPane(b.dataset.pane);
    });

    const drop = $('exportDrop');
    $('btnExport').addEventListener('click', (e) => {
      e.stopPropagation();
      drop.classList.toggle('open');
    });
    document.addEventListener('click', () => drop.classList.remove('open'));

    $('exportMenu').addEventListener('click', (e) => {
      const a = e.target.closest('a');
      if (!a) return;
      e.preventDefault();
      drop.classList.remove('open');
      if (a.dataset.act === 'reports') { showReports(); return; }
      const fmt = a.dataset.fmt;
      const detail = a.dataset.detail || 'full';
      const q = new URLSearchParams({ format: fmt });
      if (fmt === 'docx') q.set('detail', detail);
      if (VIEW_PID) q.set('project', VIEW_PID);   // 历史项目模式：导出该项目快照
      const label = fmt === 'docx'
        ? 'Word 报告（' + (detail === 'summary' ? '精简清单' : '完整明细') + '）'
        : fmt.toUpperCase() + ' 报告';
      toast('正在生成 ' + label + '，请稍候…', '', 5000);
      // 用带 download 属性的临时链接触发下载，避免页面跳转丢失当前浏览状态
      const link = document.createElement('a');
      link.href = '/api/export?' + q.toString();
      link.download = '';
      link.style.display = 'none';
      document.body.appendChild(link);
      link.click();
      setTimeout(() => {
        link.remove();
        toast(label + ' 已生成，同时存档至 reports 目录', 'ok', 3800);
      }, 1500);
    });

    $('btnRules').addEventListener('click', showRules);
    $('btnDeps').addEventListener('click', showDeps);

    /* ---------- 关于与反馈：顶栏按钮 + 状态栏入口 ---------- */
    $('btnAbout').addEventListener('click', showAbout);
    $('btnFeedback').addEventListener('click', showAbout);
    $('aboutCopyMail').addEventListener('click', () => {
      const f = feedbackInfo();
      if (f.email) copyText(f.email);
      else toast('反馈邮箱未配置', 'err');
    });
    $('aboutCopyDiag').addEventListener('click', () => {
      const f = feedbackInfo();
      copyText(diagText(ABOUT_ENV) + (f.email ? '' : ''));
    });

    /* ---------- 审计项目：每次扫描独立建档，可回看 / 删除 / 追溯 ---------- */
    const projDrop = $('projDrop');
    $('btnProj').addEventListener('click', async (e) => {
      e.stopPropagation();
      projDrop.classList.toggle('open');
      if (projDrop.classList.contains('open')) await loadProjList();
    });
    document.addEventListener('click', () => projDrop.classList.remove('open'));
    $('projMenu').addEventListener('click', (e) => e.stopPropagation());
    $('projList').addEventListener('click', onProjListClick);
    $('btnAllHistory').addEventListener('click', () => {
      projDrop.classList.remove('open');
      goHistory();                            // 进入一级页面：扫描历史列表
    });

    let PROJ_ITEMS = [];
    function fmtTs(sec) {
      if (!sec) return '—';
      const d = new Date(sec * 1000);
      const p = (n) => String(n).padStart(2, '0');
      return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
             `${p(d.getHours())}:${p(d.getMinutes())}`;
    }

    // 提升到模块作用域：init() 恢复会话时需要调用（修复 v1.5.0 的 ReferenceError 回归）
    loadProjList = async function () {
      try {
        const data = await api('/api/projects');
        PROJ_ITEMS = data.projects || [];
        const badge = $('projCount');
        badge.textContent = String(PROJ_ITEMS.length);
        badge.hidden = PROJ_ITEMS.length === 0;
        const host = $('projList');
        if (!PROJ_ITEMS.length) {
          host.innerHTML = '<div class="empty-mini">还没有审计项目，开始第一次扫描即可建档</div>';
          return;
        }
        host.innerHTML = PROJ_ITEMS.map((m) => {
          const cur = (m.id === VIEW_PID) || (!VIEW_PID && m.id === data.current);
          const isLive = m.id === data.current;
          return '<div class="proj-row' + (cur ? ' cur' : '') + '" data-pid="' + m.id + '">' +
            '<div class="pr-main"><b>' + escapeHtml((m.target || {}).name || m.id) +
            (isLive ? ' <span class="tag-mini t-easy">当前</span>' : '') + '</b>' +
            '<i>' + escapeHtml((m.target || {}).root || '') + '</i></div>' +
            '<div class="pr-stats">' + fmtTs(m.created_at) + ' · ' +
            fmtNum(m.findings_total || 0) + ' 项风险 · ' +
            fmtNum(m.vuln_total || 0) + ' 漏洞</div>' +
            '<button class="pr-info" data-info="' + m.id + '" title="跳转到该次扫描的详情页">详情</button>' +
            (isLive ? '' : '<button class="pr-del" data-del="' + m.id +
              '" title="删除该项目及其全部数据">✕</button>') +
            '</div>';
        }).join('');
      } catch (e) {
        $('projList').innerHTML = '<div class="empty-mini">加载失败：' + escapeHtml(e.message) + '</div>';
      }
    }

    async function onProjListClick(e) {
      const info = e.target.closest('.pr-info');
      if (info) {                             // 一级列表 → 二级详情（只传主键）
        e.stopPropagation();
        projDrop.classList.remove('open');
        goDetail(info.dataset.info);
        return;
      }
      const del = e.target.closest('.pr-del');
      if (del) {
        e.stopPropagation();
        const pid = del.dataset.del;
        if (!confirm('删除该项目？其全部审计结果与漏洞数据将被清除，且不可恢复。\n' + pid)) return;
        await api('/api/project/delete', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ id: pid }),
        });
        if (VIEW_PID === pid) VIEW_PID = '';
        await loadProjList();
        toast('项目已删除', 'ok');
        return;
      }
      const row = e.target.closest('.proj-row');
      if (!row) return;
      projDrop.classList.remove('open');
      await openProject(row.dataset.pid);
    }

    async function openProject(pid) {
      try {
        VIEW_PID = pid;
        stopVulnPoll();
        VULN.data = null;                     // 丢弃实时漏洞缓存，按项目重新加载
        VULN.loading = false;
        S.depLoaded = false;
        S.tree = null;
        setStatus('正在加载历史项目…', 'busy');
        await Promise.all([loadSummary(), loadTree(true)]);
        await loadFindings(true);
        renderBoard();
        S.deps = [];                          // 清空旧依赖视图，切到依赖页时按项目重载
        S.depLoaded = false;
        if (S.centerTab === 'deps') showDeps();
        const m = PROJ_ITEMS.find((x) => x.id === pid) || {};
        const t = m.target || {};
        $('targetName').textContent = (t.name || '历史项目');
        $('targetPath').textContent = '历史项目 ' + pid + ' · ' + (t.root || '');
        setStatus('历史项目 · 只读', 'ok',
          fmtNum(m.findings_total || 0) + ' 项风险 · ' +
          fmtNum(m.vuln_total || 0) + ' 条依赖漏洞 · 建档 ' + fmtTs(m.created_at));
        toast('已切换到历史项目（只读），导出报告也将基于该项目数据', 'ok', 3600);
      } catch (e) {
        toast('加载项目失败：' + e.message, 'err', 4500);
      }
    }
    openProjectRef = openProject;      // 供「扫描历史详情页」调用（模块级引用）

    $('centerTabs').addEventListener('click', (e) => {
      const b = e.target.closest('button');
      if (b) switchTab(b.dataset.tab);
    });

    $('btnPrevHit').addEventListener('click', () => stepHit(-1));
    $('btnNextHit').addEventListener('click', () => stepHit(1));
    $('btnCopyPath').addEventListener('click', () => {
      if (S.currentFile) copyText(S.currentFile);
    });
    $('btnWrap').addEventListener('click', () => {
      S.wrap = !S.wrap;
      $('viewer').classList.toggle('wrap', S.wrap);
      $('btnWrap').classList.toggle('on', S.wrap);
    });

    qsa('[data-close]').forEach((b) => b.addEventListener('click', closeModals));
    qsa('.modal').forEach((m) => m.addEventListener('click', (e) => { if (e.target === m) closeModals(); }));

    // 规则库 / 依赖搜索
    $('ruleSearch').addEventListener('input', debounce((e) => {
      S.ruleKw = e.target.value.trim().toLowerCase();
      renderRuleList();
    }, 180));
    $('ruleSevChips').addEventListener('click', (e) => {
      const b = e.target.closest('button');
      if (!b) return;
      S.ruleSev = b.dataset.sev;
      qsa('button', $('ruleSevChips')).forEach((x) => x.classList.toggle('on', x === b));
      renderRuleList();
    });
    $('depSearch').addEventListener('input', debounce((e) => {
      S.depKw = e.target.value.trim().toLowerCase();
      renderDepList({ go: 'Go Modules', npm: 'npm', pypi: 'PyPI' });
    }, 180));
  }

  /* ============================================================ 拖拽分栏 */
  function bindGutters() {
    const ws = $('workspace');
    const saved = (() => {
      try { return JSON.parse(localStorage.getItem('audit-cols') || '{}'); } catch (e) { return {}; }
    })();
    if (saved.files) ws.style.setProperty('--col-files', saved.files + 'px');
    if (saved.findings) ws.style.setProperty('--col-findings', saved.findings + 'px');

    function drag(gutter, varName, invert) {
      gutter.addEventListener('mousedown', (e) => {
        e.preventDefault();
        gutter.classList.add('dragging');
        const startX = e.clientX;
        const cur = parseFloat(getComputedStyle(ws).getPropertyValue(varName)) || 300;
        const move = (ev) => {
          const delta = invert ? (startX - ev.clientX) : (ev.clientX - startX);
          const next = Math.max(200, Math.min(720, cur + delta));
          ws.style.setProperty(varName, next + 'px');
        };
        const up = () => {
          gutter.classList.remove('dragging');
          document.removeEventListener('mousemove', move);
          document.removeEventListener('mouseup', up);
          document.body.style.cursor = '';
          try {
            localStorage.setItem('audit-cols', JSON.stringify({
              files: parseInt(getComputedStyle(ws).getPropertyValue('--col-files'), 10),
              findings: parseInt(getComputedStyle(ws).getPropertyValue('--col-findings'), 10),
            }));
          } catch (err) { /* 忽略存储失败 */ }
        };
        document.body.style.cursor = 'col-resize';
        document.addEventListener('mousemove', move);
        document.addEventListener('mouseup', up);
      });
    }
    drag($('gutterLeft'), '--col-files', false);
    drag($('gutterRight'), '--col-findings', true);

    // 双击分隔条恢复默认宽度
    [$('gutterLeft'), $('gutterRight')].forEach((g, i) => {
      g.addEventListener('dblclick', () => {
        ws.style.setProperty(i ? '--col-findings' : '--col-files', (i ? 470 : 300) + 'px');
      });
    });
  }

  /* ============================================================ 快捷键 */
  function bindKeyboard() {
    document.addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        closeModals();
        if (document.activeElement && document.activeElement.tagName === 'INPUT') {
          document.activeElement.blur();
        }
        return;
      }
      if (e.ctrlKey || e.metaKey || e.altKey) return;
      const tag = (document.activeElement && document.activeElement.tagName) || '';
      if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;

      switch (e.key.toLowerCase()) {
        case '/': e.preventDefault(); $('findSearch').focus(); break;
        case 'f': e.preventDefault(); $('fileSearch').focus(); break;
        case 's': e.preventDefault(); startScan(); break;
        case 'b': e.preventDefault(); switchTab(S.centerTab === 'board' ? 'code' : 'board'); break;
        case 'd': e.preventDefault(); switchTab(S.centerTab === 'deps' ? 'code' : 'deps'); break;
        case 't': e.preventDefault(); openTarget(); break;
        case 'e':
          e.preventDefault();
          if ($('btnExport').disabled) return;
          $('exportDrop').classList.toggle('open');
          break;
        case 'n': if (S.currentFindings.length) stepHit(1); break;
        case 'p': if (S.currentFindings.length) stepHit(-1); break;
        default: break;
      }
    });
  }

  /* ======================================================== 审计目标选择 */
  // 浏览器原生目录选择器不会把本机绝对路径交给网页，
  // 因此「网页选目录」必须把文件上传到服务端副本再扫描（见服务端 /api/upload/*）。
  const BIN_EXT = new Set([
    'png', 'jpg', 'jpeg', 'gif', 'bmp', 'ico', 'webp', 'tiff', 'svgz',
    'mp3', 'mp4', 'avi', 'mov', 'mkv', 'wav', 'flac', 'webm', 'ogg',
    'zip', 'gz', 'tgz', 'bz2', 'xz', '7z', 'rar', 'jar', 'war', 'apk',
    'exe', 'dll', 'so', 'dylib', 'bin', 'o', 'a', 'lib', 'class', 'pyc', 'wasm',
    'pdf', 'doc', 'docx', 'xls', 'xlsx', 'ppt', 'pptx',
    'woff', 'woff2', 'ttf', 'otf', 'eot', 'db', 'sqlite', 'pack', 'idx',
  ]);

  function extOf(name) {
    const s = String(name || '');
    const i = s.lastIndexOf('.');
    return i < 0 ? '' : s.slice(i + 1).toLowerCase();
  }

  function uploadLimits() {
    const L = (S.meta && S.meta.limits) || {};
    return {
      maxFiles: L.max_files || 8000,
      maxFile: L.max_file || 12 * 1024 * 1024,
      maxTotal: L.max_total || 400 * 1024 * 1024,
    };
  }

  function skipDirs() { return new Set((S.meta && S.meta.skip_dirs) || []); }

  function fmtBytes(n) {
    if (!n) return '0 B';
    const u = ['B', 'KB', 'MB', 'GB'];
    let v = n, i = 0;
    while (v >= 1024 && i < u.length - 1) { v /= 1024; i++; }
    return (i === 0 || v >= 100 ? Math.round(v) : v.toFixed(1)) + ' ' + u[i];
  }

  function isNarrow() {
    return window.matchMedia && window.matchMedia('(max-width: 900px)').matches;
  }

  /* ---- 弹窗 ---- */
  function openTarget() {
    $('modalTarget').classList.add('show');
    if (!$('targetTabs').querySelector('.on')) switchTargetTab('browser');
    $('serverPath').value = (S.target && S.target.kind === 'path') ? S.target.root : '';
    $('serverPath').setAttribute('placeholder',
      (S.target && S.target.root) || (S.meta && S.meta.root) || 'C:\\path\\to\\source');
    /* tkinter 只是「系统原生对话框」这一可选快捷方式；缺失时自动隐藏该按钮，
       由网页目录浏览器承担全部选目录能力（功能等价，不要求任何额外组件）。 */
    const hasTk = !!(S.meta && S.meta.browse);
    $('btnBrowse').hidden = !hasTk;
    $('btnBrowse').title = '调用操作系统原生目录对话框（需 Python 自带 tkinter）';
    $('tkNote').hidden = hasTk;
    $('dirBrowser').hidden = true;
    setTimeout(() => { try { $('pickZone').focus(); } catch (e) { /* 忽略 */ } }, 60);
  }

  function closeTarget() { $('modalTarget').classList.remove('show'); }

  function switchTargetTab(name) {
    qsa('#targetTabs button').forEach((b) => {
      const on = b.dataset.ttab === name;
      b.classList.toggle('on', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
    $('tpBrowser').classList.toggle('on', name === 'browser');
    $('tpServer').classList.toggle('on', name === 'server');
    if (name === 'server') setTimeout(() => { try { $('serverPath').focus(); } catch (e) { /* 忽略 */ } }, 40);
  }

  /* ---- 目标状态回填 ---- */
  function applyTarget(t) {
    if (!t || !t.root) return;
    S.target = { name: t.name || t.root, root: t.root, kind: t.kind || 'path' };
    if (S.meta) S.meta.root = t.root;
    $('targetName').textContent = S.target.name;
    $('targetPath').textContent = S.target.root;
    $('btnTarget').title = '当前审计目录\n' + S.target.root + '\n点击可切换';
    const badge = $('targetKind');
    badge.hidden = false;
    badge.textContent = S.target.kind === 'upload' ? '已上传' : '服务器';
    badge.classList.toggle('up', S.target.kind === 'upload');
    if (S.target.kind === 'path') $('serverPath').value = S.target.root;
    $('btnScan').disabled = false;
    if (!S.summary) $('riskNote').textContent = '当前目标：' + S.target.name + '，点击「开始扫描」执行审计';
    document.title = S.target.name + ' · 源代码静态审计平台';
  }

  function resetResultUI() {
    S.summary = null;
    S.currentFile = null;
    S.currentFindings = [];
    F.items = []; F.groups = []; F.total = 0; F.hasMore = false; F.offset = 0;
    $('kpiRisk').textContent = '--';
    $('ringFg').style.strokeDashoffset = RING_C;
    ['critical', 'high', 'medium', 'low', 'info'].forEach((s) => {
      $('kpi-' + s).textContent = '0';
      const c = document.querySelector('.sev-card[data-sev="' + s + '"] .bar');
      if (c) c.style.width = '0';
    });
    ['kpiFiles', 'kpiLines', 'kpiHitFiles', 'kpiSuppressed'].forEach((id) => { $(id).textContent = '--'; });
    $('riskVerdict').textContent = '等待扫描';
    $('riskNote').textContent = '当前目标已切换，点击「开始扫描」执行审计';
    $('findings').innerHTML = '<div class="empty">暂无审计结果</div>';
    $('findingCount').textContent = '0 项';
    $('mCount').textContent = '0';
    $('filterSummary').textContent = '';
    $('board').innerHTML = '<div class="empty">完成扫描后，此处展示风险分布看板</div>';
    $('btnExport').disabled = true;
    $('btnDeps').disabled = true;
    // 依赖漏洞：清空结果与轮询，避免残留上一个目标的数据
    stopVulnPoll();
    VULN.data = null;
    $('vulnBody').innerHTML = '<div class="empty">完成扫描后，此处展示第三方依赖的已知漏洞与修复建议</div>';
    $('kpiVulns').textContent = '--';
    $('vulnDot').hidden = true;
    $('depsBadge').hidden = true;
    $('statVuln').classList.remove('on-alert');
    $('vulnSevChips').innerHTML = '';
    $('vulnMeta').textContent = '';
    $('vulnSrc').className = 'vuln-src off';
    $('vulnSrc').textContent = '尚未分析依赖漏洞';
  }

  /* ---- 模式一：浏览器原生目录选择器 ---- */
  async function pickFolder() {
    if (S.pickBusy) return;
    const canNative = typeof window.showDirectoryPicker === 'function' && window.isSecureContext;
    if (!canNative) { $('dirPicker').click(); return; }
    let handle;
    try {
      handle = await window.showDirectoryPicker({ id: 'audit-source', mode: 'read' });
    } catch (e) {
      if (e && (e.name === 'AbortError' || e.name === 'NotAllowedError')) return;   // 用户取消
      toast('目录选择器不可用（' + (e.message || e.name) + '），改用兼容模式', 'err', 4200);
      $('dirPicker').click();
      return;
    }
    await collectFromHandle(handle);
  }

  async function collectFromHandle(handle) {
    const L = uploadLimits(), skip = skipDirs();
    const files = [];
    let skipped = 0, bytes = 0, capped = false;
    S.pickBusy = true;
    setPickZone('正在读取目录结构…', true);
    try {
      async function walk(dir, prefix) {
        const items = [];
        for await (const [name, h] of dir.entries()) items.push([name, h]);
        items.sort((a, b) => (a[1].kind === b[1].kind
          ? a[0].localeCompare(b[0])
          : (a[1].kind === 'directory' ? -1 : 1)));
        for (const [name, h] of items) {
          if (h.kind === 'directory') {
            if (skip.has(name) || (name.charAt(0) === '.' && name !== '.github')) { skipped++; continue; }
            await walk(h, prefix ? prefix + '/' + name : name);
            continue;
          }
          const rel = prefix ? prefix + '/' + name : name;
          if (skip.has(name) || BIN_EXT.has(extOf(name))) { skipped++; continue; }
          if (files.length >= L.maxFiles) { skipped++; capped = true; continue; }
          let f;
          try { f = await h.getFile(); } catch (e) { skipped++; continue; }
          if (!f.size || f.size > L.maxFile || bytes + f.size > L.maxTotal) { skipped++; continue; }
          bytes += f.size;
          files.push({ rel: rel, file: f });
        }
      }
      await walk(handle, '');
    } finally {
      S.pickBusy = false;
    }
    commitPick({ name: handle.name, files: files, skipped: skipped, bytes: bytes, capped: capped });
  }

  function collectFromInput(fileList) {
    const L = uploadLimits(), skip = skipDirs();
    const files = [];
    let skipped = 0, bytes = 0, name = '', capped = false;
    for (let i = 0; i < fileList.length; i++) {
      const f = fileList[i];
      const rp = String(f.webkitRelativePath || f.name).replace(/\\/g, '/');
      const parts = rp.split('/');
      if (!name && parts.length > 1) name = parts[0];
      const dirs = parts.slice(0, -1);
      if (dirs.some((d) => skip.has(d) || (d.charAt(0) === '.' && d !== '.github'))) { skipped++; continue; }
      if (BIN_EXT.has(extOf(f.name))) { skipped++; continue; }
      if (files.length >= L.maxFiles) { skipped++; capped = true; continue; }
      if (!f.size || f.size > L.maxFile || bytes + f.size > L.maxTotal) { skipped++; continue; }
      bytes += f.size;
      // 去掉首段（所选文件夹名），使相对路径与「服务器目录」模式一致
      files.push({ rel: parts.slice(1).join('/') || f.name, file: f });
    }
    return { name: name || '上传目录', files: files, skipped: skipped, bytes: bytes, capped: capped };
  }

  function setPickZone(text, busy) {
    $('pickZoneTitle').textContent = text;
    $('pickZone').classList.toggle('busy', !!busy);
  }

  function commitPick(p) {
    S.pick = p;
    if (!p.files.length) {
      $('pickInfo').hidden = true;
      $('btnUploadScan').disabled = true;
      $('btnUploadOnly').disabled = true;
      $('btnClearPick').disabled = false;
      setPickZone('没有可上传的源代码文件', false);
      toast('所选文件夹中没有可审计的源代码文件（已忽略 ' + fmtNum(p.skipped) + ' 个）', 'err', 5000);
      return;
    }
    $('pickInfo').hidden = false;
    $('pickName').textContent = p.name;
    $('pickName').title = p.name;
    $('pickFiles').textContent = fmtNum(p.files.length);
    $('pickSize').textContent = fmtBytes(p.bytes);
    $('pickSkip').textContent = fmtNum(p.skipped);
    $('btnUploadScan').disabled = false;
    $('btnUploadOnly').disabled = false;
    $('btnClearPick').disabled = false;
    setPickZone('已选择「' + p.name + '」，点击可重新选择', false);
    const L = uploadLimits();
    if (p.capped) toast('文件数已达上限 ' + fmtNum(L.maxFiles) + ' 个，其余已忽略', 'err', 5200);
    else toast('已选中 ' + fmtNum(p.files.length) + ' 个文件 · ' + fmtBytes(p.bytes), 'ok', 2800);
  }

  function clearPick() {
    S.pick = null;
    $('pickInfo').hidden = true;
    $('btnUploadScan').disabled = true;
    $('btnUploadOnly').disabled = true;
    $('btnClearPick').disabled = true;
    setPickZone('点击选择本地文件夹', false);
  }

  async function uploadPick(thenScan) {
    const p = S.pick;
    if (!p || !p.files.length) { toast('请先选择文件夹', 'err'); return; }
    const btnA = $('btnUploadScan'), btnB = $('btnUploadOnly'), btnC = $('btnClearPick');
    btnA.disabled = btnB.disabled = btnC.disabled = true;
    $('pickZone').classList.add('busy');
    $('upProgress').hidden = false;
    const bar = $('upBar'), txt = $('upText');
    bar.style.width = '0%';
    let failed = 0;
    try {
      const init = await api('/api/upload/init', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ folder: p.name }),
      });
      const total = p.files.length;
      let done = 0, sent = 0;
      txt.textContent = '正在上传 0 / ' + fmtNum(total) + ' 个文件…';

      let cursor = 0;
      const worker = async () => {
        while (cursor < p.files.length) {
          const item = p.files[cursor++];
          try {
            const res = await fetch('/api/upload/file?ws=' + encodeURIComponent(init.ws) +
              '&path=' + encodeURIComponent(item.rel), {
              method: 'POST',
              headers: { 'Content-Type': 'application/octet-stream' },
              body: item.file,
            });
            if (!res.ok) {
              const j = await res.json().catch(() => ({}));
              throw new Error(j.message || ('HTTP ' + res.status));
            }
          } catch (e) {
            failed++;
          }
          done++;
          sent += item.file.size;
          if (done % 4 === 0 || done === total) {
            bar.style.width = Math.round((done / total) * 100) + '%';
            txt.textContent = '正在上传 ' + fmtNum(done) + ' / ' + fmtNum(total) + ' 个文件（' +
              fmtBytes(sent) + '）' + (failed ? ' · 失败 ' + failed : '');
          }
        }
      };
      await Promise.all(Array.from({ length: Math.min(4, total) }, worker));

      const info = await api('/api/upload/done', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ws: init.ws }),
      });
      bar.style.width = '100%';
      txt.textContent = '上传完成：' + fmtNum(info.files) + ' 个文件 / ' + fmtBytes(info.bytes) +
        (failed ? '（' + failed + ' 个失败，请确认网络后重试）' : '');
      await switchTarget({ root: info.root, name: info.name, kind: 'upload', label: info.name },
        { scan: !!thenScan, silent: true });
      toast('审计目标已更新：' + info.name + '（' + fmtNum(info.files) + ' 个文件）', 'ok', 3600);
      setTimeout(closeTarget, 650);
    } catch (e) {
      txt.textContent = '上传失败：' + e.message;
      toast('上传失败：' + e.message, 'err', 6000);
    } finally {
      btnA.disabled = btnB.disabled = btnC.disabled = false;
      $('pickZone').classList.remove('busy');
      setTimeout(() => { $('upProgress').hidden = true; }, 2800);
    }
  }

  /* ---- 模式二·a：网页目录浏览器（零 tkinter，任何 Python 环境可用） ----
     与 browseServer() 的区别：目录列举完全由本工具的 HTTP 接口完成，
     不依赖 Python 是否自带 tkinter，因此在精简版 Python / Linux 服务器上
     同样可用；tkinter 存在时「系统对话框」按钮作为可选快捷方式保留。 */
  function openDirBrowser() {
    $('dirBrowser').hidden = false;
    const cur = ($('serverPath').value || '').trim()
      || (S.target && S.target.root) || (S.meta && S.meta.root) || '';
    loadDir(cur);
  }

  function closeDirBrowser() { $('dirBrowser').hidden = true; }

  async function loadDir(path) {
    if (S.dirBusy) return;
    S.dirBusy = true;
    const list = $('dbList');
    list.innerHTML = '<div class="db-empty">正在读取目录…</div>';
    $('dbUp').disabled = true;
    try {
      const d = await api('/api/dir' + (path ? '?path=' + encodeURIComponent(path) : ''));
      S.dirData = d;
      renderDir(d);
    } catch (e) {
      S.dirData = null;
      $('dbCrumbs').innerHTML = '';
      $('dbRoots').innerHTML = '';
      $('dbSelf').textContent = '';
      $('dbPath').textContent = '';
      $('dbUp').disabled = true;
      $('dbPick').disabled = true;
      $('dbPickScan').disabled = true;
      list.innerHTML = '<div class="db-empty err">' + escapeHtml(e.message)
        + '<button class="mini" data-goto="">返回起始位置</button></div>';
    } finally {
      S.dirBusy = false;
    }
  }

  function renderDir(d) {
    /* 面包屑：逐级可点击 */
    $('dbCrumbs').innerHTML = (d.crumbs || []).map((c) =>
      '<button class="crumb" data-goto="' + escapeHtml(c.path) + '" title="' + escapeHtml(c.path) + '">'
      + escapeHtml(c.name) + '</button>').join('<i aria-hidden="true">›</i>');

    /* 起始位置快捷入口（盘符 / 根 / 主目录） */
    $('dbRoots').innerHTML = (d.roots || []).map((r) =>
      '<button class="mini root-chip" data-goto="' + escapeHtml(r.path) + '">'
      + escapeHtml(r.name) + '</button>').join('');

    /* 当前目录概况：告诉用户「这里有多少能扫的代码」 */
    const sf = d.self || {};
    $('dbSelf').textContent = d.path
      ? ('可审计源码 ≈ ' + fmtNum(sf.n_src_total) + (sf.partial ? '+' : '') + ' 个'
         + ' · 本层 ' + fmtNum(sf.n_src) + ' · 子目录 ' + fmtNum(sf.n_sub)
         + (sf.n_manifest ? ' · 依赖清单 ' + fmtNum(sf.n_manifest) : '')
         + (sf.n_hidden ? ' · 已忽略 ' + fmtNum(sf.n_hidden) : ''))
      : '请选择起始位置';
    $('dbPath').textContent = d.path || '';
    $('dbPath').title = d.path || '';
    $('dbUp').disabled = !d.parent;
    $('dbPick').disabled = !d.path;
    $('dbPickScan').disabled = !d.path;

    /* 子目录列表 */
    if (!d.dirs.length) {
      $('dbList').innerHTML = '<div class="db-empty">该目录下没有可浏览的子目录'
        + (sf.n_src ? '（本层已有 ' + fmtNum(sf.n_src) + ' 个源码文件，可直接「选择此目录」）' : '')
        + '</div>';
      return;
    }
    const rows = d.dirs.map((it) => {
      const badge = it.n_src == null ? ''
        : '<span class="db-badge' + (it.n_src ? ' has' : '') + '">'
          + (it.n_src ? fmtNum(it.n_src) + ' 源码' : '无源码') + '</span>';
      const man = it.has_manifest ? '<span class="db-badge man">清单</span>' : '';
      const sub = it.n_sub ? '<span class="db-badge dim">' + fmtNum(it.n_sub) + ' 子目录</span>' : '';
      return '<div class="db-row" role="option" tabindex="0" data-goto="' + escapeHtml(it.path)
        + '" title="' + escapeHtml(it.path) + '">'
        + '<span class="db-ico" aria-hidden="true">📁</span>'
        + '<span class="db-name">' + escapeHtml(it.name) + '</span>'
        + man + sub + badge + '</div>';
    }).join('');
    $('dbList').innerHTML = rows + (d.truncated
      ? '<div class="db-empty">子目录过多，仅列出前 ' + fmtNum(d.dirs.length)
        + ' 个；可直接在上方输入框填写完整路径。</div>' : '');
  }

  function pickDir(scan) {
    const d = S.dirData;
    if (!d || !d.path) { toast('请先选择一个目录', 'err'); return; }
    $('serverPath').value = d.path;
    closeDirBrowser();
    if (scan) { useServerPath(true); return; }
    toast('已选择：' + d.path, 'ok', 2800);
  }

  /* ---- 模式二：服务器目录 ---- */
  async function browseServer() {
    if (S.browseBusy) return;
    S.browseBusy = true;
    const b = $('btnBrowse'), old = b.textContent;
    b.disabled = true;
    b.textContent = '等待选择…';
    try {
      const r = await api('/api/browse', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          initial: $('serverPath').value.trim() || (S.target && S.target.root) || '',
        }),
      });
      if (!r.path) { toast('已取消目录选择'); return; }
      $('serverPath').value = r.path;
      toast('已选择：' + r.path, 'ok', 2800);
    } catch (e) {
      toast(e.message, 'err', 6500);
    } finally {
      S.browseBusy = false;
      b.disabled = false;
      b.textContent = old;
    }
  }

  function useServerPath(scan) {
    const p = ($('serverPath').value || '').trim();
    if (!p) { toast('请输入服务器上的目录路径', 'err'); $('serverPath').focus(); return; }
    const name = p.replace(/[\\/]+$/, '').split(/[\\/]/).pop() || p;
    switchTarget({ root: p, name: name, kind: 'path' }, { scan: scan !== false });
  }

  /* ---- 统一的目标切换：先同步服务端，再回填页面状态 ---- */
  async function switchTarget(payload, opts) {
    opts = opts || {};
    const info = await api('/api/target', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ root: payload.root, label: payload.label || payload.name, kind: payload.kind }),
    });
    applyTarget({ name: info.name, root: info.root, kind: info.kind });
    if (!opts.silent) closeTarget();
    if (opts.scan) {
      startScan({ root: info.root, label: info.name, kind: info.kind });
      return info;
    }
    resetResultUI();
    await loadTree(true).catch(() => {});
    setStatus('已切换审计目录', '', info.root);
    if (isNarrow()) setPane('files');
    return info;
  }

  /* ---- 窄屏分栏切换 ---- */
  function setPane(name) {
    document.body.dataset.pane = name;
    qsa('#paneSwitch button').forEach((b) => {
      const on = b.dataset.pane === name;
      b.classList.toggle('on', on);
      b.setAttribute('aria-selected', on ? 'true' : 'false');
    });
  }

  /* ============================================================ 初始化 */
  async function init() {
    bindFilters();
    bindTopbar();
    bindGutters();
    bindKeyboard();
    bindTree();
    bindVuln();
    bindHistoryPages();          // 扫描历史：一级列表页 / 二级详情页

    try {
      S.meta = await api('/api/meta');
      $('brandVer').textContent = S.meta.tool + ' · v' + S.meta.version;
      // 当前审计目标由服务端持有：刷新页面后据此恢复顶栏状态与扫描入口
      if (S.meta.root) {
        const t = S.meta.target || {};
        applyTarget({ name: t.name || S.meta.root, root: t.root || S.meta.root,
                      kind: t.kind || 'path' });
      }
      VIEW_PID = S.meta.project_id || '';     // 恢复会话时对齐当前项目
      loadProjList().catch(() => {});         // 静默刷新项目徽标
      if (!S.meta.browse) {
        $('btnBrowse').hidden = true;           // 无 tkinter：只用网页目录浏览器
        $('tkNote').hidden = false;
      }

      const catSel = $('catFilter');
      Object.keys(S.meta.categories).forEach((k) => {
        const o = document.createElement('option');
        o.value = k; o.textContent = S.meta.categories[k];
        catSel.appendChild(o);
      });
      const groupSel = $('groupBy');
      (S.meta.group_dims || []).forEach((g) => {
        const o = document.createElement('option');
        o.value = g.key; o.textContent = g.label;
        groupSel.appendChild(o);
      });

      await loadTree(false);
      setStatus('就绪', '', '未执行扫描');

      const p = await api('/api/progress');
      if (p.done && S.summary === null) {
        await loadSummary();
        await loadFindings(true);
        renderBoard();
        // 恢复既有结果时，顶栏入口必须随之解锁：这两个按钮原先只在页面内
        // 触发扫描后的 refreshAll() 里启用，导致刷新页面后「依赖清单 / 导出报告」
        // 明明有数据却是灰的（点击无反应）。
        S.depLoaded = false;
        $('btnDeps').disabled = false;
        $('btnExport').disabled = false;
        setStatusMeta();
        startVulnPoll();   // 漏洞库结果同样在服务端，恢复后继续拉取/轮询
      } else if (p.done === false && p.phase && p.phase !== 'idle') {
        // 页面刷新时扫描仍在进行
        S.scanning = true;
        $('progressWrap').classList.add('show');
        $('btnScan').disabled = true;
        $('btnScan').classList.add('scanning');
        $('btnScanText').textContent = '扫描中…';
        poll();
      }

      // URL 深链：#board 直达看板；#file=<路径>:<行号> 直接打开源码定位
      let hash = '';
      try { hash = decodeURIComponent((location.hash || '').replace(/^#/, '')); } catch (err) { hash = ''; }
      if (hash === 'board') {
        switchTab('board');
      } else if (hash === 'deps') {
        switchTab('deps');
      } else if (hash.indexOf('file=') === 0) {
        const spec = hash.slice(5);
        const ci = spec.lastIndexOf(':');
        const fp = ci > 0 ? spec.slice(0, ci) : spec;
        const ln = ci > 0 ? parseInt(spec.slice(ci + 1), 10) : 0;
        switchTab('code');
        if (fp) openFile(fp, ln || undefined);
      }
      // 扫描历史路由（#/history、#/history/<pid>）：既支持页面内跳转，也支持
      // 直接粘贴/刷新深链——数据全部按 URL 里的主键现取，不依赖内存状态。
      applyRoute();
    } catch (e) {
      console.error('[audit] 初始化失败：', e);
      toast('初始化失败：' + e.message, 'err', 4200);
      setStatus('初始化失败', 'err');
    }
  }

  /* ==========================================================================
     扫描历史：一级列表页（#/history） → 二级详情页（#/history/<项目ID>）

     跳转关系与数据传递（与 README「扫描历史」章节一致）：
       ① 主键走 URL hash —— 列表页点击某条记录时，只把「项目 ID」写进 hash；
          详情页拿着这个 ID 自行向 /api/project/detail 取全量数据。URL 是页面
          层级的唯一真源，所以刷新、收藏、粘贴链接、浏览器前进/后退都能正常工作，
          也不依赖内存里的中间状态。
       ② 首屏秒开靠 sessionStorage —— 列表页点击时把已渲染的行概览写入
          sessionStorage['audit:hist:row:<pid>']，详情页先用它立即渲染页头与
          骨架，再异步补全重区块，避免白屏（刷新详情页时该缓存依然有效）。
       ③ 返回列表时恢复现场 —— 搜索/状态/排序/页码与滚动位置存
          sessionStorage（'audit:hist:view' / 'audit:hist:scroll'），
          从详情页返回即可回到原来的浏览位置。
     ========================================================================== */
  const HIST = {
    items: [], totals: null, statuses: {}, current: '',
    view: { kw: '', status: 'all', sort: 'time_desc', size: 20, page: 1 },
    lastRendered: '', detailPid: '', detail: null,
  };
  const SS = {
    get(k, dflt) {
      try {
        const v = sessionStorage.getItem(k);
        return v === null ? dflt : JSON.parse(v);
      } catch (e) { return dflt; }
    },
    set(k, v) { try { sessionStorage.setItem(k, JSON.stringify(v)); } catch (e) { /* 隐私模式 */ } },
    del(k) { try { sessionStorage.removeItem(k); } catch (e) { /* 忽略 */ } },
  };
  const ROW_KEY = (pid) => 'audit:hist:row:' + pid;
  const VIEW_KEY = 'audit:hist:view';
  const SCROLL_KEY = 'audit:hist:scroll';
  const SORTS = [
    ['time_desc', '时间：最新在前'],
    ['time_asc', '时间：最早在前'],
    ['risk_desc', '风险指数：高 → 低'],
    ['findings_desc', '隐患数：多 → 少'],
    ['high_desc', '严重+高危：多 → 少'],
    ['vuln_desc', '依赖漏洞：多 → 少'],
  ];
  const SIZES = [10, 20, 50, 100];

  /* ---- 时间 / 数值格式化（历史页与详情页共用） ---- */
  const pad2 = (n) => String(n).padStart(2, '0');

  function fmtTime(sec, withSec) {
    if (!sec) return '—';
    const d = new Date(sec * 1000);
    return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ` +
           `${pad2(d.getHours())}:${pad2(d.getMinutes())}` +
           (withSec ? ':' + pad2(d.getSeconds()) : '');
  }

  function fmtDay(sec) {
    if (!sec) return '—';
    const d = new Date(sec * 1000);
    return `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}`;
  }

  function fmtClock(sec) {
    if (!sec) return '—';
    const d = new Date(sec * 1000);
    return `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
  }

  function fmtAgo(sec) {
    if (!sec) return '';
    const s = Math.max(0, Math.floor(Date.now() / 1000 - sec));
    if (s < 60) return '刚刚';
    if (s < 3600) return Math.floor(s / 60) + ' 分钟前';
    if (s < 86400) return Math.floor(s / 3600) + ' 小时前';
    if (s < 86400 * 30) return Math.floor(s / 86400) + ' 天前';
    return Math.floor(s / 86400 / 30) + ' 个月前';
  }

  function fmtDur(sec) {
    const s = Number(sec) || 0;
    if (s <= 0) return '—';
    if (s < 60) return (s < 10 ? s.toFixed(1) : Math.round(s)) + ' 秒';
    return Math.floor(s / 60) + ' 分 ' + Math.round(s % 60) + ' 秒';
  }

  function fmtBytes(n) {
    const b = Number(n) || 0;
    if (b < 1024) return b + ' B';
    if (b < 1048576) return (b / 1024).toFixed(1) + ' KB';
    return (b / 1048576).toFixed(2) + ' MB';
  }

  /* ---- 路由：hash 是页面层级的唯一真源 ---- */
  function parseRoute() {
    const raw = String(location.hash || '').replace(/^#\/?/, '');
    let parts = raw.split('/').filter(Boolean);
    try { parts = parts.map(decodeURIComponent); } catch (e) { /* 保留原样 */ }
    if (parts[0] === 'history') {
      return parts.length > 1 ? { page: 'detail', pid: parts[1] }
                              : { page: 'list', pid: '' };
    }
    return { page: 'workbench', pid: '' };
  }

  function applyRoute() {
    const r = parseRoute();
    $('pageHistory').hidden = r.page !== 'list';
    $('pageHistDetail').hidden = r.page !== 'detail';
    document.body.classList.toggle('paging', r.page !== 'workbench');
    if (r.page === 'list') showHistoryList();
    else if (r.page === 'detail') showHistDetail(r.pid);
    else HIST.lastRendered = '';
  }

  function gotoHash(h) {
    if (String(location.hash || '') === h) { applyRoute(); return; }
    location.hash = h;
    setTimeout(applyRoute, 0);         // 兜底：个别浏览器在 hash 未变化时不派发事件
  }
  const goHistory = () => gotoHash('#/history');
  const goDetail = (pid) => gotoHash('#/history/' + encodeURIComponent(pid));
  const goWorkbench = () => gotoHash('#');

  /* 载入工作台并可直接定位到某文件（详情页「定位」按钮用） */
  async function openInWorkbench(pid, path, line) {
    await openProjectRef(pid);
    goWorkbench();
    if (!path) return;
    switchTab('code');
    setTimeout(() => { try { openFile(path, line || undefined); } catch (e) { /* 忽略 */ } }, 80);
  }

  /* ---------------------------------------------------------- 一级：列表页 */
  function persistView() { SS.set(VIEW_KEY, HIST.view); }

  function syncHistTools() {
    const v = HIST.view;
    $('histKw').value = v.kw || '';
    // 状态选项依赖服务端返回的 statuses；首次进入时数据尚未到达，故每次都按
    // 当前已知状态重建（否则会只剩「全部状态」一项，筛选功能形同虚设）。
    const st = $('histStatus');
    const opts = [['all', '全部状态']].concat(
      Object.keys(HIST.statuses || {}).map((k) => [k, HIST.statuses[k]]));
    st.innerHTML = opts.map(([k, l]) =>
      '<option value="' + k + '">' + escapeHtml(l) + '</option>').join('');
    st.value = v.status || 'all';
    const so = $('histSort');
    if (!so.options.length) {
      so.innerHTML = SORTS.map(([k, l]) =>
        '<option value="' + k + '">' + escapeHtml(l) + '</option>').join('');
    }
    so.value = v.sort || 'time_desc';
    const sz = $('histSize');
    if (!sz.options.length) {
      sz.innerHTML = SIZES.map((n) => '<option value="' + n + '">每页 ' + n + ' 条</option>').join('');
    }
    sz.value = String(v.size || 20);
  }

  async function showHistoryList() {
    const fresh = HIST.lastRendered !== 'list';
    HIST.lastRendered = 'list';
    if (fresh) {
      const saved = SS.get(VIEW_KEY, null);
      if (saved) HIST.view = Object.assign(HIST.view, saved);
      syncHistTools();
      await loadHistory(true);
    }
  }

  async function loadHistory(keepScroll) {
    const host = $('histList');
    if (!HIST.items.length) host.innerHTML = '<div class="empty-mini">加载中…</div>';
    try {
      const d = await api('/api/projects');
      HIST.items = d.projects || [];
      HIST.totals = d.totals || null;
      HIST.statuses = d.statuses || {};
      HIST.current = d.current || '';
      syncHistTools();
      renderHistory(keepScroll);
    } catch (e) {
      host.innerHTML = '<div class="empty-mini">加载失败：' + escapeHtml(e.message) + '</div>';
    }
  }

  function histFiltered() {
    const v = HIST.view;
    const kw = String(v.kw || '').trim().toLowerCase();
    const list = HIST.items.filter((m) => {
      if (v.status && v.status !== 'all' && (m.status || 'completed') !== v.status) return false;
      if (!kw) return true;
      const t = m.target || {};
      return (m.id + ' ' + (t.name || '') + ' ' + (t.root || '')).toLowerCase().indexOf(kw) >= 0;
    });
    const num = (x) => Number(x) || 0;
    const cmp = {
      time_desc: (a, b) => num(b.created_at) - num(a.created_at),
      time_asc: (a, b) => num(a.created_at) - num(b.created_at),
      risk_desc: (a, b) => num(b.risk_index) - num(a.risk_index),
      findings_desc: (a, b) => num(b.findings_total) - num(a.findings_total),
      high_desc: (a, b) => num(b.high_total) - num(a.high_total),
      vuln_desc: (a, b) => num(b.vuln_total) - num(a.vuln_total),
    }[v.sort] || ((a, b) => num(b.created_at) - num(a.created_at));
    return list.sort(cmp);
  }

  function renderHistKpis() {
    const t = HIST.totals || {};
    const sev = t.by_severity || {};
    const sevTotal = SEV_ORDER.reduce((n, k) => n + (Number(sev[k]) || 0), 0);
    const bar = sevTotal
      ? SEV_ORDER.filter((k) => sev[k]).map((k) =>
          '<i class="hsb-' + k + '" style="flex:' + sev[k] + '" title="' +
          escapeHtml(sevLabel(k)) + ' ' + sev[k] + '"></i>').join('')
      : '<i class="hsb-none"></i>';
    const span = t.first_at
      ? (fmtDay(t.first_at) === fmtDay(t.last_at) ? fmtDay(t.first_at)
         : fmtDay(t.first_at) + ' ~ ' + fmtDay(t.last_at))
      : '—';
    const cards = [
      ['扫描次数', fmtNum(t.scans), '次', '覆盖 ' + fmtNum(t.targets) + ' 个审计目录'],
      ['累计隐患', fmtNum(t.findings), '项',
        '严重+高危 ' + fmtNum(t.high_total) + ' 项', bar],
      ['依赖漏洞', fmtNum(t.vulns), '条', '来自 SCA 依赖漏洞分析'],
      ['累计规模', fmtNum(t.files), '文件', fmtNum(t.lines) + ' 行代码'],
      ['时间跨度', escapeHtml(span), '', '最近一次 ' + fmtTime(t.last_at)],
    ];
    $('histKpis').innerHTML = cards.map(([label, val, unit, sub, extra]) =>
      '<div class="hk"><span>' + escapeHtml(label) + '</span>' +
      '<b>' + val + (unit ? '<em>' + unit + '</em>' : '') + '</b>' +
      (extra ? '<div class="hk-bar">' + extra + '</div>' : '') +
      '<i>' + escapeHtml(sub || '') + '</i></div>').join('');
  }

  function histCard(m) {
    const t = m.target || {};
    const sev = m.by_severity || {};
    const totalSev = SEV_ORDER.reduce((n, k) => n + (Number(sev[k]) || 0), 0);
    const bar = totalSev
      ? SEV_ORDER.filter((k) => sev[k]).map((k) =>
          '<i class="hsb-' + k + '" style="flex:' + sev[k] + '" title="' +
          escapeHtml(sevLabel(k)) + ' ' + sev[k] + '"></i>').join('')
      : '<i class="hsb-none" title="无命中"></i>';
    const idx = Number(m.risk_index) || 0;
    const lv = idx >= 70 ? 'hi' : idx >= 40 ? 'mid' : 'lo';
    const live = m.id === HIST.current;
    return '<article class="hcard' + (live ? ' live' : '') + '" data-pid="' + m.id +
      '" tabindex="0" role="button" aria-label="查看该次扫描的详情">' +
      '<div class="hc-when"><b>' + escapeHtml(fmtDay(m.created_at)) + '</b>' +
        '<span>' + escapeHtml(fmtClock(m.created_at)) + '</span>' +
        '<em>' + escapeHtml(fmtAgo(m.created_at)) + '</em></div>' +
      '<div class="hc-main">' +
        '<div class="hc-top"><b class="hc-name">' + escapeHtml(t.name || m.id) + '</b>' +
          '<span class="hst hst-' + escapeHtml(m.status || 'completed') + '">' +
            escapeHtml(m.status_label || m.status || '') + '</span>' +
          '<span class="hc-chip">' + (t.kind === 'upload' ? '上传副本' : '服务器目录') + '</span>' +
          (live ? '<span class="hc-chip cur">当前工作台</span>' : '') +
          '<span class="hc-id">' + escapeHtml(m.id) + '</span></div>' +
        '<div class="hc-path" title="' + escapeHtml(t.root || '') + '">' +
          escapeHtml(t.root || '—') + '</div>' +
        '<div class="hc-metrics">' +
          '<span><em>规模</em>' + fmtNum(m.files_total) + ' 文件 / ' +
            fmtNum(m.lines_total) + ' 行</span>' +
          '<span><em>隐患</em><b>' + fmtNum(m.findings_total) + '</b></span>' +
          '<span><em>严重+高危</em><b class="' + (m.high_total ? 'hi' : '') + '">' +
            fmtNum(m.high_total) + '</b></span>' +
          '<span><em>依赖漏洞</em><b class="' + (m.vuln_total ? 'hi' : '') + '">' +
            fmtNum(m.vuln_total) + '</b></span>' +
          '<span><em>耗时</em>' + escapeHtml(fmtDur(m.elapsed)) + '</span>' +
          '<span><em>快照</em>' + escapeHtml(fmtBytes(m.size_bytes)) + '</span></div>' +
        '<div class="hc-sevbar">' + bar + '</div>' +
      '</div>' +
      '<div class="hc-side">' +
        '<div class="hc-ring ' + lv + '"><b>' + idx + '</b><span>风险指数</span></div>' +
        '<div class="hc-ops">' +
          '<button class="mini" data-act="open" data-pid="' + m.id + '">查看详情 →</button>' +
          (live ? '' : '<button class="mini danger" data-act="del" data-pid="' + m.id +
            '" title="删除该记录及其全部数据">✕</button>') +
        '</div>' +
      '</div>' +
    '</article>';
  }

  function renderHistory(keepScroll) {
    renderHistKpis();
    const list = histFiltered();
    const v = HIST.view;
    const size = Number(v.size) || 20;
    const pages = Math.max(1, Math.ceil(list.length / size));
    if (v.page > pages) v.page = pages;
    if (v.page < 1) v.page = 1;
    const start = (v.page - 1) * size;
    const pageItems = list.slice(start, start + size);

    $('histCount').textContent = list.length === HIST.items.length
      ? '共 ' + fmtNum(HIST.items.length) + ' 条记录'
      : '筛选出 ' + fmtNum(list.length) + ' / ' + fmtNum(HIST.items.length) + ' 条';

    const host = $('histList');
    const pager = $('histPager');
    if (!HIST.items.length) {
      host.innerHTML = '<div class="h-empty"><b>还没有扫描记录</b>' +
        '<span>回到工作台，选择审计目录后点「开始扫描」——每次扫描都会自动建档并出现在这里。</span>' +
        '<button class="primary" data-act="workbench">返回工作台</button></div>';
      pager.hidden = true;
      return;
    }
    if (!pageItems.length) {
      host.innerHTML = '<div class="h-empty"><b>没有匹配的记录</b>' +
        '<span>试着放宽关键字或状态筛选条件。</span>' +
        '<button class="mini" data-act="reset">清除筛选</button></div>';
      pager.hidden = true;
      return;
    }
    host.innerHTML = pageItems.map(histCard).join('');
    if (pages <= 1) {
      pager.hidden = true;
    } else {
      pager.hidden = false;
      pager.innerHTML =
        '<button class="mini" data-page="prev"' + (v.page <= 1 ? ' disabled' : '') +
          '>‹ 上一页</button>' +
        '<span>第 ' + v.page + ' / ' + pages + ' 页 · 第 ' + (start + 1) + '–' +
          (start + pageItems.length) + ' 条</span>' +
        '<button class="mini" data-page="next"' + (v.page >= pages ? ' disabled' : '') +
          '>下一页 ›</button>';
    }
    const sc = $('histScroll');
    const y = keepScroll ? (Number(SS.get(SCROLL_KEY, 0)) || 0) : 0;
    requestAnimationFrame(() => { try { sc.scrollTop = y; } catch (e) { /* 忽略 */ } });
  }

  /* 列表页 → 详情页：只传主键，并顺手缓存行概览用于详情页秒开 */
  function gotoDetailFromCard(pid) {
    const m = HIST.items.filter((x) => x.id === pid)[0];
    if (m) SS.set(ROW_KEY(pid), m);
    goDetail(pid);
  }

  async function deleteProject(pid) {
    const m = HIST.items.filter((x) => x.id === pid)[0] || {};
    const name = (m.target || {}).name || pid;
    if (!confirm('删除这次扫描记录？\n\n' + name + '\n' + pid +
                 '\n\n该项目的结果快照、依赖与漏洞数据会被彻底清除，且不可恢复。')) return false;
    try {
      await api('/api/project/delete', { method: 'POST', body: { id: pid } });
      if (VIEW_PID === pid) { VIEW_PID = ''; }
      SS.del(ROW_KEY(pid));
      toast('已删除记录 ' + pid, 'ok');
      return true;
    } catch (e) {
      toast(e.message, 'err', 5200);
      return false;
    }
  }

  /* ---------------------------------------------------------- 二级：详情页 */
  async function showHistDetail(pid) {
    if (!pid) { goHistory(); return; }
    const key = 'd:' + pid;
    if (HIST.lastRendered === key && !$('pageHistDetail').hidden) return;
    HIST.lastRendered = key;
    HIST.detailPid = pid;

    // ② 用 sessionStorage 里的行概览先渲染页头与骨架（刷新详情页同样有效）
    renderDetailShell(SS.get(ROW_KEY(pid), null), pid);
    try {
      const d = await api('/api/project/detail?id=' + encodeURIComponent(pid));
      if (HIST.detailPid !== pid) return;          // 期间又跳到了别的详情页
      HIST.detail = d;
      renderDetail(d);
    } catch (e) {
      $('detBody').innerHTML = '<div class="h-empty"><b>无法加载这次扫描的详情</b>' +
        '<span>' + escapeHtml(e.message) + '</span>' +
        '<button class="mini" data-act="back">← 返回扫描历史</button></div>';
    }
  }

  function renderDetailShell(row, pid) {
    if (row) {
      const t = row.target || {};
      $('detTitle').textContent = t.name || row.id;
      $('detSub').innerHTML = escapeHtml(row.id) + ' · ' +
        '<span class="hst hst-' + escapeHtml(row.status || 'completed') + '">' +
        escapeHtml(row.status_label || '') + '</span> · 建档 ' +
        escapeHtml(fmtTime(row.created_at, true)) + ' · 正在读取完整数据…';
    } else {
      $('detTitle').textContent = '扫描详情';
      $('detSub').textContent = pid + ' · 正在读取完整数据…';
    }
    $('detBody').innerHTML = '<div class="det-skel"><div class="skel-kpis">' +
      '<i></i><i></i><i></i><i></i><i></i><i></i></div>' +
      '<div class="skel-block"></div><div class="skel-block"></div></div>';
  }

  function dcard(title, sub, body, cls) {
    return '<section class="dcard' + (cls ? ' ' + cls : '') + '">' +
      '<header class="dc-head"><b>' + title + '</b>' +
      (sub ? '<span>' + sub + '</span>' : '') + '</header>' +
      '<div class="dc-body">' + body + '</div></section>';
  }

  function renderDetail(d) {
    const m = d.meta || {}, t = d.target || {}, cfg = d.config || {};
    const sv = d.severity || {}, idx = d.index || {};
    const dp = d.deps || {}, v = dp.vuln || {}, vs = v.summary || {};
    const sev = sv.by_severity || {};
    const total = Number(sv.total) || 0;

    /* ---- 页头 ---- */
    $('detTitle').textContent = t.name || m.id;
    $('detSub').innerHTML = escapeHtml(m.id) + ' · ' +
      '<span class="hst hst-' + escapeHtml(m.status || 'completed') + '">' +
      escapeHtml(m.status_label || '') + '</span>' +
      (d.live ? ' · <span class="hc-chip cur">当前工作台</span>' : '') +
      ' · 建档 ' + escapeHtml(fmtTime(m.created_at, true)) +
      ' · ' + escapeHtml(fmtAgo(m.created_at));

    /* ---- 异常状态横幅 ---- */
    const warn = (m.status === 'error' || m.status === 'interrupted')
      ? '<div class="det-warn ' + escapeHtml(m.status) + '"><b>' +
        escapeHtml(m.status_label || '') + '</b>' +
        escapeHtml(m.error || (m.status === 'interrupted'
          ? '扫描进程中断，未生成结果快照，此处仅保留建档信息。' : '')) + '</div>'
      : '';

    /* ---- 关键指标 ---- */
    const kpis = [
      ['风险指数', String(m.risk_index == null ? '—' : m.risk_index), '0–100，越高越应优先处置'],
      ['隐患总数', fmtNum(m.findings_total), '严重 ' + fmtNum(sev.critical || 0) +
        ' · 高危 ' + fmtNum(sev.high || 0) + ' · 中危 ' + fmtNum(sev.medium || 0)],
      ['工程规模', fmtNum(m.files_total) + ' 文件', fmtNum(m.lines_total) + ' 行 · 有命中的文件 ' +
        fmtNum(m.files_with_findings || 0) + ' 个'],
      ['扫描耗时', fmtDur(m.elapsed), '开始于 ' + fmtTime(m.created_at)],
      ['依赖清单', fmtNum(dp.manifests) + ' 个', '解析出依赖 ' + fmtNum(dp.total) + ' 项' +
        (dp.unresolved ? ' · 版本未定 ' + fmtNum(dp.unresolved) : '')],
      ['依赖漏洞', fmtNum(m.vuln_total) + ' 条', '受影响依赖 ' + fmtNum(m.vuln_packages || 0) +
        ' 个 · 可修复 ' + fmtNum(m.vuln_fixable || 0) + ' 个'],
    ];
    const kpiHtml = kpis.map(([label, val, sub]) =>
      '<div class="dk"><span>' + escapeHtml(label) + '</span>' +
      '<b>' + escapeHtml(val) + '</b><i>' + escapeHtml(sub) + '</i></div>').join('');

    /* ---- 严重程度分布 ---- */
    const sevRows = SEV_ORDER.map((k) => {
      const n = Number(sev[k]) || 0;
      const pct = total ? Math.round(n / total * 100) : 0;
      return '<div class="sv-row"><span class="sv-dot s-' + k + '"></span>' +
        '<b>' + escapeHtml(sevLabel(k)) + '</b>' +
        '<div class="sv-track"><i class="s-' + k + '" style="width:' + pct + '%"></i></div>' +
        '<em>' + fmtNum(n) + '<small>' + pct + '%</small></em></div>';
    }).join('');
    const scope = idx.by_scope || {};
    const scopeHtml = Object.keys(scope).filter((k) => scope[k]).map((k) =>
      '<span class="tag-mini">' + escapeHtml(SCOPE_CN[k] || k) + ' ' + fmtNum(scope[k]) + '</span>')
      .join(' ') || '<span class="tag-mini">—</span>';

    /* ---- 时间线 ---- */
    const tline = (d.timeline || []).map((n) =>
      '<div class="tl-node"><i></i><div><b>' + escapeHtml(n.label) + '</b>' +
      '<span>' + (n.at ? escapeHtml(fmtTime(n.at, true)) : '未发生') + '</span>' +
      '<em>' + escapeHtml(n.note || '') + '</em></div></div>').join('');

    /* ---- 扫描配置（追溯当时参数） ---- */
    const cfgRows = [
      ['审计目录', cfg.root || '—', 'mono'],
      ['目标来源', cfg.kind === 'upload' ? '浏览器上传副本（workspaces/）' : '服务器本地目录', ''],
      ['排除目录', (cfg.excludes || []).length + ' 项' +
        ((cfg.excludes || []).length
          ? '：' + (cfg.excludes || []).slice(0, 10).join('、') +
            ((cfg.excludes || []).length > 10 ? ' …' : '')
          : ''), 'small'],
      ['启用严重级别', (cfg.severities || []).map((s) => sevLabel(s)).join(' / ') || '—', ''],
      ['启用漏洞类型', (cfg.categories || []).length + ' 类', ''],
      ['依赖漏洞扫描', cfg.vulndb_enabled
        ? ('已启用（数据源 ' + escapeHtml(v.source || 'OSV.dev') + '）') : '未启用', ''],
      ['工具 / 规则库', escapeHtml(cfg.tool_version || '—') + ' · ' +
        fmtNum(cfg.rule_count) + ' 条规则', ''],
    ];
    const cfgHtml = cfgRows.map(([k, val, cls]) =>
      '<div class="kv2"><span>' + escapeHtml(k) + '</span>' +
      '<b class="' + cls + '">' + (cls === 'mono' ? escapeHtml(val) : val) + '</b></div>').join('');

    /* ---- 风险构成 ---- */
    const catRows = (idx.by_category || []).map((c) => {
      const pct = idx.total ? Math.round(c.count / idx.total * 100) : 0;
      return '<div class="cat-row"><b>' + escapeHtml(catLabel(c.key)) + '</b>' +
        '<div class="cat-track"><i style="width:' + pct + '%"></i></div>' +
        '<em>' + fmtNum(c.count) + '<small>' + pct + '%</small></em></div>';
    }).join('') || '<div class="empty-mini">未采集到类型分布</div>';
    const ruleRows = (idx.by_rule || []).map((r) =>
      '<tr><td><span class="sv-pill s-' + escapeHtml(r.severity || 'info') + '">' +
        escapeHtml(r.severity_label || '') + '</span></td>' +
      '<td class="mono">' + escapeHtml(r.rule_id || '') + '</td>' +
      '<td>' + escapeHtml(r.category_label || r.category || '') + '</td>' +
      '<td class="num">' + fmtNum(r.count) + '</td></tr>').join('') ||
      '<tr><td colspan="4" class="empty-mini">未采集到规则分布</td></tr>';
    const langRows = (idx.by_language || []).map((l) =>
      '<span class="tag-mini">' + escapeHtml(l.key) + ' ' + fmtNum(l.count) + '</span>').join(' ') ||
      '<span class="tag-mini">—</span>';

    /* ---- 高危隐患清单 ---- */
    const fRows = (d.findings || []).map((f) =>
      '<tr>' +
      '<td><span class="sv-pill s-' + escapeHtml(f.severity) + '">' +
        escapeHtml(f.severity_label || f.severity) + '</span></td>' +
      '<td class="mono">' + escapeHtml(f.rule_id) + '</td>' +
      '<td class="fcell"><span class="floc" data-act="goto" data-file="' +
        escapeHtml(f.file) + '" data-line="' + escapeHtml(String(f.line)) +
        '" title="在工作台中打开该文件">' + escapeHtml(f.file) + ':' +
        escapeHtml(String(f.line)) + '</span>' +
        '<i>' + escapeHtml(f.title) + '</i></td>' +
      '<td class="num">' + escapeHtml(f.confidence || '—') + '</td>' +
      '</tr>').join('') ||
      '<tr><td colspan="4" class="empty-mini">本次扫描没有命中任何隐患</td></tr>';

    /* ---- 依赖与漏洞 ---- */
    const ecoTags = Object.keys(dp.by_ecosystem || {}).filter((k) => dp.by_ecosystem[k])
      .map((k) => '<span class="tag-mini">' + escapeHtml(k) + ' ' +
        fmtNum(dp.by_ecosystem[k]) + '</span>').join(' ') || '<span class="tag-mini">—</span>';
    const vRows = (v.top || []).map((x) =>
      '<tr><td><span class="sv-pill s-' + escapeHtml(x.severity || 'info') + '">' +
        escapeHtml(x.severity || '') + '</span></td>' +
      '<td class="num">' + escapeHtml(String(x.cvss == null ? '—' : x.cvss)) + '</td>' +
      '<td class="mono">' + escapeHtml(x.package) + '<i>@' + escapeHtml(x.version) + '</i></td>' +
      '<td>' + (x.has_fix
        ? '<span class="fix-ok">可升级至 ' + escapeHtml(x.fixed || '') + '</span>'
        : '<span class="fix-no">暂无官方修复</span>') + '</td>' +
      '<td class="fcell">' + escapeHtml(x.title || x.vuln_id) +
        '<i class="mono">' + escapeHtml(x.cve || x.vuln_id) + '</i></td></tr>').join('') ||
      '<tr><td colspan="5" class="empty-mini">' +
        (v.error ? '依赖漏洞分析未成功' : '未发现已知漏洞或未采集到依赖') + '</td></tr>';
    const vSum = Object.keys(vs).length
      ? ('漏洞 ' + fmtNum(vs.vuln_total) + ' 条 · 受影响依赖 ' + fmtNum(vs.vuln_packages) +
         ' 个 · 可修复 ' + fmtNum(vs.fixable) + ' · 无修复 ' + fmtNum(vs.no_fix))
      : (v.error ? '分析失败' : '未采集');

    /* ---- 处置建议 ---- */
    const adv = (d.advice || []).map((a) =>
      '<li>' + escapeHtml(a) + '</li>').join('') ||
      '<li>本次扫描未发现需要特别处置的事项。</li>';

    /* ---- 组装 ---- */
    $('detBody').innerHTML =
      warn +
      dcard('关键指标', '本次扫描的核心结论', '<div class="det-kpis">' + kpiHtml + '</div>') +
      dcard('严重程度分布', '共 ' + fmtNum(total) + ' 项命中 · 作用域：' + scopeHtml,
            '<div class="sv-list">' + sevRows + '</div>') +
      dcard('执行时间线', '从建档到依赖分析的完整过程', '<div class="tl">' + tline + '</div>') +
      dcard('扫描配置', '可追溯当时使用的目录、过滤条件与规则库版本',
            '<div class="kv-grid">' + cfgHtml + '</div>') +
      dcard('风险构成', '按漏洞类型与规则聚合',
            '<div class="cat-list">' + catRows + '</div>' +
            '<div class="dc-sub">命中最多的规则</div>' +
            '<table class="dtable"><thead><tr><th>等级</th><th>规则</th><th>类型</th>' +
            '<th class="num">数量</th></tr></thead><tbody>' + ruleRows + '</tbody></table>' +
            '<div class="dc-sub">语言分布</div><div class="tag-wrap">' + langRows + '</div>') +
      dcard('高危隐患清单', '按「严重度 → 置信度 → 文件行号」排序，共 ' + fmtNum(idx.total) +
            ' 项，此处展示前 ' + fmtNum(idx.shown) + ' 项',
            '<table class="dtable ftable"><thead><tr><th>等级</th><th>规则</th>' +
            '<th>文件 / 问题</th><th class="num">置信度</th></tr></thead><tbody>' +
            fRows + '</tbody></table>' +
            '<div class="dc-note">点击文件路径可在工作台中打开对应源码位置。</div>') +
      dcard('依赖与漏洞', escapeHtml(vSum),
            '<div class="kv-grid">' +
            '<div class="kv2"><span>依赖清单</span><b>' + fmtNum(dp.manifests) + ' 个</b></div>' +
            '<div class="kv2"><span>依赖项总数</span><b>' + fmtNum(dp.total) + ' 项</b></div>' +
            '<div class="kv2"><span>生态分布</span><b>' + ecoTags + '</b></div>' +
            '<div class="kv2"><span>版本未确定</span><b>' + fmtNum(dp.unresolved) + ' 项</b></div>' +
            '</div>' +
            (v.error ? '<div class="det-warn partial"><b>依赖漏洞分析未成功</b>' +
              escapeHtml(v.error) + '</div>' : '') +
            '<table class="dtable"><thead><tr><th>等级</th><th class="num">CVSS</th>' +
            '<th>依赖</th><th>修复</th><th>漏洞</th></tr></thead><tbody>' + vRows +
            '</tbody></table>') +
      dcard('下一步处置建议', '依据本次扫描数据自动推导', '<ul class="adv">' + adv + '</ul>') +
      '<div class="det-foot">项目 ID <b class="mono">' + escapeHtml(m.id) + '</b> · ' +
      '快照体积 ' + escapeHtml(fmtBytes(d.integrity ? d.integrity.size_bytes : 0)) + ' · ' +
      (d.integrity && d.integrity.root_exists
        ? '源目录可用（可在工作台中打开源码浏览）'
        : '源目录已不可访问（仍可查看结果与导出报告）') + '</div>';
  }

  /* ---- 详情页导出：按格式下载该项目的报告快照 ---- */
  function detExport(fmtKey) {
    const pid = HIST.detailPid;
    const q = new URLSearchParams({ format: fmtKey });
    if (pid) q.set('project', pid);
    const link = document.createElement('a');
    link.href = '/api/export?' + q.toString();
    link.download = '';
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    setTimeout(() => {
      link.remove();
      toast('报告已生成，同时存档至 reports 目录', 'ok', 3600);
    }, 1500);
  }

  function toggleDetMenu() {
    const host = $('detExport');
    const old = $('detMenu');
    if (old) { old.remove(); return; }
    const formats = (S.meta && S.meta.formats) || [];
    const el = document.createElement('div');
    el.className = 'det-menu';
    el.id = 'detMenu';
    el.innerHTML = formats.map((f) =>
      '<button data-fmt="' + f.key + '">' + escapeHtml(f.label) + '</button>').join('');
    host.parentNode.appendChild(el);
    el.addEventListener('click', (e) => {
      const b = e.target.closest('button[data-fmt]');
      if (!b) return;
      el.remove();
      detExport(b.dataset.fmt);
    });
    setTimeout(() => {
      const close = (ev) => {
        if (el.contains(ev.target) || ev.target === host) return;
        el.remove();
        document.removeEventListener('click', close);
      };
      document.addEventListener('click', close);
    }, 0);
  }

  /* ---- 历史页事件绑定 ---- */
  function bindHistoryPages() {
    $('histBack').addEventListener('click', goWorkbench);
    $('histRefresh').addEventListener('click', () => loadHistory(false));
    $('histKw').addEventListener('input', debounce(() => {
      HIST.view.kw = $('histKw').value;
      HIST.view.page = 1;
      persistView(); renderHistory(false);
    }, 180));
    $('histStatus').addEventListener('change', () => {
      HIST.view.status = $('histStatus').value;
      HIST.view.page = 1; persistView(); renderHistory(false);
    });
    $('histSort').addEventListener('change', () => {
      HIST.view.sort = $('histSort').value;
      HIST.view.page = 1; persistView(); renderHistory(false);
    });
    $('histSize').addEventListener('change', () => {
      HIST.view.size = Number($('histSize').value) || 20;
      HIST.view.page = 1; persistView(); renderHistory(false);
    });
    $('histScroll').addEventListener('scroll', debounce(() => {
      SS.set(SCROLL_KEY, $('histScroll').scrollTop || 0);
    }, 200));

    const onListClick = async (e) => {
      const act = e.target.closest('[data-act]');
      if (act) {
        const a = act.dataset.act;
        if (a === 'workbench') { goWorkbench(); return; }
        if (a === 'reset') {
          HIST.view.kw = ''; HIST.view.status = 'all'; HIST.view.page = 1;
          persistView(); syncHistTools(); renderHistory(false);
          return;
        }
        if (a === 'open') { gotoDetailFromCard(act.dataset.pid); return; }
        if (a === 'del') {
          if (await deleteProject(act.dataset.pid)) await loadHistory(false);
          return;
        }
      }
      const card = e.target.closest('.hcard');
      if (card) gotoDetailFromCard(card.dataset.pid);
    };
    $('histList').addEventListener('click', onListClick);
    $('histList').addEventListener('keydown', (e) => {
      if (e.key !== 'Enter' && e.key !== ' ') return;
      const card = e.target.closest('.hcard');
      if (!card) return;
      e.preventDefault();
      gotoDetailFromCard(card.dataset.pid);
    });
    $('histPager').addEventListener('click', (e) => {
      const b = e.target.closest('button[data-page]');
      if (!b || b.disabled) return;
      HIST.view.page += (b.dataset.page === 'next' ? 1 : -1);
      persistView();
      renderHistory(false);
      try { $('histScroll').scrollTop = 0; } catch (err) { /* 忽略 */ }
    });

    $('detBack').addEventListener('click', goHistory);
    $('detExport').addEventListener('click', (e) => { e.stopPropagation(); toggleDetMenu(); });
    $('detOpen').addEventListener('click', async () => {
      const pid = HIST.detailPid;
      if (!pid) return;
      try {
        await openInWorkbench(pid);            // 载入工作台（只读历史项目）
      } catch (e) {
        toast('载入工作台失败：' + e.message, 'err', 4500);
      }
    });
    $('detDelete').addEventListener('click', async () => {
      const pid = HIST.detailPid;
      if (!pid) return;
      if (await deleteProject(pid)) goHistory();
    });
    $('detBody').addEventListener('click', (e) => {
      const t = e.target.closest('[data-act]');
      if (!t) return;
      const a = t.dataset.act;
      if (a === 'back') { goHistory(); return; }
      if (a === 'goto') {
        openInWorkbench(HIST.detailPid, t.dataset.file,
                        parseInt(t.dataset.line, 10) || 0).catch((err) => {
          toast('打开失败：' + err.message, 'err', 4200);
        });
      }
    });

    window.addEventListener('hashchange', applyRoute);
  }

  document.addEventListener('DOMContentLoaded', init);
})();
