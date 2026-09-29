/**
 * 依赖风险面板的真实浏览器验收（CDP 驱动无头 Chromium，零依赖）。
 *
 * ⚠️ 开发机专用验收脚本，不随便携交付运行：
 *    CHROME 常量为开发机 Playwright Chromium 路径，在其他电脑上使用前
 *    请改为本机已安装的 Chrome/Chromium 可执行文件路径（仅需改这一行）。
 *
 * 覆盖点：
 *   1. 中栏出现「依赖风险」标签，徽标数字与实际漏洞数一致
 *   2. 概览卡「依赖漏洞」可点击并跳转到该标签
 *   3. 摘要区、筛选器、排序、聚合、搜索均可用且结果正确变化
 *   4. 严重程度筛选 chip 生效
 *   5. 分组视图可展开并懒加载明细
 *   6. 依赖清单弹窗中出现漏洞标记
 *   7. 桌面 / 移动端两种视口下均无横向溢出或元素重叠
 */
import { spawn } from 'node:child_process';
import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';

const CHROME = 'C:/Users/wk/AppData/Local/ms-playwright/chromium-1228/chrome-win64/chrome.exe';
const APP = 'http://127.0.0.1:8770';
const OUT = path.join(process.cwd(), 'reports', 'shots');
const PORT = 9333;
fs.mkdirSync(OUT, { recursive: true });

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function getJSON(url) {
  return new Promise((resolve, reject) => {
    http.get(url, (res) => {
      let b = '';
      res.on('data', (c) => (b += c));
      res.on('end', () => { try { resolve(JSON.parse(b)); } catch (e) { reject(e); } });
    }).on('error', reject);
  });
}

let pass = 0, fail = 0;
function check(name, ok, extra) {
  if (ok) { pass++; console.log(`  PASS  ${name}${extra ? '  — ' + extra : ''}`); }
  else { fail++; console.log(`  FAIL  ${name}${extra ? '  — ' + extra : ''}`); }
}

const chrome = spawn(CHROME, [
  '--headless=new', `--remote-debugging-port=${PORT}`,
  '--no-first-run', '--no-default-browser-check', '--disable-gpu',
  '--window-size=1680,1000', '--user-data-dir=' + path.join(process.cwd(), '_tmp', 'cdp-profile-vuln'),
  '--disable-features=Translate,BackForwardCache', 'about:blank',
], { stdio: 'ignore' });

let wsUrl = null;
for (let i = 0; i < 60 && !wsUrl; i++) {
  await sleep(400);
  try {
    const v = await getJSON(`http://127.0.0.1:${PORT}/json/version`);
    wsUrl = v.webSocketDebuggerUrl;
  } catch (e) { /* 还没起来 */ }
}
if (!wsUrl) { console.error('无法启动 Chromium'); chrome.kill(); process.exit(1); }

const ws = new WebSocket(wsUrl);
await new Promise((r) => { ws.onopen = r; });
let msgId = 0;
const pending = new Map();
const events = [];
ws.onmessage = (ev) => {
  const m = JSON.parse(ev.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m); pending.delete(m.id); }
  else if (m.method) events.push(m);
};
function send(method, params, sessionId) {
  const id = ++msgId;
  return new Promise((resolve, reject) => {
    pending.set(id, (m) => (m.error ? reject(new Error(m.method + ': ' + m.error.message)) : resolve(m.result)));
    ws.send(JSON.stringify({ id, method, params, sessionId }));
  });
}

const { targetId } = await send('Target.createTarget', { url: 'about:blank' });
const { sessionId } = await send('Target.attachToTarget', { targetId, flatten: true });
const S = (method, params) => send(method, params, sessionId);
await S('Page.enable');
await S('Runtime.enable');
await S('Network.enable');

async function evaluate(expr, awaitPromise = false) {
  const r = await S('Runtime.evaluate', {
    expression: expr, returnByValue: true, awaitPromise, userGesture: true,
  });
  if (r.exceptionDetails) throw new Error(r.exceptionDetails.exception?.description || 'eval 失败');
  return r.result.value;
}
async function goto(url) {
  await S('Page.navigate', { url });
  for (let i = 0; i < 60; i++) {
    await sleep(300);
    const ok = await evaluate('document.readyState === "complete" && !!document.getElementById("vulnBody")').catch(() => false);
    if (ok) break;
  }
  await sleep(700);
}
async function viewport(w, h, mobile = false) {
  await S('Emulation.setDeviceMetricsOverride', {
    width: w, height: h, deviceScaleFactor: 1, mobile,
  });
  await sleep(320);
}
async function shot(name) {
  const r = await S('Page.captureScreenshot', { format: 'png' });
  fs.writeFileSync(path.join(OUT, name), Buffer.from(r.data, 'base64'));
}

console.log('='.repeat(78));
console.log('依赖风险面板 · 真实浏览器验收');
console.log('='.repeat(78));

// ---------------------------------------------------------------- 准备数据
// 触发一次扫描并等待漏洞分析完成，保证页面有数据可验
const post = (p, body) => new Promise((resolve, reject) => {
  const data = JSON.stringify(body || {});
  const req = http.request(APP + p, {
    method: 'POST', headers: { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(data) },
  }, (res) => { let b = ''; res.on('data', (c) => (b += c)); res.on('end', () => resolve(JSON.parse(b))); });
  req.on('error', reject);
  req.write(data); req.end();
});
const get = (p) => new Promise((resolve, reject) => {
  http.get(APP + p, (res) => { let b = ''; res.on('data', (c) => (b += c)); res.on('end', () => resolve(JSON.parse(b))); }).on('error', reject);
});

const ROOT = 'C:\\Users\\wk\\Desktop\\雕塑北京源代码';
const meta0 = (await get('/api/meta')).data;
const prevTarget = meta0.target || null;

await post('/api/scan', { root: ROOT, label: '雕塑北京源代码', kind: 'path' });
for (let i = 0; i < 120; i++) { await sleep(1000); const p = (await get('/api/progress')).data; if (p.done) break; }
let vulnSummary = {};
for (let i = 0; i < 180; i++) {
  await sleep(1000);
  const st = (await get('/api/vulndb/status')).data;
  if (!st.running && st.analyzed_at) { vulnSummary = st.summary || {}; break; }
}
const apiVulns = (await get('/api/vulns?limit=300')).data;
console.log(`\n[基线] 依赖 ${apiVulns.deps_meta.total} 项，漏洞 ${apiVulns.summary.vuln_total} 条，`
  + `受影响依赖 ${apiVulns.summary.vuln_packages} 个\n`);

// 归一化基线：离线开关初始置为「关」，使第 [10] 组的往返断言可复现，且不把服务留在离线态
{
  const stNow = (await get('/api/vulndb/status')).data;
  if (stNow.offline) {
    await post('/api/vulndb/update', { refresh: false, offline: false });
    for (let i = 0; i < 60; i++) {
      await sleep(500);
      const st = (await get('/api/vulndb/status')).data;
      if (!st.running && st.offline === false) break;
    }
    console.log('[基线] 离线开关已归位为「关」\n');
  }
}

// ---------------------------------------------------------------- 桌面端
await viewport(1680, 1000);
await goto(APP + '/#deps');
await sleep(1600);

console.log('[1] 标签与徽标');
check('中栏存在「依赖风险」标签',
  await evaluate('!!document.querySelector("#centerTabs button[data-tab=deps]")'));
check('点击标签后该面板处于激活态',
  await evaluate('document.getElementById("tabDeps").classList.contains("on")'));
const badge = await evaluate('document.getElementById("depsBadge").textContent');
check('徽标数字与接口一致',
  badge === String(apiVulns.summary.vuln_total), `徽标=${badge} 接口=${apiVulns.summary.vuln_total}`);

console.log('[2] 顶部摘要与状态');
const kpi = await evaluate('document.getElementById("kpiVulns").textContent');
check('概览卡显示漏洞总数', kpi === String(apiVulns.summary.vuln_total), `kpi=${kpi}`);
const srcTxt = await evaluate('document.getElementById("vulnSrc").textContent');
check('数据源标识正确', srcTxt.includes('OSV.dev'), srcTxt);
const metaTxt = await evaluate('document.getElementById("vulnMeta").textContent');
check('状态栏含更新时间和已查询依赖数',
  metaTxt.includes('更新于') && metaTxt.includes('已查询'), metaTxt.slice(0, 80));
const sumItems = await evaluate('document.querySelectorAll(".vuln-sum-item").length');
check('摘要卡渲染完整（7 项）', sumItems === 7, String(sumItems));

console.log('[3] 漏洞卡片内容');
const cards = await evaluate('document.querySelectorAll(".vuln-card").length');
check('卡片数与接口返回一致', cards === apiVulns.findings.length, `卡片=${cards} 接口=${apiVulns.findings.length}`);
const firstCard = await evaluate(`(() => {
  const c = document.querySelector('.vuln-card');
  if (!c) return null;
  return {
    cls: c.className,
    hasBadge: !!c.querySelector('.badge'),
    hasCvss: !!c.querySelector('.vuln-cvss'),
    hasId: !!c.querySelector('.vuln-id'),
    hasAdvice: !!c.querySelector('.vuln-advice'),
    hasDep: !!c.querySelector('.vuln-dep'),
    adviceLen: (c.querySelector('.vuln-advice') || {}).textContent?.length || 0,
  };
})()`);
check('首卡含等级徽标 / CVSS / 编号 / 依赖 / 建议',
  !!(firstCard && firstCard.hasBadge && firstCard.hasCvss && firstCard.hasId
     && firstCard.hasDep && firstCard.hasAdvice), JSON.stringify(firstCard));
check('首卡为最高等级（critical）', firstCard && firstCard.cls.includes('sev-critical'), firstCard?.cls);
const cmdCount = await evaluate('document.querySelectorAll(".vuln-advice .cmd").length');
const fixable = apiVulns.findings.filter((f) => f.command).length;
check('升级命令胶囊数量相符', cmdCount === fixable, `胶囊=${cmdCount} 可修复=${fixable}`);

console.log('[4] 排序与筛选');
const sevSeq = await evaluate(`Array.from(document.querySelectorAll('.vuln-card')).slice(0,30)
  .map(c => (c.className.match(/sev-(\\w+)/)||[])[1])`);
const order = ['critical', 'high', 'medium', 'low', 'info'];
const idx = sevSeq.map((s) => order.indexOf(s));
check('默认按严重程度降序排列', idx.every((v, i) => i === 0 || idx[i - 1] <= v), sevSeq.join(','));

await evaluate(`(() => { const s = document.getElementById('vulnSort');
  s.value = 'cvss'; s.dispatchEvent(new Event('change', {bubbles:true})); })()`);
await sleep(900);
const cvssSeq = await evaluate(`Array.from(document.querySelectorAll('.vuln-cvss'))
  .slice(0,20).map(e => parseFloat(e.textContent))`);
check('按 CVSS 排序生效', cvssSeq.every((v, i) => i === 0 || cvssSeq[i - 1] >= v), cvssSeq.join(','));
await evaluate(`(() => { const s = document.getElementById('vulnSort');
  s.value = 'severity'; s.dispatchEvent(new Event('change', {bubbles:true})); })()`);
await sleep(800);

await evaluate(`(() => { const b = document.querySelector('#vulnSevChips button[data-sev=critical]');
  if (b && !b.disabled) b.click(); })()`);
await sleep(900);
const critOnly = await evaluate(`Array.from(document.querySelectorAll('.vuln-card'))
  .every(c => c.className.includes('sev-critical'))`);
const critCount = await evaluate('document.querySelectorAll(".vuln-card").length');
check('严重等级筛选只看严重',
  critOnly && critCount === apiVulns.by_severity.critical,
  `${critCount} 条（接口 ${apiVulns.by_severity.critical}）`);
await shot('20-vuln-critical-filter.png');
await evaluate(`document.querySelector('#vulnSevChips button[data-sev=all]').click()`);
await sleep(800);

const noFixN = apiVulns.findings.filter((f) => !f.has_fix).length;
await evaluate(`(() => { const s = document.getElementById('vulnFix');
  s.value = 'none'; s.dispatchEvent(new Event('change', {bubbles:true})); })()`);
await sleep(900);
const noFixCards = await evaluate('document.querySelectorAll(".vuln-card").length');
check('「暂无修复版本」筛选生效', noFixCards === noFixN, `${noFixCards} 条（接口 ${noFixN}）`);
await evaluate(`(() => { const s = document.getElementById('vulnFix');
  s.value = 'all'; s.dispatchEvent(new Event('change', {bubbles:true})); })()`);
await sleep(800);

console.log('[5] 搜索');
await evaluate(`(() => { const i = document.getElementById('vulnSearch');
  i.value = 'fastjson'; i.dispatchEvent(new Event('input', {bubbles:true})); })()`);
await sleep(1000);
const kwCards = await evaluate('document.querySelectorAll(".vuln-card").length');
const kwExpect = apiVulns.findings.filter((f) => (f.package + f.title).toLowerCase().includes('fastjson')).length;
check('关键字搜索命中 fastjson', kwCards === kwExpect, `${kwCards} 条（接口 ${kwExpect}）`);
await shot('21-vuln-search.png');
await evaluate(`document.getElementById('vulnSearchClear').click()`);
await sleep(900);

console.log('[6] 分组聚合');
await evaluate(`(() => { const s = document.getElementById('vulnGroup');
  s.value = 'package'; s.dispatchEvent(new Event('change', {bubbles:true})); })()`);
await sleep(1100);
const groups = await evaluate('document.querySelectorAll(".vuln-group").length');
check('按依赖包聚合分组渲染', groups > 1, `${groups} 组`);
await evaluate(`document.querySelector('.vuln-group .vuln-group-head').click()`);
await sleep(1400);
const inGroup = await evaluate(`document.querySelectorAll('.vuln-group.open .vuln-group-items .vuln-card').length`);
check('分组展开后懒加载出明细卡片', inGroup > 0, `${inGroup} 张`);
await shot('22-vuln-grouped.png');
await evaluate(`(() => { const s = document.getElementById('vulnGroup');
  s.value = ''; s.dispatchEvent(new Event('change', {bubbles:true})); })()`);
await sleep(900);

console.log('[7] 概览卡联动与依赖清单标记');
await evaluate(`document.querySelector('#centerTabs button[data-tab=code]').click()`);
await sleep(500);
await evaluate(`document.getElementById('statVuln').click()`);
await sleep(1200);
check('点击概览卡「依赖漏洞」跳到该标签',
  await evaluate('document.getElementById("tabDeps").classList.contains("on")'));

await evaluate(`document.getElementById('btnDeps').click()`);
await sleep(1600);
const flags = await evaluate('document.querySelectorAll("#depList .dep-item.has-vuln").length');
const depItems = await evaluate('document.querySelectorAll("#depList .dep-item").length');
check('依赖清单弹窗标出有漏洞的条目', flags === apiVulns.summary.vuln_packages,
  `标记=${flags} 受影响依赖=${apiVulns.summary.vuln_packages}（清单共 ${depItems} 项）`);
const depHead = await evaluate('(document.querySelector("#depList .rule-meta") || {}).textContent || ""');
check('依赖清单头部提示漏洞数与跳转指引',
  depHead.includes('依赖风险') && depHead.includes('已知漏洞'), depHead.slice(0, 70));
await shot('23-dep-list-flagged.png');
await evaluate(`document.querySelector('#modalDeps .close').click()`);
await sleep(500);

console.log('[8] 桌面端布局完整性');
await S('Emulation.setDeviceMetricsOverride', { width: 1680, height: 1000, deviceScaleFactor: 1, mobile: false });
await sleep(400);
const overflow = await evaluate(`(() => {
  const de = document.documentElement;
  const wide = [];
  document.querySelectorAll('#tabDeps *').forEach((el) => {
    const r = el.getBoundingClientRect();
    if (r.width > 0 && (r.right > window.innerWidth + 2 || r.left < -2)) {
      wide.push(el.className || el.tagName);
    }
  });
  return { scrollW: de.scrollWidth, clientW: de.clientWidth, wide: wide.slice(0, 5) };
})()`);
check('无横向溢出', overflow.scrollW <= overflow.clientW + 2,
  `scrollW=${overflow.scrollW} clientW=${overflow.clientW} 越界元素=${overflow.wide.join('|') || '无'}`);
await shot('24-vuln-desktop.png');

console.log('[9] 移动端布局');
await viewport(390, 844, true);
await sleep(700);
// 窄屏用 body[data-pane] 做三栏切换，中心栏默认收起；先切到中心栏再点依赖风险标签
await evaluate(`(() => { const p = document.querySelector('#paneSwitch button[data-pane=center]'); if (p) p.click(); })()`);
await sleep(600);
await evaluate(`(() => { const b = document.querySelector('#centerTabs button[data-tab=deps]'); if (b) b.click(); })()`);
await sleep(1400);
const mPane = await evaluate('document.body.dataset.pane');
const mOverflow = await evaluate(`(() => {
  const de = document.documentElement;
  const bad = [];
  document.querySelectorAll('#tabDeps *').forEach((el) => {
    const r = el.getBoundingClientRect();
    if (r.width > 0 && r.right > window.innerWidth + 2) bad.push(el.className || el.tagName);
  });
  return { scrollW: de.scrollWidth, clientW: de.clientWidth, bad: bad.slice(0, 5) };
})()`);
check('移动端无横向溢出', mOverflow.scrollW <= mOverflow.clientW + 2,
  `pane=${mPane} scrollW=${mOverflow.scrollW} clientW=${mOverflow.clientW} 越界=${mOverflow.bad.join('|') || '无'}`);
const mVisible = await evaluate(`(() => {
  const b = document.getElementById('vulnBody').getBoundingClientRect();
  const bar = document.querySelector('.vuln-bar').getBoundingClientRect();
  return { bodyH: Math.round(b.height), barH: Math.round(bar.height),
           cards: document.querySelectorAll('.vuln-card').length };
})()`);
check('移动端漏洞列表可见且有高度', mVisible.bodyH > 100 && mVisible.cards > 0, JSON.stringify(mVisible));
await shot('25-vuln-mobile.png');

console.log('[10] 离线模式开关');
// 记录真实的 /api/vulndb/update 请求体，失败时可直接看出是「参数没送到」还是「服务端没生效」
await evaluate(`(() => {
  window.__net = [];
  const of = window.fetch;
  window.fetch = async (...a) => {
    const r = await of(...a);
    let b = ''; try { b = (await r.clone().text()).slice(0, 200); } catch (e) {}
    window.__net.push({ url: String(a[0]), status: r.status,
                        req: a[1] && a[1].body ? String(a[1].body) : '', resp: b });
    return r;
  };
  return true;
})()`);
const before = await evaluate('document.getElementById("vulnOffline").checked');
const want = !before;
await evaluate(`(() => { const c = document.getElementById('vulnOffline');
  c.checked = ${want}; c.dispatchEvent(new Event('change', {bubbles:true})); })()`);
let stOff = null, stErr = '';
for (let i = 0; i < 25; i++) {
  await sleep(600);
  const st = (await get('/api/vulndb/status')).data;
  stOff = st.offline; stErr = st.error || '';
  if (stOff === want) break;
}
let after = await evaluate('document.getElementById("vulnOffline").checked');
const netUpd = await evaluate(`(window.__net||[]).filter(n=>n.url.indexOf('vulndb/update')>=0)
  .map(n=>'HTTP '+n.status+' 请求体='+n.req).join(' ; ')`);
check('离线开关往返一致（界面 → 服务端 → 界面）',
  stOff === want && after === want,
  `期望=${want} 服务端=${stOff} 界面=${after}｜${netUpd || '未捕获到请求'}${stErr ? '｜错误=' + stErr : ''}`);
// 还原为初始状态
await evaluate(`(() => { const c = document.getElementById('vulnOffline');
  c.checked = ${before}; c.dispatchEvent(new Event('change', {bubbles:true})); })()`);
for (let i = 0; i < 25; i++) {
  await sleep(600);
  const st = (await get('/api/vulndb/status')).data;
  if (st.offline === before) break;
}

console.log('[11] 控制台无报错');
const errs = events.filter((e) => e.method === 'Runtime.exceptionThrown');
check('页面运行期间无未捕获异常', errs.length === 0,
  errs.slice(0, 2).map((e) => e.params?.exceptionDetails?.text).join(' | ') || '无');

// ---------------------------------------------------------------- 收尾
console.log('\n' + '='.repeat(78));
console.log(`结果：${pass} 通过 / ${fail} 失败`);
console.log('='.repeat(78));

// 还原宿主原有审计目标（避免打断用户正在看的结果）
if (prevTarget && prevTarget.root) {
  await post('/api/target', { root: prevTarget.root, label: prevTarget.name, kind: prevTarget.kind || 'path' });
  console.log(`已还原审计目标：${prevTarget.name}`);
}

try { await S('Target.closeTarget', { targetId }); } catch (e) { /* 忽略 */ }
ws.close();
chrome.kill();
await sleep(300);
process.exit(fail === 0 ? 0 : 1);
