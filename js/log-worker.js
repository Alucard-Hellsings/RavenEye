/**
 * 中间件日志分析 —— Web Worker（数据层）
 *
 * 职责：流式分片读取大文件 → 自动识别格式 → 逐行解析为列式存储 →
 *       一次遍历完成聚合统计与高危标记 → 维护过滤/排序索引 → 分页向主线程返回可视行。
 *
 * 全程在 Worker 线程，主线程不阻塞；FileReaderSync 同步读分片，内存可控。
 */
'use strict';

/* ──────────────────────────────────────────────────────────────
 *  列式存储（全量明细，面向千万级行的 off-heap 设计）
 *
 *  关键点：V8 字符串/数组堆上限约 4GB，千万行若以 JS 字符串保存 raw/path/ua
 *  会轻松突破上限而崩溃（“解析到 ~94% 卡死”即此）。因此：
 *    · 原始整行 → 分块 Uint8Array 竞技场（ArrayBuffer，off-heap，不占 V8 堆）
 *    · ip/path/ua → 仅记录其在原始行内的「字节偏移+长度」（TypedArray，off-heap）
 *      取值时按需从竞技场切片解码，零额外字节拷贝
 *    · method → 字典编码（基数极低，U16 索引 + 字符串表）
 *    · status/bytes/ts/risk → 定长 TypedArray（off-heap）
 *  这样 V8 堆几乎不增长，可承载数千万行。
 * ────────────────────────────────────────────────────────────── */
var ENC = new TextEncoder();
var DEC = new TextDecoder('utf-8');
var ARENA_CHUNK = 256 * 1024 * 1024;        /* 竞技场单块 256MB */
var GROW_SHIFT = 20, GROW_SIZE = 1 << GROW_SHIFT, GROW_MASK = GROW_SIZE - 1; /* 每块 ~104万元素 */

/* 可增长的分块 TypedArray（避免预先知道总行数） */
function Grow(Ctor) { this.C = Ctor; this.b = []; this.len = 0; }
Grow.prototype.push = function (v) {
  var ci = this.len >>> GROW_SHIFT;
  if (ci >= this.b.length) this.b.push(new this.C(GROW_SIZE));
  this.b[ci][this.len & GROW_MASK] = v; this.len++;
};
Grow.prototype.get = function (i) { return this.b[i >>> GROW_SHIFT][i & GROW_MASK]; };
Grow.prototype.clear = function () { this.b = []; this.len = 0; };

/* 原始行字节竞技场：用 encodeInto 直写，避免每行分配临时 Uint8Array（千万次分配→0） */
var RAW = { chunks: [], cur: null, used: 0, ci: new Grow(Uint16Array), off: new Grow(Uint32Array), len: new Grow(Uint32Array) };
function rawPut(line) {
  var maxBytes = line.length * 3;            /* UTF-8 最坏膨胀 3 倍，确保一次写完 */
  if (!RAW.cur || RAW.used + maxBytes > RAW.cur.length) {
    var sz = maxBytes > ARENA_CHUNK ? maxBytes : ARENA_CHUNK;
    RAW.cur = new Uint8Array(sz); RAW.chunks.push(RAW.cur); RAW.used = 0;
  }
  var off = RAW.used;
  var n = ENC.encodeInto(line, RAW.cur.subarray(off)).written;
  RAW.ci.push(RAW.chunks.length - 1); RAW.off.push(off); RAW.len.push(n);
  RAW.used += n;
  return n;
}
function rawStr(i) { var L = RAW.len.get(i); return L ? DEC.decode(RAW.chunks[RAW.ci.get(i)].subarray(RAW.off.get(i), RAW.off.get(i) + L)) : ''; }
/* 字段：行内字节偏移(rel) + 字节长度(len) → 从竞技场切片解码 */
function fieldStr(i, relG, lenG) {
  var L = lenG.get(i); if (!L) return '';
  var base = RAW.off.get(i) + relG.get(i);
  return DEC.decode(RAW.chunks[RAW.ci.get(i)].subarray(base, base + L));
}

/* 数值列（off-heap TypedArray） */
var C_ts = new Grow(Float64Array), C_status = new Grow(Uint16Array), C_bytes = new Grow(Float64Array), C_risk = new Grow(Uint8Array);
/* 字段在原始行内的字节偏移/长度 */
var C_ipRel = new Grow(Uint32Array), C_ipLen = new Grow(Uint32Array);
var C_pRel = new Grow(Uint32Array), C_pLen = new Grow(Uint32Array);
var C_uaRel = new Grow(Uint32Array), C_uaLen = new Grow(Uint32Array);
/* method 字典编码 */
var C_mId = new Grow(Uint16Array);
var METH = { map: new Map(), arr: [] };
function methId(s) { s = s || '-'; var v = METH.map.get(s); if (v === undefined) { v = METH.arr.length; METH.arr.push(s); METH.map.set(s, v); } return v; }

/* 统一取值访问器（替代旧的 COL.x[i]） */
function gRaw(i) { return rawStr(i); }
function gIp(i) { return fieldStr(i, C_ipRel, C_ipLen); }
function gPath(i) { return fieldStr(i, C_pRel, C_pLen); }
function gUa(i) { return fieldStr(i, C_uaRel, C_uaLen); }
function gMethod(i) { return METH.arr[C_mId.get(i)] || '-'; }
function gStatus(i) { return C_status.get(i); }
function gBytes(i) { return C_bytes.get(i); }
function gTs(i) { return C_ts.get(i); }
function gRisk(i) { return C_risk.get(i); }

/* 把字段在行内的字符位置换算成字节偏移并写入（ASCII 快速路径） */
function pushRel(relG, lenG, line, ascii, str, charPos) {
  if (str == null || str === '' || charPos < 0) { relG.push(0); lenG.push(0); return; }
  var bOff, bLen;
  if (ascii) { bOff = charPos; bLen = str.length; }
  else { bOff = ENC.encode(line.slice(0, charPos)).length; bLen = ENC.encode(str).length; }
  relG.push(bOff); lenG.push(bLen);
}

function clearStore() {
  RAW.chunks = []; RAW.cur = null; RAW.used = 0; RAW.ci.clear(); RAW.off.clear(); RAW.len.clear();
  C_ts.clear(); C_status.clear(); C_bytes.clear(); C_risk.clear();
  C_ipRel.clear(); C_ipLen.clear(); C_pRel.clear(); C_pLen.clear(); C_uaRel.clear(); C_uaLen.clear();
  C_mId.clear(); METH.map = new Map(); METH.arr = [];
}

var N = 0;                 /* 总行数（解析成功的） */
var viewIdx = null;        /* 当前视图（过滤/排序后）的行索引 */

/* ── 风险位掩码 ── */
var R_SQLI = 1, R_XSS = 2, R_TRAV = 4, R_SENS = 8, R_SCAN = 16, R_METHOD = 32, R_5XX = 64, R_RCE = 128;
var ATTACK_MASK = R_SQLI | R_XSS | R_TRAV | R_SENS | R_SCAN | R_METHOD | R_RCE;

var SIG = {
  sqli: /(union\s+select|\bor\s+1\s*=\s*1|sleep\s*\(|benchmark\s*\(|information_schema|concat\s*\(|\bxp_cmdshell|select.+from)/i,
  xss: /(<script|onerror\s*=|onload\s*=|javascript:|<img[^>]+src|alert\s*\(|document\.cookie|<svg)/i,
  trav: /(\.\.\/|\.\.\\|%2e%2e%2f|%2e%2e\/|\.\.%2f|\/etc\/passwd|c:\\windows)/i,
  sens: /(\/\.env|\/\.git|\/\.svn|\/\.ssh|\/wp-login|\/wp-admin|\/phpmyadmin|\/administrator|\/manager\/html|\/actuator|\/\.aws|\/config\.|\/backup|\.bak\b|\/druid\/|\/solr\/|\/console)/i,
  scan: /(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wpscan|hydra|fuzz|nuclei|xray|crawler|zgrab)/i,
  rce: /(\/bin\/sh|\/bin\/bash|cmd\.exe|powershell|whoami|system\s*\(|exec\s*\(|eval\s*\(|base64_decode|\$\{jndi:|phpinfo\s*\()/i
};
var DANGER_METHODS = { PUT: 1, DELETE: 1, TRACE: 1, CONNECT: 1, PATCH: 0 };

/* ── 聚合统计 ── */
var AGG;
function resetAgg() {
  aggCapped = false;
  AGG = {
    lines: 0, parsed: 0, failed: 0, bytes: 0,
    tsMin: Infinity, tsMax: -Infinity,
    status: {}, statusClass: { '2xx': 0, '3xx': 0, '4xx': 0, '5xx': 0, other: 0 },
    method: {},
    ipCount: new Map(), pathCount: new Map(),
    ip4xx: new Map(),
    hour: new Map(),
    riskTotal: 0, riskCat: { sqli: 0, xss: 0, trav: 0, sens: 0, scan: 0, method: 0, rce: 0, e5xx: 0 }
  };
}

/* ── 时间解析：10/Oct/2000:13:55:36 -0700 → epoch ms（解析失败返回 NaN） ── */
var MON = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
function parseTime(s) {
  if (!s) return NaN;
  var m = /^(\d{2})\/([A-Za-z]{3})\/(\d{4}):(\d{2}):(\d{2}):(\d{2})\s*([+\-]\d{4})?/.exec(s);
  if (m) {
    var mon = MON[m[2]]; if (mon == null) return NaN;
    var ms = Date.UTC(+m[3], mon, +m[1], +m[4], +m[5], +m[6]);
    if (m[7]) { var sign = m[7][0] === '-' ? 1 : -1; var oh = +m[7].slice(1, 3), om = +m[7].slice(3, 5); ms += sign * (oh * 60 + om) * 60000; }
    return ms;
  }
  var d = Date.parse(s);
  return isNaN(d) ? NaN : d;
}

/* ── 格式预设 ── */
var FORMATS = [
  /* K8s ingress-nginx 访问日志（兼容可选 CRI 容器前缀「<ts> stdout|stderr F|P 」）：
     [time] remote_addr "host" "request" status body_bytes upstream_addr "ua" "xff" req_time up_time */
  { name: 'ingress-nginx',
    re: /^(?:\S+\s+(?:stdout|stderr)\s+[FP]\s+)?\[([^\]]+)\]\s+(\S+)\s+"[^"]*"\s+"([A-Z]+)\s+(\S+)[^"]*"\s+(\d{3})\s+(\d+|-)\s+\S+\s+"([^"]*)"/d,
    gi: { ip: 2, path: 4, ua: 7 },
    map: function (m) { return { ip: m[2], time: m[1], method: m[3], path: m[4], status: +m[5], bytes: m[6] === '-' ? 0 : +m[6], ref: '', ua: m[7] }; } },
  { name: 'combined', re: /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)[^"]*"\s+(\d{3})\s+(\d+|-)\s+"([^"]*)"\s+"([^"]*)"/d,
    gi: { ip: 1, path: 4, ua: 8 },
    map: function (m) { return { ip: m[1], time: m[2], method: m[3], path: m[4], status: +m[5], bytes: m[6] === '-' ? 0 : +m[6], ref: m[7], ua: m[8] }; } },
  { name: 'common', re: /^(\S+)\s+\S+\s+\S+\s+\[([^\]]+)\]\s+"([A-Z]+)\s+(\S+)[^"]*"\s+(\d{3})\s+(\d+|-)/d,
    gi: { ip: 1, path: 4, ua: 0 },
    map: function (m) { return { ip: m[1], time: m[2], method: m[3], path: m[4], status: +m[5], bytes: m[6] === '-' ? 0 : +m[6], ref: '', ua: '' }; } }
];
var GENERIC = {
  ipRe: /(\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]{3,}:[0-9a-fA-F:]+)/,
  reqRe: /"([A-Z]+)\s+(\S+)[^"]*"/,
  statusRe: /\s(\d{3})\s/,
  timeRe: /\[([^\]]+)\]/,
  uaRe: /"([^"]*)"\s*$/
};

function detectFormat(samples) {
  var best = null, bestHits = -1;
  for (var f = 0; f < FORMATS.length; f++) {
    var hits = 0;
    for (var i = 0; i < samples.length; i++) if (FORMATS[f].re.test(samples[i])) hits++;
    if (hits > bestHits) { bestHits = hits; best = FORMATS[f]; }
  }
  /* 至少一半样本命中才采用预设，否则用通用提取 */
  if (best && bestHits >= Math.max(1, Math.floor(samples.length / 2))) return best;
  return null;
}

function classifyStatus(code) {
  if (code >= 200 && code < 300) return '2xx';
  if (code >= 300 && code < 400) return '3xx';
  if (code >= 400 && code < 500) return '4xx';
  if (code >= 500 && code < 600) return '5xx';
  return 'other';
}

function safeDecode(s) { try { return decodeURIComponent(String(s).replace(/\+/g, ' ')); } catch (e) { return String(s); } }
function detectRisk(method, path, ua, status) {
  /* 攻击面集中在 path（含 query）与 UA；仅在含百分号编码时才解码（省去逐行 decodeURIComponent）。
   * 不再把整行原文拼入检测串，既快又减少对标准日志字段的误报。 */
  var p = path || '';
  var dec = p.indexOf('%') >= 0 ? safeDecode(p) : p;
  var hay = dec === p ? p : (p + ' ' + dec);
  var r = 0;
  if (SIG.sqli.test(hay)) { r |= R_SQLI; AGG.riskCat.sqli++; }
  if (SIG.xss.test(hay)) { r |= R_XSS; AGG.riskCat.xss++; }
  if (SIG.trav.test(hay)) { r |= R_TRAV; AGG.riskCat.trav++; }
  if (SIG.sens.test(hay)) { r |= R_SENS; AGG.riskCat.sens++; }
  if (ua && SIG.scan.test(ua)) { r |= R_SCAN; AGG.riskCat.scan++; }
  if (SIG.rce.test(hay)) { r |= R_RCE; AGG.riskCat.rce++; }
  if (DANGER_METHODS[method]) { r |= R_METHOD; AGG.riskCat.method++; }
  if (status >= 500) { r |= R_5XX; AGG.riskCat.e5xx++; }
  if (r & ATTACK_MASK) AGG.riskTotal++;
  return r;
}

function bump(map, key) { map.set(key, (map.get(key) || 0) + 1); }
/* 高基数字段（ip/path）专用：限制 distinct 键数量，防止聚合 Map 撑爆 V8 堆。
 * 达到上限后只对已存在的键累加，新键忽略（Top-N 仍以热点为主，统计影响极小）。 */
var AGG_CAP = 500000;
var aggCapped = false;
function bumpCapped(map, key) {
  var c = map.get(key);
  if (c !== undefined) map.set(key, c + 1);
  else if (map.size < AGG_CAP) map.set(key, 1);
  else aggCapped = true;
}

function handleLine(line, fmt) {
  if (!line) return;
  AGG.lines++;
  var rec = null, mi = null, gi = null;
  if (fmt) {
    var m = fmt.re.exec(line);
    if (m) { rec = fmt.map(m); mi = m.indices; gi = fmt.gi; }
  }
  if (!rec) {
    /* 通用提取兜底 */
    var ipM = GENERIC.ipRe.exec(line);
    var reqM = GENERIC.reqRe.exec(line);
    var stM = GENERIC.statusRe.exec(line);
    var tM = GENERIC.timeRe.exec(line);
    var uaM = GENERIC.uaRe.exec(line);
    if (!ipM && !reqM && !stM) { AGG.failed++; return; }
    rec = {
      ip: ipM ? ipM[1] : '-', time: tM ? tM[1] : '',
      method: reqM ? reqM[1] : '-', path: reqM ? reqM[2] : '-',
      status: stM ? +stM[1] : 0, bytes: 0, ref: '', ua: uaM ? uaM[1] : ''
    };
  }

  var ts = parseTime(rec.time);
  var risk = detectRisk(rec.method, rec.path, rec.ua, rec.status);

  N++;
  /* 原始整行 → 竞技场（off-heap，encodeInto 直写） */
  var n = rawPut(line);
  var ascii = n === line.length;              /* 纯 ASCII：字节偏移==字符偏移 */

  /* 字段在行内的字符位置：优先用正则 d 标志的 match.indices（零额外扫描），
     通用兜底行无 indices 时退回 indexOf。 */
  var ip = rec.ip, path = rec.path, ua = rec.ua || '', method = rec.method || '-';
  var ipPos, pathPos, uaPos;
  if (mi && gi) {
    ipPos = (gi.ip && mi[gi.ip]) ? mi[gi.ip][0] : -1;
    pathPos = (gi.path && mi[gi.path]) ? mi[gi.path][0] : -1;
    uaPos = (gi.ua && mi[gi.ua]) ? mi[gi.ua][0] : -1;
  } else {
    ipPos = ip ? line.indexOf(ip) : -1;
    var reqPos = method !== '-' ? line.indexOf('"' + method + ' ') : -1;
    pathPos = reqPos >= 0 ? reqPos + 1 + method.length + 1 : (path ? line.indexOf(path) : -1);
    uaPos = ua ? line.lastIndexOf(ua) : -1;
  }

  pushRel(C_ipRel, C_ipLen, line, ascii, ip, ipPos);
  pushRel(C_pRel, C_pLen, line, ascii, path, pathPos);
  pushRel(C_uaRel, C_uaLen, line, ascii, ua, uaPos);
  C_mId.push(methId(method));
  C_ts.push(ts);
  C_status.push(rec.status);
  C_bytes.push(rec.bytes);
  C_risk.push(risk);

  /* 聚合 */
  AGG.parsed++;
  AGG.bytes += rec.bytes;
  if (!isNaN(ts)) { if (ts < AGG.tsMin) AGG.tsMin = ts; if (ts > AGG.tsMax) AGG.tsMax = ts; bump(AGG.hour, Math.floor(ts / 3600000)); }
  AGG.status[rec.status] = (AGG.status[rec.status] || 0) + 1;
  AGG.statusClass[classifyStatus(rec.status)]++;
  AGG.method[method] = (AGG.method[method] || 0) + 1;
  bumpCapped(AGG.ipCount, ip);
  bumpCapped(AGG.pathCount, path);
  if (rec.status >= 400 && rec.status < 500) bumpCapped(AGG.ip4xx, ip);
}

function topN(map, n) {
  var arr = [];
  map.forEach(function (v, k) { arr.push([k, v]); });
  arr.sort(function (a, b) { return b[1] - a[1]; });
  return arr.slice(0, n).map(function (p) { return { key: p[0], count: p[1] }; });
}

function finalize(fmtName) {
  /* 默认视图：全量、按原始顺序 */
  viewIdx = null;
  var hourArr = [];
  AGG.hour.forEach(function (v, k) { hourArr.push([k, v]); });
  hourArr.sort(function (a, b) { return a[0] - b[0]; });

  var summary = {
    format: fmtName, lines: AGG.lines, parsed: AGG.parsed, failed: AGG.failed,
    bytes: AGG.bytes, uniqueIp: AGG.ipCount.size,
    tsMin: AGG.tsMin === Infinity ? null : AGG.tsMin,
    tsMax: AGG.tsMax === -Infinity ? null : AGG.tsMax,
    statusClass: AGG.statusClass, riskTotal: AGG.riskTotal, riskCat: AGG.riskCat,
    aggCapped: aggCapped
  };
  var analytics = {
    topIp: topN(AGG.ipCount, 12),
    topPath: topN(AGG.pathCount, 12),
    topScanner: topN(AGG.ip4xx, 12),
    statusList: Object.keys(AGG.status).map(function (k) { return { code: +k, count: AGG.status[k] }; }).sort(function (a, b) { return b.count - a.count; }).slice(0, 12),
    methodList: Object.keys(AGG.method).map(function (k) { return { key: k, count: AGG.method[k] }; }).sort(function (a, b) { return b.count - a.count; }),
    hour: hourArr.map(function (p) { return { h: p[0], count: p[1] }; })
  };
  self.postMessage({ type: 'done', total: N, summary: summary, analytics: analytics });
}

/* ── 解析入口 ── */
function parseFile(file) {
  resetAgg();
  clearStore();
  N = 0; viewIdx = null;

  var reader = new FileReaderSync();
  var decoder = new TextDecoder('utf-8');
  var CHUNK = 8 * 1024 * 1024;
  var offset = 0, leftover = '';
  var total = file.size || 0;

  var fmt = null, pending = [], detected = false;

  function drainPending() {
    for (var i = 0; i < pending.length; i++) handleLine(pending[i], fmt);
    pending = [];
  }

  try {
    while (offset < total) {
      var buf = reader.readAsArrayBuffer(file.slice(offset, offset + CHUNK));
      offset += CHUNK;
      var text = leftover + decoder.decode(buf, { stream: true });
      var lines = text.split('\n');
      leftover = lines.pop();

      for (var li = 0; li < lines.length; li++) {
        var ln = lines[li];
        if (ln.charCodeAt(ln.length - 1) === 13) ln = ln.slice(0, -1); /* 去掉 \r */
        if (!detected) {
          if (ln.trim()) pending.push(ln);
          if (pending.length >= 25) { fmt = detectFormat(pending); detected = true; drainPending(); }
        } else {
          handleLine(ln, fmt);
        }
      }
      self.postMessage({ type: 'progress', bytes: Math.min(offset, total), total: total, lines: N });
    }
    /* 收尾 */
    leftover += decoder.decode();
    if (leftover) {
      var last = leftover.charCodeAt(leftover.length - 1) === 13 ? leftover.slice(0, -1) : leftover;
      if (!detected) { if (last.trim()) pending.push(last); }
      else if (last.length) handleLine(last, fmt);
    }
    if (!detected) { fmt = detectFormat(pending); drainPending(); }

    finalize(fmt ? fmt.name : 'generic');
  } catch (err) {
    self.postMessage({ type: 'error', message: String(err && err.message || err) });
  }
}

/* ============================================================
 *  高级查询 DSL
 *  - 字段：英文或中文列名（状态/ip/路径/方法/字节/时间/风险/原文/ua）
 *  - 运算符：= == != > >= < <= ~（包含）!~（不含）
 *  - 组合：&（与，优先级高）|（或）；值可用单/双引号包裹以含 & |
 *  - 裸词：在 IP/路径/方法/状态/UA/原文中做包含匹配
 * ============================================================ */
var QFIELDS = { status: 1, bytes: 1, ip: 1, method: 1, path: 1, ua: 1, raw: 1, time: 1, ts: 1, risk: 1 };
var QFIELD_ALIASES = {
  status: 'status', 状态: 'status', 状态码: 'status',
  ip: 'ip', 地址: 'ip', 客户端: 'ip', 客户端ip: 'ip',
  method: 'method', 方法: 'method', 请求方法: 'method',
  path: 'path', 路径: 'path', uri: 'path', url: 'path', 请求路径: 'path',
  bytes: 'bytes', 字节: 'bytes', 大小: 'bytes', 响应大小: 'bytes', 流量: 'bytes',
  time: 'time', ts: 'time', 时间: 'time', 日期: 'time', 时刻: 'time',
  risk: 'risk', 风险: 'risk', 威胁: 'risk', 高危: 'risk',
  raw: 'raw', 原文: 'raw', 内容: 'raw', 日志: 'raw', 行: 'raw',
  ua: 'ua', useragent: 'ua', user_agent: 'ua', 浏览器: 'ua', 用户代理: 'ua'
};
var RISK_BITS = {
  none: 0, sqli: R_SQLI, xss: R_XSS, trav: R_TRAV, sens: R_SENS, scan: R_SCAN,
  method: R_METHOD, rce: R_RCE, e5xx: R_5XX, '5xx': R_5XX,
  attack: ATTACK_MASK, any: ATTACK_MASK, 高危: ATTACK_MASK, 有高危: ATTACK_MASK
};
var RISK_CN = {
  'sql注入': 'sqli', 'sql注入攻击': 'sqli', '注入': 'sqli', sqli: 'sqli',
  xss: 'xss', '跨站': 'xss', '跨站脚本': 'xss',
  '路径穿越': 'trav', '目录穿越': 'trav', '目录遍历': 'trav',
  '敏感路径': 'sens', '敏感文件': 'sens', '敏感': 'sens',
  '扫描器': 'scan', '扫描': 'scan', '爬虫': 'scan',
  '危险方法': 'method', '非常规方法': 'method',
  '命令执行': 'rce', 'rce攻击': 'rce', '远程执行': 'rce',
  '5xx错误': 'e5xx', '服务端错误': 'e5xx',
  '无风险': 'none', '无': 'none', '正常': 'none'
};
var Q_OPS = '!~|>=|<=|!=|==|~|>|<|=';

function normalizeField(name) {
  var raw = String(name || '').trim();
  if (!raw) return null;
  var lower = raw.toLowerCase();
  if (QFIELDS[lower]) return lower;
  if (QFIELD_ALIASES[raw]) return QFIELD_ALIASES[raw];
  if (QFIELD_ALIASES[lower]) return QFIELD_ALIASES[lower];
  return null;
}
function unquoteVal(v) {
  v = String(v == null ? '' : v).trim();
  if (v.length >= 2 && ((v[0] === '"' && v[v.length - 1] === '"') || (v[0] === "'" && v[v.length - 1] === "'"))) {
    return v.slice(1, -1).replace(/\\(["'])/g, '$1');
  }
  return v;
}
function splitQueryParts(q, sep) {
  var parts = [], cur = '', inQ = false, qch = '', i, c;
  for (i = 0; i < q.length; i++) {
    c = q[i];
    if (!inQ && (c === '"' || c === "'")) { inQ = true; qch = c; cur += c; continue; }
    if (inQ && c === qch && q[i - 1] !== '\\') { inQ = false; cur += c; continue; }
    if (!inQ && c === sep) { if (cur.trim()) parts.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}
function parseQueryTime(v) {
  v = String(v).trim();
  if (/^\d+$/.test(v)) { var n = +v; return v.length <= 11 ? n * 1000 : n; }
  var d = new Date(v.replace(' ', 'T'));
  var t = d.getTime();
  return isNaN(t) ? NaN : t;
}
function normalizeRiskKey(v) {
  v = String(v || '').trim();
  if (!v) return '';
  var lower = v.toLowerCase();
  if (RISK_BITS[lower] !== undefined) return lower;
  if (RISK_BITS[v] !== undefined) return v;
  if (RISK_CN[lower]) return RISK_CN[lower];
  if (RISK_CN[v]) return RISK_CN[v];
  return lower;
}
function stripOuterGroup(text) {
  text = String(text || '').trim();
  while (text.length >= 2 && text[0] === '(') {
    var depth = 0, end = -1, i;
    for (i = 0; i < text.length; i++) {
      if (text[i] === '(') depth++;
      else if (text[i] === ')') {
        depth--;
        if (depth === 0) { end = i; break; }
      }
    }
    if (end === text.length - 1) text = text.slice(1, -1).trim();
    else break;
  }
  return text;
}
function parseAtom(text) {
  text = stripOuterGroup(text.trim()); if (!text) return null;
  var re = new RegExp('^([\\w\\u4e00-\\u9fff\\u3400-\\u4dbf]+)\\s*(' + Q_OPS + ')\\s*([\\s\\S]*)$', 'u');
  var m = re.exec(text);
  if (m) {
    var field = normalizeField(m[1]);
    if (field) return { field: field, op: m[2], val: unquoteVal(m[3]) };
  }
  return { field: '_bare', op: '~', val: unquoteVal(text) };
}
function parseQuery(q) {
  q = String(q == null ? '' : q).trim();
  if (!q) return null;
  var groups = splitQueryParts(q, '|').map(function (g) {
    return splitQueryParts(g, '&').map(parseAtom).filter(Boolean);
  }).filter(function (a) { return a.length; });
  return groups.length ? groups : null;
}
function numOp(a, op, b) {
  switch (op) {
    case '>': return a > b; case '>=': return a >= b; case '<': return a < b; case '<=': return a <= b;
    case '=': case '==': return a === b; case '!=': return a !== b;
    case '~': return String(a).indexOf(String(b)) >= 0; case '!~': return String(a).indexOf(String(b)) < 0;
  }
  return false;
}
function strOp(a, op, b) {
  a = String(a).toLowerCase(); b = String(b).toLowerCase();
  switch (op) {
    case '=': case '==': return a === b; case '!=': return a !== b;
    case '~': return a.indexOf(b) >= 0; case '!~': return a.indexOf(b) < 0;
    case '>': return a > b; case '<': return a < b; case '>=': return a >= b; case '<=': return a <= b;
  }
  return false;
}
function boolOp(has, op) {
  switch (op) {
    case '=': case '==': case '~': return has;
    case '!=': case '!~': return !has;
    default: return has;
  }
}
function evalRiskAtom(i, op, v) {
  var mask = gRisk(i);
  var key = normalizeRiskKey(v);
  if (key === 'none') {
    var noAttack = !(mask & ATTACK_MASK);
    return op === '!=' || op === '!~' ? !noAttack : noAttack;
  }
  if (key === 'attack' || key === 'any' || key === '高危') return boolOp(!!(mask & ATTACK_MASK), op);
  if (RISK_BITS[key] !== undefined) return boolOp(!!(mask & RISK_BITS[key]), op);
  return strOp(riskTags(mask).join(' '), op, v);
}
function evalAtom(at, i) {
  var f = at.field, op = at.op, v = at.val;
  if (f === '_bare') {
    /* 原始整行已包含 ip/method/status/path/ua，单次解码即可覆盖 */
    var hay = gRaw(i).toLowerCase();
    return hay.indexOf(String(v).toLowerCase()) >= 0;
  }
  if (f === 'status') {
    var cv = gStatus(i);
    if (/^\dxx$/i.test(v)) return strOp(classifyStatus(cv), op, v.toLowerCase());
    var nv = parseFloat(v);
    if (!isNaN(nv) && v !== '') return isNaN(cv) ? (op === '!=' || op === '!~') : numOp(cv, op, nv);
    return strOp(String(cv), op, v);
  }
  if (f === 'bytes' || f === 'ts' || f === 'time') {
    var cv2 = f === 'bytes' ? gBytes(i) : gTs(i);
    var nv2 = (f === 'ts' || f === 'time') ? parseQueryTime(v) : parseFloat(v);
    if (isNaN(nv2)) return strOp(String(cv2), op, v);
    if (isNaN(cv2)) return op === '!=' || op === '!~';
    return numOp(cv2, op, nv2);
  }
  if (f === 'risk') return evalRiskAtom(i, op, v);
  var sv = f === 'ip' ? gIp(i) : f === 'method' ? gMethod(i) : f === 'path' ? gPath(i) : f === 'ua' ? gUa(i) : gRaw(i);
  return strOp(sv, op, v);
}
function evalGroups(groups, i) {
  for (var g = 0; g < groups.length; g++) {
    var atoms = groups[g], ok = true;
    for (var a = 0; a < atoms.length; a++) { if (!evalAtom(atoms[a], i)) { ok = false; break; } }
    if (ok) return true;
  }
  return false;
}

/* ── 过滤 + 排序 → 重建 viewIdx ── */
function applyView(opt) {
  opt = opt || {};
  var groups = parseQuery(opt.q);
  var sc = opt.statusClass || '';        /* '2xx'..'5xx' */
  var method = opt.method || '';
  var riskOnly = !!opt.riskOnly;
  var ipExact = opt.ip || '';

  var idx;
  var needFilter = groups || sc || method || riskOnly || ipExact;
  if (!needFilter) {
    idx = new Int32Array(N);
    for (var k = 0; k < N; k++) idx[k] = k;
  } else {
    var tmp = [];
    for (var i = 0; i < N; i++) {
      if (sc && classifyStatus(gStatus(i)) !== sc) continue;
      if (method && gMethod(i) !== method) continue;
      if (riskOnly && !(gRisk(i) & ATTACK_MASK)) continue;
      if (ipExact && gIp(i) !== ipExact) continue;
      if (groups && !evalGroups(groups, i)) continue;
      tmp.push(i);
    }
    idx = Int32Array.from(tmp);
  }

  /* 排序 */
  if (opt.sortKey) {
    var key = opt.sortKey, dir = opt.sortDir === 'desc' ? -1 : 1;
    var numGet = (key === 'ts') ? gTs : (key === 'status') ? gStatus : (key === 'bytes') ? gBytes : null;
    var arr = Array.prototype.slice.call(idx);
    if (numGet) {
      arr.sort(function (a, b) { var va = numGet(a), vb = numGet(b); if (isNaN(va)) va = -Infinity; if (isNaN(vb)) vb = -Infinity; return (va - vb) * dir; });
    } else {
      var strGet = (key === 'ip') ? gIp : (key === 'method') ? gMethod : (key === 'path') ? gPath : null;
      if (strGet) arr.sort(function (a, b) { var sa = strGet(a), sb = strGet(b); return (sa < sb ? -1 : sa > sb ? 1 : 0) * dir; });
    }
    idx = Int32Array.from(arr);
  }

  viewIdx = idx;
  self.postMessage({ type: 'view', total: viewIdx.length });
}

function riskTags(mask) {
  var t = [];
  if (mask & R_SQLI) t.push('SQLi');
  if (mask & R_XSS) t.push('XSS');
  if (mask & R_TRAV) t.push('路径穿越');
  if (mask & R_SENS) t.push('敏感路径');
  if (mask & R_SCAN) t.push('扫描器');
  if (mask & R_METHOD) t.push('危险方法');
  if (mask & R_RCE) t.push('命令执行');
  if (mask & R_5XX) t.push('5xx');
  return t;
}

function rowObj(i) {
  var mask = gRisk(i);
  return {
    n: i + 1, ip: gIp(i), ts: gTs(i), method: gMethod(i),
    path: gPath(i), status: gStatus(i), bytes: gBytes(i),
    risk: riskTags(mask), attack: !!(mask & ATTACK_MASK), raw: gRaw(i)
  };
}

/* ── 取可视行 ── */
function getRows(start, count) {
  var idx = viewIdx;
  var total = idx ? idx.length : N;
  var end = Math.min(start + count, total);
  var rows = [];
  for (var k = start; k < end; k++) rows.push(rowObj(idx ? idx[k] : k));
  self.postMessage({ type: 'rows', start: start, rows: rows });
}

/* ── 导出：返回当前视图前 limit 行（不影响当前虚拟表渲染） ── */
function exportRows(limit) {
  var idx = viewIdx, total = idx ? idx.length : N;
  var cap = Math.min(limit || 2000, total);
  var rows = [];
  for (var k = 0; k < cap; k++) rows.push(rowObj(idx ? idx[k] : k));
  self.postMessage({ type: 'export', rows: rows, total: total, capped: total > cap });
}

/* ── 全局搜索：在当前视图范围内按 raw 原文匹配，返回匹配的视图行号数组 ── */
var SEARCH_MAX = 100000;
function searchView(query, caseSensitive) {
  var raw = String(query == null ? '' : query);
  var matches = [];
  var capped = false;
  if (raw) {
    var q = caseSensitive ? raw : raw.toLowerCase();
    var idx = viewIdx, total = idx ? idx.length : N;
    for (var k = 0; k < total; k++) {
      var row = idx ? idx[k] : k;
      var hay = rawStr(row);
      if (!hay) continue;
      hay = caseSensitive ? hay : hay.toLowerCase();
      if (hay.indexOf(q) >= 0) {
        matches.push(k);
        if (matches.length >= SEARCH_MAX) { capped = true; break; }
      }
    }
  }
  self.postMessage({ type: 'search', matches: matches, query: query, capped: capped });
}

/* ── 概览缩略图：把当前视图全量行聚合成 N 个桶（状态严重度 + 是否含高危） ── */
function statusSev(code) {
  var c = classifyStatus(code);
  return c === '2xx' ? 1 : c === '3xx' ? 2 : c === '4xx' ? 3 : c === '5xx' ? 4 : 0;
}
function buildMinimap(buckets) {
  buckets = buckets || 360;
  var idx = viewIdx, total = idx ? idx.length : N;
  var stat = new Uint8Array(buckets), risk = new Uint8Array(buckets);
  if (total > 0) {
    for (var b = 0; b < buckets; b++) {
      var s0 = Math.floor(b * total / buckets);
      var s1 = Math.floor((b + 1) * total / buckets);
      if (s1 <= s0) s1 = s0 + 1;
      var worst = 0, hr = 0;
      for (var k = s0; k < s1 && k < total; k++) {
        var row = idx ? idx[k] : k;
        var sv = statusSev(gStatus(row));
        if (sv > worst) worst = sv;
        if (gRisk(row) & ATTACK_MASK) hr = 1;
      }
      stat[b] = worst; risk[b] = hr;
    }
  }
  self.postMessage({ type: 'minimap', buckets: buckets, stat: stat, risk: risk, total: total }, [stat.buffer, risk.buffer]);
}

self.onmessage = function (e) {
  var d = e.data;
  if (d.type === 'parse') parseFile(d.file);
  else if (d.type === 'view') applyView(d.opt);
  else if (d.type === 'rows') getRows(d.start, d.count);
  else if (d.type === 'export') exportRows(d.limit);
  else if (d.type === 'search') searchView(d.query, d.caseSensitive);
  else if (d.type === 'minimap') buildMinimap(d.buckets);
};
