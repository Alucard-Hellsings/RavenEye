/**
 * 系统日志分析 —— 主线程控制器（视图层）
 * 与 syslog-worker.js（数据层）协作；虚拟滚动表格 + 安全仪表盘 + 概览缩略图 + 全局查找 + 报告导出。
 * 全程浏览器本地运行，日志数据不上传任何服务器。
 * 模块：Loader（载入）/ Dash（仪表盘）/ Table（虚拟滚动）/ Filters（筛选排序）/ Find / Minimap / Export
 */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  function fmtTs(ms) { if (ms == null || isNaN(ms)) return '-'; var d = new Date(ms); if (isNaN(d.getTime())) return '-'; var p = function (x) { return (x < 10 ? '0' : '') + x; }; return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds()); }

  var ROW_H = 30;
  var MAX_SPACER = 16000000;

  var SEV_LABEL = ['调试', '信息', '通知', '警告', '错误', '严重'];
  var SEV_KEY = ['debug', 'info', 'notice', 'warn', 'err', 'crit'];
  /* 仪表盘/缩略图按严重从高到低排列 */
  var SEV_ORDER = [5, 4, 3, 2, 1, 0];

  var RISK_CATS = [
    ['authfail', '登录失败'], ['priv', '提权/特权'], ['account', '账户变更'], ['service', '服务/持久化'],
    ['clearlog', '日志清除'], ['scan', '扫描/异常'], ['malware', '恶意软件'], ['fw', '防火墙拦截'],
    ['kernel', '内核/崩溃'], ['sev', '高严重级别']
  ];

  function hlEsc(text, q, caseSensitive) {
    var s = String(text == null ? '' : text);
    if (!q) return esc(s);
    var needle = caseSensitive ? q : String(q).toLowerCase();
    if (!needle) return esc(s);
    var hay = caseSensitive ? s : s.toLowerCase();
    var out = '', from = 0, pos;
    while ((pos = hay.indexOf(needle, from)) >= 0) {
      out += esc(s.slice(from, pos)) + '<mark class="lt-hl">' + esc(s.slice(pos, pos + needle.length)) + '</mark>';
      from = pos + needle.length;
    }
    out += esc(s.slice(from));
    return out;
  }

  function cpSet(key, css) { if (window.CpStyle) CpStyle.set(key, css); }
  function cpClear(prefix) { if (window.CpStyle) CpStyle.clear(prefix); }
  function applyBarWidths(container, selector, prefix) {
    cpClear(prefix);
    if (!container) return;
    container.querySelectorAll(selector).forEach(function (el, i) {
      var w = el.getAttribute('data-w');
      if (w == null) return;
      var key = prefix + i;
      el.setAttribute('data-bar-key', key);
      cpSet(key, '[data-bar-key="' + key + '"]{width:' + w + '%}');
    });
  }

  /* ── 快速筛选字段 / 运算符（与 Worker 中文列名对齐） ── */
  var SF_FIELDS = [
    { key: 'msg', label: '消息', cn: '消息', type: 'text' },
    { key: 'host', label: '主机', cn: '主机', type: 'text' },
    { key: 'source', label: '来源', cn: '来源', type: 'text' },
    { key: 'level', label: '级别', cn: '级别', type: 'level' },
    { key: 'eid', label: '事件ID', cn: '事件ID', type: 'number' },
    { key: 'time', label: '时间', cn: '时间', type: 'time' },
    { key: 'risk', label: '风险', cn: '风险', type: 'risk' },
    { key: 'raw', label: '原文', cn: '原文', type: 'text' }
  ];
  var SF_OPS = {
    text: [{ op: '~', label: '包含' }, { op: '!~', label: '不含' }, { op: '=', label: '等于' }, { op: '!=', label: '不等于' }],
    number: [{ op: '=', label: '等于' }, { op: '!=', label: '不等于' }, { op: '>', label: '大于' }, { op: '>=', label: '≥' }, { op: '<', label: '小于' }, { op: '<=', label: '≤' }],
    time: [{ op: '>', label: '晚于' }, { op: '>=', label: '不早于' }, { op: '<', label: '早于' }, { op: '<=', label: '不晚于' }, { op: '=', label: '等于' }, { op: '!=', label: '不等于' }],
    level: [{ op: '=', label: '等于' }, { op: '!=', label: '不等于' }, { op: '>=', label: '≥(更严重)' }, { op: '<=', label: '≤(更轻)' }],
    risk: [{ op: '=', label: '包含' }, { op: '!=', label: '不含' }]
  };
  var SF_RISK_VALS = [
    { v: 'attack', label: '任意高危' }, { v: 'none', label: '无高危' },
    { v: 'authfail', label: '登录失败' }, { v: 'priv', label: '提权/特权' },
    { v: 'account', label: '账户变更' }, { v: 'service', label: '服务/持久化' },
    { v: 'clearlog', label: '日志清除' }, { v: 'scan', label: '扫描/异常' },
    { v: 'malware', label: '恶意软件' }, { v: 'fw', label: '防火墙拦截' },
    { v: 'kernel', label: '内核/崩溃' }, { v: 'sev', label: '高严重级别' }
  ];
  var SF_LEVEL_VALS = [
    { v: 'crit', label: '严重' }, { v: 'err', label: '错误' }, { v: 'warn', label: '警告' },
    { v: 'notice', label: '通知' }, { v: 'info', label: '信息' }, { v: 'debug', label: '调试' }
  ];
  function sfField(key) { for (var i = 0; i < SF_FIELDS.length; i++) if (SF_FIELDS[i].key === key) return SF_FIELDS[i]; return SF_FIELDS[0]; }
  function sfOpLabel(type, op) { var ops = SF_OPS[type] || SF_OPS.text; for (var i = 0; i < ops.length; i++) if (ops[i].op === op) return ops[i].label; return op; }
  function sfValLabel(type, val) {
    if (type === 'risk') { for (var i = 0; i < SF_RISK_VALS.length; i++) if (SF_RISK_VALS[i].v === val) return SF_RISK_VALS[i].label; }
    if (type === 'level') { for (var j = 0; j < SF_LEVEL_VALS.length; j++) if (SF_LEVEL_VALS[j].v === val) return SF_LEVEL_VALS[j].label; }
    return val;
  }
  function quoteQueryVal(val) {
    val = String(val == null ? '' : val);
    if (/[&|]/.test(val) || /^\s|\s$/.test(val)) return '"' + val.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
    return val;
  }
  function defaultView() {
    return { q: '', simpleFilters: [], level: '', source: '', riskOnly: false, sortKey: '', sortDir: 'asc' };
  }

  var Sys = {
    worker: null,
    total: 0,
    view: defaultView(),
    lastReqStart: -1,
    rowsCache: {},
    analytics: null,
    summary: null,
    started: false,
    selPos: -1,             /* 当前选中行（视图索引），与右侧详情侧栏联动 */
    sideW: 0,               /* 详情侧栏宽度（px），拖拽可调并持久化 */
    search: { open: false, query: '', matches: [], set: null, cur: -1, caseSensitive: false, capped: false },

    init: function () {
      if (this.started) return;
      this.started = true;
      var self = this;
      var drop = $('sys-drop'), file = $('sys-file');
      if (!drop) return;
      // 使用 <input type="file"> 选文件
            // 使用 <input type="file"> 选文件
      document.getElementById('sys-file-btn').addEventListener('click', function () { file.click(); });
      file.addEventListener('change', function () { if (file.files && file.files[0]) self.load(file.files[0]); });

      // Electron 额外支持 IPC 拖拽/命令行
      if (window.electronAPI) {
        window.electronAPI.onFileDrop(function (fileData) {
          self.loadFromBuffer(fileData);
        });
      }
      drop.addEventListener('drop', function (e) { var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]; if (f) self.load(f); });
      var deb = null;
      $('sys-q').addEventListener('input', function () { clearTimeout(deb); deb = setTimeout(function () { self.view.q = $('sys-q').value.trim(); self.refreshView(); }, 200); });
      $('sys-level').addEventListener('change', function () { self.view.level = $('sys-level').value; self.refreshView(); });
      $('sys-risk').addEventListener('change', function () { self.view.riskOnly = $('sys-risk').checked; self.refreshView(); });
      $('sys-reset').addEventListener('click', function () { self.resetFilters(); });
      this.initSimpleFilter();

      $('sys-thead').addEventListener('click', function (e) {
        var th = e.target.closest('[data-sort]'); if (!th) return;
        var key = th.getAttribute('data-sort');
        if (self.view.sortKey === key) self.view.sortDir = self.view.sortDir === 'asc' ? 'desc' : 'asc';
        else { self.view.sortKey = key; self.view.sortDir = 'asc'; }
        self.renderSortIndicators();
        self.refreshView();
      });

      $('sys-viewport').addEventListener('scroll', function () { self.onScroll(); });
      /* 行点击 → 右侧详情侧栏展开 */
      $('sys-rows').addEventListener('click', function (e) {
        var row = e.target.closest('.lt-row'); if (!row) return;
        self.showDetail(row.getAttribute('data-raw') || '', row.getAttribute('data-meta') || '', parseInt(row.getAttribute('data-pos'), 10));
      });

      var expBar = $('sys-export');
      if (expBar) expBar.addEventListener('click', function (e) { var b = e.target.closest('[data-export]'); if (!b) return; self.exportReport(b.getAttribute('data-export')); });

      this.initResize();
      this.initSide();
      this.initFind();
      this.initMap();
    },

    /* ── 右侧详情侧栏：丝滑展开/收起 + 左缘手柄拖拽调宽 ── */
    initSide: function () {
      var self = this;
      var lt = $('sys-lt'), grip = $('sys-side-grip');
      if (!lt || !grip) return;
      try { this.sideW = parseInt(localStorage.getItem('sysSideW'), 10) || 0; } catch (_e) { this.sideW = 0; }
      $('sys-side-close').addEventListener('click', function () { self.closeSide(); });
      document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && !self.search.open && lt.classList.contains('is-side-open') && self.isSysActive()) self.closeSide();
      });
      grip.addEventListener('mousedown', function (e) {
        e.preventDefault();
        var rect = lt.getBoundingClientRect();
        lt.classList.add('lt--side-drag');
        document.body.classList.add('lt-resizing');
        function mm(ev) { self.sideW = Math.round(rect.right - ev.clientX); self.applySideW(); }
        function mu() {
          document.removeEventListener('mousemove', mm); document.removeEventListener('mouseup', mu);
          lt.classList.remove('lt--side-drag'); document.body.classList.remove('lt-resizing');
          try { localStorage.setItem('sysSideW', String(self.sideW)); } catch (_e2) {}
        }
        document.addEventListener('mousemove', mm); document.addEventListener('mouseup', mu);
      });
    },
    clampSideW: function (w) {
      var lt = $('sys-lt');
      var full = lt ? lt.clientWidth : 1200;
      var max = Math.max(260, full - 420);          /* 至少给表格留 420px */
      if (!w) w = Math.min(440, max);
      return Math.min(Math.max(w, 260), max);
    },
    applySideW: function () {
      this.sideW = this.clampSideW(this.sideW);
      cpSet('sys-side-w', '#sys-lt{--lt-side-w:' + this.sideW + 'px}');
    },
    closeSide: function () {
      var lt = $('sys-lt'); if (lt) lt.classList.remove('is-side-open');
      this.selPos = -1;
      this.markSel();
    },
    markSel: function () {
      var box = $('sys-rows'); if (!box) return;
      var rows = box.children, sp = String(this.selPos);
      for (var i = 0; i < rows.length; i++) {
        rows[i].classList.toggle('lt-row--sel', this.selPos >= 0 && rows[i].getAttribute('data-pos') === sp);
      }
    },

    /* ── 快速筛选 ── */
    initSimpleFilter: function () {
      var self = this;
      var fieldSel = $('sys-sf-field'); if (!fieldSel) return;
      if (!this.view.simpleFilters) this.view.simpleFilters = [];
      fieldSel.innerHTML = SF_FIELDS.map(function (f) { return '<option value="' + f.key + '">' + f.label + '</option>'; }).join('');
      fieldSel.addEventListener('change', function () { self.syncSfControls(); });
      $('sys-sf-add').addEventListener('click', function () { self.addSimpleFilter(); });
      $('sys-sf-val').addEventListener('keydown', function (e) { if (e.key === 'Enter') { e.preventDefault(); self.addSimpleFilter(); } });
      $('sys-sf-val-select').addEventListener('change', function () { var v = $('sys-sf-val-select').value; if (v) $('sys-sf-val').value = v; });
      this.syncSfControls();
      this.renderSfChips();
    },
    syncSfControls: function () {
      var field = sfField($('sys-sf-field').value);
      var opSel = $('sys-sf-op');
      var ops = SF_OPS[field.type] || SF_OPS.text;
      opSel.innerHTML = ops.map(function (o) { return '<option value="' + o.op + '">' + o.label + '</option>'; }).join('');
      var valIn = $('sys-sf-val'), valSel = $('sys-sf-val-select');
      if (field.type === 'risk' || field.type === 'level') {
        var vals = field.type === 'risk' ? SF_RISK_VALS : SF_LEVEL_VALS;
        valIn.classList.add('u-hidden');
        valSel.classList.remove('u-hidden');
        valSel.innerHTML = vals.map(function (r) { return '<option value="' + r.v + '">' + r.label + '</option>'; }).join('');
        valIn.value = valSel.value;
      } else {
        valIn.classList.remove('u-hidden');
        valSel.classList.add('u-hidden');
        valIn.value = '';
        valIn.placeholder = field.type === 'time' ? '2026-06-08 10:00:00' : field.type === 'number' ? '4625' : '输入值…';
      }
    },
    addSimpleFilter: function () {
      if (!this.view) this.view = defaultView();
      if (!this.view.simpleFilters) this.view.simpleFilters = [];
      var field = sfField($('sys-sf-field').value);
      var op = $('sys-sf-op').value;
      var val = ((field.type === 'risk' || field.type === 'level') ? $('sys-sf-val-select').value : $('sys-sf-val').value).trim();
      if (!val) { this.flash('请输入或选择筛选值'); return; }
      this.view.simpleFilters.push({ field: field.key, cn: field.cn, type: field.type, op: op, val: val });
      if (field.type !== 'risk' && field.type !== 'level') $('sys-sf-val').value = '';
      this.renderSfChips();
      this.refreshView();
    },
    renderSfChips: function () {
      var box = $('sys-sf-chips'); if (!box) return;
      var list = this.view.simpleFilters || [];
      if (!list.length) { box.hidden = true; box.innerHTML = ''; return; }
      box.hidden = false;
      var self = this;
      box.innerHTML = list.map(function (f, i) {
        return '<span class="log-chip">' + esc(self.chipLabel(f)) + '<button type="button" class="log-chip__x" data-i="' + i + '" aria-label="移除">×</button></span>';
      }).join('');
      box.querySelectorAll('.log-chip__x').forEach(function (btn) {
        btn.addEventListener('click', function () { self.view.simpleFilters.splice(+btn.getAttribute('data-i'), 1); self.renderSfChips(); self.refreshView(); });
      });
    },
    chipLabel: function (f) {
      var field = sfField(f.field), type = f.type || field.type;
      return (f.cn || field.cn) + ' ' + sfOpLabel(type, f.op) + ' ' + sfValLabel(type, f.val);
    },
    formatAtom: function (f) { return (f.cn || sfField(f.field).cn) + f.op + quoteQueryVal(f.val); },
    compileQuery: function () {
      var parts = [];
      (this.view.simpleFilters || []).forEach(function (f) { parts.push(Sys.formatAtom(f)); });
      var adv = (this.view.q || '').trim();
      if (adv) { if (parts.length && adv.indexOf('|') >= 0) parts.push('(' + adv + ')'); else parts.push(adv); }
      return parts.join(' & ');
    },

    /* ── 列宽拖拽 ── */
    cols: ['56px', '150px', '116px', '152px', '74px', '78px', 'minmax(220px,1fr)', '150px'],
    initResize: function () {
      var lt = $('sys-lt'), thead = $('sys-thead'); if (!lt || !thead) return;
      var self = this;
      function apply() { cpSet('sys-lt-cols', '#sys-lt{--lt-cols:' + self.cols.join(' ') + '}'); }
      apply();
      var heads = thead.children, MSG_COL = 6;
      for (var c = 0; c < heads.length; c++) {
        if (c === MSG_COL) continue;
        (function (idx) {
          var grip = document.createElement('span');
          grip.className = 'lt-resz';
          grip.addEventListener('click', function (e) { e.stopPropagation(); });
          grip.addEventListener('mousedown', function (e) {
            e.preventDefault(); e.stopPropagation();
            var startX = e.clientX, startW = heads[idx].getBoundingClientRect().width;
            document.body.classList.add('lt-resizing');
            function mm(ev) { self.cols[idx] = Math.max(40, Math.round(startW + (ev.clientX - startX))) + 'px'; apply(); }
            function mu() { document.removeEventListener('mousemove', mm); document.removeEventListener('mouseup', mu); document.body.classList.remove('lt-resizing'); }
            document.addEventListener('mousemove', mm); document.addEventListener('mouseup', mu);
          });
          heads[idx].appendChild(grip);
        })(c);
      }
    },

    loadFromBuffer: function (fd) {
      var bytes = new Uint8Array(fd.data);
      var wrapper = new Blob([bytes], { type: 'application/octet-stream' });
      wrapper.name = fd.name;
      wrapper.size = fd.size;
      this.load(wrapper);
    },

    load: function (file) {
      var self = this;
      this.fileName = file.name;
      $('sys-empty').hidden = true;
      $('sys-result').hidden = true;
      $('sys-progress').hidden = false;
      cpSet('sys-progress', '#sys-progress-bar{width:0%}');
      $('sys-progress-text').textContent = '正在读取 ' + esc(file.name) + '…';

      if (this.worker) { this.worker.terminate(); this.worker = null; }
      this.rowsCache = {}; this.lastReqStart = -1;
      try { // Blob URL Worker (避免 file:// 协议下 Worker 加载问题)
      var _wCode2 = `/**
 * 系统日志分析 —— Web Worker（数据层）
 *
 * 支持格式（自动识别）：
 *   · Windows EVTX 二进制事件日志（.evtx 原生格式：ElfFile 文件头 + ElfChnk 块 + Binary XML 模板编码）
 *   · Windows 事件日志 CSV（事件查看器「另存为 CSV」/ Get-WinEvent | Export-Csv，中英文表头）
 *   · Windows 事件日志 文本（事件查看器「另存为 .txt」，以「Log Name / 日志名称」分隔记录）
 *   · Linux Syslog RFC3164（/var/log/messages、syslog、auth.log、secure、journalctl 默认输出）
 *   · Linux Syslog ISO / RFC5424（rsyslog ISO 时间戳、含 <pri> 优先级、journalctl -o short-iso）
 *   · 通用文本兜底（逐行，按行首时间戳与关键字推断）
 *
 * 设计与「中间件日志分析」一致：全程 Worker 线程、FileReaderSync 流式分片读取、
 *   列式 off-heap 存储（原始/消息存入 ArrayBuffer 竞技场，主机/来源字典编码，数值用 TypedArray），
 *   一次遍历完成聚合统计与安全风险标记，维护过滤/排序索引，分页向主线程返回可视行。
 *   所有数据仅在浏览器本地处理，绝不上传任何服务器。
 */
'use strict';

var ENC = new TextEncoder();
var DEC = new TextDecoder('utf-8');
var DEC16 = new TextDecoder('utf-16le');
var ARENA_CHUNK = 128 * 1024 * 1024;        /* 竞技场单块 128MB */
var GROW_SHIFT = 20, GROW_SIZE = 1 << GROW_SHIFT, GROW_MASK = GROW_SIZE - 1;

/* 可增长的分块 TypedArray */
function Grow(Ctor) { this.C = Ctor; this.b = []; this.len = 0; }
Grow.prototype.push = function (v) {
  var ci = this.len >>> GROW_SHIFT;
  if (ci >= this.b.length) this.b.push(new this.C(GROW_SIZE));
  this.b[ci][this.len & GROW_MASK] = v; this.len++;
};
Grow.prototype.get = function (i) { return this.b[i >>> GROW_SHIFT][i & GROW_MASK]; };
Grow.prototype.clear = function () { this.b = []; this.len = 0; };

/* 字节竞技场：encodeInto 直写，避免逐条分配临时数组 */
function Arena() {
  this.chunks = []; this.cur = null; this.used = 0;
  this.ci = new Grow(Uint16Array); this.off = new Grow(Uint32Array); this.len = new Grow(Uint32Array);
}
Arena.prototype.put = function (s) {
  s = s || '';
  var maxBytes = s.length * 3;
  if (!this.cur || this.used + maxBytes > this.cur.length) {
    var sz = maxBytes > ARENA_CHUNK ? maxBytes : ARENA_CHUNK;
    this.cur = new Uint8Array(sz); this.chunks.push(this.cur); this.used = 0;
  }
  var off = this.used;
  var n = ENC.encodeInto(s, this.cur.subarray(off)).written;
  this.ci.push(this.chunks.length - 1); this.off.push(off); this.len.push(n);
  this.used += n;
};
Arena.prototype.str = function (i) {
  var L = this.len.get(i);
  return L ? DEC.decode(this.chunks[this.ci.get(i)].subarray(this.off.get(i), this.off.get(i) + L)) : '';
};
Arena.prototype.clear = function () {
  this.chunks = []; this.cur = null; this.used = 0;
  this.ci.clear(); this.off.clear(); this.len.clear();
};

/* 字典编码（主机 / 来源，基数低） */
function Dict() { this.map = new Map(); this.arr = []; }
Dict.prototype.id = function (s) {
  s = s || '';
  var v = this.map.get(s);
  if (v === undefined) { v = this.arr.length; this.arr.push(s); this.map.set(s, v); }
  return v;
};
Dict.prototype.clear = function () { this.map = new Map(); this.arr = []; };

/* ── 列存储 ── */
var rawArena = new Arena();      /* 原始记录文本（用于详情/全局搜索） */
var msgArena = new Arena();      /* 消息正文（用于消息列展示） */
var hostDict = new Dict();
var srcDict = new Dict();
var C_ts = new Grow(Float64Array);
var C_sev = new Grow(Uint8Array);
var C_eid = new Grow(Uint32Array);
var C_risk = new Grow(Uint16Array);
var C_hostId = new Grow(Uint32Array);
var C_srcId = new Grow(Uint32Array);

function gRaw(i) { return rawArena.str(i); }
function gMsg(i) { return msgArena.str(i); }
function gHost(i) { return hostDict.arr[C_hostId.get(i)] || ''; }
function gSource(i) { return srcDict.arr[C_srcId.get(i)] || ''; }
function gTs(i) { return C_ts.get(i); }
function gSev(i) { return C_sev.get(i); }
function gEid(i) { return C_eid.get(i); }
function gRisk(i) { return C_risk.get(i); }

function clearStore() {
  rawArena.clear(); msgArena.clear(); hostDict.clear(); srcDict.clear();
  C_ts.clear(); C_sev.clear(); C_eid.clear(); C_risk.clear(); C_hostId.clear(); C_srcId.clear();
}

var N = 0;
var viewIdx = null;
var baseYear = new Date().getFullYear();

/* ── 严重级别 ── */
var SEV_LABEL = ['调试', '信息', '通知', '警告', '错误', '严重'];
var SEV_KEY = ['debug', 'info', 'notice', 'warn', 'err', 'crit'];

/* ── 风险位掩码 ── */
var R_AUTHFAIL = 1, R_PRIV = 2, R_ACCOUNT = 4, R_SERVICE = 8, R_CLEARLOG = 16,
    R_SCAN = 32, R_MALWARE = 64, R_FW = 128, R_KERNEL = 256, R_SEV = 512;
var ATTACK_MASK = R_AUTHFAIL | R_PRIV | R_ACCOUNT | R_SERVICE | R_CLEARLOG | R_SCAN | R_MALWARE | R_FW | R_KERNEL;

var SIG = {
  authfail: /(failed password|authentication failure|invalid user|failed (?:publickey|keyboard-interactive)|failed login|login failed|auth(?:entication)? fail|too many authentication failures|maximum authentication attempts|logon failure|account failed to log on|bad password|pam_unix\\([^)]*\\): authentication)/i,
  priv: /(\\bsudo\\b|session opened for user root|\\bsu(?:do)?\\[|command=|elevated privileges|special privileges assigned|\\brunas\\b|pkexec|setuid|granted)/i,
  account: /(useradd|userdel|usermod|groupadd|groupdel|gpasswd|new user|new group|password (?:changed|reset)|account (?:created|enabled|disabled|locked)|user account was (?:created|changed|enabled)|added to (?:group|security))/i,
  service: /(a service was installed|service control manager|new service installed|systemd.*(?:failed|start request repeated)|failed to start|cron(?:tab)?\\[|scheduled task (?:created|registered)|created a scheduled task|new task registered)/i,
  clearlog: /(log (?:file )?(?:was )?cleared|audit log (?:was )?cleared|event log .*? cleared|the (?:security|system|application) log was cleared|wtmp begins)/i,
  scan: /(possible break-in attempt|did not receive identification string|bad protocol version|reverse mapping checking|port ?scan|repeated login failures|\\bnmap\\b|\\bmasscan\\b|negotiation failed)/i,
  malware: /(\\bvirus\\b|\\bmalware\\b|\\btrojan\\b|ransomware|threat (?:detected|found)|quarantine|defender (?:detected|found)|\\bclamav\\b|infected|malicious)/i,
  fw: /(ufw block|\\[ufw |iptables|firewalld|windows firewall|wfp .*? block|packet dropped|\\bDROP\\b in=|\\bREJECT\\b in=|blocked by firewall)/i,
  kernel: /(segfault|kernel panic|\\bpanic:|oom[- ]?killer|out of memory|general protection fault|\\bBUG:|call trace|i\\/o error|ext4-fs error|hung task|soft lockup|watchdog|machine check|\\bmce:|unexpected shutdown|bugcheck|blue ?screen)/i
};

/* Windows 事件 ID → 风险位（最可靠的判定来源） */
var WIN_EID = {
  4625: R_AUTHFAIL, 529: R_AUTHFAIL, 4771: R_AUTHFAIL, 4776: R_AUTHFAIL,
  4672: R_PRIV, 4673: R_PRIV, 4648: R_PRIV,
  4720: R_ACCOUNT, 4722: R_ACCOUNT, 4723: R_ACCOUNT, 4724: R_ACCOUNT, 4725: R_ACCOUNT, 4726: R_ACCOUNT, 4738: R_ACCOUNT, 4728: R_ACCOUNT, 4732: R_ACCOUNT, 4756: R_ACCOUNT, 4767: R_ACCOUNT,
  7045: R_SERVICE, 7034: R_SERVICE, 4697: R_SERVICE, 4698: R_SERVICE, 4699: R_SERVICE, 4700: R_SERVICE, 4701: R_SERVICE, 4702: R_SERVICE,
  1102: R_CLEARLOG, 104: R_CLEARLOG, 1100: R_CLEARLOG,
  1116: R_MALWARE, 1117: R_MALWARE, 1006: R_MALWARE, 1007: R_MALWARE, 1015: R_MALWARE,
  5152: R_FW, 5157: R_FW,
  41: R_KERNEL, 6008: R_KERNEL, 1001: R_KERNEL, 1003: R_KERNEL, 1000: R_KERNEL
};

/* ── 聚合统计 ── */
var AGG, aggCapped;
var AGG_CAP = 300000;
function resetAgg() {
  aggCapped = false;
  AGG = {
    lines: 0, parsed: 0, failed: 0,
    tsMin: Infinity, tsMax: -Infinity,
    sevDist: [0, 0, 0, 0, 0, 0],
    hostCount: new Map(), srcCount: new Map(), eidCount: new Map(), authFail: new Map(),
    hour: new Map(),
    riskTotal: 0,
    riskCat: { authfail: 0, priv: 0, account: 0, service: 0, clearlog: 0, scan: 0, malware: 0, fw: 0, kernel: 0, sev: 0 }
  };
}
function bump(map, key) { map.set(key, (map.get(key) || 0) + 1); }
function bumpCapped(map, key) {
  var c = map.get(key);
  if (c !== undefined) map.set(key, c + 1);
  else if (map.size < AGG_CAP) map.set(key, 1);
  else aggCapped = true;
}

/* ── 时间解析 ── */
var MON = { Jan: 0, Feb: 1, Mar: 2, Apr: 3, May: 4, Jun: 5, Jul: 6, Aug: 7, Sep: 8, Oct: 9, Nov: 10, Dec: 11 };
function parseAnyTime(s) {
  if (!s) return NaN;
  s = String(s).replace(/[\\u200e\\u200f\\u202a-\\u202e]/g, '').trim();
  if (!s) return NaN;
  var t = Date.parse(s);
  if (!isNaN(t)) return t;
  t = Date.parse(s.replace(' ', 'T'));
  if (!isNaN(t)) return t;
  return NaN;
}
function parseBsdTime(s) {
  var m = /^([A-Z][a-z]{2})\\s+(\\d{1,2})\\s+(\\d{1,2}):(\\d{2}):(\\d{2})/.exec(s);
  if (!m) return NaN;
  var mon = MON[m[1]]; if (mon == null) return NaN;
  var y = baseYear;
  var t = new Date(y, mon, +m[2], +m[3], +m[4], +m[5]).getTime();
  if (t - Date.now() > 2 * 86400000) t = new Date(y - 1, mon, +m[2], +m[3], +m[4], +m[5]).getTime();
  return t;
}
/* syslog 优先级 → 我们的 sevId（syslog severity: 0 emerg..7 debug） */
function priToSev(pri) { return [5, 5, 5, 4, 3, 2, 1, 0][pri & 7]; }

/* ── 级别推断 ── */
function inferSev(msg) {
  var s = (msg || '').toLowerCase();
  if (/\\b(emerg|alert|fatal)\\b|kernel panic/.test(s)) return 5;
  if (/\\b(crit|critical)\\b/.test(s)) return 5;
  if (/\\b(err|error|errors|fail|failed|failure|denied|refused|unable|cannot|can't|segfault|corrupt|exception|timed out|timeout)\\b/.test(s)) return 4;
  if (/\\b(warn|warning|deprecated|retry|retrying|throttl|degraded)\\b/.test(s)) return 3;
  if (/\\b(debug)\\b/.test(s)) return 0;
  if (/\\b(notice)\\b/.test(s)) return 2;
  return 1;
}
function winSev(level) {
  var l = (level || '').toLowerCase();
  if (l.indexOf('critical') >= 0 || l.indexOf('严重') >= 0) return 5;
  if (l.indexOf('error') >= 0 || l.indexOf('错误') >= 0) return 4;
  if (l.indexOf('warn') >= 0 || l.indexOf('警告') >= 0) return 3;
  if (l.indexOf('verbose') >= 0 || l.indexOf('详细') >= 0) return 0;
  if (l.indexOf('info') >= 0 || l.indexOf('信息') >= 0) return 1;
  var n = parseInt(level, 10);
  if (!isNaN(n)) return n === 1 ? 5 : n === 2 ? 4 : n === 3 ? 3 : n === 5 ? 0 : 1;
  return 1;
}

/* ── 风险识别 ── */
function extractAuthSrc(msg) {
  var ipm = /(\\d{1,3}(?:\\.\\d{1,3}){3})/.exec(msg);
  if (ipm) { bumpCapped(AGG.authFail, ipm[1]); return; }
  var um = /(?:invalid user |user |account name:\\s*|for )([A-Za-z0-9_.\\-\\\\$]{2,40})/i.exec(msg);
  if (um) bumpCapped(AGG.authFail, '用户:' + um[1]);
}
function detectRisk(rec) {
  var msg = rec.msg || '', src = rec.source || '';
  var hay = (msg + ' ' + src).toLowerCase();
  var r = 0, eid = rec.eid || 0;
  if (eid && WIN_EID[eid]) r |= WIN_EID[eid];
  if (SIG.authfail.test(hay)) r |= R_AUTHFAIL;
  if (SIG.priv.test(hay)) r |= R_PRIV;
  if (SIG.account.test(hay)) r |= R_ACCOUNT;
  if (SIG.service.test(hay)) r |= R_SERVICE;
  if (SIG.clearlog.test(hay)) r |= R_CLEARLOG;
  if (SIG.scan.test(hay)) r |= R_SCAN;
  if (SIG.malware.test(hay)) r |= R_MALWARE;
  if (SIG.fw.test(hay)) r |= R_FW;
  if (SIG.kernel.test(hay)) r |= R_KERNEL;
  if ((rec.sevId || 0) >= 4) r |= R_SEV;

  if (r & R_AUTHFAIL) { AGG.riskCat.authfail++; extractAuthSrc(msg); }
  if (r & R_PRIV) AGG.riskCat.priv++;
  if (r & R_ACCOUNT) AGG.riskCat.account++;
  if (r & R_SERVICE) AGG.riskCat.service++;
  if (r & R_CLEARLOG) AGG.riskCat.clearlog++;
  if (r & R_SCAN) AGG.riskCat.scan++;
  if (r & R_MALWARE) AGG.riskCat.malware++;
  if (r & R_FW) AGG.riskCat.fw++;
  if (r & R_KERNEL) AGG.riskCat.kernel++;
  if (r & R_SEV) AGG.riskCat.sev++;
  if ((r & ATTACK_MASK) || (r & R_SEV)) AGG.riskTotal++;
  return r;
}
function riskTags(mask) {
  var t = [];
  if (mask & R_AUTHFAIL) t.push('登录失败');
  if (mask & R_PRIV) t.push('提权');
  if (mask & R_ACCOUNT) t.push('账户变更');
  if (mask & R_SERVICE) t.push('服务/持久化');
  if (mask & R_CLEARLOG) t.push('日志清除');
  if (mask & R_SCAN) t.push('扫描/异常');
  if (mask & R_MALWARE) t.push('恶意软件');
  if (mask & R_FW) t.push('防火墙');
  if (mask & R_KERNEL) t.push('内核/崩溃');
  if ((mask & R_SEV) && !t.length) t.push('高严重');
  return t;
}

/* ── 记录入库 ── */
function handleRecord(rec) {
  AGG.lines++;
  if (!rec) { AGG.failed++; return; }
  var risk = detectRisk(rec);
  N++;
  rawArena.put(rec.raw || '');
  msgArena.put(rec.msg || '');
  C_hostId.push(hostDict.id(rec.host || ''));
  C_srcId.push(srcDict.id(rec.source || ''));
  var ts = rec.ts; if (ts == null) ts = NaN;
  C_ts.push(ts);
  C_sev.push(rec.sevId || 0);
  C_eid.push(rec.eid || 0);
  C_risk.push(risk);

  AGG.parsed++;
  AGG.sevDist[rec.sevId || 0]++;
  if (!isNaN(ts)) { if (ts < AGG.tsMin) AGG.tsMin = ts; if (ts > AGG.tsMax) AGG.tsMax = ts; bump(AGG.hour, Math.floor(ts / 3600000)); }
  if (rec.host) bumpCapped(AGG.hostCount, rec.host);
  if (rec.source) bumpCapped(AGG.srcCount, rec.source);
  if (rec.eid) bumpCapped(AGG.eidCount, String(rec.eid));
}

/* ============================================================
 *  各格式解析
 * ============================================================ */
var RE_ISO = /^(?:<(\\d+)>(?:\\d\\s+)?)?(\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}(?:[.,]\\d+)?(?:Z|[+\\-]\\d{2}:?\\d{2})?)\\s+(\\S+)\\s+([\\s\\S]*)$/;
var RE_BSD = /^([A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{1,2}:\\d{2}:\\d{2})\\s+(\\S+)\\s+([\\s\\S]*)$/;
var RE_TAG = /^([^:\\[\\s][^:\\[]*?)(?:\\[(\\d+)\\])?:\\s?([\\s\\S]*)$/;
var RE_LEADTS = /^(\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}\\S*)\\s+([\\s\\S]*)$/;

var RE_ISO_TEST = /^(?:<\\d+>(?:\\d\\s)?)?\\d{4}-\\d{2}-\\d{2}[T ]\\d{2}:\\d{2}:\\d{2}/;
var RE_BSD_TEST = /^[A-Z][a-z]{2}\\s+\\d{1,2}\\s+\\d{1,2}:\\d{2}:\\d{2}\\s+\\S+\\s+\\S/;

function splitTag(rest) {
  var m = RE_TAG.exec(rest);
  if (m) return { tag: (m[1] || '').trim(), pid: m[2] ? +m[2] : 0, msg: m[3] || '' };
  return { tag: '', pid: 0, msg: rest };
}
function parseLine(line) {
  var m;
  if ((m = RE_ISO.exec(line))) {
    var pri = m[1] != null ? +m[1] : null;
    var ts = parseAnyTime(m[2]);
    var host = m[3];
    var tp = splitTag(m[4]);
    var sevId = pri != null ? priToSev(pri) : inferSev(tp.msg || m[4]);
    return { ts: ts, host: host, source: tp.tag, pid: tp.pid, sevId: sevId, eid: 0, msg: tp.msg || m[4], raw: line };
  }
  if ((m = RE_BSD.exec(line))) {
    var ts2 = parseBsdTime(m[1]);
    var tp2 = splitTag(m[3]);
    return { ts: ts2, host: m[2], source: tp2.tag, pid: tp2.pid, sevId: inferSev(tp2.msg || m[3]), eid: 0, msg: tp2.msg || m[3], raw: line };
  }
  /* 通用兜底 */
  var gm = RE_LEADTS.exec(line);
  if (gm) return { ts: parseAnyTime(gm[1]), host: '', source: '', pid: 0, sevId: inferSev(gm[2]), eid: 0, msg: gm[2], raw: line };
  return { ts: NaN, host: '', source: '', pid: 0, sevId: inferSev(line), eid: 0, msg: line, raw: line };
}

/* ── CSV ── */
function makeCsvReader() {
  var field = '', row = [], inQ = false;
  return {
    feed: function (text) {
      var out = [];
      for (var i = 0; i < text.length; i++) {
        var c = text[i];
        if (inQ) {
          if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else inQ = false; }
          else field += c;
        } else {
          if (c === '"') inQ = true;
          else if (c === ',') { row.push(field); field = ''; }
          else if (c === '\\n') { row.push(field); field = ''; out.push(row); row = []; }
          else if (c === '\\r') { /* skip */ }
          else field += c;
        }
      }
      return out;
    },
    end: function () {
      if (inQ) inQ = false;
      if (field.length || row.length) { row.push(field); field = ''; var r = row; row = []; return [r]; }
      return [];
    }
  };
}
function parseCsvLineSimple(line) {
  var r = makeCsvReader();
  var rows = r.feed(line + '\\n');
  return rows.length ? rows[0] : [line];
}
function matchCol(c) {
  c = c.replace(/\\s+/g, ' ').trim().toLowerCase().replace(/^["']|["']$/g, '');
  if (/date.*time/.test(c) || /^(time ?created|date and time|date|time|时间|日期和时间|日期|记录时间)$/.test(c)) return 'time';
  if (c.indexOf('level') >= 0 || /^(级别|等级|严重性|严重级别)$/.test(c)) return 'level';
  if (c.indexOf('provider') >= 0 || /^(source|来源|事件来源|提供程序|提供者)$/.test(c)) return 'source';
  if (/^(event ?id|id|事件\\s*id|事件\\s*标识|事件\\s*编号)$/.test(c)) return 'eid';
  if (/^(message|description|消息|描述|说明|常规)$/.test(c)) return 'msg';
  if (/^(machinename|computer ?name|computer|计算机|计算机名|主机|主机名)$/.test(c)) return 'host';
  if (/^(task ?category|任务类别|类别)$/.test(c)) return 'cat';
  if (/^(log ?name|logname|日志名称|日志)$/.test(c)) return 'logname';
  if (/^(user|用户|帐户|账户)$/.test(c)) return 'user';
  return null;
}
function isCsvHeader(line) {
  if (line.indexOf(',') < 0) return false;
  if (RE_ISO_TEST.test(line) || RE_BSD_TEST.test(line)) return false;
  var cells = parseCsvLineSimple(line);
  var known = 0;
  for (var i = 0; i < cells.length; i++) if (matchCol(cells[i])) known++;
  return known >= 2;
}
function composeRaw(o) {
  var parts = [];
  if (o.time) parts.push(o.time);
  if (o.level) parts.push('[' + o.level + ']');
  if (o.host) parts.push(o.host);
  if (o.source) parts.push(o.source);
  if (o.eid) parts.push('EventID ' + o.eid);
  if (o.logname) parts.push(o.logname);
  var head = parts.join('  ');
  return head + (o.msg ? '\\n' + o.msg : '');
}

/* ── Windows 文本块 ── */
function normalizeWinKey(k) {
  k = k.replace(/\\s+/g, ' ').trim().toLowerCase();
  if (/^(log name|日志名称)$/.test(k)) return 'logname';
  if (/^(source|来源)$/.test(k)) return 'source';
  if (/^(event id|事件 id|事件id)$/.test(k)) return 'eid';
  if (/^(level|级别)$/.test(k)) return 'level';
  if (/^(date|logged|日期|记录时间)$/.test(k)) return 'time';
  if (/^(computer|计算机)$/.test(k)) return 'host';
  if (/^(task category|任务类别)$/.test(k)) return 'cat';
  if (/^(user|用户)$/.test(k)) return 'user';
  if (/^(description|说明|常规)$/.test(k)) return 'msg';
  return null;
}
function parseWinBlock(block) {
  var lines = block.split('\\n');
  var o = {}, descMode = false, desc = [];
  for (var i = 0; i < lines.length; i++) {
    var line = lines[i];
    if (descMode) { desc.push(line); continue; }
    var m = /^([A-Za-z][A-Za-z ]*?|[\\u4e00-\\u9fff ]+?)\\s*[:：]\\s?(.*)$/.exec(line);
    if (m) {
      var key = normalizeWinKey(m[1]);
      if (key === 'msg') { descMode = true; if (m[2] && m[2].trim()) desc.push(m[2]); continue; }
      if (key) o[key] = m[2].trim();
    }
  }
  o.msgText = desc.join('\\n').trim();
  if (!o.logname && !o.source && !o.eid && !o.level && !o.msgText) return null;
  var eidN = parseInt(String(o.eid || '').replace(/[^\\d]/g, ''), 10) || 0;
  return {
    ts: parseAnyTime(o.time), host: o.host || '', source: o.source || o.logname || '',
    pid: 0, sevId: winSev(o.level), eid: eidN, msg: o.msgText || o.cat || '', raw: block.trim()
  };
}

/* ── 格式识别 ── */
function detectFormat(sample) {
  var lines = sample.split('\\n').map(function (s) { return s.replace(/\\r$/, ''); }).filter(function (s) { return s.trim(); });
  if (!lines.length) return { mode: 'line', name: '通用文本' };
  if (isCsvHeader(lines[0])) return { mode: 'csv', name: 'Windows 事件 CSV' };
  var winHits = 0;
  for (var i = 0; i < lines.length && i < 60; i++) {
    if (/^(Log Name|Source|Event ID|Level|Date|Description|Computer|Task Category|日志名称|来源|事件\\s*ID|级别|日期|说明|计算机|任务类别)\\s*[:：]/i.test(lines[i])) winHits++;
  }
  if (winHits >= 3) return { mode: 'winText', name: 'Windows 事件文本' };
  var iso = 0, bsd = 0, sn = Math.min(lines.length, 80);
  for (var j = 0; j < sn; j++) { if (RE_ISO_TEST.test(lines[j])) iso++; else if (RE_BSD_TEST.test(lines[j])) bsd++; }
  var need = Math.max(1, Math.floor(sn * 0.35));
  if (iso >= bsd && iso >= need) return { mode: 'line', name: 'Linux Syslog（ISO/RFC5424）' };
  if (bsd >= need) return { mode: 'line', name: 'Linux Syslog（RFC3164）' };
  return { mode: 'line', name: '通用文本' };
}

/* ============================================================
 *  Windows EVTX 二进制事件日志解析
 *  结构：4096B 文件头(ElfFile) + N × 65536B 块(ElfChnk)；
 *  每块：512B 块头 + 事件记录(0x2A2A0000 签名)；记录正文为 Binary XML：
 *  片段头(0x0F) + 模板实例(0x0C，含驻留模板定义 + 替换值数组) / 元素流。
 *  名称字符串与模板定义均为块内偏移引用，逐块独立缓存。
 * ============================================================ */
function trimNul(s) { return s.replace(/\\u0000+$/, ''); }
function utf16(u8, off, charCount) { return charCount > 0 ? DEC16.decode(u8.subarray(off, off + charCount * 2)) : ''; }
function hexBytes(u8, off, n) {
  var s = '';
  for (var i = 0; i < n; i++) { var b = u8[off + i].toString(16); s += (b.length < 2 ? '0' : '') + b; }
  return s.toUpperCase();
}
/* FILETIME(100ns 自 1601-01-01) → Unix 毫秒 */
function ftToMs(dv, off) {
  var lo = dv.getUint32(off, true), hi = dv.getUint32(off + 4, true);
  if (!lo && !hi) return NaN;
  return hi * 429496.7296 + lo / 10000 - 11644473600000;
}
function guidStr(dv, off) {
  function hx(n, w) { var s = n.toString(16); while (s.length < w) s = '0' + s; return s; }
  var s = hx(dv.getUint32(off, true), 8) + '-' + hx(dv.getUint16(off + 4, true), 4) + '-' + hx(dv.getUint16(off + 6, true), 4) + '-' +
    hx(dv.getUint8(off + 8), 2) + hx(dv.getUint8(off + 9), 2) + '-';
  for (var i = 10; i < 16; i++) s += hx(dv.getUint8(off + i), 2);
  return '{' + s + '}';
}
function sidStr(c, off, size) {
  if (size < 8) return '';
  var rev = c.u8[off], cnt = c.u8[off + 1], auth = 0, i;
  for (i = 2; i < 8; i++) auth = auth * 256 + c.u8[off + i];
  var s = 'S-' + rev + '-' + auth;
  for (var j = 0; j < cnt && 8 + j * 4 + 4 <= size; j++) s += '-' + c.dv.getUint32(off + 8 + j * 4, true);
  return s;
}
function sysTimeStr(dv, off) {
  function p(n) { return (n < 10 ? '0' : '') + n; }
  return dv.getUint16(off, true) + '-' + p(dv.getUint16(off + 2, true)) + '-' + p(dv.getUint16(off + 6, true)) + ' ' +
    p(dv.getUint16(off + 8, true)) + ':' + p(dv.getUint16(off + 10, true)) + ':' + p(dv.getUint16(off + 12, true));
}

function XEl(name) { this.name = name; this.attrs = {}; this.children = []; this.text = ''; }
var X_ENTITY = { amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ' };
var EX_TOKEN_MAX = 400000;   /* 单条记录 BinXML 标记上限，防止脏数据死循环 */

/* 名称字符串：next(4) + hash(2) + 字符数(2) + UTF-16 + \\0；驻留时跳过其字节 */
function exResolveName(c, st, off, tokenStart) {
  if (off >= tokenStart) {
    var cnt = c.dv.getUint16(off + 6, true);
    var s = utf16(c.u8, off + 8, cnt);
    c.names[off] = s;
    st.p = off + 8 + cnt * 2 + 2;
    return s;
  }
  var cached = c.names[off];
  if (cached !== undefined) return cached;
  var cnt2 = c.dv.getUint16(off + 6, true);
  var s2 = utf16(c.u8, off + 8, cnt2);
  c.names[off] = s2;
  return s2;
}

/* 内联值（Value token 0x05/0x45 的负载，type 已读出） */
function exValueText(c, st, t) {
  var dv = c.dv, u8 = c.u8, s, n;
  switch (t) {
    case 0x00: return '';
    case 0x01: n = dv.getUint16(st.p, true); st.p += 2; s = utf16(u8, st.p, n); st.p += n * 2; return s;
    case 0x02: n = dv.getUint16(st.p, true); st.p += 2; s = DEC.decode(u8.subarray(st.p, st.p + n)); st.p += n; return s;
    case 0x03: s = String(dv.getInt8(st.p)); st.p += 1; return s;
    case 0x04: s = String(u8[st.p]); st.p += 1; return s;
    case 0x05: s = String(dv.getInt16(st.p, true)); st.p += 2; return s;
    case 0x06: s = String(dv.getUint16(st.p, true)); st.p += 2; return s;
    case 0x07: s = String(dv.getInt32(st.p, true)); st.p += 4; return s;
    case 0x08: s = String(dv.getUint32(st.p, true)); st.p += 4; return s;
    case 0x09: s = String(dv.getBigInt64(st.p, true)); st.p += 8; return s;
    case 0x0a: s = String(dv.getBigUint64(st.p, true)); st.p += 8; return s;
    case 0x0b: s = String(dv.getFloat32(st.p, true)); st.p += 4; return s;
    case 0x0c: s = String(dv.getFloat64(st.p, true)); st.p += 8; return s;
    case 0x0d: s = u8[st.p] ? 'true' : 'false'; st.p += 4; return s;
    case 0x0f: s = guidStr(dv, st.p); st.p += 16; return s;
    case 0x11: { var ms = ftToMs(dv, st.p); st.p += 8; return isNaN(ms) ? '' : new Date(ms).toISOString(); }
    case 0x14: s = '0x' + dv.getUint32(st.p, true).toString(16); st.p += 4; return s;
    case 0x15: s = '0x' + dv.getBigUint64(st.p, true).toString(16); st.p += 8; return s;
    default: throw new Error('未支持的内联值类型 0x' + t.toString(16));
  }
}

/* 替换值（substitution array 项）→ 字符串 */
function exSubText(c, sb) {
  var t = sb.type, off = sb.off, n = sb.size, dv = c.dv, u8 = c.u8;
  if (t === 0x00 || n === 0) return '';
  if (t & 0x80) {
    var base = t & 0x7f;
    if (base === 0x01) return trimNul(DEC16.decode(u8.subarray(off, off + n))).split('\\u0000').filter(Boolean).join(', ');
    if (base === 0x06 || base === 0x08) {
      var step = base === 0x06 ? 2 : 4, outA = [];
      for (var k = 0; k + step <= n; k += step) outA.push(base === 0x06 ? dv.getUint16(off + k, true) : dv.getUint32(off + k, true));
      return outA.join(', ');
    }
    return hexBytes(u8, off, Math.min(n, 32)) + (n > 32 ? '…' : '');
  }
  switch (t) {
    case 0x01: return trimNul(DEC16.decode(u8.subarray(off, off + n)));
    case 0x02: return trimNul(DEC.decode(u8.subarray(off, off + n)));
    case 0x03: return String(dv.getInt8(off));
    case 0x04: return String(u8[off]);
    case 0x05: return String(dv.getInt16(off, true));
    case 0x06: return String(dv.getUint16(off, true));
    case 0x07: return String(dv.getInt32(off, true));
    case 0x08: return String(dv.getUint32(off, true));
    case 0x09: return n >= 8 ? String(dv.getBigInt64(off, true)) : '';
    case 0x0a: return n >= 8 ? String(dv.getBigUint64(off, true)) : '';
    case 0x0b: return String(dv.getFloat32(off, true));
    case 0x0c: return String(dv.getFloat64(off, true));
    case 0x0d: return u8[off] ? 'true' : 'false';
    case 0x0e: return hexBytes(u8, off, Math.min(n, 64)) + (n > 64 ? '…' : '');
    case 0x0f: return n >= 16 ? guidStr(dv, off) : '';
    case 0x10: return '0x' + (n >= 8 ? dv.getBigUint64(off, true).toString(16) : dv.getUint32(off, true).toString(16));
    case 0x11: { var ms = ftToMs(dv, off); return isNaN(ms) ? '' : new Date(ms).toISOString(); }
    case 0x12: return n >= 16 ? sysTimeStr(dv, off) : '';
    case 0x13: return sidStr(c, off, n);
    case 0x14: return '0x' + dv.getUint32(off, true).toString(16);
    case 0x15: return n >= 8 ? '0x' + dv.getBigUint64(off, true).toString(16) : '';
    case 0x21: return '';   /* 嵌套 BinXML 由 exSubNodes 展开 */
    default: return hexBytes(u8, off, Math.min(n, 32));
  }
}

/* 替换值 → 节点/字符串数组（type 0x21 递归展开嵌套 BinXML 片段） */
function exSubNodes(c, subs, idx) {
  if (!subs || idx >= subs.length) return [];
  var sb = subs[idx];
  if (sb.type === 0x21) {
    var out = [];
    exFragment(c, { p: sb.off, n: 0 }, null, out, sb.off + sb.size);
    return out;
  }
  var s = exSubText(c, sb);
  return s ? [s] : [];
}

function exElement(c, st, subs) {
  if (++st.n > EX_TOKEN_MAX) throw new Error('BinXML 标记数超限');
  var start = st.p;
  var tok = c.u8[st.p]; st.p += 1;
  var hasAttrs = (tok & 0x40) !== 0;
  st.p += 6;                                            /* 依赖标识(2) + 元素大小(4) */
  var nameOff = c.dv.getUint32(st.p, true); st.p += 4;
  /* 注意顺序：内联名称结构紧跟名称偏移字段，属性列表大小在名称之后 */
  var el = new XEl(exResolveName(c, st, nameOff, start));
  if (hasAttrs) st.p += 4;                              /* 属性列表大小 */
  if (hasAttrs) {
    var more = true;
    while (more) {
      if (++st.n > EX_TOKEN_MAX) throw new Error('BinXML 标记数超限');
      var aStart = st.p;
      var atok = c.u8[st.p]; st.p += 1;
      if (atok !== 0x06 && atok !== 0x46) throw new Error('属性标记异常 0x' + atok.toString(16));
      more = atok === 0x46;
      var aOff = c.dv.getUint32(st.p, true); st.p += 4;
      var aname = exResolveName(c, st, aOff, aStart);
      var vtok = c.u8[st.p];
      if (vtok === 0x05 || vtok === 0x45) {
        st.p += 1; var t = c.u8[st.p]; st.p += 1;
        el.attrs[aname] = exValueText(c, st, t);
      } else if (vtok === 0x0d || vtok === 0x0e) {
        st.p += 1; var ix = c.dv.getUint16(st.p, true); st.p += 3;
        var nodes = exSubNodes(c, subs, ix), sv = '';
        for (var q = 0; q < nodes.length; q++) if (typeof nodes[q] === 'string') sv += nodes[q];
        el.attrs[aname] = sv;
      } else throw new Error('属性值标记异常 0x' + vtok.toString(16));
    }
  }
  var ct = c.u8[st.p]; st.p += 1;
  if (ct === 0x03) return el;                           /* <El/> 空元素 */
  if (ct !== 0x02) throw new Error('元素闭合标记异常 0x' + ct.toString(16));
  exContent(c, st, subs, el);
  return el;
}

function exContent(c, st, subs, el) {
  for (;;) {
    if (++st.n > EX_TOKEN_MAX) throw new Error('BinXML 标记数超限');
    var tok = c.u8[st.p];
    if (tok === 0x04 || tok === 0x00) { st.p += 1; return; }          /* EndElement / EOF */
    if (tok === 0x01 || tok === 0x41) { el.children.push(exElement(c, st, subs)); continue; }
    if (tok === 0x05 || tok === 0x45) { st.p += 1; var t = c.u8[st.p]; st.p += 1; el.text += exValueText(c, st, t); continue; }
    if (tok === 0x0d || tok === 0x0e) {
      st.p += 1; var ix = c.dv.getUint16(st.p, true); st.p += 3;
      var nodes = exSubNodes(c, subs, ix);
      for (var i = 0; i < nodes.length; i++) { if (typeof nodes[i] === 'string') el.text += nodes[i]; else el.children.push(nodes[i]); }
      continue;
    }
    if (tok === 0x07 || tok === 0x47) { st.p += 1; var cc = c.dv.getUint16(st.p, true); st.p += 2; el.text += utf16(c.u8, st.p, cc); st.p += cc * 2; continue; }
    if (tok === 0x08 || tok === 0x48) { st.p += 1; el.text += String.fromCharCode(c.dv.getUint16(st.p, true)); st.p += 2; continue; }
    if (tok === 0x09 || tok === 0x49) { var eS = st.p; st.p += 1; var eO = c.dv.getUint32(st.p, true); st.p += 4; var en = exResolveName(c, st, eO, eS); el.text += X_ENTITY[en] || ''; continue; }
    if (tok === 0x0a) { var pS = st.p; st.p += 1; var pO = c.dv.getUint32(st.p, true); st.p += 4; exResolveName(c, st, pO, pS); continue; }
    if (tok === 0x0b) { st.p += 1; var pc = c.dv.getUint16(st.p, true); st.p += 2 + pc * 2; continue; }
    if (tok === 0x0c) { exTemplateInstance(c, st, el.children); continue; }
    if (tok === 0x0f) { st.p += 4; continue; }
    throw new Error('未知内容标记 0x' + tok.toString(16));
  }
}

/* 模板实例：头(10B) + [驻留模板定义] + 替换值数组；展开定义并代入替换值 */
function exTemplateInstance(c, st, out) {
  var instStart = st.p;
  st.p += 2;                                            /* token(0x0C) + 版本字节 */
  st.p += 4;                                            /* 模板标识 */
  var defOff = c.dv.getUint32(st.p, true); st.p += 4;
  var def;
  if (defOff >= instStart) {                            /* 定义驻留在实例内部 */
    def = { body: defOff + 24, len: c.dv.getUint32(defOff + 20, true) };
    c.templates[defOff] = def;
    st.p = defOff + 24 + def.len;                       /* 定义头：next(4)+GUID(16)+长度(4) */
  } else {
    def = c.templates[defOff];
    if (!def) { def = { body: defOff + 24, len: c.dv.getUint32(defOff + 20, true) }; c.templates[defOff] = def; }
  }
  var n = c.dv.getUint32(st.p, true); st.p += 4;
  if (n > 4096) throw new Error('替换值数量异常 ' + n);
  var subs = [], i;
  for (i = 0; i < n; i++) { subs.push({ size: c.dv.getUint16(st.p, true), type: c.u8[st.p + 2], off: 0 }); st.p += 4; }
  for (i = 0; i < n; i++) { subs[i].off = st.p; st.p += subs[i].size; }
  exFragment(c, { p: def.body, n: 0 }, subs, out, def.body + def.len);
}

function exFragment(c, st, subs, out, end) {
  while (st.p < end) {
    if (++st.n > EX_TOKEN_MAX) throw new Error('BinXML 标记数超限');
    var tok = c.u8[st.p];
    if (tok === 0x00) { st.p += 1; return; }
    if (tok === 0x0f) { st.p += 4; continue; }
    if (tok === 0x0c) { exTemplateInstance(c, st, out); continue; }
    if (tok === 0x01 || tok === 0x41) { out.push(exElement(c, st, subs)); continue; }
    if (tok === 0x05 || tok === 0x45) { st.p += 1; var t = c.u8[st.p]; st.p += 1; out.push(exValueText(c, st, t)); continue; }
    if (tok === 0x0d || tok === 0x0e) {
      st.p += 1; var ix = c.dv.getUint16(st.p, true); st.p += 3;
      var nodes = exSubNodes(c, subs, ix);
      for (var i = 0; i < nodes.length; i++) out.push(nodes[i]);
      continue;
    }
    throw new Error('未知片段标记 0x' + tok.toString(16));
  }
}

/* ── 事件树 → 业务字段 ── */
function xChild(el, name) {
  if (!el) return null;
  for (var i = 0; i < el.children.length; i++) { var ch = el.children[i]; if (ch && ch.name === name) return ch; }
  return null;
}
function xText(el) { return el ? String(el.text || '').trim() : ''; }

function renderX(node, pad) {
  if (typeof node === 'string') return pad + node;
  var s = pad + '<' + node.name, k;
  for (k in node.attrs) s += ' ' + k + '="' + node.attrs[k] + '"';
  var kids = node.children, txt = String(node.text || '').trim();
  if (!kids.length && !txt) return s + '/>';
  if (!kids.length) return s + '>' + txt + '</' + node.name + '>';
  var out = [s + '>' + txt];
  for (var i = 0; i < kids.length; i++) out.push(renderX(kids[i], pad + '  '));
  out.push(pad + '</' + node.name + '>');
  return out.join('\\n');
}

function evtxMsg(ev, channel) {
  var parts = [], i;
  var ed = xChild(ev, 'EventData');
  if (ed) {
    for (i = 0; i < ed.children.length; i++) {
      var d = ed.children[i];
      if (!d || !d.name) continue;
      var val = String(d.text || '').trim();
      if (!val) continue;
      if (d.name === 'Data') parts.push(d.attrs.Name ? d.attrs.Name + '=' + val : val);
      else parts.push(d.name + '=' + val);
    }
  }
  if (!parts.length) {
    var ud = xChild(ev, 'UserData');
    if (ud) (function walk(e) {
      for (var k = 0; k < e.children.length; k++) {
        var ch = e.children[k];
        if (!ch || !ch.name) continue;
        if (ch.children.length) { walk(ch); continue; }
        var t = String(ch.text || '').trim();
        if (t) parts.push(ch.name + '=' + t);
      }
    })(ud);
  }
  if (parts.length) return parts.join(' · ');
  var rd = xChild(ev, 'RenderingInfo');
  if (rd) { var m = xText(xChild(rd, 'Message')); if (m) return m.replace(/\\s+/g, ' ').trim(); }
  return channel ? '(' + channel + ' 通道事件，无附加数据)' : '(无事件数据)';
}

/* Windows Level → 内部 sevId：1=Critical 2=Error 3=Warning 4=Info 5=Verbose 0=LogAlways */
function evtxLevelToSev(n) { return n === 1 ? 5 : n === 2 ? 4 : n === 3 ? 3 : n === 5 ? 0 : 1; }

function parseEvtxRecord(c, start, end, writtenTs) {
  var out = [];
  exFragment(c, { p: start, n: 0 }, null, out, end);
  var ev = null;
  for (var i = 0; i < out.length; i++) if (out[i] && out[i].name) { ev = out[i]; break; }
  if (!ev) return null;
  var sys = xChild(ev, 'System');
  var prov = xChild(sys, 'Provider');
  var provName = prov ? (prov.attrs.Name || prov.attrs.EventSourceName || prov.attrs.Guid || '') : '';
  var eid = parseInt(xText(xChild(sys, 'EventID')), 10) || 0;
  var levelN = parseInt(xText(xChild(sys, 'Level')), 10);
  var host = xText(xChild(sys, 'Computer'));
  var channel = xText(xChild(sys, 'Channel'));
  var ts = NaN;
  var tc = xChild(sys, 'TimeCreated');
  if (tc && tc.attrs.SystemTime) ts = Date.parse(tc.attrs.SystemTime);
  if (isNaN(ts)) ts = writtenTs;
  return {
    ts: ts, host: host, source: provName || channel, pid: 0,
    sevId: isNaN(levelN) ? 1 : evtxLevelToSev(levelN), eid: eid,
    msg: evtxMsg(ev, channel), raw: renderX(ev, '')
  };
}

function parseEvtxChunk(buf, base) {
  var u8 = new Uint8Array(buf, base, 65536);
  /* "ElfChnk\\0" */
  if (!(u8[0] === 0x45 && u8[1] === 0x6c && u8[2] === 0x66 && u8[3] === 0x43 && u8[4] === 0x68 && u8[5] === 0x6e && u8[6] === 0x6b && u8[7] === 0x00)) return;
  var dv = new DataView(buf, base, 65536);
  var c = { u8: u8, dv: dv, names: Object.create(null), templates: Object.create(null) };
  var freeOff = dv.getUint32(0x30, true);
  var endAll = (freeOff >= 512 && freeOff <= 65536) ? freeOff : 65536;
  var pos = 512;
  while (pos + 28 <= endAll) {
    /* 记录签名 0x2A2A0000 */
    if (!(u8[pos] === 0x2a && u8[pos + 1] === 0x2a && u8[pos + 2] === 0x00 && u8[pos + 3] === 0x00)) break;
    var size = dv.getUint32(pos + 4, true);
    if (size < 28 || pos + size > 65536) break;
    var rec = null;
    try { rec = parseEvtxRecord(c, pos + 24, pos + size - 4, ftToMs(dv, pos + 16)); } catch (_eRec) { rec = null; }
    handleRecord(rec);
    pos += size;
  }
}

function parseEvtxFile(file, reader, total) {
  var BATCH = 64;                                       /* 每批 64 块 = 4MB */
  var off = 4096;
  while (off + 65536 <= total) {
    var n = Math.min(BATCH, Math.floor((total - off) / 65536));
    var buf = reader.readAsArrayBuffer(file.slice(off, off + n * 65536));
    for (var i = 0; i < n; i++) parseEvtxChunk(buf, i * 65536);
    off += n * 65536;
    self.postMessage({ type: 'progress', bytes: Math.min(off, total), total: total, lines: N });
  }
  finalize('Windows EVTX 事件日志');
}

/* ── 解析入口（流式） ── */
function parseFile(file) {
  resetAgg(); clearStore(); N = 0; viewIdx = null;
  baseYear = file.lastModified ? new Date(file.lastModified).getFullYear() : new Date().getFullYear();

  var reader = new FileReaderSync();
  var decoder = new TextDecoder('utf-8');
  var CHUNK = 8 * 1024 * 1024;
  var offset = 0, total = file.size || 0;
  var SAMPLE_MAX = 128 * 1024;

  var fmt = null, mode = null, detected = false, preBuf = '';
  var lineLeftover = '', winBuf = '', csv = null, colMap = null, headerDone = false;
  var WIN_SPLIT = /\\n(?=(?:Log Name|日志名称)\\s*[:：])/;

  function handleCsvRows(rows) {
    for (var r = 0; r < rows.length; r++) {
      var cells = rows[r];
      if (!headerDone) {
        colMap = {};
        for (var c = 0; c < cells.length; c++) { var f = matchCol(cells[c]); if (f && colMap[f] == null) colMap[f] = c; }
        headerDone = true;
        continue;
      }
      if (cells.length === 1 && !cells[0].trim()) continue;
      var get = function (k) { var idx = colMap[k]; return idx == null ? '' : (cells[idx] || '').trim(); };
      var time = get('time'), level = get('level'), source = get('source') || get('logname');
      var host = get('host'), eid = get('eid'), msg = get('msg') || get('cat'), logname = get('logname');
      var eidN = parseInt(eid.replace(/[^\\d]/g, ''), 10) || 0;
      handleRecord({
        ts: parseAnyTime(time), host: host, source: source, pid: 0,
        sevId: winSev(level), eid: eidN, msg: msg,
        raw: composeRaw({ time: time, level: level, host: host, source: source, eid: eidN, logname: logname, msg: msg })
      });
    }
  }
  function feedLine(text) {
    var buf = lineLeftover + text;
    var idx, from = 0;
    while ((idx = buf.indexOf('\\n', from)) >= 0) {
      var ln = buf.slice(from, idx);
      if (ln.charCodeAt(ln.length - 1) === 13) ln = ln.slice(0, -1);
      if (ln.trim()) handleRecord(parseLine(ln)); else { AGG.lines++; }
      from = idx + 1;
    }
    lineLeftover = buf.slice(from);
  }
  function feedWin(text) {
    winBuf += text;
    var parts = winBuf.split(WIN_SPLIT);
    winBuf = parts.pop();
    for (var i = 0; i < parts.length; i++) { var b = parts[i].trim(); if (b) handleRecord(parseWinBlock(b)); }
  }
  function feed(text) {
    if (mode === 'csv') handleCsvRows(csv.feed(text));
    else if (mode === 'winText') feedWin(text);
    else feedLine(text);
  }
  function startMode() {
    mode = fmt.mode;
    if (mode === 'csv') { csv = makeCsvReader(); headerDone = false; colMap = null; }
  }
  function flush() {
    if (mode === 'csv') { handleCsvRows(csv.end()); }
    else if (mode === 'winText') { if (winBuf.trim()) handleRecord(parseWinBlock(winBuf.trim())); }
    else { var ln = lineLeftover; if (ln.charCodeAt(ln.length - 1) === 13) ln = ln.slice(0, -1); if (ln.trim()) handleRecord(parseLine(ln)); }
  }

  try {
    /* ── EVTX 二进制头探测："ElfFile\\0" → 走二进制解析通道 ── */
    if (total >= 8) {
      var magic8 = new Uint8Array(reader.readAsArrayBuffer(file.slice(0, 8)));
      if (magic8[0] === 0x45 && magic8[1] === 0x6c && magic8[2] === 0x66 && magic8[3] === 0x46 &&
          magic8[4] === 0x69 && magic8[5] === 0x6c && magic8[6] === 0x65 && magic8[7] === 0x00) {
        parseEvtxFile(file, reader, total);
        return;
      }
    }
    while (offset < total) {
      var buf = reader.readAsArrayBuffer(file.slice(offset, offset + CHUNK));
      offset += CHUNK;
      var text = decoder.decode(buf, { stream: true });
      if (!detected) {
        preBuf += text;
        if (preBuf.length >= SAMPLE_MAX || offset >= total) {
          fmt = detectFormat(preBuf); startMode(); detected = true;
          feed(preBuf); preBuf = '';
        }
      } else {
        feed(text);
      }
      self.postMessage({ type: 'progress', bytes: Math.min(offset, total), total: total, lines: N });
    }
    var tail = decoder.decode();
    if (!detected) { preBuf += tail; fmt = detectFormat(preBuf); startMode(); detected = true; feed(preBuf); }
    else if (tail) feed(tail);
    flush();
    finalize(fmt ? fmt.name : '通用文本');
  } catch (err) {
    self.postMessage({ type: 'error', message: String(err && err.message || err) });
  }
}

function topN(map, n) {
  var arr = [];
  map.forEach(function (v, k) { arr.push([k, v]); });
  arr.sort(function (a, b) { return b[1] - a[1]; });
  return arr.slice(0, n).map(function (p) { return { key: p[0], count: p[1] }; });
}
function finalize(fmtName) {
  viewIdx = null;
  var hourArr = [];
  AGG.hour.forEach(function (v, k) { hourArr.push([k, v]); });
  hourArr.sort(function (a, b) { return a[0] - b[0]; });

  var summary = {
    format: fmtName, lines: AGG.lines, parsed: AGG.parsed, failed: AGG.failed,
    uniqueHost: AGG.hostCount.size, uniqueSource: AGG.srcCount.size, eidKinds: AGG.eidCount.size,
    tsMin: AGG.tsMin === Infinity ? null : AGG.tsMin,
    tsMax: AGG.tsMax === -Infinity ? null : AGG.tsMax,
    sevDist: AGG.sevDist, riskTotal: AGG.riskTotal, riskCat: AGG.riskCat, aggCapped: aggCapped
  };
  var analytics = {
    topHost: topN(AGG.hostCount, 12),
    topSource: topN(AGG.srcCount, 12),
    topAuthFail: topN(AGG.authFail, 12),
    topEid: topN(AGG.eidCount, 12),
    hour: hourArr.map(function (p) { return { h: p[0], count: p[1] }; })
  };
  self.postMessage({ type: 'done', total: N, summary: summary, analytics: analytics });
}

/* ============================================================
 *  高级查询 DSL（字段：主机/来源/级别/事件ID/消息/时间/风险/原文）
 * ============================================================ */
var QFIELDS = { host: 1, source: 1, level: 1, eid: 1, msg: 1, time: 1, ts: 1, risk: 1, raw: 1 };
var QFIELD_ALIASES = {
  host: 'host', 主机: 'host', 主机名: 'host', 计算机: 'host', computer: 'host', machine: 'host',
  source: 'source', 来源: 'source', 进程: 'source', 服务: 'source', provider: 'source', tag: 'source', unit: 'source',
  level: 'level', 级别: 'level', 等级: 'level', 严重级别: 'level', 严重性: 'level', severity: 'level',
  eid: 'eid', 事件id: 'eid', 事件: 'eid', 事件编号: 'eid', id: 'eid', eventid: 'eid',
  msg: 'msg', 消息: 'msg', 描述: 'msg', 说明: 'msg', 内容: 'msg', message: 'msg',
  time: 'time', ts: 'time', 时间: 'time', 日期: 'time', 时刻: 'time',
  risk: 'risk', 风险: 'risk', 威胁: 'risk', 高危: 'risk',
  raw: 'raw', 原文: 'raw', 行: 'raw', 日志: 'raw'
};
var LEVEL_ALIASES = {
  crit: 5, critical: 5, 严重: 5, emerg: 5, alert: 5, fatal: 5,
  err: 4, error: 4, 错误: 4,
  warn: 3, warning: 3, 警告: 3,
  notice: 2, 通知: 2,
  info: 1, information: 1, 信息: 1,
  debug: 0, verbose: 0, 调试: 0, 详细: 0
};
var RISK_BITS = {
  none: 0, authfail: R_AUTHFAIL, priv: R_PRIV, account: R_ACCOUNT, service: R_SERVICE,
  clearlog: R_CLEARLOG, scan: R_SCAN, malware: R_MALWARE, fw: R_FW, kernel: R_KERNEL, sev: R_SEV,
  attack: ATTACK_MASK, any: ATTACK_MASK
};
var RISK_CN = {
  登录失败: 'authfail', 认证失败: 'authfail', 爆破: 'authfail',
  提权: 'priv', 特权: 'priv',
  账户变更: 'account', 账号变更: 'account', 用户变更: 'account',
  服务: 'service', 持久化: 'service', 计划任务: 'service',
  日志清除: 'clearlog', 清日志: 'clearlog',
  扫描: 'scan', 异常: 'scan',
  恶意软件: 'malware', 病毒: 'malware',
  防火墙: 'fw', 拦截: 'fw',
  内核: 'kernel', 崩溃: 'kernel', 宕机: 'kernel',
  高严重: 'sev', 高危: 'attack', 无: 'none', 无风险: 'none', 正常: 'none'
};
var Q_OPS = '!~|>=|<=|!=|==|~|>|<|=';

function normalizeField(name) {
  var raw = String(name || '').trim(); if (!raw) return null;
  var lower = raw.toLowerCase();
  if (QFIELDS[lower]) return lower;
  if (QFIELD_ALIASES[raw]) return QFIELD_ALIASES[raw];
  if (QFIELD_ALIASES[lower]) return QFIELD_ALIASES[lower];
  return null;
}
function normalizeLevel(v) {
  v = String(v || '').trim(); if (!v) return NaN;
  var lower = v.toLowerCase();
  if (LEVEL_ALIASES[lower] !== undefined) return LEVEL_ALIASES[lower];
  if (LEVEL_ALIASES[v] !== undefined) return LEVEL_ALIASES[v];
  var n = parseInt(v, 10);
  return isNaN(n) ? NaN : Math.max(0, Math.min(5, n));
}
function normalizeRiskKey(v) {
  v = String(v || '').trim(); if (!v) return '';
  var lower = v.toLowerCase();
  if (RISK_BITS[lower] !== undefined) return lower;
  if (RISK_CN[v]) return RISK_CN[v];
  if (RISK_CN[lower]) return RISK_CN[lower];
  return lower;
}
function unquoteVal(v) {
  v = String(v == null ? '' : v).trim();
  if (v.length >= 2 && ((v[0] === '"' && v[v.length - 1] === '"') || (v[0] === "'" && v[v.length - 1] === "'"))) {
    return v.slice(1, -1).replace(/\\\\(["'])/g, '$1');
  }
  return v;
}
function splitQueryParts(q, sep) {
  var parts = [], cur = '', inQ = false, qch = '', i, c;
  for (i = 0; i < q.length; i++) {
    c = q[i];
    if (!inQ && (c === '"' || c === "'")) { inQ = true; qch = c; cur += c; continue; }
    if (inQ && c === qch && q[i - 1] !== '\\\\') { inQ = false; cur += c; continue; }
    if (!inQ && c === sep) { if (cur.trim()) parts.push(cur.trim()); cur = ''; continue; }
    cur += c;
  }
  if (cur.trim()) parts.push(cur.trim());
  return parts;
}
function parseQueryTime(v) {
  v = String(v).trim();
  if (/^\\d+$/.test(v)) { var n = +v; return v.length <= 11 ? n * 1000 : n; }
  var d = new Date(v.replace(' ', 'T')); var t = d.getTime();
  return isNaN(t) ? NaN : t;
}
function stripOuterGroup(text) {
  text = String(text || '').trim();
  while (text.length >= 2 && text[0] === '(') {
    var depth = 0, end = -1, i;
    for (i = 0; i < text.length; i++) {
      if (text[i] === '(') depth++;
      else if (text[i] === ')') { depth--; if (depth === 0) { end = i; break; } }
    }
    if (end === text.length - 1) text = text.slice(1, -1).trim(); else break;
  }
  return text;
}
function parseAtom(text) {
  text = stripOuterGroup(text.trim()); if (!text) return null;
  var re = new RegExp('^([\\\\w\\\\u4e00-\\\\u9fff\\\\u3400-\\\\u4dbf]+)\\\\s*(' + Q_OPS + ')\\\\s*([\\\\s\\\\S]*)$', 'u');
  var m = re.exec(text);
  if (m) { var field = normalizeField(m[1]); if (field) return { field: field, op: m[2], val: unquoteVal(m[3]) }; }
  return { field: '_bare', op: '~', val: unquoteVal(text) };
}
function parseQuery(q) {
  q = String(q == null ? '' : q).trim(); if (!q) return null;
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
  switch (op) { case '=': case '==': case '~': return has; case '!=': case '!~': return !has; default: return has; }
}
function evalRiskAtom(i, op, v) {
  var mask = gRisk(i), key = normalizeRiskKey(v);
  if (key === 'none') { var no = !((mask & ATTACK_MASK) || (mask & R_SEV)); return (op === '!=' || op === '!~') ? !no : no; }
  if (key === 'attack' || key === 'any') return boolOp(!!(mask & ATTACK_MASK), op);
  if (RISK_BITS[key] !== undefined) return boolOp(!!(mask & RISK_BITS[key]), op);
  return strOp(riskTags(mask).join(' '), op, v);
}
function evalAtom(at, i) {
  var f = at.field, op = at.op, v = at.val;
  if (f === '_bare') return gRaw(i).toLowerCase().indexOf(String(v).toLowerCase()) >= 0;
  if (f === 'level') { var id = normalizeLevel(v); if (isNaN(id)) return strOp(SEV_KEY[gSev(i)], op, v); return numOp(gSev(i), op, id); }
  if (f === 'eid') { var ev = parseInt(v, 10); var cv = gEid(i); if (isNaN(ev)) return strOp(String(cv), op, v); return numOp(cv, op, ev); }
  if (f === 'time' || f === 'ts') { var tv = parseQueryTime(v), ct = gTs(i); if (isNaN(tv)) return strOp(String(ct), op, v); if (isNaN(ct)) return op === '!=' || op === '!~'; return numOp(ct, op, tv); }
  if (f === 'risk') return evalRiskAtom(i, op, v);
  var sv = f === 'host' ? gHost(i) : f === 'source' ? gSource(i) : f === 'msg' ? gMsg(i) : gRaw(i);
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
  var levelId = (opt.level !== '' && opt.level != null) ? normalizeLevel(opt.level) : NaN;
  var riskOnly = !!opt.riskOnly;
  var srcExact = opt.source || '';

  var idx, needFilter = groups || !isNaN(levelId) || riskOnly || srcExact;
  if (!needFilter) {
    idx = new Int32Array(N);
    for (var k = 0; k < N; k++) idx[k] = k;
  } else {
    var tmp = [];
    for (var i = 0; i < N; i++) {
      if (!isNaN(levelId) && gSev(i) !== levelId) continue;
      if (riskOnly && !((gRisk(i) & ATTACK_MASK) || (gRisk(i) & R_SEV))) continue;
      if (srcExact && gSource(i) !== srcExact) continue;
      if (groups && !evalGroups(groups, i)) continue;
      tmp.push(i);
    }
    idx = Int32Array.from(tmp);
  }

  if (opt.sortKey) {
    var key = opt.sortKey, dir = opt.sortDir === 'desc' ? -1 : 1;
    var numGet = key === 'ts' ? gTs : key === 'level' ? gSev : key === 'eid' ? gEid : null;
    var arr = Array.prototype.slice.call(idx);
    if (numGet) {
      arr.sort(function (a, b) { var va = numGet(a), vb = numGet(b); if (isNaN(va)) va = -Infinity; if (isNaN(vb)) vb = -Infinity; return (va - vb) * dir; });
    } else {
      var strGet = key === 'host' ? gHost : key === 'source' ? gSource : key === 'msg' ? gMsg : null;
      if (strGet) arr.sort(function (a, b) { var sa = strGet(a), sb = strGet(b); return (sa < sb ? -1 : sa > sb ? 1 : 0) * dir; });
    }
    idx = Int32Array.from(arr);
  }
  viewIdx = idx;
  self.postMessage({ type: 'view', total: viewIdx.length });
}

function rowObj(i) {
  var mask = gRisk(i);
  return {
    n: i + 1, ts: gTs(i), host: gHost(i), source: gSource(i), sevId: gSev(i),
    sev: SEV_LABEL[gSev(i)], sevKey: SEV_KEY[gSev(i)], eid: gEid(i), msg: gMsg(i),
    risk: riskTags(mask), attack: !!((mask & ATTACK_MASK) || (mask & R_SEV)), redFlag: !!(mask & ATTACK_MASK), raw: gRaw(i)
  };
}
function getRows(start, count) {
  var idx = viewIdx, total = idx ? idx.length : N;
  var end = Math.min(start + count, total), rows = [];
  for (var k = start; k < end; k++) rows.push(rowObj(idx ? idx[k] : k));
  self.postMessage({ type: 'rows', start: start, rows: rows });
}
function exportRows(limit) {
  var idx = viewIdx, total = idx ? idx.length : N;
  var cap = Math.min(limit || 2000, total), rows = [];
  for (var k = 0; k < cap; k++) rows.push(rowObj(idx ? idx[k] : k));
  self.postMessage({ type: 'export', rows: rows, total: total, capped: total > cap });
}

var SEARCH_MAX = 100000;
function searchView(query, caseSensitive) {
  var raw = String(query == null ? '' : query), matches = [], capped = false;
  if (raw) {
    var q = caseSensitive ? raw : raw.toLowerCase();
    var idx = viewIdx, total = idx ? idx.length : N;
    for (var k = 0; k < total; k++) {
      var row = idx ? idx[k] : k;
      var hay = rawArena.str(row); if (!hay) continue;
      hay = caseSensitive ? hay : hay.toLowerCase();
      if (hay.indexOf(q) >= 0) { matches.push(k); if (matches.length >= SEARCH_MAX) { capped = true; break; } }
    }
  }
  self.postMessage({ type: 'search', matches: matches, query: query, capped: capped });
}

function buildMinimap(buckets) {
  buckets = buckets || 360;
  var idx = viewIdx, total = idx ? idx.length : N;
  var stat = new Uint8Array(buckets), risk = new Uint8Array(buckets);
  if (total > 0) {
    for (var b = 0; b < buckets; b++) {
      var s0 = Math.floor(b * total / buckets), s1 = Math.floor((b + 1) * total / buckets);
      if (s1 <= s0) s1 = s0 + 1;
      var worst = 0, hr = 0;
      for (var k = s0; k < s1 && k < total; k++) {
        var row = idx ? idx[k] : k;
        var sv = gSev(row); if (sv > worst) worst = sv;
        if ((gRisk(row) & ATTACK_MASK)) hr = 1;
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
`;
      this.worker = new Worker(URL.createObjectURL(new Blob([_wCode2], { type: 'application/javascript' }))); }
      catch (err) {
        $('sys-progress').hidden = true; $('sys-empty').hidden = false;
        $('sys-empty').innerHTML = '<div class="tool-hint is-error">无法创建解析线程：' + esc(err.message) + '</div>';
        return;
      }
      this.worker.onmessage = function (e) {
        var d = e.data;
        if (d.type === 'progress') {
          var pct = d.total ? Math.min(100, Math.round(d.bytes / d.total * 100)) : 0;
          cpSet('sys-progress', '#sys-progress-bar{width:' + pct + '%}');
          $('sys-progress-text').textContent = '解析中… ' + pct + '%（已解析 ' + d.lines.toLocaleString() + ' 条）';
        } else if (d.type === 'done') self.onDone(d);
        else if (d.type === 'view') { self.total = d.total; self.afterView(); }
        else if (d.type === 'rows') self.onRows(d);
        else if (d.type === 'export') self.doExport(d);
        else if (d.type === 'search') self.onSearch(d);
        else if (d.type === 'minimap') self.onMinimap(d);
        else if (d.type === 'error') { $('sys-progress').hidden = true; $('sys-empty').hidden = false; $('sys-empty').innerHTML = '<div class="tool-hint is-error">解析失败：' + esc(d.message) + '</div>'; }
      };
      this.worker.postMessage({ type: 'parse', file: file });
    },

    onDone: function (d) {
      this.analytics = d.analytics; this.summary = d.summary; this.total = d.total;
      $('sys-progress').hidden = true; $('sys-result').hidden = false;
      this.renderDash(d.summary, d.analytics);
      this.resetFind();
      this.closeSide();
      this.view = defaultView();
      $('sys-q').value = ''; $('sys-level').value = ''; $('sys-risk').checked = false;
      this.renderSfChips(); this.renderSortIndicators(); this.refreshView();
    },

    /* ── 仪表盘 ── */
    renderDash: function (s, a) {
      var span = (s.tsMin && s.tsMax) ? (fmtTs(s.tsMin) + ' ~ ' + fmtTs(s.tsMax)) : '—';
      var cards = [
        { label: '事件总数', value: s.lines.toLocaleString(), sub: '解析成功 ' + s.parsed.toLocaleString() + (s.failed ? ' · 失败 ' + s.failed.toLocaleString() : '') },
        { label: '高危事件', value: s.riskTotal.toLocaleString(), accent: s.riskTotal > 0 },
        { label: '独立主机', value: s.uniqueHost.toLocaleString() },
        { label: '独立来源', value: s.uniqueSource.toLocaleString() },
        { label: '事件ID种类', value: s.eidKinds.toLocaleString() },
        { label: '识别格式', value: esc(s.format) },
        { label: '时间跨度', value: span, wide: true }
      ];
      $('sys-cards').innerHTML = cards.map(function (c) {
        return '<div class="log-card' + (c.wide ? ' log-card--wide' : '') + (c.accent ? ' log-card--accent' : '') + '">' +
          '<div class="log-card__v">' + c.value + '</div><div class="log-card__l">' + esc(c.label) + (c.sub ? ' · ' + esc(c.sub) : '') + '</div></div>';
      }).join('');

      /* 级别分布条（严重 → 调试） */
      var dist = s.sevDist || [0, 0, 0, 0, 0, 0];
      var distTotal = dist.reduce(function (x, y) { return x + y; }, 0) || 1;
      $('sys-sevbar').innerHTML = SEV_ORDER.filter(function (id) { return dist[id]; }).map(function (id) {
        return '<div class="slt-seg slt-seg--' + SEV_KEY[id] + '" data-w="' + (dist[id] / distTotal * 100) + '" title="' + SEV_LABEL[id] + ': ' + dist[id] + '"></div>';
      }).join('');
      applyBarWidths($('sys-sevbar'), '.slt-seg', 'sys-sev-');
      $('sys-sevlegend').innerHTML = SEV_ORDER.map(function (id) {
        return '<span class="log-leg"><i class="log-dot slt-seg--' + SEV_KEY[id] + '"></i>' + SEV_LABEL[id] + ' ' + dist[id].toLocaleString() + '</span>';
      }).join('');

      /* 安全风险分类 */
      var rc = s.riskCat;
      $('sys-risklist').innerHTML = RISK_CATS.map(function (c) {
        var v = rc[c[0]] || 0;
        return '<div class="log-riskitem' + (v ? ' is-hit' : '') + '"><span>' + esc(c[1]) + '</span><b>' + v.toLocaleString() + '</b></div>';
      }).join('');

      this.renderTopList('sys-tophost', a.topHost, 'host');
      this.renderTopList('sys-topsource', a.topSource, 'source');
      this.renderTopList('sys-topauth', a.topAuthFail, 'auth');
      this.renderTrend(a.hour);
    },

    renderTopList: function (id, list, kind) {
      var max = list.length ? list[0].count : 1;
      $(id).innerHTML = list.map(function (it) {
        return '<div class="log-toprow" data-kind="' + kind + '" data-key="' + esc(it.key) + '">' +
          '<div class="log-topbar" data-w="' + (it.count / max * 100) + '"></div>' +
          '<span class="log-topkey" title="' + esc(it.key) + '">' + esc(it.key) + '</span>' +
          '<span class="log-topcnt">' + it.count.toLocaleString() + '</span></div>';
      }).join('') || '<div class="tool-hint">无数据</div>';
      applyBarWidths($(id), '.log-topbar', id + '-bar-');
      var self = this;
      $(id).querySelectorAll('.log-toprow').forEach(function (row) {
        row.addEventListener('click', function () {
          var k = row.getAttribute('data-kind'), val = row.getAttribute('data-key');
          if (k === 'host') { self.view.simpleFilters.push({ field: 'host', cn: '主机', type: 'text', op: '=', val: val }); self.flash('已添加条件：主机 等于 ' + val); }
          else if (k === 'source') { self.view.simpleFilters.push({ field: 'source', cn: '来源', type: 'text', op: '=', val: val }); self.flash('已添加条件：来源 等于 ' + val); }
          else { var v = val.replace(/^用户:/, ''); self.view.simpleFilters.push({ field: 'raw', cn: '原文', type: 'text', op: '~', val: v }); self.flash('已添加条件：原文 包含 ' + v); }
          self.renderSfChips(); self.refreshView();
        });
      });
    },

    renderTrend: function (hours) {
      var cv = $('sys-trend'); if (!cv || !cv.getContext) return;
      var ctx = cv.getContext('2d');
      var W = cv.width = cv.clientWidth * (window.devicePixelRatio || 1);
      var H = cv.height = 80 * (window.devicePixelRatio || 1);
      ctx.clearRect(0, 0, W, H);
      if (!hours.length) return;
      var max = 0; hours.forEach(function (p) { if (p.count > max) max = p.count; });
      var n = hours.length, bw = W / n;
      ctx.fillStyle = '#3a6ea5';
      for (var i = 0; i < n; i++) {
        var h = max ? (hours[i].count / max) * (H - 4) : 0;
        ctx.globalAlpha = 0.78;
        ctx.fillRect(i * bw + 1, H - h, Math.max(1, bw - 2), h);
      }
      ctx.globalAlpha = 1;
    },

    /* ── 筛选 / 排序 ── */
    refreshView: function () {
      if (!this.worker) return;
      this.rowsCache = {}; this.lastReqStart = -1;
      this.selPos = -1;     /* 视图重建后行索引失效，清除选中态（侧栏内容保留） */
      this.worker.postMessage({ type: 'view', opt: {
        q: this.compileQuery(), level: this.view.level, riskOnly: this.view.riskOnly,
        source: this.view.source, sortKey: this.view.sortKey, sortDir: this.view.sortDir
      } });
    },
    afterView: function () {
      $('sys-count').textContent = this.total.toLocaleString() + ' 条';
      cpSet('sys-spacer-h', '#sys-spacer{height:' + this.contentHeight() + 'px}');
      $('sys-viewport').scrollTop = 0;
      this.lastReqStart = -1; this.onScroll(true); this.requestMinimap();
    },
    resetFilters: function () {
      this.view = defaultView();
      $('sys-q').value = ''; $('sys-level').value = ''; $('sys-risk').checked = false;
      this.renderSfChips(); this.syncSfControls(); this.renderSortIndicators(); this.refreshView();
    },
    renderSortIndicators: function () {
      var self = this;
      $('sys-thead').querySelectorAll('[data-sort]').forEach(function (th) {
        var k = th.getAttribute('data-sort');
        var base = th.getAttribute('data-label');
        if (base == null) { base = (th.textContent || '').replace(/[▲▼]/g, '').trim(); th.setAttribute('data-label', base); }
        var grip = th.querySelector('.lt-resz');
        th.textContent = base + (self.view.sortKey === k ? (self.view.sortDir === 'asc' ? ' ▲' : ' ▼') : '');
        if (grip) th.appendChild(grip);
      });
    },

    /* ── 虚拟滚动 ── */
    contentHeight: function () { return Math.min(this.total * ROW_H, MAX_SPACER); },
    isScaled: function () { return this.total * ROW_H > MAX_SPACER; },
    rowForScrollTop: function (scrollTop, clientH) {
      if (!this.isScaled()) return Math.floor(scrollTop / ROW_H);
      var scrollable = this.contentHeight() - clientH; if (scrollable <= 0) return 0;
      var visible = Math.ceil(clientH / ROW_H), maxFirst = Math.max(0, this.total - visible);
      var ratio = scrollTop / scrollable; if (ratio < 0) ratio = 0; if (ratio > 1) ratio = 1;
      return Math.round(ratio * maxFirst);
    },
    scrollTopForRow: function (row, clientH) {
      if (!this.isScaled()) return row * ROW_H;
      var scrollable = this.contentHeight() - clientH; if (scrollable <= 0) return 0;
      var visible = Math.ceil(clientH / ROW_H), maxFirst = Math.max(0, this.total - visible);
      if (maxFirst <= 0) return 0;
      var ratio = row / maxFirst; if (ratio < 0) ratio = 0; if (ratio > 1) ratio = 1;
      return ratio * scrollable;
    },
    onScroll: function (force) {
      var vp = $('sys-viewport');
      this.drawMap();
      var baseStart = this.rowForScrollTop(vp.scrollTop, vp.clientHeight);
      var start = Math.max(0, baseStart - 8);
      if (!force && start === this.lastReqStart) return;
      this.lastReqStart = start;
      var count = Math.ceil(vp.clientHeight / ROW_H) + 16;
      if (this.rowsCache[start]) { this.renderRows(start, this.rowsCache[start]); return; }
      if (this.worker) this.worker.postMessage({ type: 'rows', start: start, count: count });
    },
    onRows: function (d) {
      this.rowsCache[d.start] = d.rows;
      var keys = Object.keys(this.rowsCache); if (keys.length > 6) delete this.rowsCache[keys[0]];
      if (d.start === this.lastReqStart) this.renderRows(d.start, d.rows);
    },
    renderRows: function (start, rows) {
      var vpEl = $('sys-viewport'), ty;
      if (this.isScaled()) { var baseStart = this.rowForScrollTop(vpEl.scrollTop, vpEl.clientHeight); ty = vpEl.scrollTop - (baseStart - start) * ROW_H; }
      else ty = start * ROW_H;
      cpSet('sys-rows-y', '#sys-rows{transform:translateY(' + ty + 'px)}');
      var sc = this.search;
      var q = (sc && sc.query) ? sc.query : '';
      var cs = sc ? sc.caseSensitive : false;
      var matchSet = (q && sc.set) ? sc.set : null;
      var activePos = (q && sc.cur >= 0 && sc.matches.length) ? sc.matches[sc.cur] : -1;
      var selPos = this.selPos;
      function H(text) { return q ? hlEsc(text, q, cs) : esc(text); }
      $('sys-rows').innerHTML = rows.map(function (r, i) {
        var pos = start + i;
        var isMatch = matchSet ? matchSet.has(pos) : false;
        var isActive = pos === activePos;
        var meta = '主机 ' + (r.host || '-') + ' · 来源 ' + (r.source || '-') + ' · ' + r.sev + (r.eid ? ' · 事件ID ' + r.eid : '') + ' · ' + fmtTs(r.ts);
        var tags = r.risk.map(function (t) { return '<span class="lt-tag">' + esc(t) + '</span>'; }).join('');
        var cls = 'lt-row' + (r.redFlag ? ' lt-row--risk' : '') + (isMatch ? ' lt-row--match' : '') + (isActive ? ' lt-row--match-active' : '') + (pos === selPos ? ' lt-row--sel' : '');
        return '<div class="' + cls + '" data-pos="' + pos + '" data-raw="' + esc(r.raw) + '" data-meta="' + esc(meta) + '">' +
          '<div class="lt-c lt-c--n">' + r.n + '</div>' +
          '<div class="lt-c lt-c--ts">' + H(fmtTs(r.ts)) + '</div>' +
          '<div class="lt-c lt-c--host">' + H(r.host || '-') + '</div>' +
          '<div class="lt-c lt-c--src">' + H(r.source || '-') + '</div>' +
          '<div class="lt-c lt-c--lv"><span class="slt-lv slt-lv--' + r.sevKey + '">' + esc(r.sev) + '</span></div>' +
          '<div class="lt-c lt-c--eid">' + (r.eid ? r.eid : '-') + '</div>' +
          '<div class="lt-c lt-c--msg" title="' + esc(r.msg) + '">' + H(r.msg) + '</div>' +
          '<div class="lt-c lt-c--risk">' + tags + '</div>' +
          '</div>';
      }).join('');
      if (q && activePos >= start && activePos < start + rows.length) {
        var ar = rows[activePos - start];
        this.showDetail(ar.raw, '主机 ' + (ar.host || '-') + ' · 来源 ' + (ar.source || '-') + ' · ' + ar.sev + (ar.eid ? ' · 事件ID ' + ar.eid : '') + ' · ' + fmtTs(ar.ts), activePos);
      }
    },

    showDetail: function (raw, meta, pos) {
      var lt = $('sys-lt'); if (!lt) return;
      var sc = this.search;
      var q = (sc && sc.query) ? sc.query : '';
      var cs = sc ? sc.caseSensitive : false;
      $('sys-side-meta').innerHTML = esc(meta);
      $('sys-side-raw').innerHTML = q ? hlEsc(raw, q, cs) : esc(raw);
      if (pos != null && !isNaN(pos)) this.selPos = pos;
      this.applySideW();
      lt.classList.add('is-side-open');
      this.markSel();
    },

    flash: function (msg) {
      var el = $('sys-flash'); if (!el) return;
      el.textContent = msg; el.classList.add('is-show');
      clearTimeout(this._ft);
      this._ft = setTimeout(function () { el.classList.remove('is-show'); }, 1600);
    },

    /* ── 报告导出 ── */
    exportReport: function (fmt) {
      if (!this.worker || !this.summary) { this.flash('请先载入日志文件'); return; }
      this.pendingFmt = fmt; this.flash('正在生成报告…');
      this.worker.postMessage({ type: 'export', limit: 5000 });
    },
    doExport: function (d) {
      var fmt = this.pendingFmt || 'html';
      var html = this.buildReportHtml(d.rows, d.total, d.capped);
      var stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
      var base = '系统日志分析报告_' + stamp;
      if (fmt === 'pdf') { this.printReport(html); this.flash('已打开打印窗口，选择「另存为 PDF」即可'); }
      else if (fmt === 'doc') { this.dlBlob(base + '.doc', 'application/msword', html); this.flash('已导出 Word 文档'); }
      else { this.dlBlob(base + '.html', 'text/html;charset=utf-8', html); this.flash('已导出 HTML 报告'); }
    },
    dlBlob: function (name, mime, content) {
      var blob = new Blob(['\ufeff' + content], { type: mime });
      var url = URL.createObjectURL(blob), a = document.createElement('a');
      a.href = url; a.download = name; document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
    },
    printReport: function (html) {
      var w = window.open('', '_blank');
      if (!w) { this.flash('浏览器拦截了弹窗，请允许弹窗后重试'); return; }
      w.document.open(); w.document.write(html); w.document.close(); w.focus();
      setTimeout(function () { try { w.print(); } catch (e) {} }, 400);
    },
    buildReportHtml: function (rows, total, capped) {
      var s = this.summary, a = this.analytics;
      var span = (s.tsMin && s.tsMax) ? (fmtTs(s.tsMin) + ' ~ ' + fmtTs(s.tsMax)) : '—';
      function bar(list, color) {
        var max = list.length ? list[0].count : 1;
        return list.map(function (it) {
          return '<tr><td class="k">' + esc(it.key) + '</td><td class="bar"><span style="display:inline-block;height:10px;border-radius:2px;background:' + color + ';width:' + Math.max(2, it.count / max * 100) + '%"></span></td><td class="c">' + it.count.toLocaleString() + '</td></tr>';
        }).join('');
      }
      var rc = s.riskCat;
      var riskRows = RISK_CATS.map(function (c) {
        return '<tr><td>' + c[1] + '</td><td class="c" style="color:' + ((rc[c[0]] || 0) ? '#9b1c1c' : '#888') + '">' + (rc[c[0]] || 0).toLocaleString() + '</td></tr>';
      }).join('');
      var dist = s.sevDist || [];
      var sevRows = SEV_ORDER.map(function (id) {
        return '<tr><td>' + SEV_LABEL[id] + '</td><td class="c">' + (dist[id] || 0).toLocaleString() + '</td></tr>';
      }).join('');
      var detail = rows.map(function (r) {
        var sevColor = r.sevId >= 5 ? '#9b1c1c' : r.sevId >= 4 ? '#b91c1c' : r.sevId === 3 ? '#854d0e' : r.sevId === 2 ? '#1e40af' : '#166534';
        return '<tr' + (r.redFlag ? ' class="risk"' : '') + '><td>' + r.n + '</td><td>' + esc(fmtTs(r.ts)) + '</td><td>' + esc(r.host || '-') +
          '</td><td>' + esc(r.source || '-') + '</td><td style="color:' + sevColor + ';font-weight:700">' + esc(r.sev) +
          '</td><td>' + (r.eid ? r.eid : '-') + '</td><td class="path">' + esc(r.msg) + '</td><td>' + esc(r.risk.join(' ')) + '</td></tr>';
      }).join('');
      var css = 'body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;color:#1a1a1a;margin:32px;font-size:13px;line-height:1.6}' +
        'h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:24px 0 8px;border-bottom:1px solid #ddd;padding-bottom:4px}' +
        '.meta{color:#666;font-size:12px;margin-bottom:8px}.cards{display:flex;flex-wrap:wrap;gap:10px;margin:10px 0}' +
        '.card{border:1px solid #e0e0e0;border-radius:6px;padding:10px 14px;min-width:120px}.card .v{font-size:20px;font-weight:800}.card .l{font-size:11px;color:#777}' +
        'table{border-collapse:collapse;width:100%;font-size:12px;margin:6px 0}th,td{border:1px solid #e6e6e6;padding:5px 8px;text-align:left}th{background:#f4f4f2}' +
        'td.c{text-align:right;font-variant-numeric:tabular-nums}td.k{white-space:nowrap;font-family:monospace}td.bar{width:50%}td.path{font-family:monospace;word-break:break-all}' +
        '.grid3{display:flex;gap:18px;flex-wrap:wrap}.grid3>div{flex:1;min-width:220px}tr.risk td{background:#fef2f2}' +
        '.foot{margin-top:24px;color:#999;font-size:11px;border-top:1px solid #eee;padding-top:8px}@media print{body{margin:12mm}h2{page-break-after:avoid}}';
      var cards = [
        ['事件总数', s.lines.toLocaleString()], ['解析成功', s.parsed.toLocaleString()], ['解析失败', s.failed.toLocaleString()],
        ['高危事件', s.riskTotal.toLocaleString()], ['独立主机', s.uniqueHost.toLocaleString()], ['独立来源', s.uniqueSource.toLocaleString()]
      ].map(function (c) { return '<div class="card"><div class="v">' + c[1] + '</div><div class="l">' + c[0] + '</div></div>'; }).join('');
      return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="ProgId" content="Word.Document"><title>系统日志分析报告</title><style>' + css + '</style></head><body>' +
        '<h1>系统日志分析报告</h1>' +
        '<div class="meta">来源文件：' + esc(this.fileName || '-') + ' ｜ 识别格式：' + esc(s.format) + ' ｜ 时间跨度：' + esc(span) + ' ｜ 生成时间：' + fmtTs(Date.now()) + '</div>' +
        '<div class="cards">' + cards + '</div>' +
        '<div class="grid3"><div><h2>级别分布</h2><table><tbody>' + sevRows + '</tbody></table></div>' +
        '<div><h2>安全风险识别</h2><table><tbody>' + riskRows + '</tbody></table></div></div>' +
        '<div class="grid3"><div><h2>Top 主机</h2><table><tbody>' + bar(a.topHost, '#2c5282') + '</tbody></table></div>' +
        '<div><h2>Top 来源</h2><table><tbody>' + bar(a.topSource, '#2c5282') + '</tbody></table></div>' +
        '<div><h2>可疑来源（登录失败最多）</h2><table><tbody>' + bar(a.topAuthFail, '#9b1c1c') + '</tbody></table></div></div>' +
        '<h2>事件明细（' + rows.length.toLocaleString() + ' / ' + total.toLocaleString() + ' 条' + (capped ? '，超出部分已截断，可先用筛选缩小范围' : '') + '）</h2>' +
        '<table><thead><tr><th>#</th><th>时间</th><th>主机</th><th>来源</th><th>级别</th><th>事件ID</th><th>消息</th><th>风险</th></tr></thead><tbody>' + detail + '</tbody></table>' +
        '<div class="foot">本报告由 RavenEye 本地生成，原始日志数据未上传任何服务器。</div></body></html>';
    },

    /* ── 全局查找（Ctrl+F） ── */
    initFind: function () {
      var self = this, input = $('sys-find-input'); if (!input) return;
      var deb = null;
      input.addEventListener('input', function () { clearTimeout(deb); deb = setTimeout(function () { self.runSearch(input.value); }, 160); });
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); self.gotoRel(e.shiftKey ? -1 : 1); }
        else if (e.key === 'Escape') { e.preventDefault(); self.closeFind(); }
      });
      $('sys-find-prev').addEventListener('click', function () { self.gotoRel(-1); input.focus(); });
      $('sys-find-next').addEventListener('click', function () { self.gotoRel(1); input.focus(); });
      $('sys-find-close').addEventListener('click', function () { self.closeFind(); });
      $('sys-find-case').addEventListener('click', function () { self.search.caseSensitive = !self.search.caseSensitive; $('sys-find-case').classList.toggle('is-on', self.search.caseSensitive); self.runSearch(input.value); input.focus(); });
      document.addEventListener('keydown', function (e) {
        if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === 'f' || e.key === 'F')) {
          if (!self.isSysActive()) return;
          e.preventDefault(); self.openFind();
        }
      });
    },
    isSysActive: function () { var pane = $('pane-syslog'), res = $('sys-result'); return !!(pane && !pane.hidden && res && !res.hidden); },
    openFind: function () {
      var box = $('sys-find'); if (!box) return;
      box.hidden = false; this.search.open = true;
      var input = $('sys-find-input'); input.focus(); input.select();
      if (input.value.trim()) this.runSearch(input.value); else this.updateFindCount();
    },
    closeFind: function () {
      var box = $('sys-find'); if (box) box.hidden = true;
      this.search.open = false; this.search.query = ''; this.search.matches = []; this.search.set = null; this.search.cur = -1; this.search.capped = false;
      this.rowsCache = {}; this.lastReqStart = -1; this.onScroll(true); this.updateFindCount();
    },
    resetFind: function () {
      this.search.open = false; this.search.query = ''; this.search.matches = []; this.search.set = null; this.search.cur = -1; this.search.capped = false;
      var box = $('sys-find'); if (box) box.hidden = true;
      var input = $('sys-find-input'); if (input) input.value = '';
      this.updateFindCount();
    },
    runSearch: function (value) {
      this.search.query = String(value || ''); this.search.matches = []; this.search.set = null; this.search.cur = -1; this.search.capped = false;
      if (!this.search.query) { this.rowsCache = {}; this.lastReqStart = -1; this.onScroll(true); this.updateFindCount(); return; }
      if (!this.worker) { this.updateFindCount(); return; }
      this.worker.postMessage({ type: 'search', query: this.search.query, caseSensitive: this.search.caseSensitive });
    },
    onSearch: function (d) {
      if (d.query !== this.search.query) return;
      var m = d.matches || []; this.search.matches = m;
      var set = new Set(); for (var i = 0; i < m.length; i++) set.add(m[i]);
      this.search.set = set; this.search.capped = !!d.capped;
      if (m.length) { this.search.cur = 0; this.gotoMatch(0); }
      else { this.search.cur = -1; this.rowsCache = {}; this.lastReqStart = -1; this.onScroll(true); }
      this.updateFindCount(); this.drawMap();
    },
    gotoRel: function (delta) {
      var n = this.search.matches.length; if (!n) return;
      var cur = this.search.cur < 0 ? (delta > 0 ? -1 : 0) : this.search.cur;
      cur = ((cur + delta) % n + n) % n; this.search.cur = cur; this.gotoMatch(cur); this.updateFindCount();
    },
    gotoMatch: function (i) {
      var m = this.search.matches; if (!m.length) return;
      var pos = m[i], vp = $('sys-viewport');
      var visible = Math.ceil(vp.clientHeight / ROW_H), maxFirst = Math.max(0, this.total - visible);
      var desiredFirst = Math.max(0, Math.min(pos - Math.floor(visible / 2), maxFirst));
      var maxTop = Math.max(0, this.contentHeight() - vp.clientHeight);
      vp.scrollTop = Math.max(0, Math.min(this.scrollTopForRow(desiredFirst, vp.clientHeight), maxTop));
      this.lastReqStart = -1; this.onScroll(true);
    },
    updateFindCount: function () {
      var el = $('sys-find-count'); if (!el) return;
      var m = this.search.matches;
      if (!this.search.query) { el.textContent = '无结果'; el.classList.remove('is-empty'); return; }
      if (!m.length) { el.textContent = '无匹配'; el.classList.add('is-empty'); return; }
      el.classList.remove('is-empty');
      el.textContent = (this.search.cur + 1) + ' / ' + m.length + (this.search.capped ? '+' : '');
    },

    /* ── 概览缩略图 ── */
    initMap: function () {
      var self = this, cv = $('sys-map'); if (!cv) return;
      var dragging = false; self.mapHover = { on: false, y: 0 };
      function jump(e) {
        var rect = cv.getBoundingClientRect();
        var frac = Math.min(1, Math.max(0, (e.clientY - rect.top) / rect.height));
        if (!self.total) return;
        var vp = $('sys-viewport'), contentH = self.contentHeight();
        vp.scrollTop = Math.max(0, Math.min(frac * contentH - vp.clientHeight / 2, contentH - vp.clientHeight));
        self.lastReqStart = -1; self.onScroll(true);
      }
      cv.addEventListener('mousedown', function (e) { dragging = true; jump(e); e.preventDefault(); });
      cv.addEventListener('mousemove', function (e) { var rect = cv.getBoundingClientRect(); self.mapHover = { on: true, y: e.clientY - rect.top }; if (!dragging) self.drawMap(); });
      cv.addEventListener('mouseleave', function () { self.mapHover = { on: false, y: 0 }; self.drawMap(); });
      document.addEventListener('mousemove', function (e) { if (dragging) jump(e); });
      document.addEventListener('mouseup', function () { dragging = false; });
      window.addEventListener('resize', function () { self.drawMap(); });
    },
    requestMinimap: function () { if (this.worker) this.worker.postMessage({ type: 'minimap', buckets: 360 }); },
    onMinimap: function (d) { this.map = { buckets: d.buckets, stat: d.stat, risk: d.risk, total: d.total }; this.drawMap(); },
    drawMap: function () {
      var cv = $('sys-map'); if (!cv || !cv.getContext) return;
      var vp = $('sys-viewport'); if (!vp) return;
      var dpr = window.devicePixelRatio || 1;
      var cssW = cv.clientWidth || 60, cssH = cv.clientHeight || vp.clientHeight || 1;
      var pw = Math.round(cssW * dpr), ph = Math.round(cssH * dpr);
      if (cv.width !== pw || cv.height !== ph) { cv.width = pw; cv.height = ph; }
      var ctx = cv.getContext('2d');
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0); ctx.clearRect(0, 0, cssW, cssH);
      var total = this.total || 0, map = this.map;
      /* 级别配色：sevId 0..5 */
      var COLS = [
        'rgba(150,150,150,.10)',   /* debug */
        'rgba(90,165,120,.26)',    /* info */
        'rgba(90,150,205,.30)',    /* notice */
        'rgba(225,160,55,.55)',    /* warn */
        'rgba(212,68,68,.62)',     /* err */
        'rgba(150,30,30,.85)'      /* crit */
      ];
      if (map && map.total > 0 && map.stat) {
        var buckets = map.buckets, stat = map.stat, risk = map.risk;
        for (var b = 0; b < buckets; b++) {
          var y = b / buckets * cssH, h = cssH / buckets + 0.8;
          ctx.fillStyle = COLS[stat[b] || 0]; ctx.fillRect(0, y, cssW, h);
          if (risk[b]) { ctx.fillStyle = 'rgba(150,30,30,.9)'; ctx.fillRect(0, y, 4, Math.max(1.5, h)); }
        }
      } else { ctx.fillStyle = 'rgba(150,150,150,.05)'; ctx.fillRect(0, 0, cssW, cssH); }

      var sc = this.search;
      if (sc && sc.query && sc.matches && sc.matches.length && total > 0) {
        ctx.fillStyle = 'rgba(255,150,50,.95)';
        var m = sc.matches, seen = {};
        for (var i = 0; i < m.length; i++) { var yp = Math.round(m[i] / total * cssH); if (seen[yp]) continue; seen[yp] = 1; ctx.fillRect(cssW - 7, yp, 7, 2); }
        if (sc.cur >= 0 && sc.cur < m.length) { ctx.fillStyle = 'rgba(255,110,20,1)'; var yc = m[sc.cur] / total * cssH; ctx.fillRect(0, Math.max(0, yc - 1.5), cssW, 3); }
      }
      if (total > 0) {
        var firstRow = this.rowForScrollTop(vp.scrollTop, vp.clientHeight);
        var y0 = firstRow / total * cssH, hh = Math.max(12, (vp.clientHeight / ROW_H) / total * cssH);
        if (y0 + hh > cssH) y0 = cssH - hh; if (y0 < 0) y0 = 0;
        ctx.fillStyle = 'rgba(70,130,215,.16)'; ctx.fillRect(0, y0, cssW, hh);
        ctx.fillStyle = 'rgba(70,130,215,.95)'; ctx.fillRect(0, y0, 3, hh);
        ctx.strokeStyle = 'rgba(70,130,215,.9)'; ctx.lineWidth = 1.5; ctx.strokeRect(0.75, y0 + 0.75, cssW - 1.5, Math.max(1, hh - 1.5));
      }
      var hov = this.mapHover;
      if (hov && hov.on && total > 0) {
        var hvH = Math.max(12, (vp.clientHeight / ROW_H) / total * cssH), hy0 = hov.y - hvH / 2;
        if (hy0 < 0) hy0 = 0; if (hy0 + hvH > cssH) hy0 = cssH - hvH;
        ctx.fillStyle = 'rgba(130,160,210,.16)'; ctx.fillRect(0, hy0, cssW, hvH);
        ctx.strokeStyle = 'rgba(130,160,210,.55)'; ctx.lineWidth = 1; ctx.strokeRect(0.5, hy0 + 0.5, cssW - 1, Math.max(1, hvH - 1));
      }
    }
  };

  window.SysLogAnalyzer = Sys;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { Sys.init(); });
  else Sys.init();
})();
