/**
 * 中间件日志分析 —— 主线程控制器（视图层）
 * 与 log-worker.js（数据层）通过消息协作；表格虚拟滚动，仪表盘聚合展示。
 * 模块：Loader（载入）/ Dash（仪表盘）/ Table（虚拟滚动）/ Filters（筛选排序）
 */
(function () {
  'use strict';

  function $(id) { return document.getElementById(id); }
  function esc(s) { return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;'); }
  function humanBytes(n) { if (!n || n < 1024) return (n || 0) + ' B'; var u = ['KB', 'MB', 'GB', 'TB'], i = -1; do { n /= 1024; i++; } while (n >= 1024 && i < u.length - 1); return n.toFixed(1) + ' ' + u[i]; }
  function fmtTs(ms) { if (ms == null || isNaN(ms)) return '-'; var d = new Date(ms); if (isNaN(d.getTime())) return '-'; var p = function (x) { return (x < 10 ? '0' : '') + x; }; return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + ' ' + p(d.getHours()) + ':' + p(d.getMinutes()) + ':' + p(d.getSeconds()); }
  function statusClass(c) { if (c >= 200 && c < 300) return '2xx'; if (c >= 300 && c < 400) return '3xx'; if (c >= 400 && c < 500) return '4xx'; if (c >= 500) return '5xx'; return 'other'; }

  var ROW_H = 30;
  /* 浏览器单元素最大像素高度的安全上限（Firefox≈17.9M / Chrome≈33.5M，取保守跨浏览器值）。
     当 total*ROW_H 超过此值时，spacer 会被浏览器截断导致无法滚动到全部行，
     故改用「比例映射」虚拟滚动：spacer 封顶，scrollTop↔行号按比例换算。 */
  var MAX_SPACER = 16000000;

  /* 高亮转义：在 esc 安全转义的同时，对匹配子串包裹 <mark>（防 XSS） */
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
  function cpDel(key) { if (window.CpStyle) CpStyle.remove(key); }
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

  /* ── 快速筛选：字段 / 运算符配置（与 Worker 中文列名对齐） ── */
  var SF_FIELDS = [
    { key: 'path', label: '路径', cn: '路径', type: 'text' },
    { key: 'ip', label: 'IP', cn: 'IP', type: 'text' },
    { key: 'status', label: '状态', cn: '状态', type: 'status' },
    { key: 'method', label: '方法', cn: '方法', type: 'text' },
    { key: 'time', label: '时间', cn: '时间', type: 'time' },
    { key: 'risk', label: '风险', cn: '风险', type: 'risk' },
    { key: 'bytes', label: '字节', cn: '字节', type: 'number' },
    { key: 'raw', label: '原文', cn: '原文', type: 'text' },
    { key: 'ua', label: 'UA', cn: 'UA', type: 'text' }
  ];
  var SF_OPS = {
    text: [
      { op: '~', label: '包含' }, { op: '!~', label: '不含' },
      { op: '=', label: '等于' }, { op: '!=', label: '不等于' }
    ],
    number: [
      { op: '=', label: '等于' }, { op: '!=', label: '不等于' },
      { op: '>', label: '大于' }, { op: '>=', label: '≥' },
      { op: '<', label: '小于' }, { op: '<=', label: '≤' }
    ],
    time: [
      { op: '>', label: '晚于' }, { op: '>=', label: '不早于' },
      { op: '<', label: '早于' }, { op: '<=', label: '不晚于' },
      { op: '=', label: '等于' }, { op: '!=', label: '不等于' }
    ],
    status: [
      { op: '=', label: '等于' }, { op: '!=', label: '不等于' },
      { op: '>=', label: '≥' }, { op: '<=', label: '≤' },
      { op: '>', label: '>' }, { op: '<', label: '<' }
    ],
    risk: [{ op: '=', label: '包含' }, { op: '!=', label: '不含' }]
  };
  var SF_RISK_VALS = [
    { v: 'attack', label: '任意高危' }, { v: 'none', label: '无高危' },
    { v: 'sqli', label: 'SQL注入' }, { v: 'xss', label: 'XSS' },
    { v: 'trav', label: '路径穿越' }, { v: 'sens', label: '敏感路径' },
    { v: 'scan', label: '扫描器' }, { v: 'method', label: '危险方法' },
    { v: 'rce', label: '命令执行' }, { v: 'e5xx', label: '5xx错误' }
  ];
  var SF_STATUS_VALS = [
    { v: '2xx', label: '2xx 成功' }, { v: '3xx', label: '3xx 跳转' },
    { v: '4xx', label: '4xx 客户端错误' }, { v: '5xx', label: '5xx 服务端错误' }
  ];
  function sfField(key) {
    for (var i = 0; i < SF_FIELDS.length; i++) if (SF_FIELDS[i].key === key) return SF_FIELDS[i];
    return SF_FIELDS[0];
  }
  function sfOpLabel(type, op) {
    var ops = SF_OPS[type] || SF_OPS.text;
    for (var i = 0; i < ops.length; i++) if (ops[i].op === op) return ops[i].label;
    return op;
  }
  function sfValLabel(type, val) {
    if (type === 'risk') {
      for (var i = 0; i < SF_RISK_VALS.length; i++) if (SF_RISK_VALS[i].v === val) return SF_RISK_VALS[i].label;
    }
    if (type === 'status') {
      for (var j = 0; j < SF_STATUS_VALS.length; j++) if (SF_STATUS_VALS[j].v === val) return SF_STATUS_VALS[j].label;
    }
    return val;
  }
  function quoteQueryVal(val) {
    val = String(val == null ? '' : val);
    if (/[&|]/.test(val) || /^\s|\s$/.test(val)) return '"' + val.replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"';
    return val;
  }
  function defaultView() {
    return { q: '', simpleFilters: [], statusClass: '', method: '', riskOnly: false, ip: '', sortKey: '', sortDir: 'asc' };
  }

  var Logs = {
    worker: null,
    total: 0,
    view: defaultView(),
    lastReqStart: -1,
    rowsCache: {},          /* start -> rows（减少快速滚动闪烁） */
    analytics: null,
    started: false,
    selPos: -1,             /* 当前选中行（视图索引），与右侧详情侧栏联动 */
    sideW: 0,               /* 详情侧栏宽度（px），拖拽可调并持久化 */
    search: { open: false, query: '', matches: [], set: null, cur: -1, caseSensitive: false, capped: false },

    /* ── 初始化（绑定载入控件；worker 延迟到载入文件时创建） ── */
    init: function () {
      if (this.started) return;
      this.started = true;
      var self = this;
      var drop = $('log-drop'), file = $('log-file');
      if (!drop) return;

      // 使用 <input type="file"> 选文件（Electron 渲染进程也是 Chromium，完全支持）
      $('log-file-btn').addEventListener('click', function () { file.click(); });
      file.addEventListener('change', function () { if (file.files && file.files[0]) self.load(file.files[0]); });

      // Electron 额外支持 IPC 拖拽/命令行
      if (window.electronAPI) {
        window.electronAPI.onFileDrop(function (fileData) {
          self.loadFromBuffer(fileData);
        });
      }

      ['dragenter', 'dragover'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.add('is-over'); }); });
      ['dragleave', 'drop'].forEach(function (ev) { drop.addEventListener(ev, function (e) { e.preventDefault(); drop.classList.remove('is-over'); }); });
      drop.addEventListener('drop', function (e) { var f = e.dataTransfer && e.dataTransfer.files && e.dataTransfer.files[0]; if (f) self.load(f); });

      /* 筛选控件 */
      var deb = null;
      $('log-q').addEventListener('input', function () { clearTimeout(deb); deb = setTimeout(function () { self.view.q = $('log-q').value.trim(); self.refreshView(); }, 200); });
      $('log-status').addEventListener('change', function () { self.view.statusClass = $('log-status').value; self.refreshView(); });
      $('log-method').addEventListener('change', function () { self.view.method = $('log-method').value; self.refreshView(); });
      $('log-risk').addEventListener('change', function () { self.view.riskOnly = $('log-risk').checked; self.refreshView(); });
      $('log-reset').addEventListener('click', function () { self.resetFilters(); });
      this.initSimpleFilter();

      /* 排序：点击表头 */
      $('log-thead').addEventListener('click', function (e) {
        var th = e.target.closest('[data-sort]'); if (!th) return;
        var key = th.getAttribute('data-sort');
        if (self.view.sortKey === key) self.view.sortDir = self.view.sortDir === 'asc' ? 'desc' : 'asc';
        else { self.view.sortKey = key; self.view.sortDir = 'asc'; }
        self.renderSortIndicators();
        self.refreshView();
      });

      /* 虚拟滚动 */
      var vp = $('log-viewport');
      vp.addEventListener('scroll', function () { self.onScroll(); });

      /* 行点击 → 右侧详情侧栏展开 */
      $('log-rows').addEventListener('click', function (e) {
        var row = e.target.closest('.lt-row'); if (!row) return;
        var raw = row.getAttribute('data-raw') || '';
        self.showDetail(raw, row.getAttribute('data-meta') || '', parseInt(row.getAttribute('data-pos'), 10));
      });

      var expBar = $('log-export');
      if (expBar) expBar.addEventListener('click', function (e) {
        var b = e.target.closest('[data-export]'); if (!b) return;
        self.exportReport(b.getAttribute('data-export'));
      });

      this.initResize();
      this.initSide();
      this.initFind();
      this.initMap();
    },

    /* ── 右侧详情侧栏：丝滑展开/收起 + 左缘手柄拖拽调宽 ── */
    initSide: function () {
      var self = this;
      var lt = $('log-lt'), grip = $('log-side-grip');
      if (!lt || !grip) return;
      try { this.sideW = parseInt(localStorage.getItem('logSideW'), 10) || 0; } catch (_e) { this.sideW = 0; }
      $('log-side-close').addEventListener('click', function () { self.closeSide(); });
      document.addEventListener('keydown', function (e) {
        if (e.key === 'Escape' && !self.search.open && lt.classList.contains('is-side-open') && self.isLogsActive()) self.closeSide();
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
          try { localStorage.setItem('logSideW', String(self.sideW)); } catch (_e2) {}
        }
        document.addEventListener('mousemove', mm); document.addEventListener('mouseup', mu);
      });
    },
    clampSideW: function (w) {
      var lt = $('log-lt');
      var full = lt ? lt.clientWidth : 1200;
      var max = Math.max(260, full - 420);          /* 至少给表格留 420px */
      if (!w) w = Math.min(440, max);
      return Math.min(Math.max(w, 260), max);
    },
    applySideW: function () {
      this.sideW = this.clampSideW(this.sideW);
      cpSet('log-side-w', '#log-lt{--lt-side-w:' + this.sideW + 'px}');
    },
    closeSide: function () {
      var lt = $('log-lt'); if (lt) lt.classList.remove('is-side-open');
      this.selPos = -1;
      this.markSel();
    },
    markSel: function () {
      var box = $('log-rows'); if (!box) return;
      var rows = box.children, sp = String(this.selPos);
      for (var i = 0; i < rows.length; i++) {
        rows[i].classList.toggle('lt-row--sel', this.selPos >= 0 && rows[i].getAttribute('data-pos') === sp);
      }
    },

    /* ── 快速筛选：可视化构建条件，与高级查询 AND 组合 ── */
    initSimpleFilter: function () {
      var self = this;
      var fieldSel = $('log-sf-field');
      if (!fieldSel) return;
      if (!this.view.simpleFilters) this.view.simpleFilters = [];

      fieldSel.innerHTML = SF_FIELDS.map(function (f) {
        return '<option value="' + f.key + '">' + f.label + '</option>';
      }).join('');

      fieldSel.addEventListener('change', function () { self.syncSfControls(); });
      $('log-sf-op').addEventListener('change', function () { /* noop */ });
      $('log-sf-add').addEventListener('click', function () { self.addSimpleFilter(); });
      $('log-sf-val').addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); self.addSimpleFilter(); }
      });
      $('log-sf-val-select').addEventListener('change', function () {
        var v = $('log-sf-val-select').value;
        if (v) $('log-sf-val').value = v;
      });

      this.syncSfControls();
      this.renderSfChips();
    },
    syncSfControls: function () {
      var field = sfField($('log-sf-field').value);
      var opSel = $('log-sf-op');
      var ops = SF_OPS[field.type] || SF_OPS.text;
      opSel.innerHTML = ops.map(function (o) {
        return '<option value="' + o.op + '">' + o.label + '</option>';
      }).join('');

      var valIn = $('log-sf-val');
      var valSel = $('log-sf-val-select');
      if (field.type === 'risk') {
        valIn.classList.add('u-hidden');
        valSel.classList.remove('u-hidden');
        valSel.innerHTML = SF_RISK_VALS.map(function (r) {
          return '<option value="' + r.v + '">' + r.label + '</option>';
        }).join('');
        valIn.value = valSel.value;
      } else if (field.type === 'status') {
        valIn.classList.remove('u-hidden');
        valSel.classList.remove('u-hidden');
        valSel.innerHTML = '<option value="">自定义…</option>' + SF_STATUS_VALS.map(function (s) {
          return '<option value="' + s.v + '">' + s.label + '</option>';
        }).join('');
        valIn.placeholder = '404 或 4xx';
        valIn.value = '';
      } else {
        valIn.classList.remove('u-hidden');
        valSel.classList.add('u-hidden');
        valIn.value = '';
        valIn.placeholder = field.type === 'time' ? '2026-06-03 10:00:00' : field.type === 'number' ? '1024' : '输入值…';
      }
    },
    addSimpleFilter: function () {
      if (!this.view) this.view = defaultView();
      if (!this.view.simpleFilters) this.view.simpleFilters = [];
      var field = sfField($('log-sf-field').value);
      var op = $('log-sf-op').value;
      var val = (field.type === 'risk' ? $('log-sf-val-select').value : $('log-sf-val').value).trim();
      if (!val) { this.flash('请输入或选择筛选值'); return; }
      this.view.simpleFilters.push({ field: field.key, cn: field.cn, type: field.type, op: op, val: val });
      if (field.type === 'status') { $('log-sf-val').value = ''; $('log-sf-val-select').value = ''; }
      else if (field.type !== 'risk') $('log-sf-val').value = '';
      this.renderSfChips();
      this.refreshView();
    },
    renderSfChips: function () {
      var box = $('log-sf-chips');
      if (!box) return;
      var list = this.view.simpleFilters || [];
      if (!list.length) { box.hidden = true; box.innerHTML = ''; return; }
      box.hidden = false;
      var self = this;
      box.innerHTML = list.map(function (f, i) {
        return '<span class="log-chip">' + esc(self.chipLabel(f)) +
          '<button type="button" class="log-chip__x" data-i="' + i + '" aria-label="移除">×</button></span>';
      }).join('');
      box.querySelectorAll('.log-chip__x').forEach(function (btn) {
        btn.addEventListener('click', function () {
          self.view.simpleFilters.splice(+btn.getAttribute('data-i'), 1);
          self.renderSfChips();
          self.refreshView();
        });
      });
    },
    chipLabel: function (f) {
      var field = sfField(f.field);
      var type = f.type || field.type;
      return (f.cn || field.cn) + ' ' + sfOpLabel(type, f.op) + ' ' + sfValLabel(type, f.val);
    },
    formatAtom: function (f) {
      return (f.cn || sfField(f.field).cn) + f.op + quoteQueryVal(f.val);
    },
    compileQuery: function () {
      var parts = [];
      (this.view.simpleFilters || []).forEach(function (f) { parts.push(Logs.formatAtom(f)); });
      var adv = (this.view.q || '').trim();
      if (adv) {
        /* 仅在与快速条件组合且高级式含 | 时才加括号，避免 (status>=400) 无法解析 */
        if (parts.length && adv.indexOf('|') >= 0) parts.push('(' + adv + ')');
        else parts.push(adv);
      }
      return parts.join(' & ');
    },

    /* ── 报告导出 ── */
    exportReport: function (fmt) {
      if (!this.worker || !this.summary) { this.flash('请先载入日志文件'); return; }
      this.pendingFmt = fmt;
      this.flash('正在生成报告…');
      this.worker.postMessage({ type: 'export', limit: 5000 });
    },
    doExport: function (d) {
      var fmt = this.pendingFmt || 'html';
      var html = this.buildReportHtml(d.rows, d.total, d.capped);
      var stamp = new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-');
      var base = '日志分析报告_' + stamp;
      if (fmt === 'pdf') { this.printReport(html); this.flash('已打开打印窗口，选择「另存为 PDF」即可'); }
      else if (fmt === 'doc') { this.dlBlob(base + '.doc', 'application/msword', html); this.flash('已导出 Word 文档'); }
      else { this.dlBlob(base + '.html', 'text/html;charset=utf-8', html); this.flash('已导出 HTML 报告'); }
    },
    dlBlob: function (name, mime, content) {
      var blob = new Blob(['\ufeff' + content], { type: mime });
      var url = URL.createObjectURL(blob);
      var a = document.createElement('a');
      a.href = url; a.download = name;
      document.body.appendChild(a); a.click(); document.body.removeChild(a);
      setTimeout(function () { URL.revokeObjectURL(url); }, 1500);
    },
    printReport: function (html) {
      var w = window.open('', '_blank');
      if (!w) { this.flash('浏览器拦截了弹窗，请允许弹窗后重试'); return; }
      w.document.open(); w.document.write(html); w.document.close();
      w.focus();
      setTimeout(function () { try { w.print(); } catch (e) {} }, 400);
    },
    buildReportHtml: function (rows, total, capped) {
      var s = this.summary, a = this.analytics;
      var span = (s.tsMin && s.tsMax) ? (fmtTs(s.tsMin) + ' ~ ' + fmtTs(s.tsMax)) : '—';
      function bar(list, color) {
        var max = list.length ? list[0].count : 1;
        return list.map(function (it) {
          return '<tr><td class="k">' + esc(it.key !== undefined ? it.key : it.code) + '</td>' +
            '<td class="bar"><span style="display:inline-block;height:10px;border-radius:2px;background:' + color + ';width:' + Math.max(2, it.count / max * 100) + '%"></span></td>' +
            '<td class="c">' + it.count.toLocaleString() + '</td></tr>';
        }).join('');
      }
      var sc = s.statusClass;
      var rc = s.riskCat;
      var riskRows = [['sqli', 'SQL 注入'], ['xss', 'XSS'], ['trav', '路径穿越'], ['rce', '命令执行'], ['sens', '敏感路径'], ['scan', '扫描器'], ['method', '危险方法'], ['e5xx', '5xx 错误']]
        .map(function (c) { return '<tr><td>' + c[1] + '</td><td class="c" style="color:' + ((rc[c[0]] || 0) ? '#9b1c1c' : '#888') + '">' + (rc[c[0]] || 0).toLocaleString() + '</td></tr>'; }).join('');

      var detail = rows.map(function (r) {
        var stColor = r.status >= 500 ? '#9b1c1c' : r.status >= 400 ? '#854d0e' : r.status >= 300 ? '#1e40af' : '#166534';
        return '<tr' + (r.attack ? ' class="risk"' : '') + '><td>' + r.n + '</td><td>' + esc(fmtTs(r.ts)) + '</td><td>' + esc(r.ip) +
          '</td><td>' + esc(r.method) + '</td><td style="color:' + stColor + ';font-weight:700">' + (r.status || '-') +
          '</td><td>' + (r.bytes ? humanBytes(r.bytes) : '-') + '</td><td class="path">' + esc(r.path) +
          '</td><td>' + esc(r.risk.join(' ')) + '</td></tr>';
      }).join('');

      var css = 'body{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;color:#1a1a1a;margin:32px;font-size:13px;line-height:1.6}' +
        'h1{font-size:22px;margin:0 0 4px}h2{font-size:15px;margin:24px 0 8px;border-bottom:1px solid #ddd;padding-bottom:4px}' +
        '.meta{color:#666;font-size:12px;margin-bottom:8px}.cards{display:flex;flex-wrap:wrap;gap:10px;margin:10px 0}' +
        '.card{border:1px solid #e0e0e0;border-radius:6px;padding:10px 14px;min-width:120px}.card .v{font-size:20px;font-weight:800}.card .l{font-size:11px;color:#777}' +
        'table{border-collapse:collapse;width:100%;font-size:12px;margin:6px 0}th,td{border:1px solid #e6e6e6;padding:5px 8px;text-align:left}th{background:#f4f4f2}' +
        'td.c{text-align:right;font-variant-numeric:tabular-nums}td.k{white-space:nowrap;font-family:monospace}td.bar{width:50%}td.path{font-family:monospace;word-break:break-all}' +
        '.grid3{display:flex;gap:18px;flex-wrap:wrap}.grid3>div{flex:1;min-width:220px}tr.risk td{background:#fef2f2}' +
        '.foot{margin-top:24px;color:#999;font-size:11px;border-top:1px solid #eee;padding-top:8px}' +
        '@media print{body{margin:12mm}h2{page-break-after:avoid}}';

      var cards = [
        ['总行数', s.lines.toLocaleString()], ['解析成功', s.parsed.toLocaleString()], ['解析失败', s.failed.toLocaleString()],
        ['独立 IP', s.uniqueIp.toLocaleString()], ['高危请求', s.riskTotal.toLocaleString()], ['传输量', humanBytes(s.bytes)]
      ].map(function (c) { return '<div class="card"><div class="v">' + c[1] + '</div><div class="l">' + c[0] + '</div></div>'; }).join('');

      return '<!DOCTYPE html><html lang="zh-CN"><head><meta charset="utf-8">' +
        '<meta name="ProgId" content="Word.Document"><title>中间件日志分析报告</title><style>' + css + '</style></head><body>' +
        '<h1>中间件日志分析报告</h1>' +
        '<div class="meta">来源文件：' + esc(this.fileName || '-') + ' ｜ 识别格式：' + esc(s.format) + ' ｜ 时间跨度：' + esc(span) + ' ｜ 生成时间：' + fmtTs(Date.now()) + '</div>' +
        '<div class="cards">' + cards + '</div>' +
        '<h2>状态码分布</h2><table><tbody>' +
        bar([{ key: '2xx', count: sc['2xx'] }, { key: '3xx', count: sc['3xx'] }, { key: '4xx', count: sc['4xx'] }, { key: '5xx', count: sc['5xx'] }].filter(function (x) { return x.count; }), '#854d0e') +
        '</tbody></table>' +
        '<div class="grid3">' +
        '<div><h2>高危识别</h2><table><tbody>' + riskRows + '</tbody></table></div>' +
        '<div><h2>Top 客户端 IP</h2><table><tbody>' + bar(a.topIp, '#2c5282') + '</tbody></table></div>' +
        '<div><h2>可疑扫描 IP（4xx 最多）</h2><table><tbody>' + bar(a.topScanner, '#9b1c1c') + '</tbody></table></div>' +
        '</div>' +
        '<h2>Top 请求路径</h2><table><tbody>' + bar(a.topPath, '#2c5282') + '</tbody></table>' +
        '<h2>请求明细（' + rows.length.toLocaleString() + ' / ' + total.toLocaleString() + ' 行' + (capped ? '，超出部分已截断，可先用筛选缩小范围' : '') + '）</h2>' +
        '<table><thead><tr><th>#</th><th>时间</th><th>IP</th><th>方法</th><th>状态</th><th>字节</th><th>路径</th><th>风险</th></tr></thead><tbody>' + detail + '</tbody></table>' +
        '<div class="foot">本报告由 RavenEye 本地生成，原始日志数据未上传任何服务器。</div>' +
        '</body></html>';
    },

    /* ── 列宽拖拽 ── */
    cols: ['56px', '152px', '134px', '60px', '60px', '78px', 'minmax(180px,1fr)', '168px'],
    initResize: function () {
      var lt = $('log-lt'), thead = $('log-thead');
      if (!lt || !thead) return;
      var self = this;
      function apply() { cpSet('lt-cols', '#log-lt{--lt-cols:' + self.cols.join(' ') + '}'); }
      apply();
      var heads = thead.children;
      var PATH_COL = 6; /* 路径列保持弹性，作为吸收列 */
      for (var c = 0; c < heads.length; c++) {
        if (c === PATH_COL) continue;
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
            document.addEventListener('mousemove', mm);
            document.addEventListener('mouseup', mu);
          });
          heads[idx].appendChild(grip);
        })(c);
      }
    },

    loadFromBuffer: function (fd) {
      // Electron mode: fd = { name, size, data: number[] } (普通数组, IPC安全)
      var bytes = new Uint8Array(fd.data);
      var wrapper = new Blob([bytes], { type: 'application/octet-stream' });
      wrapper.name = fd.name;
      wrapper.size = fd.size;
      this.load(wrapper);
    },

    load: function (file) {
      var self = this;
      this.fileName = file.name;
      $('log-empty').hidden = true;
      $('log-result').hidden = true;
      $('log-progress').hidden = false;
      cpSet('log-progress', '#log-progress-bar{width:0%}');
      $('log-progress-text').textContent = '正在读取 ' + esc(file.name) + ' （' + humanBytes(file.size) + '）…';

      if (this.worker) { this.worker.terminate(); this.worker = null; }
      this.rowsCache = {}; this.lastReqStart = -1;

      try {
        // Blob URL Worker (避免 file:// 协议下 Worker 加载问题)
      var _wCode1 = `/**
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
  sqli: /(union\\s+select|\\bor\\s+1\\s*=\\s*1|sleep\\s*\\(|benchmark\\s*\\(|information_schema|concat\\s*\\(|\\bxp_cmdshell|select.+from)/i,
  xss: /(<script|onerror\\s*=|onload\\s*=|javascript:|<img[^>]+src|alert\\s*\\(|document\\.cookie|<svg)/i,
  trav: /(\\.\\.\\/|\\.\\.\\\\|%2e%2e%2f|%2e%2e\\/|\\.\\.%2f|\\/etc\\/passwd|c:\\\\windows)/i,
  sens: /(\\/\\.env|\\/\\.git|\\/\\.svn|\\/\\.ssh|\\/wp-login|\\/wp-admin|\\/phpmyadmin|\\/administrator|\\/manager\\/html|\\/actuator|\\/\\.aws|\\/config\\.|\\/backup|\\.bak\\b|\\/druid\\/|\\/solr\\/|\\/console)/i,
  scan: /(sqlmap|nikto|nmap|masscan|acunetix|nessus|dirbuster|gobuster|wpscan|hydra|fuzz|nuclei|xray|crawler|zgrab)/i,
  rce: /(\\/bin\\/sh|\\/bin\\/bash|cmd\\.exe|powershell|whoami|system\\s*\\(|exec\\s*\\(|eval\\s*\\(|base64_decode|\\$\\{jndi:|phpinfo\\s*\\()/i
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
  var m = /^(\\d{2})\\/([A-Za-z]{3})\\/(\\d{4}):(\\d{2}):(\\d{2}):(\\d{2})\\s*([+\\-]\\d{4})?/.exec(s);
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
    re: /^(?:\\S+\\s+(?:stdout|stderr)\\s+[FP]\\s+)?\\[([^\\]]+)\\]\\s+(\\S+)\\s+"[^"]*"\\s+"([A-Z]+)\\s+(\\S+)[^"]*"\\s+(\\d{3})\\s+(\\d+|-)\\s+\\S+\\s+"([^"]*)"/d,
    gi: { ip: 2, path: 4, ua: 7 },
    map: function (m) { return { ip: m[2], time: m[1], method: m[3], path: m[4], status: +m[5], bytes: m[6] === '-' ? 0 : +m[6], ref: '', ua: m[7] }; } },
  { name: 'combined', re: /^(\\S+)\\s+\\S+\\s+\\S+\\s+\\[([^\\]]+)\\]\\s+"([A-Z]+)\\s+(\\S+)[^"]*"\\s+(\\d{3})\\s+(\\d+|-)\\s+"([^"]*)"\\s+"([^"]*)"/d,
    gi: { ip: 1, path: 4, ua: 8 },
    map: function (m) { return { ip: m[1], time: m[2], method: m[3], path: m[4], status: +m[5], bytes: m[6] === '-' ? 0 : +m[6], ref: m[7], ua: m[8] }; } },
  { name: 'common', re: /^(\\S+)\\s+\\S+\\s+\\S+\\s+\\[([^\\]]+)\\]\\s+"([A-Z]+)\\s+(\\S+)[^"]*"\\s+(\\d{3})\\s+(\\d+|-)/d,
    gi: { ip: 1, path: 4, ua: 0 },
    map: function (m) { return { ip: m[1], time: m[2], method: m[3], path: m[4], status: +m[5], bytes: m[6] === '-' ? 0 : +m[6], ref: '', ua: '' }; } }
];
var GENERIC = {
  ipRe: /(\\d{1,3}(?:\\.\\d{1,3}){3}|[0-9a-fA-F:]{3,}:[0-9a-fA-F:]+)/,
  reqRe: /"([A-Z]+)\\s+(\\S+)[^"]*"/,
  statusRe: /\\s(\\d{3})\\s/,
  timeRe: /\\[([^\\]]+)\\]/,
  uaRe: /"([^"]*)"\\s*$/
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

function safeDecode(s) { try { return decodeURIComponent(String(s).replace(/\\+/g, ' ')); } catch (e) { return String(s); } }
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
      var lines = text.split('\\n');
      leftover = lines.pop();

      for (var li = 0; li < lines.length; li++) {
        var ln = lines[li];
        if (ln.charCodeAt(ln.length - 1) === 13) ln = ln.slice(0, -1); /* 去掉 \\r */
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
  var re = new RegExp('^([\\\\w\\\\u4e00-\\\\u9fff\\\\u3400-\\\\u4dbf]+)\\\\s*(' + Q_OPS + ')\\\\s*([\\\\s\\\\S]*)$', 'u');
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
    if (/^\\dxx$/i.test(v)) return strOp(classifyStatus(cv), op, v.toLowerCase());
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
`;
      this.worker = new Worker(URL.createObjectURL(new Blob([_wCode1], { type: 'application/javascript' })));
      } catch (err) {
        $('log-progress').hidden = true; $('log-empty').hidden = false;
        $('log-empty').innerHTML = '<div class="tool-hint is-error">无法创建解析线程：' + esc(err.message) + '</div>';
        return;
      }

      this.worker.onmessage = function (e) {
        var d = e.data;
        if (d.type === 'progress') {
          var pct = d.total ? Math.min(100, Math.round(d.bytes / d.total * 100)) : 0;
          cpSet('log-progress', '#log-progress-bar{width:' + pct + '%}');
          $('log-progress-text').textContent = '解析中… ' + pct + '%（已解析 ' + d.lines.toLocaleString() + ' 行）';
        } else if (d.type === 'done') {
          self.onDone(d);
        } else if (d.type === 'view') {
          self.total = d.total;
          self.afterView();
        } else if (d.type === 'rows') {
          self.onRows(d);
        } else if (d.type === 'export') {
          self.doExport(d);
        } else if (d.type === 'search') {
          self.onSearch(d);
        } else if (d.type === 'minimap') {
          self.onMinimap(d);
        } else if (d.type === 'error') {
          $('log-progress').hidden = true; $('log-empty').hidden = false;
          $('log-empty').innerHTML = '<div class="tool-hint is-error">解析失败：' + esc(d.message) + '</div>';
        }
      };
      this.worker.postMessage({ type: 'parse', file: file });
    },

    onDone: function (d) {
      this.analytics = d.analytics;
      this.summary = d.summary;
      this.total = d.total;
      $('log-progress').hidden = true;
      $('log-result').hidden = false;
      this.renderDash(d.summary, d.analytics);
      this.populateMethodFilter(d.analytics.methodList);
      this.resetFind();
      this.closeSide();
      /* 初始视图 */
      this.view = defaultView();
      $('log-q').value = '';
      $('log-status').value = '';
      $('log-method').value = '';
      $('log-risk').checked = false;
      this.renderSfChips();
      this.renderSortIndicators();
      this.refreshView();
    },

    /* ── 仪表盘 ── */
    renderDash: function (s, a) {
      var span = (s.tsMin && s.tsMax) ? (fmtTs(s.tsMin) + ' ~ ' + fmtTs(s.tsMax)) : '—';
      var cards = [
        { label: '总行数', value: s.lines.toLocaleString(), sub: '解析成功 ' + s.parsed.toLocaleString() + (s.failed ? ' · 失败 ' + s.failed.toLocaleString() : '') },
        { label: '独立 IP', value: s.uniqueIp.toLocaleString() },
        { label: '高危请求', value: s.riskTotal.toLocaleString(), accent: s.riskTotal > 0 },
        { label: '传输量', value: humanBytes(s.bytes) },
        { label: '识别格式', value: esc(s.format) },
        { label: '时间跨度', value: span, wide: true }
      ];
      $('log-cards').innerHTML = cards.map(function (c) {
        return '<div class="log-card' + (c.wide ? ' log-card--wide' : '') + (c.accent ? ' log-card--accent' : '') + '">' +
          '<div class="log-card__v">' + c.value + '</div><div class="log-card__l">' + esc(c.label) + (c.sub ? ' · ' + esc(c.sub) : '') + '</div></div>';
      }).join('');

      /* 状态分布条 */
      var sc = s.statusClass, scTotal = sc['2xx'] + sc['3xx'] + sc['4xx'] + sc['5xx'] + sc.other || 1;
      var segs = [['2xx', sc['2xx']], ['3xx', sc['3xx']], ['4xx', sc['4xx']], ['5xx', sc['5xx']], ['other', sc.other]];
      $('log-statusbar').innerHTML = segs.filter(function (x) { return x[1]; }).map(function (x) {
        return '<div class="log-seg log-seg--' + x[0] + '" data-w="' + (x[1] / scTotal * 100) + '" title="' + x[0] + ': ' + x[1] + '"></div>';
      }).join('');
      applyBarWidths($('log-statusbar'), '.log-seg', 'log-seg-');
      $('log-statuslegend').innerHTML = segs.map(function (x) {
        return '<span class="log-leg"><i class="log-dot log-seg--' + x[0] + '"></i>' + x[0] + ' ' + x[1].toLocaleString() + '</span>';
      }).join('');

      /* 高危分类 */
      var rc = s.riskCat;
      var cats = [['sqli', 'SQL 注入'], ['xss', 'XSS'], ['trav', '路径穿越'], ['rce', '命令执行'], ['sens', '敏感路径'], ['scan', '扫描器'], ['method', '危险方法'], ['e5xx', '5xx 错误']];
      $('log-risklist').innerHTML = cats.map(function (c) {
        var v = rc[c[0]] || 0;
        return '<div class="log-riskitem' + (v ? ' is-hit' : '') + '"><span>' + esc(c[1]) + '</span><b>' + v.toLocaleString() + '</b></div>';
      }).join('');

      this.renderTopList('log-topip', a.topIp, 'ip');
      this.renderTopList('log-toppath', a.topPath, 'path');
      this.renderTopList('log-topscan', a.topScanner, 'ip');
      this.renderTrend(a.hour);
    },

    renderTopList: function (id, list, kind) {
      var max = list.length ? list[0].count : 1;
      $(id).innerHTML = list.map(function (it) {
        return '<div class="log-toprow" data-' + kind + '="' + esc(it.key) + '">' +
          '<div class="log-topbar" data-w="' + (it.count / max * 100) + '"></div>' +
          '<span class="log-topkey" title="' + esc(it.key) + '">' + esc(it.key) + '</span>' +
          '<span class="log-topcnt">' + it.count.toLocaleString() + '</span></div>';
      }).join('') || '<div class="tool-hint">无数据</div>';
      applyBarWidths($(id), '.log-topbar', id + '-bar-');
      var self = this;
      $(id).querySelectorAll('.log-toprow').forEach(function (row) {
        row.addEventListener('click', function () {
          var ip = row.getAttribute('data-ip');
          var path = row.getAttribute('data-path');
          if (ip != null) {
            self.view.ip = '';
            self.view.simpleFilters.push({ field: 'ip', cn: 'IP', type: 'text', op: '=', val: ip });
            self.renderSfChips();
            self.refreshView();
            self.flash('已添加条件：IP 等于 ' + ip);
          } else if (path != null) {
            self.view.simpleFilters.push({ field: 'path', cn: '路径', type: 'text', op: '~', val: path });
            self.renderSfChips();
            self.refreshView();
            self.flash('已添加条件：路径 包含 ' + path);
          }
        });
      });
    },

    renderTrend: function (hours) {
      var cv = $('log-trend'); if (!cv || !cv.getContext) return;
      var ctx = cv.getContext('2d');
      var W = cv.width = cv.clientWidth * (window.devicePixelRatio || 1);
      var H = cv.height = 80 * (window.devicePixelRatio || 1);
      ctx.clearRect(0, 0, W, H);
      if (!hours.length) return;
      var max = 0; hours.forEach(function (p) { if (p.count > max) max = p.count; });
      var n = hours.length, bw = W / n;
      ctx.fillStyle = '#9b1c1c';
      for (var i = 0; i < n; i++) {
        var h = max ? (hours[i].count / max) * (H - 4) : 0;
        ctx.globalAlpha = 0.75;
        ctx.fillRect(i * bw + 1, H - h, Math.max(1, bw - 2), h);
      }
      ctx.globalAlpha = 1;
    },

    populateMethodFilter: function (methods) {
      var sel = $('log-method');
      sel.innerHTML = '<option value="">全部方法</option>' + methods.map(function (m) { return '<option value="' + esc(m.key) + '">' + esc(m.key) + ' (' + m.count + ')</option>'; }).join('');
    },

    /* ── 筛选 / 排序 → 通知 worker 重建视图 ── */
    refreshView: function () {
      if (!this.worker) return;
      this.rowsCache = {}; this.lastReqStart = -1;
      this.selPos = -1;     /* 视图重建后行索引失效，清除选中态（侧栏内容保留） */
      var opt = {
        q: this.compileQuery(),
        statusClass: this.view.statusClass,
        method: this.view.method,
        riskOnly: this.view.riskOnly,
        ip: this.view.ip,
        sortKey: this.view.sortKey,
        sortDir: this.view.sortDir
      };
      this.worker.postMessage({ type: 'view', opt: opt });
    },
    afterView: function () {
      $('log-count').textContent = this.total.toLocaleString() + ' 条';
      cpSet('log-spacer-h', '#log-spacer{height:' + this.contentHeight() + 'px}');
      $('log-viewport').scrollTop = 0;
      this.lastReqStart = -1;
      this.onScroll(true);
      this.requestMinimap();
    },
    resetFilters: function () {
      this.view = defaultView();
      $('log-q').value = ''; $('log-status').value = ''; $('log-method').value = ''; $('log-risk').checked = false;
      this.renderSfChips();
      this.syncSfControls();
      this.renderSortIndicators();
      this.refreshView();
    },
    renderSortIndicators: function () {
      var self = this;
      $('log-thead').querySelectorAll('[data-sort]').forEach(function (th) {
        var k = th.getAttribute('data-sort');
        var base = th.getAttribute('data-label');
        if (base == null) { base = (th.textContent || '').replace(/[▲▼]/g, '').trim(); th.setAttribute('data-label', base); }
        var grip = th.querySelector('.lt-resz');            /* 保留拖拽握把，避免被 textContent 清除 */
        th.textContent = base + (self.view.sortKey === k ? (self.view.sortDir === 'asc' ? ' ▲' : ' ▼') : '');
        if (grip) th.appendChild(grip);
      });
    },

    /* ── 虚拟滚动（含超大数据「比例映射」以突破浏览器元素最大高度限制） ── */
    contentHeight: function () { return Math.min(this.total * ROW_H, MAX_SPACER); },
    isScaled: function () { return this.total * ROW_H > MAX_SPACER; },
    /* 视口顶部对应的行号 */
    rowForScrollTop: function (scrollTop, clientH) {
      if (!this.isScaled()) return Math.floor(scrollTop / ROW_H);
      var scrollable = this.contentHeight() - clientH;
      if (scrollable <= 0) return 0;
      var visible = Math.ceil(clientH / ROW_H);
      var maxFirst = Math.max(0, this.total - visible);
      var ratio = scrollTop / scrollable;
      if (ratio < 0) ratio = 0; if (ratio > 1) ratio = 1;
      return Math.round(ratio * maxFirst);
    },
    /* 指定首行对应的 scrollTop */
    scrollTopForRow: function (row, clientH) {
      if (!this.isScaled()) return row * ROW_H;
      var scrollable = this.contentHeight() - clientH;
      if (scrollable <= 0) return 0;
      var visible = Math.ceil(clientH / ROW_H);
      var maxFirst = Math.max(0, this.total - visible);
      if (maxFirst <= 0) return 0;
      var ratio = row / maxFirst;
      if (ratio < 0) ratio = 0; if (ratio > 1) ratio = 1;
      return ratio * scrollable;
    },
    onScroll: function (force) {
      var vp = $('log-viewport');
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
      var vpEl = $('log-viewport');
      var ty;
      if (this.isScaled()) {
        /* 缩放模式：渲染块相对视口定位（绝对像素已超出 spacer 上限，不能用 start*ROW_H） */
        var baseStart = this.rowForScrollTop(vpEl.scrollTop, vpEl.clientHeight);
        ty = vpEl.scrollTop - (baseStart - start) * ROW_H;
      } else {
        ty = start * ROW_H;
      }
      cpSet('log-rows-y', '#log-rows{transform:translateY(' + ty + 'px)}');
      var sc = this.search;
      var q = (sc && sc.query) ? sc.query : '';
      var cs = sc ? sc.caseSensitive : false;
      var matchSet = (q && sc.set) ? sc.set : null;
      var activePos = (q && sc.cur >= 0 && sc.matches.length) ? sc.matches[sc.cur] : -1;
      var selPos = this.selPos;
      function H(text) { return q ? hlEsc(text, q, cs) : esc(text); }
      $('log-rows').innerHTML = rows.map(function (r, i) {
        var pos = start + i;
        var isMatch = matchSet ? matchSet.has(pos) : false;
        var isActive = pos === activePos;
        var meta = 'IP ' + r.ip + ' · ' + r.method + ' ' + r.status + ' · ' + fmtTs(r.ts);
        var tags = r.risk.map(function (t) { return '<span class="lt-tag">' + esc(t) + '</span>'; }).join('');
        var cls = 'lt-row' + (r.attack ? ' lt-row--risk' : '') + (isMatch ? ' lt-row--match' : '') + (isActive ? ' lt-row--match-active' : '') + (pos === selPos ? ' lt-row--sel' : '');
        return '<div class="' + cls + '" data-pos="' + pos + '" data-raw="' + esc(r.raw) + '" data-meta="' + esc(meta) + '">' +
          '<div class="lt-c lt-c--n">' + r.n + '</div>' +
          '<div class="lt-c lt-c--ts">' + H(fmtTs(r.ts)) + '</div>' +
          '<div class="lt-c lt-c--ip">' + H(r.ip) + '</div>' +
          '<div class="lt-c lt-c--m">' + H(r.method) + '</div>' +
          '<div class="lt-c lt-c--st"><span class="lt-status lt-status--' + statusClass(r.status) + '">' + (r.status || '-') + '</span></div>' +
          '<div class="lt-c lt-c--by">' + (r.bytes ? humanBytes(r.bytes) : '-') + '</div>' +
          '<div class="lt-c lt-c--path" title="' + esc(r.path) + '">' + H(r.path) + '</div>' +
          '<div class="lt-c lt-c--risk">' + tags + '</div>' +
          '</div>';
      }).join('');
      /* 命中项位于本次渲染范围内时，自动展开其详情并高亮原文 */
      if (q && activePos >= start && activePos < start + rows.length) {
        var ar = rows[activePos - start];
        this.showDetail(ar.raw, 'IP ' + ar.ip + ' · ' + ar.method + ' ' + ar.status + ' · ' + fmtTs(ar.ts), activePos);
      }
    },

    showDetail: function (raw, meta, pos) {
      var lt = $('log-lt'); if (!lt) return;
      var sc = this.search;
      var q = (sc && sc.query) ? sc.query : '';
      var cs = sc ? sc.caseSensitive : false;
      $('log-side-meta').innerHTML = esc(meta);
      $('log-side-raw').innerHTML = q ? hlEsc(raw, q, cs) : esc(raw);
      if (pos != null && !isNaN(pos)) this.selPos = pos;
      this.applySideW();
      lt.classList.add('is-side-open');
      this.markSel();
    },

    flash: function (msg) {
      var el = $('log-flash'); if (!el) return;
      el.textContent = msg; el.classList.add('is-show');
      clearTimeout(this._ft); var self = this;
      this._ft = setTimeout(function () { el.classList.remove('is-show'); }, 1600);
    },

    /* ============================================================
     *  VSCode 风格全局查找（Ctrl+F）：全局匹配 + 高亮 + 上/下导航 + 定位
     * ============================================================ */
    initFind: function () {
      var self = this;
      var input = $('log-find-input');
      if (!input) return;

      var deb = null;
      input.addEventListener('input', function () {
        clearTimeout(deb);
        deb = setTimeout(function () { self.runSearch(input.value); }, 160);
      });
      input.addEventListener('keydown', function (e) {
        if (e.key === 'Enter') { e.preventDefault(); self.gotoRel(e.shiftKey ? -1 : 1); }
        else if (e.key === 'Escape') { e.preventDefault(); self.closeFind(); }
      });
      $('log-find-prev').addEventListener('click', function () { self.gotoRel(-1); input.focus(); });
      $('log-find-next').addEventListener('click', function () { self.gotoRel(1); input.focus(); });
      $('log-find-close').addEventListener('click', function () { self.closeFind(); });
      $('log-find-case').addEventListener('click', function () {
        self.search.caseSensitive = !self.search.caseSensitive;
        $('log-find-case').classList.toggle('is-on', self.search.caseSensitive);
        self.runSearch(input.value);
        input.focus();
      });

      /* Ctrl/Cmd+F：仅当日志模块激活且已载入数据时拦截，否则放行浏览器默认查找 */
      document.addEventListener('keydown', function (e) {
        if ((e.ctrlKey || e.metaKey) && !e.altKey && (e.key === 'f' || e.key === 'F')) {
          if (!self.isLogsActive()) return;
          e.preventDefault();
          self.openFind();
        }
      });
    },
    isLogsActive: function () {
      var pane = $('pane-logs');
      var res = $('log-result');
      return !!(pane && !pane.hidden && res && !res.hidden);
    },
    openFind: function () {
      var box = $('log-find'); if (!box) return;
      box.hidden = false;
      this.search.open = true;
      var input = $('log-find-input');
      input.focus(); input.select();
      if (input.value.trim()) this.runSearch(input.value);
      else this.updateFindCount();
    },
    closeFind: function () {
      var box = $('log-find'); if (box) box.hidden = true;
      this.search.open = false;
      this.search.query = '';
      this.search.matches = [];
      this.search.set = null;
      this.search.cur = -1;
      this.search.capped = false;
      this.rowsCache = {}; this.lastReqStart = -1;
      this.onScroll(true);
      this.updateFindCount();
    },
    resetFind: function () {
      this.search.open = false;
      this.search.query = '';
      this.search.matches = [];
      this.search.set = null;
      this.search.cur = -1;
      this.search.capped = false;
      var box = $('log-find'); if (box) box.hidden = true;
      var input = $('log-find-input'); if (input) input.value = '';
      this.updateFindCount();
    },
    runSearch: function (value) {
      this.search.query = String(value || '');
      this.search.matches = [];
      this.search.set = null;
      this.search.cur = -1;
      this.search.capped = false;
      if (!this.search.query) {
        this.rowsCache = {}; this.lastReqStart = -1;
        this.onScroll(true);
        this.updateFindCount();
        return;
      }
      if (!this.worker) { this.updateFindCount(); return; }
      this.worker.postMessage({ type: 'search', query: this.search.query, caseSensitive: this.search.caseSensitive });
    },
    onSearch: function (d) {
      if (d.query !== this.search.query) return;   /* 丢弃过期结果 */
      var m = d.matches || [];
      this.search.matches = m;
      var set = new Set();
      for (var i = 0; i < m.length; i++) set.add(m[i]);
      this.search.set = set;
      this.search.capped = !!d.capped;
      if (m.length) { this.search.cur = 0; this.gotoMatch(0); }
      else { this.search.cur = -1; this.rowsCache = {}; this.lastReqStart = -1; this.onScroll(true); }
      this.updateFindCount();
      this.drawMap();
    },
    gotoRel: function (delta) {
      var n = this.search.matches.length; if (!n) return;
      var cur = this.search.cur < 0 ? (delta > 0 ? -1 : 0) : this.search.cur;
      cur = ((cur + delta) % n + n) % n;
      this.search.cur = cur;
      this.gotoMatch(cur);
      this.updateFindCount();
    },
    gotoMatch: function (i) {
      var m = this.search.matches; if (!m.length) return;
      var pos = m[i];
      var vp = $('log-viewport');
      var visible = Math.ceil(vp.clientHeight / ROW_H);
      var maxFirst = Math.max(0, this.total - visible);
      var desiredFirst = Math.max(0, Math.min(pos - Math.floor(visible / 2), maxFirst));
      var maxTop = Math.max(0, this.contentHeight() - vp.clientHeight);
      vp.scrollTop = Math.max(0, Math.min(this.scrollTopForRow(desiredFirst, vp.clientHeight), maxTop));
      this.lastReqStart = -1;   /* 强制重渲染以刷新当前命中行高亮 */
      this.onScroll(true);
    },
    updateFindCount: function () {
      var el = $('log-find-count'); if (!el) return;
      var m = this.search.matches;
      if (!this.search.query) { el.textContent = '无结果'; el.classList.remove('is-empty'); return; }
      if (!m.length) { el.textContent = '无匹配'; el.classList.add('is-empty'); return; }
      el.classList.remove('is-empty');
      el.textContent = (this.search.cur + 1) + ' / ' + m.length + (this.search.capped ? '+' : '');
    },

    /* ============================================================
     *  右侧概览缩略图（minimap）：状态分布 + 高危标记 + 命中标记 + 视口滑块
     * ============================================================ */
    initMap: function () {
      var self = this;
      var cv = $('log-map'); if (!cv) return;
      var dragging = false;
      self.mapHover = { on: false, y: 0 };
      function jump(e) {
        var rect = cv.getBoundingClientRect();
        var frac = Math.min(1, Math.max(0, (e.clientY - rect.top) / rect.height));
        var total = self.total || 0; if (!total) return;
        var vp = $('log-viewport');
        var contentH = self.contentHeight();
        vp.scrollTop = Math.max(0, Math.min(frac * contentH - vp.clientHeight / 2, contentH - vp.clientHeight));
        self.lastReqStart = -1; self.onScroll(true);
      }
      cv.addEventListener('mousedown', function (e) { dragging = true; jump(e); e.preventDefault(); });
      cv.addEventListener('mousemove', function (e) {
        var rect = cv.getBoundingClientRect();
        self.mapHover = { on: true, y: e.clientY - rect.top };
        if (!dragging) self.drawMap();
      });
      cv.addEventListener('mouseleave', function () { self.mapHover = { on: false, y: 0 }; self.drawMap(); });
      document.addEventListener('mousemove', function (e) { if (dragging) jump(e); });
      document.addEventListener('mouseup', function () { dragging = false; });
      window.addEventListener('resize', function () { self.drawMap(); });
    },
    requestMinimap: function () {
      if (this.worker) this.worker.postMessage({ type: 'minimap', buckets: 360 });
    },
    onMinimap: function (d) {
      this.map = { buckets: d.buckets, stat: d.stat, risk: d.risk, total: d.total };
      this.drawMap();
    },
    drawMap: function () {
      var cv = $('log-map'); if (!cv || !cv.getContext) return;
      var vp = $('log-viewport'); if (!vp) return;
      var dpr = window.devicePixelRatio || 1;
      var cssW = cv.clientWidth || 60;
      var cssH = cv.clientHeight || vp.clientHeight || 1;
      var pw = Math.round(cssW * dpr), ph = Math.round(cssH * dpr);
      if (cv.width !== pw || cv.height !== ph) { cv.width = pw; cv.height = ph; }
      var ctx = cv.getContext('2d');
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      ctx.clearRect(0, 0, cssW, cssH);
      var total = this.total || 0;

      /* ── 状态分布：铺满宽度，4xx/5xx 着重，便于一眼看清错误/高危聚集 ── */
      var map = this.map;
      if (map && map.total > 0 && map.stat) {
        var buckets = map.buckets, stat = map.stat, risk = map.risk;
        var COLS = [
          'rgba(165,165,165,.12)',  /* other */
          'rgba(90,165,120,.30)',   /* 2xx 绿 */
          'rgba(90,150,205,.32)',   /* 3xx 蓝 */
          'rgba(225,160,55,.60)',   /* 4xx 橙 */
          'rgba(212,68,68,.70)'     /* 5xx 红 */
        ];
        for (var b = 0; b < buckets; b++) {
          var y = b / buckets * cssH;
          var h = cssH / buckets + 0.8;
          ctx.fillStyle = COLS[stat[b] || 0];
          ctx.fillRect(0, y, cssW, h);
          if (risk[b]) {                       /* 高危：左缘暗红窄条 */
            ctx.fillStyle = 'rgba(150,30,30,.9)';
            ctx.fillRect(0, y, 4, Math.max(1.5, h));
          }
        }
      } else {
        ctx.fillStyle = 'rgba(150,150,150,.05)';
        ctx.fillRect(0, 0, cssW, cssH);
      }

      /* ── 查找命中：右缘橙色标记（与左缘高危分列，避免混淆） ── */
      var sc = this.search;
      if (sc && sc.query && sc.matches && sc.matches.length && total > 0) {
        ctx.fillStyle = 'rgba(255,150,50,.95)';
        var m = sc.matches, seen = {};
        for (var i = 0; i < m.length; i++) {
          var yp = Math.round(m[i] / total * cssH);
          if (seen[yp]) continue; seen[yp] = 1;
          ctx.fillRect(cssW - 7, yp, 7, 2);
        }
        if (sc.cur >= 0 && sc.cur < m.length) {   /* 当前命中：整宽亮橙线 */
          ctx.fillStyle = 'rgba(255,110,20,1)';
          var yc = m[sc.cur] / total * cssH;
          ctx.fillRect(0, Math.max(0, yc - 1.5), cssW, 3);
        }
      }

      /* ── 当前视口：明显蓝框 + 蓝色滑柄，清晰指示「你在哪」 ── */
      if (total > 0) {
        var firstRow = this.rowForScrollTop(vp.scrollTop, vp.clientHeight);
        var y0 = firstRow / total * cssH;
        var hh = Math.max(12, (vp.clientHeight / ROW_H) / total * cssH);
        if (y0 + hh > cssH) y0 = cssH - hh;
        if (y0 < 0) y0 = 0;
        ctx.fillStyle = 'rgba(70,130,215,.16)';
        ctx.fillRect(0, y0, cssW, hh);
        ctx.fillStyle = 'rgba(70,130,215,.95)';   /* 左侧滑柄 */
        ctx.fillRect(0, y0, 3, hh);
        ctx.strokeStyle = 'rgba(70,130,215,.9)';
        ctx.lineWidth = 1.5;
        ctx.strokeRect(0.75, y0 + 0.75, cssW - 1.5, Math.max(1, hh - 1.5));
      }

      /* ── 鼠标悬停预览框（VSCode minimap slider 风格）：跟随鼠标的浅色框 ── */
      var hov = this.mapHover;
      if (hov && hov.on && total > 0) {
        var hvH = Math.max(12, (vp.clientHeight / ROW_H) / total * cssH);
        var hy0 = hov.y - hvH / 2;
        if (hy0 < 0) hy0 = 0;
        if (hy0 + hvH > cssH) hy0 = cssH - hvH;
        ctx.fillStyle = 'rgba(130,160,210,.16)';
        ctx.fillRect(0, hy0, cssW, hvH);
        ctx.strokeStyle = 'rgba(130,160,210,.55)';
        ctx.lineWidth = 1;
        ctx.strokeRect(0.5, hy0 + 0.5, cssW - 1, Math.max(1, hvH - 1));
      }
    }
  };

  /* 暴露给工具箱：首次切到「日志分析」时初始化 */
  window.LogAnalyzer = Logs;
  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', function () { Logs.init(); });
  else Logs.init();
})();
