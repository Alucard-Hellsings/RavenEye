/**
 * 安全工具箱 /tools —— 模块化设计，全部浏览器本地运行
 *
 * 模块：
 *   ToolNav  —— 左侧工具菜单切换
 *   CVSS     —— CVSS 3.1 基础评分（官方算法）+ 每个向量悬停详解
 *   JWT      —— 解码 + 签名校验（HS* 密钥 / RS*·ES* PEM 公钥，基于 SubtleCrypto）
 *   Encode   —— Base64 / URL / Hex / HTML 编解码
 *   Hash     —— SHA 家族摘要（SubtleCrypto）+ 哈希类型识别
 *   Desens   —— 数据脱敏（IP/手机/邮箱/身份证/银行卡/MAC/JWT/Token/URL口令）
 *   Rgx      —— 正则测试 + 安全提取库（实时高亮、分组、替换预览）
 */
(function () {
  'use strict';

  /* ── 共享工具 ── */
  var U = {
    $: function (id) { return document.getElementById(id); },
    esc: function (s) {
      return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
        .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
    },
    copy: function (text, el) {
      var done = function () { if (el) { var t = el.textContent; el.textContent = '已复制'; setTimeout(function () { el.textContent = t; }, 900); } };
      if (navigator.clipboard && navigator.clipboard.writeText) navigator.clipboard.writeText(text).then(done, done);
      else { try { var ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); document.body.removeChild(ta); done(); } catch (e) {} }
    },
    strBuf: function (s) { return new TextEncoder().encode(s); },
    base64ToBytes: function (b64) {
      b64 = b64.replace(/\s+/g, '');
      var bin = atob(b64), a = new Uint8Array(bin.length);
      for (var i = 0; i < bin.length; i++) a[i] = bin.charCodeAt(i);
      return a;
    },
    b64urlToBytes: function (s) {
      s = String(s).replace(/-/g, '+').replace(/_/g, '/');
      while (s.length % 4) s += '=';
      return U.base64ToBytes(s);
    },
    b64urlToStr: function (str) {
      var bin = String.fromCharCode.apply(null, U.b64urlToBytes(str));
      try {
        return decodeURIComponent(bin.split('').map(function (c) {
          return '%' + ('00' + c.charCodeAt(0).toString(16)).slice(-2);
        }).join(''));
      } catch (e) { return bin; }
    },
    stripPem: function (p) { return p.replace(/-----[^-]+-----/g, '').replace(/\s+/g, ''); }
  };

  /* ============================================================
   *  ToolNav
   * ============================================================ */
  var ToolNav = {
    init: function () {
      var items = document.querySelectorAll('.tool-nav__item');
      items.forEach(function (it) {
        it.addEventListener('click', function () {
          items.forEach(function (x) { x.classList.remove('is-active'); });
          it.classList.add('is-active');
          var tool = it.getAttribute('data-tool');
          ['regex', 'logs', 'syslog'].forEach(function (k) {
            var pane = U.$('pane-' + k);
            if (pane) pane.hidden = (k !== tool);
          });
        });
      });
    }
  };

  /* ============================================================
   *  CVSS 3.1
   * ============================================================ */
  var Rgx = {
    presets: [
      ['IPv4',     '\\b(?:\\d{1,3}\\.){3}\\d{1,3}\\b'],
      ['IPv6',     '\\b(?:[0-9A-Fa-f]{1,4}:){2,7}[0-9A-Fa-f]{1,4}\\b'],
      ['邮箱',     '[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}'],
      ['URL',      'https?://[^\\s"\'<>]+'],
      ['域名',     '\\b(?:[a-z0-9-]+\\.)+[a-z]{2,}\\b'],
      ['手机号',   '\\b1[3-9]\\d{9}\\b'],
      ['身份证',   '\\b\\d{17}[\\dXx]\\b'],
      ['MAC',      '\\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\\b'],
      ['JWT',      'eyJ[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+\\.[A-Za-z0-9_-]+'],
      ['MD5',      '\\b[a-f0-9]{32}\\b'],
      ['SHA1',     '\\b[a-f0-9]{40}\\b'],
      ['SHA256',   '\\b[a-f0-9]{64}\\b'],
      ['AWS Key',  '\\b(?:AKIA|ASIA)[A-Z0-9]{16}\\b'],
      ['私钥块',   '-----BEGIN [A-Z ]+PRIVATE KEY-----'],
      ['信用卡',   '\\b\\d{15,19}\\b'],
      ['HEX 颜色', '#[0-9A-Fa-f]{3,8}\\b'],
      ['日期',     '\\b\\d{4}-\\d{2}-\\d{2}\\b']
    ],
    init: function () {
      var pat = U.$('rgx-pattern');
      if (!pat) return;
      var self = this;
      U.$('rgx-presets').innerHTML = this.presets.map(function (p, i) {
        return '<button type="button" class="rgx-preset" data-i="' + i + '">' + U.esc(p[0]) + '</button>';
      }).join('');
      U.$('rgx-presets').addEventListener('click', function (e) {
        var b = e.target.closest('.rgx-preset');
        if (!b) return;
        pat.value = self.presets[+b.getAttribute('data-i')][1];
        self.run();
      });
      var deb = null;
      function sched() { clearTimeout(deb); deb = setTimeout(function () { self.run(); }, 150); }
      pat.addEventListener('input', sched);
      U.$('rgx-text').addEventListener('input', sched);
      ['g', 'i', 'm', 's'].forEach(function (f) {
        var el = U.$('rgx-flag-' + f);
        if (el) el.addEventListener('change', function () { self.run(); });
      });
      U.$('rgx-dorep').addEventListener('click', function () { self.replace(); });
      this.run();
    },
    build: function () {
      var p = U.$('rgx-pattern').value;
      if (!p) return null;
      var flags = '';
      ['g', 'i', 'm', 's'].forEach(function (f) { if (U.$('rgx-flag-' + f).checked) flags += f; });
      return new RegExp(p, flags);
    },
    highlight: function (text, re) {
      var out = '', last = 0, count = 0, list = [], m, guard = 0;
      if (!re.global) {
        m = re.exec(text);
        if (m) {
          count = 1; list.push({ text: m[0], groups: m.slice(1) });
          out = U.esc(text.slice(0, m.index)) + '<mark>' + U.esc(m[0]) + '</mark>' + U.esc(text.slice(m.index + m[0].length));
        } else out = U.esc(text);
        return { html: out, count: count, list: list };
      }
      re.lastIndex = 0;
      while ((m = re.exec(text)) !== null) {
        out += U.esc(text.slice(last, m.index)) + '<mark>' + U.esc(m[0]) + '</mark>';
        last = m.index + m[0].length;
        count++;
        if (list.length < 300) list.push({ text: m[0], groups: m.slice(1) });
        if (m[0] === '') re.lastIndex++;
        if (++guard > 200000) break;
      }
      out += U.esc(text.slice(last));
      return { html: out, count: count, list: list };
    },
    run: function () {
      var status = U.$('rgx-status'), hl = U.$('rgx-hl'), ml = U.$('rgx-matches');
      var text = U.$('rgx-text').value, re;
      try { re = this.build(); }
      catch (e) { status.className = 'tool-hint is-error'; status.textContent = '正则错误：' + e.message; return; }
      status.className = 'tool-hint';
      if (!re) { hl.innerHTML = U.esc(text); ml.innerHTML = ''; status.textContent = '请输入正则表达式'; return; }
      var res = this.highlight(text, re);
      hl.innerHTML = res.html || '<span class="tool-hint">（无文本）</span>';
      status.textContent = '匹配 ' + res.count + ' 处' + (res.count > res.list.length ? '（仅列出前 ' + res.list.length + ' 条）' : '');
      ml.innerHTML = res.list.map(function (m, i) {
        var g = m.groups.length
          ? ' <span class="g">分组: ' + m.groups.map(function (x, gi) { return '$' + (gi + 1) + '=' + U.esc(x == null ? '∅' : x); }).join('  ') + '</span>'
          : '';
        return '<div class="m">#' + (i + 1) + ' ' + U.esc(m.text) + g + '</div>';
      }).join('');
    },
    replace: function () {
      var text = U.$('rgx-text').value, rep = U.$('rgx-rep').value, re, out = U.$('rgx-repout');
      try { re = this.build(); }
      catch (e) { out.value = '正则错误：' + e.message; return; }
      if (!re) { out.value = ''; return; }
      try { out.value = text.replace(re, rep); }
      catch (e) { out.value = '替换错误：' + e.message; }
    }
  };
  function init() { ToolNav.init(); Rgx.init(); }

  /* ============================================================ */

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', init);
})();
