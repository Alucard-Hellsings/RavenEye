/* CSP 合规的动态样式：Constructable Stylesheet，不触发 style-src inline 拦截 */
(function (g) {
  'use strict';
  if (!g.document || typeof g.CSSStyleSheet === 'undefined') {
    g.CpStyle = { set: function () {}, remove: function () {}, clear: function () {} };
    return;
  }

  var sheet = new CSSStyleSheet();
  var rules = Object.create(null);
  var order = [];

  function adopt() {
    var list = g.document.adoptedStyleSheets;
    if (list.indexOf(sheet) === -1) {
      g.document.adoptedStyleSheets = list.concat(sheet);
    }
  }

  function sync() {
    sheet.replaceSync(order.map(function (k) { return rules[k]; }).join('\n'));
  }

  g.CpStyle = {
    set: function (key, cssText) {
      if (!rules[key]) order.push(key);
      rules[key] = cssText;
      adopt();
      sync();
    },
    remove: function (key) {
      if (!rules[key]) return;
      delete rules[key];
      order = order.filter(function (k) { return k !== key; });
      sync();
    },
    clear: function (prefix) {
      order.slice().forEach(function (k) {
        if (!prefix || k.indexOf(prefix) === 0) g.CpStyle.remove(k);
      });
    },
  };
})(typeof window !== 'undefined' ? window : globalThis);
