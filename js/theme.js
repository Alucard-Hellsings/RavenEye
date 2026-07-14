/**
 * 主题（暗色 / 护眼模式）——CSP 合规：外部脚本 + class，无内联。
 *   · 在 <head> 同步加载，body 渲染前即应用，避免首屏闪烁（FOUC）
 *   · 持久化到 localStorage；首访跟随系统 prefers-color-scheme
 *   · DOMContentLoaded 后向 .nav 注入切换按钮；支持跨标签同步
 */
'use strict';
(function () {
  var KEY = 'cp-theme';                 /* 'dark' | 'light' */
  var root = document.documentElement;

  var ICON_SUN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4.2"></circle><path d="M12 2.6v2.4M12 19v2.4M2.6 12h2.4M19 12h2.4M5.1 5.1l1.7 1.7M17.2 17.2l1.7 1.7M18.9 5.1l-1.7 1.7M6.8 17.2l-1.7 1.7"></path></svg>';
  var ICON_MOON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 14.5A8 8 0 0 1 9.5 4a7 7 0 1 0 10.5 10.5z"></path></svg>';

  function systemPrefersDark() {
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
  }

  function stored() {
    try { return localStorage.getItem(KEY); } catch (e) { return null; }
  }

  function resolve() {
    var s = stored();
    if (s === 'dark' || s === 'light') return s;
    return systemPrefersDark() ? 'dark' : 'light';
  }


  function apply(theme) {
    if (theme === 'dark') root.setAttribute('data-theme', 'dark');
    else root.removeAttribute('data-theme');

  }

  /* 首屏前立即应用，杜绝闪烁 */
  apply(resolve());

  var btn = null;
  function syncBtn(theme) {
    if (!btn) return;
    var dark = theme === 'dark';
    btn.innerHTML = dark ? ICON_SUN : ICON_MOON;
    btn.setAttribute('aria-label', dark ? '切换到浅色模式' : '切换到暗色模式');
    btn.setAttribute('title', dark ? '浅色模式' : '暗色模式');
    btn.setAttribute('aria-pressed', dark ? 'true' : 'false');
  }

  function prefersReducedMotion() {
    return window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  }

  /**
   * 切换主题。
   * origin：触发坐标（按钮中心）。提供时用 View Transition 做圆形扩散揭示；
   *         未提供（系统切换/跨标签同步）时做整页交叉淡化。
   * View Transition 是单次 GPU 合成层过渡，与页面节点数量无关，
   * 不支持的浏览器或「减少动态效果」时回退到 class 过渡方案。
   */
  function setTheme(theme, persist, origin) {
    if (persist !== false) {
      try { localStorage.setItem(KEY, theme); } catch (e) { }
    }
    var run = function () { apply(theme); syncBtn(theme); };

    if (typeof document.startViewTransition === 'function' && !prefersReducedMotion()) {
      var mode = origin ? 'theme-vt-circle' : 'theme-vt-fade';
      root.classList.add(mode);
      var vt = document.startViewTransition(run);
      if (origin && vt.ready && vt.ready.then) {
        vt.ready.then(function () {
          var x = Math.round(origin.x), y = Math.round(origin.y);
          var r = Math.ceil(Math.hypot(
            Math.max(x, window.innerWidth - x),
            Math.max(y, window.innerHeight - y)
          ));
          /* WAAPI 直接驱动 ::view-transition-new(root) 的 clip-path，CSP 合规（无内联样式） */
          root.animate(
            { clipPath: ['circle(0px at ' + x + 'px ' + y + 'px)', 'circle(' + r + 'px at ' + x + 'px ' + y + 'px)'] },
            { duration: 520, easing: 'cubic-bezier(0.22, 0.61, 0.36, 1)', pseudoElement: '::view-transition-new(root)' }
          );
        }).catch(function () { });
      }
      var done = function () { root.classList.remove(mode); };
      if (vt.finished && vt.finished.then) vt.finished.then(done, done);
      else window.setTimeout(done, 800);
      return;
    }

    /* 回退：临时给根节点加 class，结束后移除 */
    root.classList.add('theme-switching');
    run();
    window.clearTimeout(setTheme._t);
    setTheme._t = window.setTimeout(function () {
      root.classList.remove('theme-switching');
    }, 360);
  }

  function currentTheme() {
    return root.getAttribute('data-theme') === 'dark' ? 'dark' : 'light';
  }

  function mountButton() {
    // 主题按钮已迁移到标题栏，不再由 theme.js 创建
  }

  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', mountButton);
  } else {
    mountButton();
  }

  /* 跨标签同步 */
  window.addEventListener('storage', function (e) {
    if (e.key === KEY && (e.newValue === 'dark' || e.newValue === 'light')) {
      setTheme(e.newValue, false);
    }
  });

  /* 未手动选择时跟随系统切换 */
  if (window.matchMedia) {
    var mq = window.matchMedia('(prefers-color-scheme: dark)');
    var onChange = function () { if (!stored()) setTheme(systemPrefersDark() ? 'dark' : 'light', false); };
    if (mq.addEventListener) mq.addEventListener('change', onChange);
    else if (mq.addListener) mq.addListener(onChange);
  }

  window.CpTheme = { set: setTheme, current: currentTheme };
})();

