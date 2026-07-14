/**
 * 新拟态退出确认弹窗 — IPC 方案
 */
'use strict';
(function () {
  var overlay = document.getElementById('confirm-overlay');
  var btnCancel = document.getElementById('confirm-cancel');
  var btnOk = document.getElementById('confirm-ok');

  if (!overlay || !btnCancel || !btnOk) return;

  function show() {
    overlay.classList.remove('u-hidden');
    btnCancel.focus();
    document.body.style.overflow = 'hidden';
  }

  function hide() {
    overlay.classList.add('u-hidden');
    document.body.style.overflow = '';
  }

  btnCancel.addEventListener('click', hide);

  btnOk.addEventListener('click', function () {
    hide();
    if (window.electronAPI && window.electronAPI.doQuit) {
      window.electronAPI.doQuit();
    }
  });

  overlay.addEventListener('click', function (e) {
    if (e.target === overlay) hide();
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Escape' && !overlay.classList.contains('u-hidden')) hide();
  });

  document.addEventListener('keydown', function (e) {
    if (e.key === 'Enter' && !overlay.classList.contains('u-hidden')) btnOk.click();
  });

  // 监听主进程的退出确认请求
  if (window.electronAPI && window.electronAPI.onConfirmQuit) {
    window.electronAPI.onConfirmQuit(show);
  }
})();