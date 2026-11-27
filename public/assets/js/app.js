// public/assets/js/app.js — comportamento comum (vanilla). Carregado com nonce de CSP.
(function () {
  'use strict';
  // Confirmação em ações destrutivas: <form data-confirm="Texto">
  document.querySelectorAll('form[data-confirm]').forEach(function (form) {
    form.addEventListener('submit', function (ev) {
      if (!window.confirm(form.getAttribute('data-confirm'))) { ev.preventDefault(); }
    });
  });
  // Evita duplo envio
  document.querySelectorAll('form').forEach(function (form) {
    form.addEventListener('submit', function () {
      form.querySelectorAll('button[type="submit"]').forEach(function (b) { b.disabled = true; });
    });
  });
})();
