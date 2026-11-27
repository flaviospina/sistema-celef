// public/assets/js/google-retorno.js — encaminha o retorno do Google (code/state/error) para o callback em PHP.
// Nunca repassa os demais parâmetros (scope, iss, authuser, hd, prompt): são eles que disparam o firewall da hospedagem.
(function () {
  'use strict';
  var entrada = new URLSearchParams(window.location.search);
  var saida = new URLSearchParams();
  ['code', 'state', 'error'].forEach(function (k) { if (entrada.has(k)) { saida.set(k, entrada.get(k)); } });
  if (!saida.has('state')) {
    document.getElementById('msg').textContent = 'Retorno do Google incompleto. Volte ao sistema e tente entrar novamente.';
    return;
  }
  // "callback" relativo a /…/auth/google/callback.html → /…/auth/google/callback (rota PHP)
  window.location.replace('callback?' + saida.toString());
})();
