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

// ---- Planilhas: o link (URL) nunca é enviado ao servidor; extraímos só o ID para o campo oculto ----------------
// (o firewall da hospedagem recusa qualquer campo cujo valor seja uma URL)
(function () {
  'use strict';
  document.querySelectorAll('form[data-planilha-form]').forEach(function (form) {
    var link = form.querySelector('[data-planilha-link]');
    var hidden = form.querySelector('[data-planilha-id]');
    var status = form.querySelector('[data-planilha-status]');
    if (!link || !hidden) { return; }
    function extrair() {
      var v = link.value.trim();
      var m = v.match(/\/spreadsheets\/d\/([A-Za-z0-9_-]{20,100})/);
      var id = m ? m[1] : (/^[A-Za-z0-9_-]{20,100}$/.test(v) ? v : '');
      hidden.value = id;
      if (status && v !== '') {
        status.textContent = id ? 'ID reconhecido: ' + id : 'Não reconheci um link ou ID de planilha do Google.';
        status.className = 'form-text ' + (id ? 'text-success' : 'text-danger');
      }
      return id;
    }
    link.addEventListener('input', extrair);
    form.addEventListener('submit', function (ev) {
      if (!extrair()) { ev.preventDefault(); ev.stopImmediatePropagation(); link.focus(); }
    }, true);
  });
})();

// ---- Service Account: lê o JSON no navegador e envia só e-mail + chave privada (base64) -----------------------
(function () {
  'use strict';
  var arquivo = document.getElementById('sa_arquivo');
  if (!arquivo) { return; }
  var status = document.getElementById('sa_status'), botao = document.getElementById('sa_enviar');
  arquivo.addEventListener('change', function () {
    botao.disabled = true;
    var f = arquivo.files && arquivo.files[0];
    if (!f) { return; }
    if (f.size > 20000) { status.textContent = 'Arquivo grande demais para ser uma chave de Service Account.'; return; }
    var leitor = new FileReader();
    leitor.onload = function () {
      try {
        var j = JSON.parse(String(leitor.result));
        if (j.type !== 'service_account' || !j.client_email || !j.private_key) { throw new Error('formato'); }
        document.getElementById('sa_email').value = j.client_email;
        document.getElementById('sa_key_b64').value = window.btoa(j.private_key);
        status.textContent = 'Service Account: ' + j.client_email;
        botao.disabled = false;
      } catch (e) { status.textContent = 'Este arquivo não é uma chave JSON de Service Account.'; }
    };
    leitor.readAsText(f);
  });
})();
