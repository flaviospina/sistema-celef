<?php $c = $credencial; $ok = $c !== null && $c['status'] === 'CONNECTED' && $c['secret_enc'] !== null; ?>
<h1 class="h4 mb-3">Conta técnica Google</h1>
<p class="text-muted small">A conta técnica é o "braço" que lê e grava nas planilhas. A autoria de cada ação continua sendo sempre do usuário logado no sistema. O token fica cifrado no banco e nunca é exibido.</p>
<div class="card mb-3"><div class="card-body">
  <div class="d-flex flex-wrap justify-content-between align-items-start gap-2">
    <div>
      <div class="small text-muted">Situação</div>
      <?php if ($ok): ?>
        <div class="h5 mb-1"><span class="badge text-bg-success">Conectada</span> <?= $e($c['account_email']) ?></div>
        <div class="small text-muted"><?= $c['kind'] === 'SERVICE_ACCOUNT' ? 'Service Account' : 'Conta do Workspace (OAuth)' ?> · conectada em <?= $e(date('d/m/Y H:i', strtotime((string) $c['connected_at']))) ?>
          <?= $c['last_refresh_at'] ? ' · token renovado em ' . $e(date('d/m/Y H:i', strtotime($c['last_refresh_at']))) : '' ?></div>
      <?php elseif ($c !== null && $c['status'] === 'ERROR'): ?>
        <div class="h5 mb-1"><span class="badge text-bg-danger">Autorização inválida</span> <?= $e($c['account_email']) ?></div>
        <div class="small text-danger"><?= $e($c['last_error']) ?> — reconecte abaixo. As filas aguardam; nenhum dado se perde.</div>
      <?php else: ?>
        <div class="h5 mb-1"><span class="badge text-bg-secondary">Não conectada</span></div>
        <div class="small text-muted">Sincronização e planilha de logs ficam em espera. O sistema continua funcionando só com o banco.</div>
      <?php endif; ?>
    </div>
    <div class="d-flex flex-wrap gap-2">
      <?php if ($ok): ?><form method="post" action="<?= $e($baseUrl) ?>/admin/conta-tecnica/testar"><?= $csrf ?><button class="btn btn-outline-primary btn-sm">Testar</button></form><?php endif; ?>
      <?php if ($loginConfigurado): ?><form method="post" action="<?= $e($baseUrl) ?>/admin/conta-tecnica/conectar"><?= $csrf ?><button class="btn btn-primary btn-sm"><?= $c !== null ? 'Reconectar conta Google' : 'Conectar conta Google' ?></button></form><?php endif; ?>
    </div>
  </div>
</div></div>
<div class="card mb-3"><div class="card-body">
  <h2 class="h6">Como conectar a conta <?= $e($emailEsperado) ?></h2>
  <ol class="small mb-2">
    <li>No Google Cloud (projeto "Sistema CELEF") → APIs e serviços → <strong>Biblioteca</strong>: ative <strong>Google Sheets API</strong> e <strong>Google Drive API</strong>.</li>
    <li>O URI de redirecionamento é o mesmo do login e já está cadastrado: <code><?= $e($redirectUri) ?></code></li>
    <li>Clique em <strong>Conectar conta Google</strong>. Na tela do Google escolha <strong><?= $e($emailEsperado) ?></strong> (não a sua conta pessoal) e marque todas as permissões.</li>
    <li>Você volta para esta página com a conta conectada. Clique em <strong>Testar</strong>.</li>
  </ol>
  <div class="small text-muted">Permissões pedidas: <?php foreach ($escopos as $s): ?><code><?= $e(basename($s)) ?></code> <?php endforeach; ?>(ler e gravar planilhas; ler metadados do Drive para saber quem editou).</div>
</div></div>
<?php if ($ok): ?>
<div class="card border-danger mb-3"><div class="card-body">
  <h2 class="h6 text-danger">Revogar</h2>
  <p class="small text-muted">Revoga a autorização no Google e apaga o token cifrado. Use se a senha da conta técnica vazou ou se for trocar de conta.</p>
  <form method="post" action="<?= $e($baseUrl) ?>/admin/conta-tecnica/revogar" class="row g-2" data-confirm="Revogar a conta técnica? Sincronização e logs em planilha param até reconectar."><?= $csrf ?>
    <div class="col-md-8"><input class="form-control form-control-sm" name="motivo" placeholder="Motivo (mínimo 10 caracteres)" minlength="10" required></div>
    <div class="col-md-4"><button class="btn btn-outline-danger btn-sm w-100">Revogar conta técnica</button></div>
  </form>
</div></div>
<?php endif; ?>
<details class="card mb-3"><summary class="card-body py-2">Alternativa: Service Account do Google Cloud</summary><div class="card-body pt-0">
  <p class="small text-muted">Use só se o administrador do Workspace liberar compartilhamento com o e-mail <code>…@&lt;projeto&gt;.iam.gserviceaccount.com</code>. As planilhas passam a ser compartilhadas com esse e-mail em vez da conta <?= $e($emailEsperado) ?>. O arquivo JSON é lido no seu navegador; só o e-mail e a chave privada são enviados, e a chave é gravada cifrada.</p>
  <form method="post" action="<?= $e($baseUrl) ?>/admin/conta-tecnica/service-account" id="form-sa" data-confirm="Substituir a conta técnica atual por esta Service Account?"><?= $csrf ?>
    <input type="hidden" name="sa_email" id="sa_email"><input type="hidden" name="sa_key_b64" id="sa_key_b64">
    <div class="row g-2 align-items-center">
      <div class="col-md-8"><input class="form-control form-control-sm" type="file" id="sa_arquivo" accept="application/json,.json"></div>
      <div class="col-md-4"><button class="btn btn-outline-secondary btn-sm w-100" id="sa_enviar" disabled>Usar esta Service Account</button></div>
    </div>
    <div class="small mt-2" id="sa_status"></div>
  </form>
</div></details>
<h2 class="h6">Histórico</h2>
<div class="table-responsive"><table class="table table-sm">
  <thead><tr><th>Conta</th><th>Tipo</th><th>Situação</th><th>Conectada</th><th>Por</th><th>Revogada</th></tr></thead>
  <tbody>
  <?php foreach ($historico as $h): ?>
    <tr><td class="small"><?= $e($h['account_email']) ?></td><td class="small"><?= $h['kind'] === 'SERVICE_ACCOUNT' ? 'Service Account' : 'OAuth' ?></td>
      <td><span class="badge <?= $h['is_active'] && $h['status'] === 'CONNECTED' ? 'text-bg-success' : ($h['status'] === 'ERROR' ? 'text-bg-danger' : 'text-bg-secondary') ?>"><?= $e($h['status']) ?></span></td>
      <td class="small"><?= $h['connected_at'] ? $e(date('d/m/Y H:i', strtotime($h['connected_at']))) : '—' ?></td><td class="small"><?= $e($h['connected_by_email'] ?? '—') ?></td>
      <td class="small"><?= $h['revoked_at'] ? $e(date('d/m/Y H:i', strtotime($h['revoked_at']))) : '—' ?></td></tr>
  <?php endforeach; ?>
  <?php if ($historico === []): ?><tr><td colspan="6" class="text-muted">Nenhuma conexão ainda.</td></tr><?php endif; ?>
  </tbody>
</table></div>
