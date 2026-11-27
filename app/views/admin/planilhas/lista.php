<h1 class="h4 mb-3">Planilhas conectadas</h1>
<?php if (!$conectada): ?><div class="alert alert-warning small">A conta técnica ainda não está conectada (<a href="<?= $e($baseUrl) ?>/admin/conta-tecnica">Admin → Conta técnica</a>). Você pode cadastrar as planilhas, mas o teste de conexão só funciona depois.</div><?php endif; ?>
<div class="alert alert-info small">Cada planilha precisa estar compartilhada com <strong><?= $e($contaTecnica ?? $emailEsperado) ?></strong>: como <strong>Leitor</strong> a da Secretaria de Educação; como <strong>Editor</strong> as da escola. A planilha de logs é configurada em <a href="<?= $e($baseUrl) ?>/admin/planilha-logs">Planilha de logs</a>.</div>
<div class="table-responsive mb-4"><table class="table table-sm align-middle">
  <thead><tr><th>Nome</th><th>Papel</th><th>Sentido</th><th>Ano</th><th>Abas</th><th>Último teste</th><th>Sincronização</th></tr></thead>
  <tbody>
  <?php foreach ($planilhas as $p): ?>
    <tr><td><a href="<?= $e($baseUrl) ?>/admin/planilhas/<?= $e($p['id']) ?>"><?= $e($p['name']) ?></a></td>
      <td class="small"><?= $e($papeis[$p['sheet_role']] ?? $p['sheet_role']) ?></td><td class="small"><?= $e($sentidos[$p['direction']] ?? $p['direction']) ?></td>
      <td><?= $e($p['school_year'] ?? '—') ?></td><td><?= $e($p['abas']) ?></td>
      <td class="small"><?= $p['last_test_at'] ? $e(date('d/m H:i', strtotime($p['last_test_at']))) : 'nunca' ?></td>
      <td><?= $p['sync_enabled'] ? '<span class="badge text-bg-success">ligada</span>' : '<span class="badge text-bg-secondary">desligada</span>' ?></td></tr>
  <?php endforeach; ?>
  <?php if ($planilhas === []): ?><tr><td colspan="7" class="text-muted">Nenhuma planilha cadastrada.</td></tr><?php endif; ?>
  </tbody>
</table></div>
<div class="card"><div class="card-body">
  <h2 class="h6">Conectar planilha</h2>
  <form method="post" action="<?= $e($baseUrl) ?>/admin/planilhas" class="row g-3" data-planilha-form><?= $csrf ?>
    <div class="col-12">
      <label class="form-label" for="planilha_link">Link ou ID da planilha</label>
      <!-- sem atributo name de propósito: o link (URL) não é enviado; o script extrai o ID para o campo oculto -->
      <input class="form-control" id="planilha_link" data-planilha-link placeholder="Cole aqui o link da planilha (…/spreadsheets/d/XXXX/edit) ou só o ID" autocomplete="off" required>
      <input type="hidden" name="spreadsheet_id" data-planilha-id>
      <div class="form-text" data-planilha-status>O sistema usa apenas o identificador que fica entre <code>/d/</code> e <code>/edit</code>.</div>
    </div>
    <div class="col-md-5"><label class="form-label" for="name">Nome</label><input class="form-control" id="name" name="name" placeholder="ex.: CELEF • ALUNOS 2026" required maxlength="120"></div>
    <div class="col-md-4"><label class="form-label" for="sheet_role">Papel</label><select class="form-select" id="sheet_role" name="sheet_role"><?php foreach ($papeis as $k => $v): ?><option value="<?= $e($k) ?>" <?= $k === 'ESPELHO_ESCOLA' ? 'selected' : '' ?>><?= $e($v) ?></option><?php endforeach; ?></select></div>
    <div class="col-md-3"><label class="form-label" for="school_year">Ano letivo</label><input class="form-control" type="number" id="school_year" name="school_year" min="2020" max="2100" value="<?= $e(date('Y')) ?>"></div>
    <div class="col-12"><button class="btn btn-primary">Cadastrar</button> <span class="small text-muted ms-2">A planilha da Secretaria é cadastrada como somente leitura.</span></div>
  </form>
</div></div>
