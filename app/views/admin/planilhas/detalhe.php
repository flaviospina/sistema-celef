<?php $p = $planilha; ?>
<div class="d-flex flex-wrap justify-content-between align-items-center mb-3 gap-2">
  <h1 class="h4 mb-0"><?= $e($p['name']) ?></h1>
  <div class="d-flex gap-2">
    <form method="post" action="<?= $e($baseUrl) ?>/admin/planilhas/<?= $e($p['id']) ?>/testar"><?= $csrf ?><button class="btn btn-primary btn-sm">Testar conexão</button></form>
    <a class="btn btn-outline-secondary btn-sm" href="<?= $e($baseUrl) ?>/admin/planilhas">Voltar</a>
  </div>
</div>
<?php if ($resultado !== null): ?>
  <div class="alert <?= $resultado['ok'] ? 'alert-success' : 'alert-danger' ?>"><?= $e($resultado['mensagem']) ?>
    <?php if (!empty($resultado['arquivo'])): $a = $resultado['arquivo']; ?>
      <div class="small mt-1">Dono: <?= $e($a['owner'] ?? '—') ?> · última edição: <?= $e($a['modified_at'] ? date('d/m/Y H:i', strtotime($a['modified_at'])) : '—') ?> por <?= $e($a['last_user_email'] ?? $a['last_user_name'] ?? '—') ?> · conta técnica pode editar: <?= $a['can_edit'] ? 'sim' : 'não' ?></div>
    <?php endif; ?>
  </div>
  <?php if ($resultado['abas'] !== []): ?>
  <div class="table-responsive mb-3"><table class="table table-sm align-middle">
    <thead><tr><th>Aba</th><th>Tipo sugerido</th><th>Linhas</th><th>Cabeçalho (linha 1)</th></tr></thead>
    <tbody><?php foreach ($resultado['abas'] as $a): ?><tr><td><?= $e($a['titulo']) ?></td><td><span class="badge text-bg-light"><?= $e($a['tipo']) ?></span></td><td><?= $e($a['linhas']) ?></td><td class="small"><?= $e(implode(' | ', array_filter($a['cabecalho'], static fn($h) => $h !== ''))) ?: '<span class="text-muted">vazio</span>' ?></td></tr><?php endforeach; ?></tbody>
  </table></div>
  <?php endif; ?>
<?php elseif ($p['last_test_at']): ?>
  <div class="alert alert-secondary small">Último teste em <?= $e(date('d/m/Y H:i', strtotime($p['last_test_at']))) ?>: <?= $e($p['last_test_result']) ?></div>
<?php else: ?>
  <div class="alert alert-info small">Compartilhe esta planilha com <strong><?= $e($contaTecnica) ?></strong> (<?= $p['sheet_role'] === 'FONTE_SECRETARIA' ? 'Leitor' : 'Editor' ?>) e clique em "Testar conexão".</div>
<?php endif; ?>
<div class="card mb-3"><div class="card-body">
  <h2 class="h6">Dados da conexão</h2>
  <form method="post" action="<?= $e($baseUrl) ?>/admin/planilhas/<?= $e($p['id']) ?>" class="row g-3"><?= $csrf ?>
    <div class="col-md-6"><label class="form-label" for="name">Nome</label><input class="form-control" id="name" name="name" value="<?= $e($p['name']) ?>" required maxlength="120"></div>
    <div class="col-md-6"><label class="form-label">ID da planilha</label><input class="form-control" value="<?= $e($p['spreadsheet_id']) ?>" readonly></div>
    <div class="col-md-4"><label class="form-label" for="sheet_role">Papel</label><select class="form-select" id="sheet_role" name="sheet_role"><?php foreach ($papeis as $k => $v): ?><option value="<?= $e($k) ?>" <?= $p['sheet_role'] === $k ? 'selected' : '' ?>><?= $e($v) ?></option><?php endforeach; ?></select></div>
    <div class="col-md-4"><label class="form-label" for="direction">Sentido</label><select class="form-select" id="direction" name="direction"><?php foreach ($sentidos as $k => $v): ?><option value="<?= $e($k) ?>" <?= $p['direction'] === $k ? 'selected' : '' ?>><?= $e($v) ?></option><?php endforeach; ?></select></div>
    <div class="col-md-4"><label class="form-label" for="school_year">Ano letivo</label><input class="form-control" type="number" id="school_year" name="school_year" min="2020" max="2100" value="<?= $e($p['school_year']) ?>"></div>
    <?php if ($isSuperAdmin): ?><div class="col-12"><label class="form-label small" for="confirmar">Só para permitir <strong>escrita na planilha da Secretaria</strong>: digite SIM</label><input class="form-control form-control-sm" id="confirmar" name="confirmar_escrita_secretaria" maxlength="3" autocomplete="off" style="max-width:8rem"></div><?php endif; ?>
    <div class="col-12"><button class="btn btn-primary btn-sm">Salvar</button>
      <span class="small text-muted ms-2">Escrita <?= $p['write_enabled'] ? 'permitida' : 'bloqueada (somente leitura)' ?> · sincronização <?= $p['sync_enabled'] ? 'ligada' : 'desligada (liga após o mapeamento de colunas, Fase 5)' ?> · dono: <?= $e($p['owner_email'] ?? 'desconhecido') ?></span></div>
  </form>
</div></div>
<h2 class="h6">Abas registradas</h2>
<div class="table-responsive mb-3"><table class="table table-sm">
  <thead><tr><th>Aba</th><th>Tipo</th><th>Turma vinculada</th><th>Chave do aluno</th></tr></thead>
  <tbody>
  <?php foreach ($abas as $a): ?><tr><td><?= $e($a['tab_title']) ?></td><td><span class="badge text-bg-light"><?= $e($a['tab_kind']) ?></span></td><td><?= $e($a['class_code'] ?? '—') ?></td><td class="small"><?= $a['key_field'] === 'ra' ? 'R.A.' : 'e-mail @scseduca' ?></td></tr><?php endforeach; ?>
  <?php if ($abas === []): ?><tr><td colspan="4" class="text-muted">Nenhuma aba registrada: faça o teste de conexão.</td></tr><?php endif; ?>
  </tbody>
</table></div>
<div class="card border-danger"><div class="card-body">
  <h2 class="h6 text-danger">Desconectar do sistema</h2>
  <p class="small text-muted">Exclusão lógica: a planilha deixa de ser lida e escrita pelo sistema. O arquivo no Google não é alterado.</p>
  <form method="post" action="<?= $e($baseUrl) ?>/admin/planilhas/<?= $e($p['id']) ?>/excluir" class="row g-2" data-confirm="Desconectar esta planilha do sistema?"><?= $csrf ?>
    <div class="col-md-8"><input class="form-control form-control-sm" name="motivo" placeholder="Motivo (mínimo 10 caracteres)" minlength="10" required></div>
    <div class="col-md-4"><button class="btn btn-outline-danger btn-sm w-100">Desconectar</button></div>
  </form>
</div></div>
