<div class="d-flex flex-wrap justify-content-between align-items-center mb-3 gap-2">
  <h1 class="h4 mb-0">Auditoria</h1>
  <?php if ($can('auditoria.verificar')): ?><form method="post" action="<?= $e($baseUrl) ?>/admin/auditoria/verificar"><?= $csrf ?><button class="btn btn-outline-primary btn-sm">Verificar cadeia de hash agora</button></form><?php endif; ?>
</div>
<?php if ($ultimaVerificacao): ?>
  <div class="alert <?= $ultimaVerificacao['result'] === 'OK' && $ultimaVerificacao['triggers_ok'] ? 'alert-success' : 'alert-danger' ?> py-2 small">
    Última verificação: <?= $e(date('d/m/Y H:i', strtotime($ultimaVerificacao['started_at']))) ?> · <?= $e($ultimaVerificacao['result']) ?> · <?= $e($ultimaVerificacao['rows_checked']) ?> linhas · proteções do banco <?= $ultimaVerificacao['triggers_ok'] ? 'ativas' : 'AUSENTES' ?><?= $ultimaVerificacao['detail'] ? ' · ' . $e($ultimaVerificacao['detail']) : '' ?>
  </div>
<?php endif; ?>
<form class="row g-2 mb-3" method="get" action="<?= $e($baseUrl) ?>/admin/auditoria">
  <div class="col-md-3"><input class="form-control form-control-sm" name="usuario" value="<?= $e($filtros['usuario']) ?>" placeholder="Usuário (e-mail)"></div>
  <div class="col-md-2"><select class="form-select form-select-sm" name="acao"><option value="">Todas as ações</option><?php foreach ($acoes as $a): ?><option <?= $filtros['acao'] === $a ? 'selected' : '' ?>><?= $e($a) ?></option><?php endforeach; ?></select></div>
  <div class="col-md-2"><input class="form-control form-control-sm" name="entidade" value="<?= $e($filtros['entidade']) ?>" placeholder="Entidade (ex.: students)"></div>
  <div class="col-md-1"><input class="form-control form-control-sm" name="entity_id" value="<?= $e($filtros['entity_id']) ?>" placeholder="ID"></div>
  <div class="col-md-2"><input class="form-control form-control-sm" type="date" name="de" value="<?= $e($filtros['de']) ?>"></div>
  <div class="col-md-2"><div class="input-group input-group-sm"><input class="form-control" type="date" name="ate" value="<?= $e($filtros['ate']) ?>"><button class="btn btn-outline-primary">Buscar</button></div></div>
</form>
<div class="table-responsive"><table class="table table-sm align-middle">
  <thead><tr><th>#</th><th>Quando (UTC)</th><th>Usuário</th><th>Ação</th><th>Entidade</th><th>Resumo / alteração</th><th>IP</th><th>Origem</th><th>Hash</th></tr></thead>
  <tbody>
  <?php foreach ($linhas as $l): ?>
    <tr>
      <td class="small"><?= $e($l['id']) ?></td>
      <td class="small text-nowrap"><?= $e(substr($l['occurred_at'], 0, 19)) ?></td>
      <td class="small"><?= $e($l['user_email'] ?? '—') ?><?= $l['role_code'] ? '<br><span class="text-muted">' . $e($l['role_code']) . '</span>' : '' ?></td>
      <td><span class="badge text-bg-light"><?= $e($l['action']) ?></span></td>
      <td class="small"><?= $e($l['entity']) ?><?= $l['entity_id'] !== null ? ' #' . $e($l['entity_id']) : '' ?></td>
      <td class="small"><?= $e($l['summary']) ?><?= $l['diff_json'] ? '<pre class="celef-diff mb-0 mt-1">' . $e(json_encode(json_decode($l['diff_json'], true), JSON_PRETTY_PRINT | JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES)) . '</pre>' : '' ?></td>
      <td class="small"><?= $e($l['ip']) ?></td>
      <td class="small"><?= $e($l['origin']) ?></td>
      <td class="celef-hash" title="<?= $e($l['hash']) ?>"><?= $e(substr($l['hash'], 0, 10)) ?>…</td>
    </tr>
  <?php endforeach; ?>
  <?php if ($linhas === []): ?><tr><td colspan="9" class="text-muted">Nenhuma linha com esses filtros.</td></tr><?php endif; ?>
  </tbody>
</table></div>
<?php $paginas = (int) ceil($total / $porPagina); if ($paginas > 1): ?>
<nav><ul class="pagination pagination-sm flex-wrap">
  <?php $ini = max(1, $pagina - 5); $fim = min($paginas, $pagina + 5); for ($p = $ini; $p <= $fim; $p++): ?>
    <li class="page-item <?= $p === $pagina ? 'active' : '' ?>"><a class="page-link" href="<?= $e($baseUrl) ?>/admin/auditoria?<?= $e(http_build_query(array_filter($filtros) + ['pagina' => $p])) ?>"><?= $p ?></a></li>
  <?php endfor; ?>
</ul></nav>
<?php endif; ?>
<p class="small text-muted"><?= $e($total) ?> linha(s).</p>
<?php if ($ancoras !== []): ?>
<h2 class="h6 mt-4">Âncoras diárias</h2>
<ul class="list-unstyled small">
  <?php foreach ($ancoras as $a): ?><li><?= $e(date('d/m/Y', strtotime($a['anchor_date']))) ?> · <?= $e($a['row_count']) ?> linhas · <span class="celef-hash"><?= $e($a['last_hash']) ?></span></li><?php endforeach; ?>
</ul>
<?php endif; ?>
