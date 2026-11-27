<h1 class="h4 mb-3">Planilha de logs e segurança</h1>
<?php if ($planilha === null): ?>
  <div class="alert alert-warning">Nenhuma planilha de logs configurada. O sistema continua funcionando e registrando tudo no banco; os registros entram na fila e vão para a planilha quando ela for definida.</div>
<?php endif; ?>
<?php if (!$conectada): ?><div class="alert alert-warning small">A conta técnica não está conectada (<a href="<?= $e($baseUrl) ?>/admin/conta-tecnica">Admin → Conta técnica</a>). A fila aguarda.</div><?php endif; ?>
<div class="row g-3 mb-3">
  <?php foreach ([['Na fila', $fila['pendentes']], ['Com falha (nova tentativa agendada)', $fila['falhas']], ['Enviadas', $fila['enviadas']]] as [$t, $v]): ?>
    <div class="col-md-4"><div class="card h-100"><div class="card-body"><div class="small text-muted"><?= $e($t) ?></div><div class="h3 mb-0"><?= $e($v) ?></div></div></div></div>
  <?php endforeach; ?>
</div>
<p class="small text-muted">
  <?= $fila['mais_antiga'] ? 'Linha mais antiga na fila: ' . $e(date('d/m/Y H:i', strtotime($fila['mais_antiga']))) . ' · ' : '' ?>
  <?= $fila['ultimo_envio'] ? 'Último envio: ' . $e(date('d/m/Y H:i', strtotime($fila['ultimo_envio']))) . ' · ' : '' ?>
  <?= $ultimoCron ? 'Último cron: ' . $e(date('d/m/Y H:i', strtotime($ultimoCron['started_at']))) . ' (' . $e($ultimoCron['status']) . ')' : 'Cron flush_sheet_log.php ainda não executou' ?>
  <?= $fila['ultimo_erro'] ? '<br><span class="text-danger">Último erro: ' . $e($fila['ultimo_erro']) . '</span>' : '' ?>
</p>
<div class="card mb-3"><div class="card-body">
  <h2 class="h6">Planilha</h2>
  <?php if ($planilha !== null): ?>
    <p class="small mb-2">ID: <code><?= $e($planilha['spreadsheet_id']) ?></code><?= $planilha['last_test_at'] ? ' · último teste em ' . $e(date('d/m/Y H:i', strtotime($planilha['last_test_at']))) . ': ' . $e($planilha['last_test_result']) : '' ?></p>
    <div class="d-flex flex-wrap gap-2 mb-3">
      <form method="post" action="<?= $e($baseUrl) ?>/admin/planilha-logs/testar"><?= $csrf ?><button class="btn btn-primary btn-sm">Testar escrita</button></form>
      <form method="post" action="<?= $e($baseUrl) ?>/admin/planilha-logs/enviar"><?= $csrf ?><button class="btn btn-outline-primary btn-sm">Enviar fila agora</button></form>
      <?php if ($can('auditoria.conferir_planilha')): ?><form method="post" action="<?= $e($baseUrl) ?>/admin/planilha-logs/conferir"><?= $csrf ?><button class="btn btn-outline-secondary btn-sm">Conferir planilha de logs × banco</button></form><?php endif; ?>
    </div>
  <?php endif; ?>
  <form method="post" action="<?= $e($baseUrl) ?>/admin/planilha-logs" class="row g-2" data-planilha-form <?= $planilha !== null ? 'data-confirm="Trocar a planilha de logs? A atual deixa de receber registros."' : '' ?>><?= $csrf ?>
    <div class="col-md-9">
      <input class="form-control form-control-sm" data-planilha-link placeholder="<?= $planilha === null ? 'Cole o link ou ID da planilha de logs' : 'Para trocar: cole o link ou ID da nova planilha' ?>" autocomplete="off" required>
      <input type="hidden" name="spreadsheet_id" data-planilha-id>
      <div class="form-text" data-planilha-status>Crie uma planilha vazia logado como <?= $e($contaTecnica) ?> (ou compartilhe com essa conta como Editor). O sistema cria as abas sozinho.</div>
    </div>
    <div class="col-md-3"><button class="btn btn-outline-primary btn-sm w-100"><?= $planilha === null ? 'Definir planilha de logs' : 'Trocar planilha' ?></button></div>
  </form>
</div></div>
<?php if ($conferencia !== null): $t = $conferencia['totais']; ?>
<div class="card mb-3 <?= $conferencia['ok'] ? 'border-success' : 'border-danger' ?>"><div class="card-body">
  <h2 class="h6">Resultado da conferência</h2>
  <?php if ($conferencia['ok']): ?>
    <p class="text-success mb-0"><?= $e($conferencia['conferidas']) ?> linha(s) conferida(s): a planilha de logs corresponde exatamente ao banco.</p>
  <?php else: ?>
    <p class="text-danger"><?= $e($conferencia['conferidas']) ?> linha(s) conferida(s). Divergências: <?= $e($t['apagadas']) ?> apagada(s), <?= $e($t['alteradas']) ?> alterada(s), <?= $e($t['estranhas']) ?> estranha(s). O banco permanece íntegro e os administradores foram alertados.</p>
    <?php foreach ($conferencia['apagadas'] as $r): ?><div class="small">🗑 <strong><?= $e($r['aba']) ?></strong> linha original <?= $e($r['linha_original'] ?? '?') ?> (auditoria #<?= $e($r['audit_log_id']) ?>): <?= $e($r['resumo']) ?></div><?php endforeach; ?>
    <?php foreach ($conferencia['alteradas'] as $r): ?><div class="small">✏️ <strong><?= $e($r['aba']) ?></strong> linha <?= $e($r['linha']) ?> (auditoria #<?= $e($r['audit_log_id']) ?>): <?php foreach ($r['diferencas'] as $col => $d): ?><?= $e($col) ?>: banco "<?= $e($d['banco']) ?>" × planilha "<?= $e($d['planilha']) ?>"; <?php endforeach; ?></div><?php endforeach; ?>
    <?php foreach ($conferencia['estranhas'] as $r): ?><div class="small">❓ <strong><?= $e($r['aba']) ?></strong> linha <?= $e($r['linha']) ?>: não existe no banco (<?= $e($r['resumo']) ?>)</div><?php endforeach; ?>
  <?php endif; ?>
</div></div>
<?php endif; ?>
<div class="card"><div class="card-body small">
  <h2 class="h6">Como funciona</h2>
  <ul class="mb-0">
    <li>Abas criadas automaticamente, com cabeçalho congelado e protegidas: <?= $e(implode(', ', $abas)) ?>.</li>
    <li>Cada linha leva o <strong>hash</strong> do registro correspondente na auditoria. A conferência detecta linhas apagadas ou alteradas na planilha.</li>
    <li>A planilha nunca recebe CPF, RG, endereço, telefone ou dados de saúde.</li>
    <li>Acesso recomendado: <strong>Editor só a conta técnica</strong>; Leitor para a direção e o Super Administrador; ninguém mais.</li>
  </ul>
</div></div>
