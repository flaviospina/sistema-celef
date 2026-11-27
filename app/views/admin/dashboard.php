<h1 class="h4 mb-3">Painel administrativo</h1>
<?php foreach ($avisos as $a): ?><div class="alert alert-warning py-2 small"><?= $e($a) ?></div><?php endforeach; ?>
<div class="row g-3 mb-4">
  <?php $cards = [
    ['Usuários ativos', $stats['usuarios_ativos'], '/admin/usuarios'], ['Sessões ativas', $stats['sessoes_ativas'], '/admin/seguranca'],
    ['Eventos de segurança (24 h)', $stats['eventos_24h'], '/admin/seguranca'], ['Críticos sem ciência (7 d)', $stats['criticos_7d'], '/admin/seguranca?periodo=7d'],
    ['Logins negados (24 h)', $stats['logins_negados_24h'], '/admin/seguranca'], ['Linhas de auditoria', $stats['auditoria_total'], '/admin/auditoria'],
    ['Alertas por e-mail pendentes', $stats['alertas_pendentes'], '/admin/seguranca'], ['Linhas pendentes p/ planilha de logs', $stats['logs_planilha_pend'], '/admin/planilha-logs'],
  ]; foreach ($cards as [$t, $v, $r]): ?>
    <div class="col-6 col-md-3"><a class="card text-decoration-none h-100" href="<?= $e($baseUrl . $r) ?>"><div class="card-body"><div class="small text-muted"><?= $e($t) ?></div><div class="h3 mb-0"><?= $e($v) ?></div></div></a></div>
  <?php endforeach; ?>
</div>
<div class="row g-3">
  <div class="col-md-6"><div class="card h-100"><div class="card-body">
    <h2 class="h6">Última verificação da cadeia de auditoria</h2>
    <?php if ($ultimaVerificacao): ?>
      <p class="mb-1"><?= $e(date('d/m/Y H:i', strtotime($ultimaVerificacao['started_at']))) ?> · <span class="badge <?= $ultimaVerificacao['result'] === 'OK' ? 'text-bg-success' : 'text-bg-danger' ?>"><?= $e($ultimaVerificacao['result']) ?></span> · <?= $e($ultimaVerificacao['rows_checked']) ?> linhas · proteções <?= $ultimaVerificacao['triggers_ok'] ? 'ok' : '<strong class="text-danger">AUSENTES</strong>' ?></p>
    <?php else: ?><p class="text-muted mb-1">Nenhuma ainda. Configure o cron <code>verify_audit.php</code> ou verifique em Auditoria.</p><?php endif; ?>
    <a class="small" href="<?= $e($baseUrl) ?>/admin/auditoria">Ir para Auditoria</a>
  </div></div></div>
  <div class="col-md-6"><div class="card h-100"><div class="card-body">
    <h2 class="h6">Última âncora diária</h2>
    <?php if ($ultimaAncora): ?>
      <p class="mb-1"><?= $e(date('d/m/Y', strtotime($ultimaAncora['anchor_date']))) ?> · <?= $e($ultimaAncora['row_count']) ?> linhas</p>
      <div class="celef-hash text-break"><?= $e($ultimaAncora['last_hash']) ?></div>
    <?php else: ?><p class="text-muted mb-0">Nenhuma âncora gravada ainda.</p><?php endif; ?>
  </div></div></div>
</div>
