<div class="d-flex flex-wrap justify-content-between align-items-center mb-3 gap-2">
  <h1 class="h4 mb-0">Segurança</h1>
  <div class="btn-group btn-group-sm">
    <a class="btn btn-outline-secondary <?= $periodo === 1 ? 'active' : '' ?>" href="<?= $e($baseUrl) ?>/admin/seguranca">Últimas 24 h</a>
    <a class="btn btn-outline-secondary <?= $periodo === 7 ? 'active' : '' ?>" href="<?= $e($baseUrl) ?>/admin/seguranca?periodo=7d">7 dias</a>
  </div>
</div>
<h2 class="h6">Eventos</h2>
<div class="table-responsive mb-4"><table class="table table-sm align-middle">
  <thead><tr><th>Quando</th><th>Gravidade</th><th>Tipo</th><th>Usuário</th><th>Detalhe</th><th></th></tr></thead>
  <tbody>
  <?php foreach ($eventos as $ev): ?>
    <tr class="<?= $ev['severity'] === 'CRITICO' ? 'table-danger' : ($ev['severity'] === 'AVISO' ? 'table-warning' : '') ?>">
      <td class="small text-nowrap"><?= $e(date('d/m H:i:s', strtotime($ev['occurred_at']))) ?></td>
      <td><span class="badge <?= $ev['severity'] === 'CRITICO' ? 'text-bg-danger' : ($ev['severity'] === 'AVISO' ? 'text-bg-warning' : 'text-bg-secondary') ?>"><?= $e($ev['severity']) ?></span></td>
      <td class="small"><?= $e($ev['kind']) ?></td>
      <td class="small"><?= $e($ev['user_email'] ?? '—') ?></td>
      <td><pre class="celef-diff mb-0"><?= $e($ev['detail_json']) ?></pre><?= $ev['entity'] ? '<span class="small text-muted">' . $e($ev['entity']) . ' #' . $e($ev['entity_id']) . '</span>' : '' ?></td>
      <td><?php if ($ev['acknowledged_at'] === null): ?><form method="post" action="<?= $e($baseUrl) ?>/admin/seguranca/eventos/<?= $e($ev['id']) ?>/ciente"><?= $csrf ?><button class="btn btn-link btn-sm p-0">ciente</button></form><?php else: ?><span class="small text-muted">ciente</span><?php endif; ?></td>
    </tr>
  <?php endforeach; ?>
  <?php if ($eventos === []): ?><tr><td colspan="6" class="text-muted">Nenhum evento no período.</td></tr><?php endif; ?>
  </tbody>
</table></div>
<h2 class="h6">Sessões ativas (todos os usuários)</h2>
<div class="table-responsive mb-4"><table class="table table-sm align-middle">
  <thead><tr><th>Usuário</th><th>Início</th><th>Última atividade</th><th>IP</th><th>Navegador</th><th></th></tr></thead>
  <tbody>
  <?php foreach ($sessoes as $s): ?>
    <tr class="<?= $s['id'] === $sessaoAtual ? 'table-primary' : '' ?>">
      <td class="small"><?= $e($s['full_name']) ?><br><span class="text-muted"><?= $e($s['email']) ?></span></td>
      <td class="small"><?= $e(date('d/m H:i', strtotime($s['created_at']))) ?></td>
      <td class="small"><?= $e(date('d/m H:i', strtotime($s['last_seen_at']))) ?></td>
      <td class="small"><?= $e($s['ip']) ?></td>
      <td class="small text-truncate" style="max-width:220px"><?= $e($s['user_agent']) ?></td>
      <td><?php if ($s['id'] !== $sessaoAtual): ?><form method="post" action="<?= $e($baseUrl) ?>/admin/seguranca/sessoes/<?= $e($s['id']) ?>/encerrar" data-confirm="Encerrar a sessão de <?= $e($s['email']) ?>?"><?= $csrf ?><button class="btn btn-outline-danger btn-sm">Encerrar</button></form><?php else: ?><span class="badge text-bg-primary">você</span><?php endif; ?></td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table></div>
<h2 class="h6">Logins negados</h2>
<div class="table-responsive mb-4"><table class="table table-sm">
  <thead><tr><th>Quando</th><th>E-mail</th><th>IP</th><th>Motivo</th><th>Detalhe</th></tr></thead>
  <tbody>
  <?php foreach ($negados as $n): ?><tr><td class="small"><?= $e(date('d/m H:i', strtotime($n['occurred_at']))) ?></td><td class="small"><?= $e($n['email'] ?? '—') ?></td><td class="small"><?= $e($n['ip']) ?></td><td><span class="badge text-bg-secondary"><?= $e($n['outcome']) ?></span></td><td class="small"><?= $e($n['detail']) ?></td></tr><?php endforeach; ?>
  <?php if ($negados === []): ?><tr><td colspan="5" class="text-muted">Nenhum login negado no período.</td></tr><?php endif; ?>
  </tbody>
</table></div>
<h2 class="h6">Fila de e-mails de alerta</h2>
<div class="table-responsive"><table class="table table-sm">
  <thead><tr><th>Criado</th><th>Assunto</th><th>Situação</th><th>Tentativas</th><th>Erro</th></tr></thead>
  <tbody>
  <?php foreach ($alertas as $a): ?><tr><td class="small"><?= $e(date('d/m H:i', strtotime($a['created_at']))) ?></td><td class="small"><?= $e($a['subject']) ?></td><td><span class="badge <?= $a['status'] === 'SENT' ? 'text-bg-success' : ($a['status'] === 'FAILED' ? 'text-bg-danger' : 'text-bg-warning') ?>"><?= $e($a['status']) ?></span></td><td><?= $e($a['attempts']) ?></td><td class="small"><?= $e($a['last_error']) ?></td></tr><?php endforeach; ?>
  </tbody>
</table></div>
<p class="small text-muted">O envio dos e-mails entra na Fase 10; até lá a fila é mantida e nada se perde.</p>
