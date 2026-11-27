<h1 class="h4 mb-3">Minhas sessões</h1>
<p class="text-muted small">Sessões abertas com a sua conta. Se não reconhecer alguma, encerre as outras e avise a direção.</p>
<form method="post" action="<?= $e($baseUrl) ?>/minhas-sessoes/encerrar-outras" class="mb-3" data-confirm="Encerrar todas as outras sessões?"><?= $csrf ?>
  <button class="btn btn-outline-danger btn-sm" type="submit">Encerrar as outras sessões</button>
</form>
<div class="table-responsive"><table class="table table-sm align-middle">
  <thead><tr><th>Início</th><th>Última atividade</th><th>IP</th><th>Navegador</th><th>Situação</th></tr></thead>
  <tbody>
  <?php foreach ($sessoes as $s): ?>
    <tr class="<?= $s['id'] === $atual ? 'table-primary' : '' ?>">
      <td><?= $e(date('d/m/Y H:i', strtotime($s['created_at']))) ?></td>
      <td><?= $e(date('d/m/Y H:i', strtotime($s['last_seen_at']))) ?></td>
      <td><?= $e($s['ip']) ?></td>
      <td class="small text-truncate" style="max-width:260px"><?= $e($s['user_agent']) ?></td>
      <td><?= $s['id'] === $atual ? '<span class="badge text-bg-primary">esta sessão</span>' : ($s['revoked_at'] ? '<span class="badge text-bg-secondary">encerrada (' . $e($s['revoke_reason']) . ')</span>' : '<span class="badge text-bg-success">ativa</span>') ?></td>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table></div>
