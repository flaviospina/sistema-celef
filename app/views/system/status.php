<div class="card shadow-sm">
  <div class="card-body p-4">
    <h1 class="h4 mb-3"><?= $e($titulo) ?></h1>
    <?php if ($allOk): ?>
      <div class="alert alert-success mb-3">Sistema operacional.</div>
    <?php else: ?>
      <div class="alert alert-danger mb-3">Há itens com problema. <?= $checks === null ? 'Use o token de status para ver os detalhes.' : '' ?></div>
    <?php endif; ?>
    <?php if ($checks !== null): ?>
      <table class="table table-sm align-middle mb-0">
        <thead><tr><th>Item</th><th>Situação</th><th>Detalhe</th></tr></thead>
        <tbody>
        <?php foreach ($checks as $c): ?>
          <tr>
            <td><?= $e($c['item']) ?></td>
            <td><span class="badge <?= $c['ok'] ? 'text-bg-success' : 'text-bg-danger' ?>"><?= $c['ok'] ? 'OK' : 'ATENÇÃO' ?></span></td>
            <td class="small"><?= $e($c['info']) ?></td>
          </tr>
        <?php endforeach; ?>
        </tbody>
      </table>
    <?php endif; ?>
  </div>
</div>
