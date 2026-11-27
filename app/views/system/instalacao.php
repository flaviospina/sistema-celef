<div class="card shadow-sm">
  <div class="card-body p-4">
    <h1 class="h4 mb-3">Instalação — chaves de criptografia</h1>
    <div class="alert alert-warning">
      Estas chaves foram geradas agora e <strong>não ficaram gravadas em lugar nenhum</strong>. Copie as três linhas para o
      arquivo <code>.env</code> (fora de <code>public/</code>), salve e recarregue esta página: ela passará a responder
      "não encontrado", que é o comportamento esperado. <strong>Guarde uma cópia das chaves fora do servidor</strong>: sem
      elas, os dados cifrados e os backups são irrecuperáveis.
    </div>
    <pre class="bg-light border rounded p-3 small user-select-all">APP_KEY_VERSION=1
APP_KEY_V1=<?= $e($appKey) ?>

BLIND_INDEX_KEY=<?= $e($blindKey) ?>

STATUS_TOKEN=<?= $e($statusToken) ?></pre>
    <p class="small text-muted">Se recarregar antes de salvar, novas chaves serão geradas (as anteriores deixam de valer, mas nada foi cifrado ainda).</p>
    <h2 class="h6 mt-4">Verificações do ambiente</h2>
    <table class="table table-sm align-middle mb-0">
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
  </div>
</div>
