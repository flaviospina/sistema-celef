<div class="card shadow-sm">
  <div class="card-body p-4">
    <div class="text-muted small mb-1">Erro <?= $e($status) ?></div>
    <h1 class="h4 mb-3"><?= $e($titulo) ?></h1>
    <p class="mb-3"><?= $e($mensagem) ?></p>
    <p class="small text-muted mb-3">Código para suporte: <code><?= $e($codigo) ?></code></p>
    <?php if (!empty($detalhe)): ?>
      <pre class="small bg-light p-2 border rounded"><?= $e($detalhe) ?></pre>
    <?php endif; ?>
    <a class="btn btn-primary" href="<?= $e($baseUrl) ?>/">Voltar ao início</a>
  </div>
</div>
