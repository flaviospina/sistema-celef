<div class="card shadow">
  <div class="card-body p-4 text-center">
    <h1 class="h5 mb-2">Confirme sua identidade</h1>
    <p class="text-muted">Por segurança, esta área exige que você confirme a sua conta Google novamente. Você voltará para a página que estava abrindo.</p>
    <form method="post" action="<?= $e($baseUrl) ?>/reauth"><?= $csrf ?>
      <button type="submit" class="btn btn-primary">Confirmar no Google</button>
      <a class="btn btn-link" href="<?= $e($baseUrl) ?>/">Voltar ao início</a>
    </form>
  </div>
</div>
