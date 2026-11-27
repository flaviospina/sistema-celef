<div class="card shadow">
  <div class="card-body p-4 p-md-5 text-center">
    <img src="<?= $e($baseUrl) ?>/assets/img/marca/logo.png" alt="Logo do CELEF" class="celef-logo-grande mb-3" width="110" height="110">
    <h1 class="h4 mb-1">Sistema de Gestão Escolar CELEF</h1>
    <p class="text-muted mb-4">Entre com a sua conta institucional <strong>@<?= $e($dominio) ?></strong>. Contas pessoais ou compartilhadas não têm acesso.</p>
    <?php if ($motivoSaida): ?>
      <div class="alert alert-warning small">Sua sessão anterior foi encerrada (<?= $e($motivoSaida) ?>). Entre novamente.</div>
    <?php endif; ?>
    <?php if ($configurado): ?>
      <form method="post" action="<?= $e($baseUrl) ?>/login/google">
        <?= $csrf ?>
        <button type="submit" class="btn btn-primary btn-lg w-100 d-flex align-items-center justify-content-center gap-2">
          <svg width="20" height="20" viewBox="0 0 48 48" aria-hidden="true"><path fill="#FFC107" d="M43.6 20.5H42V20H24v8h11.3C33.7 32.7 29.2 36 24 36c-6.6 0-12-5.4-12-12s5.4-12 12-12c3.1 0 5.8 1.2 7.9 3l5.7-5.7C34.1 6.1 29.3 4 24 4 13 4 4 13 4 24s9 20 20 20 20-9 20-20c0-1.2-.1-2.4-.4-3.5z"/><path fill="#FF3D00" d="M6.3 14.7l6.6 4.8C14.7 15.1 19 12 24 12c3.1 0 5.8 1.2 7.9 3l5.7-5.7C34.1 6.1 29.3 4 24 4 16.3 4 9.7 8.3 6.3 14.7z"/><path fill="#4CAF50" d="M24 44c5.2 0 9.9-2 13.4-5.2l-6.2-5.2C29.2 35.1 26.7 36 24 36c-5.2 0-9.6-3.3-11.3-8l-6.5 5C9.5 39.6 16.2 44 24 44z"/><path fill="#1976D2" d="M43.6 20.5H42V20H24v8h11.3c-.8 2.3-2.3 4.3-4.1 5.6l6.2 5.2C40.9 35.4 44 30.2 44 24c0-1.2-.1-2.4-.4-3.5z"/></svg>
          Entrar com Google
        </button>
      </form>
    <?php else: ?>
      <div class="alert alert-secondary small mb-0">O login com Google ainda não foi configurado pelo administrador.</div>
    <?php endif; ?>
    <p class="small text-muted mt-4 mb-0">Todo acesso é registrado e vinculado à sua conta. <a href="<?= $e($baseUrl) ?>/privacidade">Aviso de privacidade</a></p>
  </div>
</div>
