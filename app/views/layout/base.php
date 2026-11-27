<?php /** layout principal (usuário logado ou páginas públicas) */ $usuario = $usuario ?? null; $can = $can ?? static fn(string $c): bool => false; ?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?= $e(($titulo ?? '') !== '' ? $titulo . ' · ' : '') ?><?= $e($appName) ?></title>
<link rel="icon" href="<?= $e($baseUrl) ?>/assets/img/marca/favicon.png">
<link rel="stylesheet" href="<?= $e($baseUrl) ?>/assets/vendor/bootstrap.min.css">
<link rel="stylesheet" href="<?= $e($baseUrl) ?>/assets/css/app.css?v=<?= $e(APP_VERSION) ?>">
</head>
<body class="d-flex flex-column min-vh-100">
<header class="celef-header">
  <nav class="navbar navbar-expand-md container-fluid px-3">
    <a class="navbar-brand d-flex align-items-center gap-2" href="<?= $e($baseUrl) ?>/">
      <img src="<?= $e($baseUrl) ?>/assets/img/marca/logo-branco.png" alt="" class="celef-logo" width="40" height="40">
      <span class="fw-semibold"><?= $e($appName) ?></span>
    </a>
    <?php if ($usuario !== null): ?>
    <button class="navbar-toggler" type="button" data-bs-toggle="collapse" data-bs-target="#menuTopo" aria-controls="menuTopo" aria-expanded="false" aria-label="Menu">
      <span class="navbar-toggler-icon"></span>
    </button>
    <div class="collapse navbar-collapse" id="menuTopo">
      <ul class="navbar-nav ms-auto align-items-md-center gap-md-2">
        <li class="nav-item"><a class="nav-link" href="<?= $e($baseUrl) ?>/">Início</a></li>
        <?php if (!empty($isAdmin)): ?><li class="nav-item"><a class="nav-link" href="<?= $e($baseUrl) ?>/admin">Admin</a></li><?php endif; ?>
        <li class="nav-item dropdown">
          <a class="nav-link dropdown-toggle" href="#" role="button" data-bs-toggle="dropdown" aria-expanded="false"><?= $e($usuario['full_name']) ?> <span class="badge bg-light text-dark ms-1"><?= $e($usuario['role_name'] ?? $usuario['role_code']) ?></span></a>
          <ul class="dropdown-menu dropdown-menu-end">
            <li><span class="dropdown-item-text small text-muted"><?= $e($usuario['email']) ?></span></li>
            <li><a class="dropdown-item" href="<?= $e($baseUrl) ?>/minhas-sessoes">Minhas sessões</a></li>
            <li><a class="dropdown-item" href="<?= $e($baseUrl) ?>/privacidade">Aviso de privacidade</a></li>
            <li><hr class="dropdown-divider"></li>
            <li><form method="post" action="<?= $e($baseUrl) ?>/logout"><?= $csrf ?><button class="dropdown-item" type="submit">Sair</button></form></li>
          </ul>
        </li>
      </ul>
    </div>
    <?php endif; ?>
  </nav>
</header>
<main class="container py-4 flex-grow-1">
  <?php foreach ($flashes as $f): ?>
    <div class="alert alert-<?= $e($f['tipo']) ?> alert-dismissible" role="alert">
      <?= $e($f['msg']) ?><button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Fechar"></button>
    </div>
  <?php endforeach; ?>
  <?= $conteudo ?>
</main>
<footer class="celef-footer text-center small py-3">
  CELEF – Centro de Estudos de Línguas do Ensino Fundamental · Secretaria Municipal de Educação de São Caetano do Sul
  · <a href="<?= $e($baseUrl) ?>/privacidade">Aviso de privacidade</a>
</footer>
<script nonce="<?= $e($nonce) ?>" src="<?= $e($baseUrl) ?>/assets/vendor/bootstrap.bundle.min.js"></script>
<script nonce="<?= $e($nonce) ?>" src="<?= $e($baseUrl) ?>/assets/js/app.js?v=<?= $e(APP_VERSION) ?>"></script>
</body>
</html>
