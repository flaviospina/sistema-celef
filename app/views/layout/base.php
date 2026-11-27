<?php /** @var callable $e @var string $nonce @var string $baseUrl @var string $appName @var string $conteudo @var array $flashes */ ?>
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
