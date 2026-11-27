<?php /** layout da tela de login / reautenticação / aceite: fachada ao fundo + logo */ ?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?= $e($titulo ?? '') ?> · <?= $e($appName) ?></title>
<link rel="icon" href="<?= $e($baseUrl) ?>/assets/img/marca/favicon.png">
<link rel="stylesheet" href="<?= $e($baseUrl) ?>/assets/vendor/bootstrap.min.css">
<link rel="stylesheet" href="<?= $e($baseUrl) ?>/assets/css/app.css?v=<?= $e(APP_VERSION) ?>">
</head>
<body class="celef-bg-login d-flex align-items-center min-vh-100">
<main class="container py-4">
  <div class="mx-auto celef-card-login">
    <?php foreach ($flashes as $f): ?>
      <div class="alert alert-<?= $e($f['tipo']) ?>" role="alert"><?= $e($f['msg']) ?></div>
    <?php endforeach; ?>
    <?= $conteudo ?>
    <p class="text-center small text-white-50 mt-3 mb-0">CELEF · Secretaria Municipal de Educação de São Caetano do Sul</p>
  </div>
</main>
<script nonce="<?= $e($nonce) ?>" src="<?= $e($baseUrl) ?>/assets/vendor/bootstrap.bundle.min.js"></script>
</body>
</html>
