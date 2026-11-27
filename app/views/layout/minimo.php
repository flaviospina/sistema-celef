<?php /** layout sem navegação: erros, status, instalação */ ?>
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="robots" content="noindex, nofollow">
<title><?= $e($titulo ?? '') ?> · <?= $e($appName) ?></title>
<link rel="stylesheet" href="<?= $e($baseUrl) ?>/assets/vendor/bootstrap.min.css">
<link rel="stylesheet" href="<?= $e($baseUrl) ?>/assets/css/app.css?v=<?= $e(APP_VERSION) ?>">
</head>
<body class="celef-bg-minimo d-flex align-items-center min-vh-100">
<main class="container py-4">
  <div class="mx-auto celef-card-min">
    <?= $conteudo ?>
  </div>
</main>
</body>
</html>
