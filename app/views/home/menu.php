<div class="d-flex flex-wrap align-items-center justify-content-between mb-3">
  <h1 class="h4 mb-0">Olá, <?= $e(explode(' ', $usuario['full_name'])[0]) ?></h1>
  <span class="text-muted small"><?= $e($usuario['role_name']) ?></span>
</div>
<div class="row g-3">
  <?php foreach ($modulos as $m): ?>
    <div class="col-6 col-md-4 col-xl-3">
      <?php if ($m['disponivel']): ?>
        <a class="card celef-modulo h-100 text-decoration-none" href="<?= $e($baseUrl . $m['path']) ?>">
          <div class="card-body text-center"><div class="celef-modulo-icone"><?= $m['icon'] ?></div><div class="fw-semibold"><?= $e($m['label']) ?></div></div>
        </a>
      <?php else: ?>
        <div class="card celef-modulo h-100 opacity-50">
          <div class="card-body text-center"><div class="celef-modulo-icone"><?= $m['icon'] ?></div><div class="fw-semibold"><?= $e($m['label']) ?></div><span class="badge bg-secondary">fase <?= $e($m['phase']) ?></span></div>
        </div>
      <?php endif; ?>
    </div>
  <?php endforeach; ?>
  <?php if ($modulos === []): ?>
    <div class="col-12"><div class="alert alert-warning">Seu perfil ainda não tem módulos liberados. Procure a direção.</div></div>
  <?php endif; ?>
</div>
