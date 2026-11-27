<h1 class="h4 mb-2">Perfis e permissões</h1>
<p class="text-muted small">Marque as permissões de cada perfil. O Super Administrador sempre tem todas. Permissões marcadas com 🔒 exigem reautenticação e motivo ao usar. Mudanças valem no próximo acesso de cada usuário.</p>
<ul class="nav nav-tabs" role="tablist">
  <?php foreach ($perfis as $i => $r): ?><li class="nav-item" role="presentation"><button class="nav-link <?= $i === 0 ? 'active' : '' ?>" data-bs-toggle="tab" data-bs-target="#perfil-<?= $e($r['id']) ?>" type="button" role="tab"><?= $e($r['name']) ?></button></li><?php endforeach; ?>
</ul>
<div class="tab-content border border-top-0 p-3 bg-white">
<?php foreach ($perfis as $i => $r): $fixo = $r['code'] === 'SUPER_ADMIN'; $somenteSuper = $r['code'] === 'ADMIN' && !$isSuperAdmin; ?>
  <div class="tab-pane fade <?= $i === 0 ? 'show active' : '' ?>" id="perfil-<?= $e($r['id']) ?>" role="tabpanel">
    <p class="small text-muted"><?= $e($r['description']) ?></p>
    <form method="post" action="<?= $e($baseUrl) ?>/admin/perfis/<?= $e($r['id']) ?>"><?= $csrf ?>
      <div class="row">
      <?php foreach ($modulos as $mod => $perms): ?>
        <div class="col-md-6 col-xl-4 mb-3">
          <div class="fw-semibold text-capitalize mb-1"><?= $e($mod) ?></div>
          <?php foreach ($perms as $p): $on = $fixo || isset($concedidas[(int) $r['id']][(int) $p['id']]); ?>
            <div class="form-check">
              <input class="form-check-input" type="checkbox" name="perms[]" value="<?= $e($p['id']) ?>" id="p<?= $e($r['id']) ?>-<?= $e($p['id']) ?>" <?= $on ? 'checked' : '' ?> <?= $fixo || $somenteSuper ? 'disabled' : '' ?>>
              <label class="form-check-label small" for="p<?= $e($r['id']) ?>-<?= $e($p['id']) ?>"><?= $p['is_sensitive'] ? '🔒 ' : '' ?><?= $e($p['description']) ?> <span class="text-muted">(<?= $e($p['code']) ?>)</span></label>
            </div>
          <?php endforeach; ?>
        </div>
      <?php endforeach; ?>
      </div>
      <?php if (!$fixo && !$somenteSuper): ?><button class="btn btn-primary btn-sm">Salvar permissões de <?= $e($r['name']) ?></button><?php elseif ($somenteSuper): ?><p class="small text-muted mb-0">Só o Super Administrador altera o perfil Administrador.</p><?php endif; ?>
    </form>
  </div>
<?php endforeach; ?>
</div>
