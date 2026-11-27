<?php $novo = $usuarioAlvo === null; $v = $valores; $emLixeira = !$novo && $usuarioAlvo['deleted_at'] !== null; ?>
<div class="d-flex flex-wrap justify-content-between align-items-center mb-3 gap-2">
  <h1 class="h4 mb-0"><?= $novo ? 'Novo usuário' : $e($usuarioAlvo['full_name']) ?></h1>
  <a class="btn btn-outline-secondary btn-sm" href="<?= $e($baseUrl) ?>/admin/usuarios">Voltar</a>
</div>
<?php if ($emLixeira): ?>
  <div class="alert alert-dark">Este usuário está na lixeira desde <?= $e(date('d/m/Y H:i', strtotime($usuarioAlvo['deleted_at']))) ?>. Motivo: <?= $e($usuarioAlvo['delete_reason']) ?>
    <?php if ($can('admin.lixeira')): ?><form method="post" action="<?= $e($baseUrl) ?>/admin/usuarios/<?= $e($usuarioAlvo['id']) ?>/restaurar" class="mt-2"><?= $csrf ?><button class="btn btn-sm btn-outline-dark">Restaurar</button></form><?php endif; ?>
  </div>
<?php else: ?>
<?php if ($protegido): ?><div class="alert alert-info small">E-mail listado em <code>SUPER_ADMIN_EMAILS</code> (.env): não pode ser rebaixado, desativado nem excluído por aqui.</div><?php endif; ?>
<?php if ($ehProprio): ?><div class="alert alert-info small">Este é o seu próprio cadastro: perfil e ativação não podem ser alterados por você mesmo.</div><?php endif; ?>
<form method="post" action="<?= $e($baseUrl) ?>/admin/usuarios<?= $novo ? '' : '/' . $e($usuarioAlvo['id']) ?>" class="card"><div class="card-body">
  <?= $csrf ?>
  <div class="row g-3">
    <div class="col-md-6">
      <label class="form-label" for="email">E-mail institucional</label>
      <input class="form-control <?= isset($erros['email']) ? 'is-invalid' : '' ?>" id="email" name="email" value="<?= $e($v['email']) ?>" <?= $novo ? 'required' : 'readonly' ?> placeholder="nome@scseduca.com.br" maxlength="190">
      <div class="form-text">Somente contas @scseduca.com.br de pessoas físicas. O e-mail não pode ser alterado depois.</div>
    </div>
    <div class="col-md-6">
      <label class="form-label" for="full_name">Nome completo</label>
      <input class="form-control <?= isset($erros['full_name']) ? 'is-invalid' : '' ?>" id="full_name" name="full_name" value="<?= $e($v['full_name']) ?>" required maxlength="160">
    </div>
    <div class="col-md-6">
      <label class="form-label" for="role_code">Perfil</label>
      <select class="form-select <?= isset($erros['role_code']) ? 'is-invalid' : '' ?>" id="role_code" name="role_code" <?= $ehProprio || $protegido ? 'disabled' : '' ?>>
        <?php foreach ($perfis as $p): if (in_array($p['code'], ['SUPER_ADMIN', 'ADMIN'], true) && !$isSuperAdmin && $p['code'] !== $v['role_code']) continue; ?>
          <option value="<?= $e($p['code']) ?>" <?= $v['role_code'] === $p['code'] ? 'selected' : '' ?>><?= $e($p['name']) ?> — <?= $e($p['description']) ?></option>
        <?php endforeach; ?>
      </select>
      <?php if ($ehProprio || $protegido): ?><input type="hidden" name="role_code" value="<?= $e($v['role_code']) ?>"><?php endif; ?>
      <?php if (!$isSuperAdmin): ?><div class="form-text">Perfis de administrador só podem ser atribuídos pelo Super Administrador.</div><?php endif; ?>
    </div>
    <div class="col-md-6">
      <label class="form-label d-block">Situação</label>
      <div class="form-check form-switch">
        <input class="form-check-input" type="checkbox" id="is_active" name="is_active" value="1" <?= (int) $v['is_active'] === 1 ? 'checked' : '' ?> <?= $ehProprio || $protegido ? 'disabled' : '' ?>>
        <label class="form-check-label" for="is_active">Ativo (pode entrar no sistema)</label>
      </div>
      <?php if ($ehProprio || $protegido): ?><input type="hidden" name="is_active" value="1"><?php endif; ?>
    </div>
    <div class="col-12" id="bloco-turmas">
      <label class="form-label">Turmas (perfis Professor e Coordenação)</label>
      <?php if ($turmas === []): ?>
        <div class="form-text">Nenhuma turma cadastrada ainda (as turmas chegam na Fase 6). O vínculo pode ser feito depois.</div>
      <?php else: ?>
        <div class="row g-1">
          <?php foreach ($turmas as $t): ?>
            <div class="col-6 col-md-3 col-lg-2"><div class="form-check"><input class="form-check-input" type="checkbox" name="turmas[]" value="<?= $e($t['id']) ?>" id="t<?= $e($t['id']) ?>" <?= in_array((int) $t['id'], $turmasVinculadas, true) ? 'checked' : '' ?>><label class="form-check-label" for="t<?= $e($t['id']) ?>"><?= $e($t['code']) ?></label></div></div>
          <?php endforeach; ?>
        </div>
        <div class="form-text">Professor só vê as turmas marcadas. O vínculo desmarcado é encerrado (com data), nunca apagado.</div>
      <?php endif; ?>
    </div>
    <div class="col-12">
      <label class="form-label" for="notes">Observações internas</label>
      <input class="form-control" id="notes" name="notes" value="<?= $e($v['notes']) ?>" maxlength="500">
    </div>
  </div>
  <div class="mt-3 d-flex gap-2">
    <button class="btn btn-primary" type="submit"><?= $novo ? 'Cadastrar' : 'Salvar' ?></button>
  </div>
</div></form>
<?php if (!$novo): ?>
<div class="row g-3 mt-1">
  <div class="col-md-6"><div class="card h-100"><div class="card-body">
    <h2 class="h6">Sessões recentes</h2>
    <?php if ($sessoes === []): ?><p class="text-muted small mb-0">Nenhuma.</p><?php else: ?>
    <ul class="list-unstyled small mb-2">
      <?php foreach ($sessoes as $s): ?><li><?= $e(date('d/m H:i', strtotime($s['created_at']))) ?> · <?= $e($s['ip']) ?> · <?= $s['revoked_at'] ? 'encerrada (' . $e($s['revoke_reason']) . ')' : '<strong>ativa</strong>' ?></li><?php endforeach; ?>
    </ul><?php endif; ?>
    <?php if ($can('admin.seguranca') && !$ehProprio): ?><form method="post" action="<?= $e($baseUrl) ?>/admin/usuarios/<?= $e($usuarioAlvo['id']) ?>/encerrar-sessoes" data-confirm="Encerrar todas as sessões deste usuário?"><?= $csrf ?><button class="btn btn-outline-warning btn-sm">Encerrar todas as sessões</button></form><?php endif; ?>
  </div></div></div>
  <?php if (!$protegido && !$ehProprio): ?>
  <div class="col-md-6"><div class="card border-danger h-100"><div class="card-body">
    <h2 class="h6 text-danger">Excluir (lixeira)</h2>
    <p class="small text-muted">Exclusão lógica: o cadastro vai para a lixeira com motivo e responsável, e pode ser restaurado por um administrador. Nada é apagado.</p>
    <form method="post" action="<?= $e($baseUrl) ?>/admin/usuarios/<?= $e($usuarioAlvo['id']) ?>/excluir" data-confirm="Enviar este usuário para a lixeira?"><?= $csrf ?>
      <input class="form-control form-control-sm mb-2" name="motivo" placeholder="Motivo (mínimo 10 caracteres)" minlength="10" required>
      <button class="btn btn-outline-danger btn-sm">Excluir</button>
    </form>
  </div></div></div>
  <?php endif; ?>
</div>
<?php endif; endif; ?>
