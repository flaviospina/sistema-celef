<h1 class="h4 mb-3">Administradores</h1>
<p class="text-muted small">Somente o Super Administrador promove ou rebaixa administradores. E-mails em <code>SUPER_ADMIN_EMAILS</code> (.env) são protegidos: <?= $e(implode(', ', $protegidos)) ?>.</p>
<div class="table-responsive"><table class="table table-sm align-middle">
  <thead><tr><th>Nome</th><th>E-mail</th><th>Perfil</th><th>Último login</th><?php if ($isSuperAdmin): ?><th>Ação</th><?php endif; ?></tr></thead>
  <tbody>
  <?php foreach ($admins as $a): $prot = in_array(strtolower($a['email']), $protegidos, true); ?>
    <tr>
      <td><a href="<?= $e($baseUrl) ?>/admin/usuarios/<?= $e($a['id']) ?>"><?= $e($a['full_name']) ?></a> <?= $a['is_active'] ? '' : '<span class="badge text-bg-secondary">inativo</span>' ?></td>
      <td class="small"><?= $e($a['email']) ?> <?= $prot ? '<span class="badge text-bg-info">protegido</span>' : '' ?></td>
      <td><span class="badge <?= $a['role_code'] === 'SUPER_ADMIN' ? 'text-bg-dark' : 'text-bg-primary' ?>"><?= $e($a['role_code']) ?></span></td>
      <td class="small"><?= $a['last_login_at'] ? $e(date('d/m/Y H:i', strtotime($a['last_login_at']))) : 'nunca' ?></td>
      <?php if ($isSuperAdmin): ?>
      <td>
        <?php if (!$prot && (int) $a['id'] !== (int) $usuario['id']): ?>
        <form method="post" action="<?= $e($baseUrl) ?>/admin/administradores/<?= $e($a['id']) ?>/perfil" class="d-flex gap-1" data-confirm="Alterar o perfil deste administrador?"><?= $csrf ?>
          <select class="form-select form-select-sm" name="role_code">
            <option value="SUPER_ADMIN" <?= $a['role_code'] === 'SUPER_ADMIN' ? 'selected' : '' ?>>Super Administrador</option>
            <option value="ADMIN" <?= $a['role_code'] === 'ADMIN' ? 'selected' : '' ?>>Administrador</option>
            <option value="SECRETARIA">Rebaixar para Secretaria</option>
            <option value="COORDENACAO">Rebaixar para Coordenação</option>
            <option value="PROFESSOR">Rebaixar para Professor</option>
            <option value="AUDITOR">Rebaixar para Auditor</option>
          </select>
          <button class="btn btn-sm btn-outline-primary">Aplicar</button>
        </form>
        <?php else: ?><span class="text-muted small">—</span><?php endif; ?>
      </td>
      <?php endif; ?>
    </tr>
  <?php endforeach; ?>
  </tbody>
</table></div>
<?php if ($isSuperAdmin): ?>
<h2 class="h6 mt-4">Promover usuário a administrador</h2>
<?php if ($outros === []): ?><p class="text-muted small">Não há outros usuários ativos para promover. Cadastre em Usuários.</p><?php else: ?>
<form method="post" id="form-promover" class="row g-2 align-items-end" data-confirm="Promover este usuário?">
  <?= $csrf ?>
  <div class="col-md-6"><label class="form-label" for="promover-usuario">Usuário</label>
    <select class="form-select form-select-sm" id="promover-usuario" name="user_id" required>
      <?php foreach ($outros as $o): ?><option value="<?= $e($o['id']) ?>"><?= $e($o['full_name']) ?> (<?= $e($o['email']) ?>, <?= $e($o['role_code']) ?>)</option><?php endforeach; ?>
    </select></div>
  <div class="col-md-4"><label class="form-label" for="promover-perfil">Novo perfil</label>
    <select class="form-select form-select-sm" id="promover-perfil" name="role_code"><option value="ADMIN">Administrador</option><option value="SUPER_ADMIN">Super Administrador</option></select></div>
  <div class="col-md-2"><button class="btn btn-primary btn-sm w-100">Promover</button></div>
</form>
<script nonce="<?= $e($nonce) ?>">
  // a rota recebe o id do usuário no caminho: monta a action antes de enviar
  (function () {
    var f = document.getElementById('form-promover'); if (!f) return;
    f.addEventListener('submit', function () { f.action = '<?= $e($baseUrl) ?>/admin/administradores/' + document.getElementById('promover-usuario').value + '/perfil'; });
  })();
</script>
<?php endif; endif; ?>
