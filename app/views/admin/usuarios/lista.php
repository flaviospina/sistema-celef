<div class="d-flex flex-wrap justify-content-between align-items-center mb-3 gap-2">
  <h1 class="h4 mb-0"><?= $filtros['lixeira'] ? 'Usuários na lixeira' : 'Usuários' ?></h1>
  <div>
    <?php if ($filtros['lixeira']): ?><a class="btn btn-outline-secondary btn-sm" href="<?= $e($baseUrl) ?>/admin/usuarios">Voltar aos ativos</a>
    <?php else: ?><a class="btn btn-outline-secondary btn-sm" href="<?= $e($baseUrl) ?>/admin/usuarios?lixeira=1">Lixeira</a> <a class="btn btn-primary btn-sm" href="<?= $e($baseUrl) ?>/admin/usuarios/novo">Novo usuário</a><?php endif; ?>
  </div>
</div>
<form class="row g-2 mb-3" method="get" action="<?= $e($baseUrl) ?>/admin/usuarios">
  <?php if ($filtros['lixeira']): ?><input type="hidden" name="lixeira" value="1"><?php endif; ?>
  <div class="col-md-5"><input class="form-control form-control-sm" name="q" value="<?= $e($filtros['q']) ?>" placeholder="Nome ou e-mail"></div>
  <div class="col-md-3"><select class="form-select form-select-sm" name="perfil"><option value="">Todos os perfis</option><?php foreach ($perfis as $p): ?><option value="<?= $e($p['code']) ?>" <?= $filtros['role'] === $p['code'] ? 'selected' : '' ?>><?= $e($p['name']) ?></option><?php endforeach; ?></select></div>
  <div class="col-md-2"><select class="form-select form-select-sm" name="ativo"><option value="">Ativos e inativos</option><option value="1" <?= $filtros['ativo'] === '1' ? 'selected' : '' ?>>Ativos</option><option value="0" <?= $filtros['ativo'] === '0' ? 'selected' : '' ?>>Inativos</option></select></div>
  <div class="col-md-2"><button class="btn btn-outline-primary btn-sm w-100">Filtrar</button></div>
</form>
<div class="table-responsive"><table class="table table-sm table-hover align-middle">
  <thead><tr><th>Nome</th><th>E-mail</th><th>Perfil</th><th>Turmas</th><th>Situação</th><th>Último login</th></tr></thead>
  <tbody>
  <?php foreach ($lista['itens'] as $u): ?>
    <tr>
      <td><a href="<?= $e($baseUrl) ?>/admin/usuarios/<?= $e($u['id']) ?>"><?= $e($u['full_name']) ?></a></td>
      <td class="small"><?= $e($u['email']) ?></td>
      <td><span class="badge text-bg-light"><?= $e($u['role_name']) ?></span></td>
      <td><?= in_array($u['role_code'], ['PROFESSOR', 'COORDENACAO'], true) ? $e($u['turmas']) : '—' ?></td>
      <td><?= $u['deleted_at'] ? '<span class="badge text-bg-dark">lixeira</span>' : ($u['is_active'] ? '<span class="badge text-bg-success">ativo</span>' : '<span class="badge text-bg-secondary">inativo</span>') ?></td>
      <td class="small"><?= $u['last_login_at'] ? $e(date('d/m/Y H:i', strtotime($u['last_login_at']))) : 'nunca' ?></td>
    </tr>
  <?php endforeach; ?>
  <?php if ($lista['itens'] === []): ?><tr><td colspan="6" class="text-muted">Nenhum usuário encontrado.</td></tr><?php endif; ?>
  </tbody>
</table></div>
<?php $paginas = (int) ceil($lista['total'] / $lista['por_pagina']); if ($paginas > 1): ?>
<nav><ul class="pagination pagination-sm">
  <?php for ($p = 1; $p <= $paginas; $p++): $qs = http_build_query(array_filter(['q' => $filtros['q'], 'perfil' => $filtros['role'], 'ativo' => $filtros['ativo'], 'lixeira' => $filtros['lixeira'] ? 1 : null, 'pagina' => $p])); ?>
    <li class="page-item <?= $p === $lista['pagina'] ? 'active' : '' ?>"><a class="page-link" href="<?= $e($baseUrl) ?>/admin/usuarios?<?= $e($qs) ?>"><?= $p ?></a></li>
  <?php endfor; ?>
</ul></nav>
<?php endif; ?>
<p class="small text-muted"><?= $e($lista['total']) ?> usuário(s).</p>
