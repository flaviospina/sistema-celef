<h1 class="h4 mb-3">Configurações</h1>
<?php $rotulos = ['sessao' => 'Sessão', 'seguranca' => 'Segurança', 'alertas' => 'Alertas por e-mail', 'sync' => 'Sincronização', 'diario' => 'Diário', 'lgpd' => 'LGPD e privacidade', 'marca' => 'Instituição']; ?>
<?php foreach ($grupos as $g => $campos): ?>
<div class="card mb-3" id="<?= $e($g) ?>"><div class="card-body">
  <h2 class="h6"><?= $e($rotulos[$g] ?? $g) ?></h2>
  <form method="post" action="<?= $e($baseUrl) ?>/admin/configuracoes/<?= $e($g) ?>"><?= $csrf ?>
    <div class="row g-3">
    <?php foreach ($campos as $k => [$label, $tipo, $min, $max]): $v = $valores[$k]; $id = 'c-' . str_replace('.', '-', $k); ?>
      <div class="<?= $tipo === 'text' || $tipo === 'emails' ? 'col-12' : 'col-md-6' ?>">
        <?php if ($tipo === 'bool'): ?>
          <div class="form-check form-switch mt-md-4"><input type="hidden" name="<?= $e($k) ?>" value="0"><input class="form-check-input" type="checkbox" id="<?= $e($id) ?>" name="<?= $e($k) ?>" value="1" <?= $v ? 'checked' : '' ?>><label class="form-check-label" for="<?= $e($id) ?>"><?= $e($label) ?></label></div>
        <?php elseif ($tipo === 'text'): ?>
          <label class="form-label" for="<?= $e($id) ?>"><?= $e($label) ?></label><textarea class="form-control" id="<?= $e($id) ?>" name="<?= $e($k) ?>" rows="3" maxlength="<?= $e($max) ?>"><?= $e($v) ?></textarea>
        <?php elseif ($tipo === 'emails'): ?>
          <label class="form-label" for="<?= $e($id) ?>"><?= $e($label) ?></label><textarea class="form-control" id="<?= $e($id) ?>" name="<?= $e($k) ?>" rows="3"><?= $e(implode("\n", is_array($v) ? $v : [])) ?></textarea>
        <?php elseif ($tipo === 'int'): ?>
          <label class="form-label" for="<?= $e($id) ?>"><?= $e($label) ?></label><input class="form-control" type="number" min="<?= $e($min) ?>" max="<?= $e($max) ?>" id="<?= $e($id) ?>" name="<?= $e($k) ?>" value="<?= $e($v) ?>" required>
        <?php else: ?>
          <label class="form-label" for="<?= $e($id) ?>"><?= $e($label) ?></label><input class="form-control" id="<?= $e($id) ?>" name="<?= $e($k) ?>" value="<?= $e($v) ?>" maxlength="<?= $e($max) ?>">
        <?php endif; ?>
      </div>
    <?php endforeach; ?>
    </div>
    <button class="btn btn-primary btn-sm mt-3">Salvar</button>
  </form>
</div></div>
<?php endforeach; ?>
<div class="card mb-3" id="padroes"><div class="card-body">
  <h2 class="h6">Contas genéricas bloqueadas no login</h2>
  <p class="small text-muted">Padrões no formato LIKE do MySQL: <code>%</code> = qualquer sequência, <code>_</code> = um caractere. Além destes, só entra quem está cadastrado em Usuários.</p>
  <div class="table-responsive"><table class="table table-sm align-middle">
    <thead><tr><th>Padrão</th><th>Descrição</th><th>Situação</th><th></th></tr></thead>
    <tbody>
    <?php foreach ($padroes as $p): ?>
      <tr><td><code><?= $e($p['pattern']) ?></code></td><td class="small"><?= $e($p['description']) ?></td>
        <td><?= $p['is_active'] ? '<span class="badge text-bg-success">ativo</span>' : '<span class="badge text-bg-secondary">inativo</span>' ?></td>
        <td><form method="post" action="<?= $e($baseUrl) ?>/admin/configuracoes/padroes/<?= $e($p['id']) ?>/alternar"><?= $csrf ?><button class="btn btn-link btn-sm p-0"><?= $p['is_active'] ? 'desativar' : 'ativar' ?></button></form></td></tr>
    <?php endforeach; ?>
    </tbody>
  </table></div>
  <form method="post" action="<?= $e($baseUrl) ?>/admin/configuracoes/padroes" class="row g-2"><?= $csrf ?>
    <div class="col-md-4"><input class="form-control form-control-sm" name="pattern" placeholder="ex.: celef%2028@%" required maxlength="190"></div>
    <div class="col-md-6"><input class="form-control form-control-sm" name="description" placeholder="Descrição" maxlength="300"></div>
    <div class="col-md-2"><button class="btn btn-outline-primary btn-sm w-100">Adicionar</button></div>
  </form>
</div></div>
