<?php /** layout da área administrativa: barra lateral com as seções */
$secoes = [
  'inicio'          => ['Painel', '/admin', true],
  'usuarios'        => ['Usuários', '/admin/usuarios', $can('admin.usuarios')],
  'administradores' => ['Administradores', '/admin/administradores', $can('admin.administradores')],
  'perfis'          => ['Perfis e permissões', '/admin/perfis', $can('admin.perfis')],
  'conta_tecnica'   => ['Conta técnica Google', '/admin/conta-tecnica', $can('admin.conta_tecnica')],
  'planilhas'       => ['Planilhas conectadas', '/admin/planilhas', $can('admin.planilhas')],
  'planilha_logs'   => ['Planilha de logs', '/admin/planilha-logs', $can('admin.planilha_logs')],
  'sincronizacao'   => ['Sincronização', '/admin/sincronizacao', $can('admin.sincronizacao')],
  'auditoria'       => ['Auditoria', '/admin/auditoria', $can('auditoria.ver')],
  'seguranca'       => ['Segurança', '/admin/seguranca', $can('admin.seguranca')],
  'configuracoes'   => ['Configurações', '/admin/configuracoes', $can('admin.configuracoes')],
  'identidade'      => ['Identidade visual', '/admin/identidade-visual', $can('admin.identidade_visual')],
  'lixeira'         => ['Lixeira', '/admin/lixeira', $can('admin.lixeira')],
];
$disponiveis = ['inicio', 'usuarios', 'administradores', 'perfis', 'auditoria', 'seguranca', 'configuracoes'];
ob_start(); ?>
<div class="row g-4">
  <aside class="col-lg-3 col-xl-2">
    <nav class="list-group celef-admin-nav small">
      <?php foreach ($secoes as $k => [$rotulo, $rota, $pode]): if (!$pode) continue; $ok = in_array($k, $disponiveis, true); ?>
        <a class="list-group-item list-group-item-action <?= $secaoAdmin === $k ? 'active' : '' ?> <?= $ok ? '' : 'disabled text-muted' ?>" href="<?= $e($baseUrl . $rota) ?>" <?= $ok ? '' : 'aria-disabled="true"' ?>><?= $e($rotulo) ?><?= $ok ? '' : ' <span class="badge bg-secondary">em breve</span>' ?></a>
      <?php endforeach; ?>
    </nav>
  </aside>
  <section class="col-lg-9 col-xl-10">
    <?php if (!empty($erros)): ?>
      <div class="alert alert-danger"><strong>Corrija os campos:</strong><ul class="mb-0"><?php foreach ($erros as $m): ?><li><?= $e($m) ?></li><?php endforeach; ?></ul></div>
    <?php endif; ?>
    <?= $conteudo ?>
  </section>
</div>
<?php $conteudo = ob_get_clean(); require __DIR__ . '/base.php'; ?>
