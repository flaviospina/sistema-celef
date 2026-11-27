<div class="card shadow">
  <div class="card-body p-4">
    <h1 class="h5 mb-3">Aviso de privacidade <span class="text-muted small">versão <?= $e($versao) ?></span></h1>
    <p><?= nl2br($e($texto)) ?></p>
    <ul class="small">
      <li>Os dados tratados aqui pertencem a crianças e adolescentes e são usados só para a gestão escolar do CELEF.</li>
      <li>Toda consulta, inclusão, alteração e exclusão fica registrada com a sua conta, data, hora e endereço de rede, de forma permanente.</li>
      <li>Dados de identificação, contato e saúde aparecem mascarados; ver o dado completo exige permissão e justificativa.</li>
      <li>Não copie, exporte ou compartilhe dados fora do sistema sem autorização da direção.</li>
    </ul>
    <form method="post" action="<?= $e($baseUrl) ?>/privacidade/aceite"><?= $csrf ?>
      <div class="form-check mb-3">
        <input class="form-check-input" type="checkbox" value="1" id="ciente" name="ciente" required>
        <label class="form-check-label" for="ciente">Li e estou ciente, como <strong><?= $e($usuario['full_name']) ?></strong> (<?= $e($usuario['email']) ?>).</label>
      </div>
      <button type="submit" class="btn btn-primary">Continuar</button>
    </form>
    <form method="post" action="<?= $e($baseUrl) ?>/logout" class="d-inline mt-2"><?= $csrf ?><button class="btn btn-link" type="submit">Sair sem aceitar</button></form>
  </div>
</div>
