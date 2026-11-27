<?php
// tools/test_phase3.php — teste ponta a ponta do login Google (emulado), sessão, RBAC e área admin.
// Pré-requisitos: php -S 127.0.0.1:8088 (app em /celef/public) e php -S 127.0.0.1:8090 tools/mock_google.php
declare(strict_types=1);
define('APP_ROOT', dirname(__DIR__));
require APP_ROOT . '/app/bootstrap.php';
use App\Database;

$BASE = rtrim((string) App\Config::get('BASE_URL'), '/');
$MOCK = '/dev/shm/mock_google';
$pass = 0; $fail = 0;
function ok(bool $c, string $l, string $x = ''): void { global $pass, $fail; if ($c) { $pass++; echo "  ✔ $l\n"; } else { $fail++; echo "  ✘ $l $x\n"; } }

final class Browser {
    public string $jar; public string $lastUrl = ''; public int $status = 0; public string $body = ''; public string $headers = '';
    public function __construct(public string $ua = 'TesteCELEF/1.0') { $this->jar = tempnam('/dev/shm', 'jar'); }
    public function req(string $method, string $url, array $post = [], bool $follow = true, array $hdr = []): string {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_COOKIEJAR => $this->jar, CURLOPT_COOKIEFILE => $this->jar,
            CURLOPT_FOLLOWLOCATION => $follow, CURLOPT_MAXREDIRS => 10, CURLOPT_USERAGENT => $this->ua, CURLOPT_PROXY => '', CURLOPT_HTTPHEADER => $hdr]);
        if ($method === 'POST') { curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post)); }
        $r = (string) curl_exec($ch);
        $this->status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE); $this->lastUrl = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        $hs = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE); $this->headers = substr($r, 0, $hs); $this->body = substr($r, $hs); curl_close($ch);
        return $this->body;
    }
    public function get(string $u, bool $follow = true): string { return $this->req('GET', $u, [], $follow); }
    public function post(string $u, array $data, bool $follow = true): string {
        global $BASE; $data['_csrf'] = $this->csrf(); return $this->req('POST', $u, $data, $follow, ['Origin: ' . $BASE]);
    }
    /** Faz o que o JS de callback.html faria: lê code/state do fragmento (ou da query) do último Location e chama o callback PHP. */
    public function forwardCallback(): void {
        global $BASE;
        if (!preg_match_all('~^Location:\s*(\S*callback\.html[#?]\S+)~mi', $this->headers, $m)) { return; }
        $loc = end($m[1]);
        $raw = str_contains($loc, '#') ? substr($loc, strpos($loc, '#') + 1) : (string) parse_url($loc, PHP_URL_QUERY);
        parse_str($raw, $q);
        $this->get("$BASE/auth/google/callback?" . http_build_query(array_intersect_key($q, array_flip(['code', 'state', 'error']))));
    }
    public function csrf(): string { return preg_match('/name="_csrf" value="([a-f0-9]{64})"/', $this->body, $m) ? $m[1] : ''; }
    public function has(string $needle): bool { return str_contains($this->body, $needle); }
    public function login(array $user): string {
        global $BASE, $MOCK; @mkdir($MOCK, 0700, true); file_put_contents("$MOCK/user.json", json_encode($user));
        $this->get("$BASE/login"); $this->post("$BASE/login/google", []);
        $this->forwardCallback();
        return $this->body;
    }
}
$superUser = ['email' => 'flaviospina@scseduca.com.br', 'sub' => 'sub-flavio', 'hd' => 'scseduca.com.br', 'email_verified' => true, 'name' => 'Flávio Spina'];

echo "== Login Google (fluxo completo com emulador)\n";
$b = new Browser();
$b->get("$BASE/login");
ok($b->status === 200 && $b->has('Entrar com Google') && $b->csrf() !== '', 'página de login com formulário e token CSRF');
$b->login($superUser);
$authReq = json_decode((string) file_get_contents("$MOCK/last_auth_request.json"), true);
ok(str_ends_with((string) $authReq['redirect_uri'], '/auth/google/callback.html') && ($authReq['response_mode'] ?? '') === 'fragment', 'redirect_uri é a página estática callback.html e response_mode=fragment');
ok(($authReq['code_challenge_method'] ?? '') === 'S256' && ($authReq['hd'] ?? '') === 'scseduca.com.br' && !empty($authReq['nonce']) && !empty($authReq['state']), 'pedido ao Google com PKCE S256, hd, nonce e state');
ok(str_ends_with($b->lastUrl, '/privacidade/aceite') && $b->has('Aviso de privacidade'), 'primeiro acesso cai no aceite do aviso de privacidade');
$b->post("$BASE/privacidade/aceite", ['ciente' => '1']);
ok($b->status === 200 && $b->has('Olá, Flávio') && $b->has('Administração'), 'aceite registrado e menu inicial exibido com módulo Admin');
$u = Database::row("SELECT google_sub, last_login_at, privacy_version FROM users WHERE email = 'flaviospina@scseduca.com.br'");
ok($u['google_sub'] === 'sub-flavio' && $u['last_login_at'] !== null && $u['privacy_version'] === '1.0', 'users atualizado: google_sub, last_login_at, privacy_version');
ok((int) Database::value("SELECT COUNT(*) FROM user_sessions s JOIN users u ON u.id = s.user_id WHERE u.email = 'flaviospina@scseduca.com.br' AND s.revoked_at IS NULL") >= 1, 'user_sessions com sessão ativa');
ok(Database::value("SELECT action FROM audit_log WHERE action = 'LOGIN' ORDER BY id DESC LIMIT 1") === 'LOGIN', 'auditoria LOGIN gravada');
ok((int) Database::value("SELECT COUNT(*) FROM privacy_acknowledgements") >= 1, 'privacy_acknowledgements gravado');
// replay do callback
$cb = $b->lastUrl; $b->get("$BASE/auth/google/callback?code=abc&state=xyz");
ok($b->status === 403, 'callback com state desconhecido → 403');

echo "== Área admin\n";
$b->get("$BASE/admin");
ok($b->status === 200 && $b->has('Painel administrativo'), '/admin abre (login recente)');
$b->get("$BASE/admin/usuarios");
ok($b->status === 200 && $b->has('flaviospina@scseduca.com.br'), 'lista de usuários');
// cadastra professor
$b->get("$BASE/admin/usuarios/novo");
$b->post("$BASE/admin/usuarios", ['email' => 'Prof.Teste@scseduca.com.br', 'full_name' => 'Professora Teste', 'role_code' => 'PROFESSOR', 'is_active' => '1']);
ok($b->status === 200 && $b->has('Usuário prof.teste@scseduca.com.br cadastrado'), 'cadastro de professor (e-mail normalizado)');
$profId = (int) Database::value("SELECT id FROM users WHERE email = 'prof.teste@scseduca.com.br'");
ok($profId > 0 && Database::value("SELECT summary FROM audit_log WHERE action = 'ADMIN' ORDER BY id DESC LIMIT 1") !== null, 'auditoria ADMIN do cadastro');
// com um único administrador não há a quem avisar (o autor é excluído): nenhum alerta pode conter o próprio autor
ok((int) Database::value("SELECT COUNT(*) FROM alert_outbox WHERE kind = 'ACAO_ADMIN' AND recipients_json LIKE '%flaviospina%'") === 0, 'alerta ACAO_ADMIN nunca é enviado ao próprio autor');
// validações
$b->get("$BASE/admin/usuarios/novo");
$b->post("$BASE/admin/usuarios", ['email' => 'alguem@gmail.com', 'full_name' => 'X', 'role_code' => 'PROFESSOR']);
ok($b->status === 422 && $b->has('conta @scseduca.com.br'), 'e-mail fora do domínio rejeitado (422)');
$b->get("$BASE/admin/usuarios/novo");
$b->post("$BASE/admin/usuarios", ['email' => 'celef@scseduca.com.br', 'full_name' => 'Conta Celef', 'role_code' => 'PROFESSOR']);
ok($b->status === 422 && $b->has('conta genérica bloqueada'), 'conta genérica (celef@) não pode ser cadastrada');
// não pode alterar o próprio perfil nem se desativar
$selfId = (int) Database::value("SELECT id FROM users WHERE email = 'flaviospina@scseduca.com.br'");
$b->get("$BASE/admin/usuarios/$selfId");
$b->post("$BASE/admin/usuarios/$selfId", ['full_name' => 'Flávio Spina', 'role_code' => 'PROFESSOR']);
ok($b->status === 200 && Database::value("SELECT r.code FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $selfId") === 'SUPER_ADMIN' && (int) Database::value("SELECT is_active FROM users WHERE id = $selfId") === 1, 'próprio perfil/ativação ignorados na edição');
// excluir sem motivo / com motivo
$b->get("$BASE/admin/usuarios/$profId");
$b->post("$BASE/admin/usuarios/$profId/excluir", ['motivo' => 'curto']);
ok($b->has('no mínimo 10 caracteres'), 'exclusão sem motivo suficiente é recusada');
$b->post("$BASE/admin/usuarios/$profId/excluir", ['motivo' => 'Cadastro criado por engano no teste']);
ok(Database::value("SELECT deleted_at FROM users WHERE id = $profId") !== null && $b->has('lixeira'), 'exclusão lógica com motivo → lixeira');
$b->get("$BASE/admin/usuarios/$profId");
$b->post("$BASE/admin/usuarios/$profId/restaurar", []);
ok(Database::value("SELECT deleted_at FROM users WHERE id = $profId") === null, 'restauração da lixeira');
// promover a ADMIN e tentar rebaixar o único super admin
$b->get("$BASE/admin/administradores");
$b->post("$BASE/admin/administradores/$profId/perfil", ['role_code' => 'ADMIN']);
ok(Database::value("SELECT r.code FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = $profId") === 'ADMIN' && $b->has('agora é ADMIN'), 'promoção a ADMIN pelo Super Admin');
$b->post("$BASE/admin/administradores/$selfId/perfil", ['role_code' => 'ADMIN']);
ok($b->has('próprio perfil') || $b->has('último Super Administrador') || $b->has('SUPER_ADMIN_EMAILS'), 'rebaixar a si mesmo / último super admin é bloqueado');
// perfis: concede permissão ao PROFESSOR e verifica
$roleProf = (int) Database::value("SELECT id FROM roles WHERE code = 'PROFESSOR'");
$permIndic = (int) Database::value("SELECT id FROM permissions WHERE code = 'indicadores.ver'");
$cur = array_map('intval', array_column(Database::rows("SELECT permission_id FROM role_permissions WHERE role_id = $roleProf AND is_granted = 1"), 'permission_id'));
$b->get("$BASE/admin/perfis");
$b->req('POST', "$BASE/admin/perfis/$roleProf", ['_csrf' => $b->csrf(), 'perms' => array_map('strval', array_merge($cur, [$permIndic]))], true, ['Origin: ' . $BASE]);
ok((int) Database::value("SELECT is_granted FROM role_permissions WHERE role_id = $roleProf AND permission_id = $permIndic") === 1 && $b->has('Permissões do perfil'), 'matriz de permissões salva e auditada');
// configurações
$b->get("$BASE/admin/configuracoes");
$b->post("$BASE/admin/configuracoes/diario", ['diary.edit_days' => '10']);
ok(App\Settings::get('diary.edit_days') === 10 || (int) Database::value("SELECT value_json FROM settings WHERE setting_key = 'diary.edit_days'") === 10, 'configuração salva (diary.edit_days = 10)');
$b->post("$BASE/admin/configuracoes/diario", ['diary.edit_days' => '999']);
ok($b->has('entre 0 e 60'), 'configuração fora da faixa é recusada');
$b->post("$BASE/admin/configuracoes/padroes", ['pattern' => 'biblioteca%@%', 'description' => 'conta de setor']);
ok(Database::value("SELECT id FROM blocked_email_patterns WHERE pattern = 'biblioteca%@%'") !== null, 'padrão de e-mail bloqueado adicionado');
// auditoria e segurança
$b->get("$BASE/admin/auditoria?acao=LOGIN");
ok($b->status === 200 && $b->has('LOGIN'), 'busca na auditoria por ação');
$b->post("$BASE/admin/auditoria/verificar", []);
ok($b->has('Cadeia íntegra'), 'verificação manual da cadeia OK');
$b->get("$BASE/admin/seguranca?periodo=7d");
ok($b->status === 200 && $b->has('Sessões ativas'), 'painel de segurança');

echo "== Sessões\n";
$b2 = new Browser('OutroNavegador/2.0');
$b2->login($superUser);
ok($b2->has('Olá, Flávio'), 'segundo login (outro navegador) entra direto (aviso já aceito)');
$b2->get("$BASE/minhas-sessoes");
ok($b2->status === 200 && substr_count($b2->body, 'badge text-bg-success">ativa') >= 1, 'minhas sessões lista a outra sessão ativa');
$b2->post("$BASE/minhas-sessoes/encerrar-outras", []);
$b->get("$BASE/");
ok(str_ends_with($b->lastUrl, '/login') && $b->has('encerrada'), 'sessão do 1º navegador foi encerrada remotamente → volta ao login');
// troca de user-agent na mesma sessão
$b2->ua = 'NavegadorTrocado/3.0'; $b2->get("$BASE/");
ok(str_ends_with($b2->lastUrl, '/login'), 'mudança de user-agent derruba a sessão');
ok(Database::value("SELECT kind FROM security_events WHERE kind = 'SESSAO_TROCA_UA' ORDER BY id DESC LIMIT 1") === 'SESSAO_TROCA_UA', 'evento SESSAO_TROCA_UA registrado');

echo "== Recusas de login\n";
$cases = [
    ['Conta Gmail (sem hd)',            ['email' => 'alguem@gmail.com', 'sub' => 'g1', 'email_verified' => true], 'DOMINIO_INVALIDO'],
    ['hd forjado com e-mail de fora',   ['email' => 'alguem@gmail.com', 'sub' => 'g2', 'hd' => 'scseduca.com.br', 'email_verified' => true], 'DOMINIO_INVALIDO'],
    ['Domínio certo, não cadastrado',   ['email' => 'desconhecido@scseduca.com.br', 'sub' => 'd1', 'hd' => 'scseduca.com.br', 'email_verified' => true], 'NAO_CADASTRADO'],
    ['Conta genérica celef@',           ['email' => 'celef@scseduca.com.br', 'sub' => 'c1', 'hd' => 'scseduca.com.br', 'email_verified' => true], 'CONTA_GENERICA'],
    ['E-mail não verificado',           ['email' => 'flaviospina@scseduca.com.br', 'sub' => 'sub-flavio', 'hd' => 'scseduca.com.br', 'email_verified' => false], 'TOKEN_INVALIDO'],
    ['Assinatura do token adulterada',  ['email' => 'flaviospina@scseduca.com.br', 'sub' => 'sub-flavio', 'hd' => 'scseduca.com.br', 'email_verified' => true, 'tamper' => true], 'TOKEN_INVALIDO'],
    ['Mesmo e-mail, outra conta Google (sub)', ['email' => 'flaviospina@scseduca.com.br', 'sub' => 'sub-impostor', 'hd' => 'scseduca.com.br', 'email_verified' => true], 'TOKEN_INVALIDO'],
];
foreach ($cases as [$label, $user, $outcome]) {
    $n = new Browser('Teste/' . bin2hex(random_bytes(2)));
    $n->login($user);
    $last = Database::row('SELECT outcome FROM login_attempts ORDER BY id DESC LIMIT 1');
    ok($n->status === 403 && $n->has('Acesso negado') && ($last['outcome'] ?? '') === $outcome, "$label → 403 ($outcome)", "status={$n->status} outcome=" . ($last['outcome'] ?? '?'));
}
Database::run("UPDATE users SET is_active = 0 WHERE id = $profId");
$n = new Browser('Teste/inativo'); $n->login(['email' => 'prof.teste@scseduca.com.br', 'sub' => 'p1', 'hd' => 'scseduca.com.br', 'email_verified' => true]);
ok($n->status === 403 && Database::value('SELECT outcome FROM login_attempts ORDER BY id DESC LIMIT 1') === 'INATIVO', 'usuário desativado → 403 (INATIVO)');
Database::run("UPDATE users SET is_active = 1 WHERE id = $profId");
ok((int) Database::value("SELECT COUNT(*) FROM audit_log WHERE action = 'LOGIN_NEGADO'") >= 8, 'cada recusa gera LOGIN_NEGADO na auditoria');

echo "== RBAC e escopo\n";
Database::run("UPDATE users SET role_id = (SELECT id FROM roles WHERE code = 'PROFESSOR') WHERE id = $profId");
$p = new Browser('Teste/prof');
$p->login(['email' => 'prof.teste@scseduca.com.br', 'sub' => 'p1', 'hd' => 'scseduca.com.br', 'email_verified' => true]);
$p->post("$BASE/privacidade/aceite", ['ciente' => '1']);
ok($p->has('Olá, Professora') && !$p->has('/admin"'), 'professor entra e não vê o módulo Admin');
$p->get("$BASE/admin");
ok($p->status === 403, 'professor em /admin → 403');
$p->get("$BASE/admin/auditoria");
ok($p->status === 403, 'professor em /admin/auditoria → 403 (sem auditoria.ver)');
$profRow = App\models\UserService::find($profId);
$profRow['role_code'] = 'PROFESSOR';
ok(App\Auth\Rbac::classScope($profRow) === [] && App\Auth\Rbac::classScopeSql('e.class_id', $profRow)[0] === ' AND 1 = 0', 'professor sem turmas: escopo nega tudo (1 = 0)');
$sup = App\models\UserService::find($selfId);
ok(App\Auth\Rbac::classScope($sup) === null && App\Auth\Rbac::classScopeSql('e.class_id', $sup) === ['', []], 'super admin: sem restrição de escopo');
ok(App\Auth\Rbac::can('aluno.ver', $profRow) && !App\Auth\Rbac::can('admin.usuarios', $profRow) && App\Auth\Rbac::can('indicadores.ver', $profRow), 'permissões do professor conforme matriz (inclui a concedida há pouco)');

echo "== Reautenticação\n";
$a = new Browser('Teste/reauth'); $a->login($superUser);
App\Settings::set('session.admin_reauth_minutes', 0); // qualquer idade > 0 s exige reautenticar
sleep(1);
$a->get("$BASE/admin/usuarios");
ok(str_ends_with($a->lastUrl, '/reauth') && $a->has('Confirme sua identidade'), 'admin com login "antigo" é levado à reautenticação');
$a->post("$BASE/reauth", []);
$a->forwardCallback();
ok(str_contains($a->lastUrl, '/admin/usuarios'), 'reautenticação no Google concluída e retorno ao destino');
ok(Database::value("SELECT action FROM audit_log WHERE action = 'REAUTH' ORDER BY id DESC LIMIT 1") === 'REAUTH', 'auditoria REAUTH gravada');
$authReq = json_decode((string) file_get_contents("$MOCK/last_auth_request.json"), true);
ok(($authReq['prompt'] ?? '') === 'login' && ($authReq['max_age'] ?? '') === '0', 'pedido de reautenticação usa prompt=login e max_age=0');
App\Settings::set('session.admin_reauth_minutes', 10);
$a->post("$BASE/logout", []);
ok(str_ends_with($a->lastUrl, '/login') && $a->has('Você saiu'), 'logout invalida a sessão');
ok(Database::value("SELECT revoke_reason FROM user_sessions WHERE revoke_reason = 'LOGOUT' ORDER BY created_at DESC LIMIT 1") === 'LOGOUT', 'user_sessions revogada com motivo LOGOUT');

echo "\nRESULTADO: $pass ok, $fail falhas\n";
exit($fail === 0 ? 0 : 1);
