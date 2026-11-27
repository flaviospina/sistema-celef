<?php
// tools/test_phase4.php — conta técnica, Sheets/Drive, planilhas conectadas e planilha de logs (com o emulador do Google).
// Pré-requisitos: app em 127.0.0.1:8088 (/celef/public), emulador em localhost:8090, banco recriado (tools/reset_test_db.sh).
declare(strict_types=1);
define('APP_ROOT', dirname(__DIR__));
require APP_ROOT . '/app/bootstrap.php';
require __DIR__ . '/lib_test.php';

use App\Database;
use App\Google\GoogleJwt;
use App\Google\GoogleOAuthToken;
use App\Google\SheetLogger;
use App\Google\SheetsClient;
use App\Security\AuditLog;

$BASE = rtrim((string) App\Config::get('BASE_URL'), '/');
$MOCK = '/dev/shm/mock_google';
@mkdir("$MOCK/sheets", 0700, true);
$sheet = static fn(string $id): array => json_decode((string) file_get_contents("$MOCK/sheets/$id.json"), true);
$putSheet = static function (string $id, array $s) use ($MOCK): void { file_put_contents("$MOCK/sheets/$id.json", json_encode($s, JSON_UNESCAPED_UNICODE)); };
$tabOf = static function (array $s, string $title): ?array { foreach ($s['tabs'] as $t) { if ($t['title'] === $title) { return $t; } } return null; };

$ALUNOS = 'ALUNOS2026_abcdefghijklmnopqrstuvwxyz0123'; $SECR = 'SECRETARIA_abcdefghijklmnopqrstuvwxyz012'; $NAO = 'NAOCOMPARTILHADA_abcdefghijklmnopqrstuv'; $LOGS = 'LOGSHEET_abcdefghijklmnopqrstuvwxyz01234';
$hdr = ['Nº', 'NOME', 'E-MAIL', 'ENTRADA', 'SAÍDA', 'NASCIMENTO', 'R.A.', 'CPF'];
$putSheet($ALUNOS, ['title' => 'CELEF • ALUNOS 2026', 'shared' => 'editor', 'owner' => 'celef@scseduca.com.br', 'revisions' => [], 'tabs' => [
    ['gid' => 11, 'title' => '1A', 'frozen' => 1, 'protected' => [], 'values' => [$hdr, ['1', 'Ana Souza', 'ana@scseduca.com.br']]],
    ['gid' => 12, 'title' => '6A', 'frozen' => 1, 'protected' => [], 'values' => [$hdr]],
    ['gid' => 13, 'title' => 'REMANEJAMENTOS 2027', 'frozen' => 0, 'protected' => [], 'values' => [['ALUNO', 'TURMA ANTIGA', 'TURMA NOVA']]],
    ['gid' => 14, 'title' => 'TOTAL ALUNOS', 'frozen' => 0, 'protected' => [], 'values' => []]]]);
$putSheet($SECR, ['title' => 'Secretaria — alunos', 'shared' => 'reader', 'owner' => 'secretaria.educacao@scseduca.com.br', 'revisions' => [], 'tabs' => [['gid' => 1, 'title' => 'Alunos', 'frozen' => 0, 'protected' => [], 'values' => [['NOME', 'R.A.', 'ESCOLA']]]]]);
$putSheet($NAO, ['title' => 'Privada', 'shared' => false, 'owner' => 'outro@scseduca.com.br', 'revisions' => [], 'tabs' => []]);
$putSheet($LOGS, ['title' => 'CELEF • LOGS', 'shared' => 'editor', 'owner' => 'celef@scseduca.com.br', 'revisions' => [], 'tabs' => [['gid' => 0, 'title' => 'Página1', 'frozen' => 0, 'protected' => [], 'values' => []]]]);

$flavio = ['email' => 'flaviospina@scseduca.com.br', 'sub' => 'sub-flavio', 'hd' => 'scseduca.com.br', 'email_verified' => true, 'name' => 'Flávio Spina'];
$celef = ['email' => 'celef@scseduca.com.br', 'sub' => 'sub-celef', 'hd' => 'scseduca.com.br', 'email_verified' => true, 'name' => 'CELEF'];

echo "== Unidades: SheetsClient e GoogleJwt\n";
ok(SheetsClient::sanitizeCell('=SOMA(A1)') === "'=SOMA(A1)" && SheetsClient::sanitizeCell('+5511999') === "'+5511999" && SheetsClient::sanitizeCell('-1') === "'-1" && SheetsClient::sanitizeCell('@x') === "'@x", 'valores iniciados por = + - @ recebem apóstrofo');
ok(SheetsClient::sanitizeCell('Ana = Bia') === 'Ana = Bia' && SheetsClient::sanitizeCell(12) === 12 && SheetsClient::sanitizeCell(null) === '', 'texto comum, números e nulos passam inalterados');
ok(SheetsClient::range("Turma d'água", 'A1:B2') === "'Turma d''água'!A1:B2" && SheetsClient::colLetter(1) === 'A' && SheetsClient::colLetter(27) === 'AA', 'notação A1 com aspas escapadas e letras de coluna');
ok(SheetsClient::parseId("https://docs.google.com/spreadsheets/d/$ALUNOS/edit#gid=0") === $ALUNOS && SheetsClient::parseId($ALUNOS) === $ALUNOS && SheetsClient::parseId('curto') === null && SheetsClient::parseId('javascript:alert(1)') === null, 'ID extraído de link ou aceito puro; lixo recusado');
$kp = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]); openssl_pkey_export($kp, $saPem); $saPub = openssl_pkey_get_details($kp)['key'];
$jwt = GoogleJwt::assertion(['client_email' => 'celef-sync@proj-celef.iam.gserviceaccount.com', 'private_key' => $saPem], 'escopo', 'https://aud/token', 1000);
[$h, $p, $sg] = explode('.', $jwt); $un = static fn($x) => base64_decode(strtr($x, '-_', '+/'));
$claims = json_decode($un($p), true);
ok(openssl_verify("$h.$p", $un($sg), $saPub, OPENSSL_ALGO_SHA256) === 1 && $claims['iss'] === 'celef-sync@proj-celef.iam.gserviceaccount.com' && $claims['exp'] === 4600 && json_decode($un($h), true)['alg'] === 'RS256', 'JWT RS256 da Service Account: assinatura e claims corretos');
ok(GoogleJwt::validate('x@gmail.com', $saPem) !== null && GoogleJwt::validate('a@p.iam.gserviceaccount.com', 'lixo') !== null && GoogleJwt::validate('a@p.iam.gserviceaccount.com', $saPem) === null, 'validação da Service Account');

echo "== Conta técnica (OAuth com refresh token)\n";
$b = new Browser($BASE, $MOCK);
$b->login($flavio);
$b->get('/admin/conta-tecnica');
ok($b->status === 200 && $b->has('Não conectada'), 'tela mostra "Não conectada"');
$b->setGoogleUser($flavio); $b->post('/admin/conta-tecnica/conectar'); $b->forwardCallback();
ok($b->has('Você autorizou com a conta flaviospina@scseduca.com.br') && GoogleOAuthToken::activeCredential() === null, 'autorizar com a conta errada é recusado e nada é gravado');
$b->setGoogleUser($celef); $b->get('/admin/conta-tecnica'); $b->post('/admin/conta-tecnica/conectar'); $b->forwardCallback();
$req = json_decode((string) file_get_contents("$MOCK/last_auth_request.json"), true);
ok(($req['access_type'] ?? '') === 'offline' && str_contains($req['prompt'] ?? '', 'consent') && ($req['login_hint'] ?? '') === 'celef@scseduca.com.br' && str_contains($req['scope'] ?? '', 'auth/spreadsheets') && str_contains($req['scope'], 'drive.metadata.readonly'), 'pedido ao Google: offline, consent, login_hint celef@ e escopos mínimos');
$cred = GoogleOAuthToken::activeCredential();
$refresh = json_decode((string) file_get_contents("$MOCK/refresh.json"), true)[0] ?? '';
ok($b->has('Conectada') && $cred !== null && $cred['account_email'] === 'celef@scseduca.com.br' && $cred['kind'] === 'OAUTH_USER_ACCOUNT', 'conta técnica celef@ conectada');
ok($refresh !== '' && !str_contains((string) $cred['secret_enc'], $refresh) && !$b->has($refresh), 'refresh token gravado cifrado e nunca exibido');
ok(Database::value("SELECT r.code FROM users u JOIN roles r ON r.id = u.role_id WHERE u.email = 'flaviospina@scseduca.com.br'") === 'SUPER_ADMIN' && $b->has('Flávio'), 'a sessão do sistema continua sendo a do Super Admin (não a da celef@)');
$b->post('/admin/conta-tecnica/testar');
ok($b->has('Token renovado com sucesso'), 'botão Testar renova o token');
ok(is_file(STORAGE_PATH . '/cache/google-access-token.bin') && !str_contains((string) file_get_contents(STORAGE_PATH . '/cache/google-access-token.bin'), 'mock-access'), 'access token em cache cifrado');

echo "== Planilhas conectadas\n";
$b->get('/admin/planilhas');
$b->post('/admin/planilhas', ['spreadsheet_id' => $ALUNOS, 'name' => 'CELEF • ALUNOS 2026', 'sheet_role' => 'ESPELHO_ESCOLA', 'school_year' => '2026']);
$idAlunos = (int) Database::value('SELECT id FROM connected_sheets WHERE spreadsheet_id = :s', ['s' => $ALUNOS]);
ok($idAlunos > 0 && $b->has('Testar conexão'), 'planilha da escola cadastrada');
$b->post("/admin/planilhas/$idAlunos/testar");
$tabs = Database::rows('SELECT tab_title, tab_kind FROM connected_sheet_tabs WHERE connected_sheet_id = :s ORDER BY id', ['s' => $idAlunos]);
ok($b->has('acessível pela conta técnica') && $b->has('4 aba(s)') && $b->has('NOME | E-MAIL'), 'teste de conexão lista abas e cabeçalhos');
ok(array_column($tabs, 'tab_kind', 'tab_title') === ['1A' => 'TURMA', '6A' => 'TURMA', 'REMANEJAMENTOS 2027' => 'REMANEJAMENTOS', 'TOTAL ALUNOS' => 'TOTAIS'], 'abas registradas com o tipo sugerido');
ok(Database::value('SELECT owner_email FROM connected_sheets WHERE id = :i', ['i' => $idAlunos]) === 'celef@scseduca.com.br', 'dono do arquivo lido via Drive API');
$b->get('/admin/planilhas'); $b->post('/admin/planilhas', ['spreadsheet_id' => $ALUNOS, 'name' => 'Duplicada', 'sheet_role' => 'ESPELHO_ESCOLA', 'school_year' => '2026']);
ok($b->has('já está cadastrada'), 'planilha duplicada é recusada');
$b->post('/admin/planilhas', ['spreadsheet_id' => 'xx', 'name' => 'Inválida', 'sheet_role' => 'ESPELHO_ESCOLA']);
ok($b->has('Informe o link ou o ID'), 'ID inválido é recusado');
$b->post('/admin/planilhas', ['spreadsheet_id' => $SECR, 'name' => 'Secretaria de Educação', 'sheet_role' => 'FONTE_SECRETARIA', 'school_year' => '2026']);
$idSecr = (int) Database::value('SELECT id FROM connected_sheets WHERE spreadsheet_id = :s', ['s' => $SECR]);
$rowSecr = Database::row('SELECT direction, write_enabled FROM connected_sheets WHERE id = :i', ['i' => $idSecr]);
ok($rowSecr['direction'] === 'IN' && (int) $rowSecr['write_enabled'] === 0, 'fonte da Secretaria nasce somente leitura');
$b->post("/admin/planilhas/$idSecr/testar");
ok($b->has('acessível pela conta técnica') && !$b->has('ATENÇÃO'), 'fonte da Secretaria: acesso de Leitor basta');
$b->post("/admin/planilhas/$idSecr", ['name' => 'Secretaria de Educação', 'sheet_role' => 'FONTE_SECRETARIA', 'direction' => 'BOTH', 'school_year' => '2026']);
ok($b->has('digite SIM') && (int) Database::value('SELECT write_enabled FROM connected_sheets WHERE id = :i', ['i' => $idSecr]) === 0, 'escrita na planilha da Secretaria exige confirmação explícita');
$b->post("/admin/planilhas/$idSecr", ['name' => 'Secretaria de Educação', 'sheet_role' => 'FONTE_SECRETARIA', 'direction' => 'IN', 'school_year' => '2026']);
$b->post('/admin/planilhas', ['spreadsheet_id' => $NAO, 'name' => 'Não compartilhada', 'sheet_role' => 'ESPELHO_ESCOLA', 'school_year' => '2026']);
$idNao = (int) Database::value('SELECT id FROM connected_sheets WHERE spreadsheet_id = :s', ['s' => $NAO]);
$b->post("/admin/planilhas/$idNao/testar");
ok($b->has('Sem permissão. Compartilhe esta planilha com celef@scseduca.com.br'), 'planilha não compartilhada: mensagem clara de como compartilhar');
$s = $sheet($ALUNOS); $s['shared'] = 'reader'; $putSheet($ALUNOS, $s);
$b->post("/admin/planilhas/$idAlunos/testar");
ok($b->has('só tem leitura') && $b->has('EDITOR'), 'espelho da escola com acesso só de leitura gera aviso');
$s['shared'] = 'editor'; $putSheet($ALUNOS, $s);
$b->post("/admin/planilhas/$idNao/excluir", ['motivo' => 'Cadastro feito por engano no teste']);
ok(Database::value('SELECT deleted_at FROM connected_sheets WHERE id = :i', ['i' => $idNao]) !== null && is_file("$MOCK/sheets/$NAO.json"), 'desconectar = exclusão lógica; o arquivo no Google não é tocado');

echo "== Planilha de logs\n";
$b->get('/admin/planilha-logs');
ok($b->has('Nenhuma planilha de logs configurada'), 'sem planilha: aviso permanente e o sistema segue só com o banco');
$pendBefore = (int) Database::value("SELECT COUNT(*) FROM sheet_log_outbox WHERE status = 'PENDING'");
ok($pendBefore > 10, "fila acumulou enquanto não havia planilha ($pendBefore linhas)");
$b->post('/admin/planilha-logs', ['spreadsheet_id' => $ALUNOS]);
ok($b->has('já está cadastrada como planilha de dados'), 'planilha de dados não pode ser usada como planilha de logs');
$b->post('/admin/planilha-logs', ['spreadsheet_id' => $LOGS]);
ok($b->has('Planilha de logs definida'), 'planilha de logs definida');
Database::setActor(1, 'APP'); AuditLog::setActor(1, 'flaviospina@scseduca.com.br', 'SUPER_ADMIN');
$inj = AuditLog::log('EDITAR', 'students', 1, '=HYPERLINK("http://mal.example","clique")');
$b->post('/admin/planilha-logs/testar');
$ls = $sheet($LOGS);
ok($b->has('Escrita OK') && count(array_intersect(SheetLogger::TABS, array_column($ls['tabs'], 'title'))) === 7, 'teste de escrita criou as 7 abas');
$aud = $tabOf($ls, 'AUDITORIA');
ok($aud['values'][0] === SheetLogger::HEADER && $aud['frozen'] === 1, 'cabeçalho gravado e linha 1 congelada');
ok(($aud['protected'][0]['editors'] ?? []) === ['celef@scseduca.com.br'] && $aud['protected'][0]['warningOnly'] === false, 'aba protegida: só a conta técnica edita');
$done = (int) Database::value("SELECT COUNT(*) FROM sheet_log_outbox WHERE status = 'DONE'");
$inSheet = 0; foreach (SheetLogger::TABS as $t) { $inSheet += count($tabOf($ls, $t)['values']) - 1; }
ok($done >= $pendBefore && $inSheet === $done && (int) Database::value("SELECT COUNT(*) FROM sheet_log_outbox WHERE status <> 'DONE'") === 0, "fila esvaziada: $done linhas no banco = $inSheet linhas na planilha");
$rowInj = Database::row('SELECT sheet_row_number FROM sheet_log_outbox WHERE audit_log_id = :a', ['a' => $inj]);
ok(str_starts_with($aud['values'][(int) $rowInj['sheet_row_number'] - 1][6], "'=HYPERLINK"), 'injeção de fórmula neutralizada na planilha (apóstrofo + RAW)');
$acessos = $tabOf($ls, 'ACESSOS'); $flat = json_encode($ls);
ok(count($acessos['values']) > 1 && $acessos['values'][1][3] === 'LOGIN' && strlen($acessos['values'][1][9]) === 64, 'aba ACESSOS recebeu o LOGIN com o hash da auditoria');
ok(!preg_match('/\d{3}\.\d{3}\.\d{3}-\d{2}/', $flat), 'nenhum CPF na planilha de logs');
$b->post('/admin/planilha-logs/testar');
ok($b->has('As 7 abas já existiam') && count($tabOf($sheet($LOGS), 'AUDITORIA')['protected']) === 1, 'repetir o teste é idempotente (não duplica abas nem proteções)');

echo "== Robustez: retentativa, token expirado, autorização revogada\n";
AuditLog::log('VER', 'students', 1, 'linha para teste de retentativa');
file_put_contents("$MOCK/fail_next.json", json_encode(['count' => 2, 'status' => 503]));
$t0 = microtime(true); $r = SheetLogger::flush(time() + 40); $dt = microtime(true) - $t0;
ok($r['enviadas'] >= 1 && $r['falhas'] === 0 && $dt >= 2.5, sprintf('dois erros 503 seguidos: retentativa exponencial e sucesso (%.1f s)', $dt));
AuditLog::log('VER', 'students', 1, 'linha para teste de token expirado');
file_put_contents("$MOCK/access.json", '[]');
$r = SheetLogger::flush(time() + 30);
ok($r['enviadas'] >= 1 && $r['falhas'] === 0, 'access token invalidado no meio: 401 → renova e reenvia');
AuditLog::log('VER', 'students', 1, 'linha para teste de autorização revogada');
file_put_contents("$MOCK/refresh.json", '[]'); file_put_contents("$MOCK/access.json", '[]'); GoogleOAuthToken::clearCache();
$r = SheetLogger::flush(time() + 30);
$cred = GoogleOAuthToken::activeCredential();
ok($r['enviadas'] === 0 && $r['pendentes'] >= 1 && $cred['status'] === 'ERROR', 'refresh token revogado: credencial vira ERROR e a fila aguarda (nada se perde)');
ok(Database::value("SELECT kind FROM security_events WHERE kind = 'TOKEN_GOOGLE_INVALIDO' ORDER BY id DESC LIMIT 1") === 'TOKEN_GOOGLE_INVALIDO', 'evento TOKEN_GOOGLE_INVALIDO e alerta aos administradores');
$b->get('/admin/conta-tecnica');
ok($b->has('Autorização inválida') && $b->has('Reconectar conta Google'), 'admin mostra "Autorização inválida" e pede Reconectar');
$b->setGoogleUser($celef); $b->post('/admin/conta-tecnica/conectar'); $b->forwardCallback();
Database::run("UPDATE sheet_log_outbox SET next_attempt_at = NOW() WHERE status = 'FAILED'");
$r = SheetLogger::flush(time() + 30);
ok($b->has('Conectada') && $r['pendentes'] === 0, 'após reconectar, a fila é enviada por completo');

echo "== Conferência planilha × banco\n";
$b->get('/admin/planilha-logs'); $b->post('/admin/planilha-logs/conferir');
ok($b->has('corresponde exatamente ao banco'), 'conferência sem divergências');
$ls = $sheet($LOGS);
foreach ($ls['tabs'] as &$t) {
    if ($t['title'] === 'AUDITORIA') { array_splice($t['values'], 2, 1); }                         // apaga uma linha
    if ($t['title'] === 'ACESSOS')   { $t['values'][1][1] = 'outra.pessoa@scseduca.com.br'; }        // altera o usuário de um login
    if ($t['title'] === 'ADMIN')     { $t['values'][] = ['2026-11-27 10:00:00 UTC', 'x@scseduca.com.br', 'ADMIN', 'ADMIN', '', '', 'linha inventada', '', 'APP', str_repeat('a', 64)]; }
}
unset($t); $putSheet($LOGS, $ls);
$b->post('/admin/planilha-logs/conferir');
ok($b->has('1 apagada(s), 1 alterada(s), 1 estranha(s)'), 'conferência detecta linha apagada, linha alterada e linha inventada');
ok($b->has('outra.pessoa@scseduca.com.br') && $b->has('linha inventada'), 'a tela mostra o que mudou (banco × planilha)');
ok(Database::value("SELECT kind FROM security_events WHERE kind = 'PLANILHA_LOGS_ADULTERADA' ORDER BY id DESC LIMIT 1") === 'PLANILHA_LOGS_ADULTERADA', 'evento crítico PLANILHA_LOGS_ADULTERADA registrado');

echo "== Cron, Service Account, revogação, permissões\n";
AuditLog::log('VER', 'students', 1, 'linha para o cron');
$out = shell_exec(PHP_BINARY . ' ' . escapeshellarg(APP_ROOT . '/cron/flush_sheet_log.php') . ' 2>&1');
ok(str_contains((string) $out, '[flush_sheet_log] OK') && str_contains((string) $out, 'enviada(s)'), 'cron flush_sheet_log.php: ' . trim((string) $out));
file_put_contents("$MOCK/sa_pub.pem", $saPub);
$b->get('/admin/conta-tecnica');
$b->post('/admin/conta-tecnica/service-account', ['sa_email' => 'celef-sync@proj-celef.iam.gserviceaccount.com', 'sa_key_b64' => base64_encode($saPem)]);
$cred = GoogleOAuthToken::activeCredential();
ok($cred['kind'] === 'SERVICE_ACCOUNT' && $b->has('Service Account gravada') && $b->has('Token renovado com sucesso') && !str_contains((string) $cred['secret_enc'], 'PRIVATE KEY'), 'Service Account: chave cifrada e token obtido por JWT RS256');
ok((int) Database::value('SELECT COUNT(*) FROM google_credentials WHERE is_active = 1') === 1, 'continua existindo uma única credencial ativa');
$b->post('/admin/conta-tecnica/service-account', ['sa_email' => 'x@gmail.com', 'sa_key_b64' => base64_encode($saPem)]);
ok($b->has('não parece ser de uma Service Account'), 'Service Account inválida é recusada');
$b->post('/admin/conta-tecnica/revogar', ['motivo' => 'curto']);
ok($b->has('no mínimo 10 caracteres'), 'revogar exige motivo');
$b->post('/admin/conta-tecnica/revogar', ['motivo' => 'Encerrando o teste da Service Account']);
ok(GoogleOAuthToken::activeCredential() === null && Database::value('SELECT secret_enc FROM google_credentials ORDER BY id DESC LIMIT 1') === null && $b->has('Não conectada'), 'revogação apaga o segredo cifrado e desativa a credencial');
$adminId = Database::insert('users', ['email' => 'admin.teste@scseduca.com.br', 'full_name' => 'Admin Teste', 'role_id' => (int) Database::value("SELECT id FROM roles WHERE code = 'ADMIN'"), 'privacy_version' => '1.0']);
$a = new Browser($BASE, $MOCK, 'Teste/admin');
$a->login(['email' => 'admin.teste@scseduca.com.br', 'sub' => 'sub-admin', 'hd' => 'scseduca.com.br', 'email_verified' => true, 'name' => 'Admin Teste']);
$a->get('/admin'); $okAdmin = $a->status === 200;
$a->get('/admin/conta-tecnica'); $s1 = $a->status; $a->get('/admin/planilhas'); $s2 = $a->status; $a->get('/admin/planilha-logs'); $s3 = $a->status;
ok($okAdmin && $s1 === 403 && $s2 === 403 && $s3 === 403, 'Administrador comum não acessa conta técnica nem planilhas (exclusivo do Super Admin)');
ok(AuditLog::verifyChain()['ok'], 'cadeia de hash da auditoria íntegra ao final');
finish();
