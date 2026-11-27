<?php
// tools/test_phase2.php — testes do núcleo de segurança (executar via CLI: php tools/test_phase2.php)
declare(strict_types=1);

define('APP_ROOT', dirname(__DIR__));
require APP_ROOT . '/app/bootstrap.php';

use App\Database;
use App\Security\AuditLog;
use App\Security\Crypto;
use App\Security\Csrf;
use App\Security\Masker;
use App\Security\RateLimiter;
use App\Security\SecureSession;
use App\Security\SecurityEvents;
use App\Security\Validator;

// a sessão precisa iniciar antes de qualquer saída (mesmo no CLI)
SecureSession::start();
$csrfToken = Csrf::token();

$pass = 0; $fail = 0;
function ok(bool $cond, string $label, string $extra = ''): void {
    global $pass, $fail;
    if ($cond) { $pass++; echo "  ✔ $label\n"; } else { $fail++; echo "  ✘ $label $extra\n"; }
}
function fails(callable $fn, string $label): void {
    try { $fn(); ok(false, $label, '(não lançou exceção)'); } catch (\Throwable $e) { ok(true, $label . '  [' . mb_substr($e->getMessage(), 0, 70) . ']'); }
}

echo "== Crypto\n";
$c = Crypto::encrypt('123.456.789-09', 'students.cpf');
ok($c !== null && Crypto::decrypt($c, 'students.cpf') === '123.456.789-09', 'cifra e decifra com contexto');
ok(Crypto::blobVersion((string) $c) === 1, 'versão da chave no blob');
ok(Crypto::encrypt('abc') !== Crypto::encrypt('abc'), 'nonce aleatório: mesmo texto, blobs diferentes');
fails(fn() => Crypto::decrypt($c, 'students.rg'), 'contexto diferente não decifra');
fails(fn() => Crypto::decrypt(substr((string) $c, 0, -1) . 'x'), 'blob adulterado não decifra');
ok(Crypto::encrypt(null) === null && Crypto::encrypt('') === null, 'vazio → NULL');
ok(Crypto::blindIndex('12345678909') === Crypto::blindIndex('12345678909') && strlen((string) Crypto::blindIndex('x')) === 32, 'blind index determinístico de 32 bytes');
ok(Crypto::normalizeDigits('123.456.789-09') === '12345678909' && Crypto::normalizeEmail(' Ana@SCSEDUCA.com.br ') === 'ana@scseduca.com.br', 'normalização');
$tmp = STORAGE_PATH . '/tmp/t_' . bin2hex(random_bytes(4));
file_put_contents($tmp . '.in', random_bytes(200000) . 'FIM');
Crypto::encryptFile($tmp . '.in', $tmp . '.enc');
$out = fopen($tmp . '.out', 'wb'); Crypto::decryptFileToStream($tmp . '.enc', $out); fclose($out);
ok(hash_file('sha256', $tmp . '.in') === hash_file('sha256', $tmp . '.out'), 'arquivo cifrado/decifrado em blocos (200 KB)');
ok(substr((string) file_get_contents($tmp . '.enc'), 1, 5) !== substr((string) file_get_contents($tmp . '.in'), 0, 5), 'conteúdo cifrado difere do original');
array_map('unlink', [$tmp . '.in', $tmp . '.enc', $tmp . '.out']);

echo "== Validator\n";
ok(Validator::isCpf('529.982.247-25') && !Validator::isCpf('529.982.247-24') && !Validator::isCpf('111.111.111-11'), 'CPF com dígitos verificadores');
ok(Validator::parseDateBr('05/03/2015') === '2015-03-05' && Validator::parseDateBr('31/02/2015') === null, 'data dd/mm/aaaa');
ok(Validator::normalizeName('  José   da Conceição ') === 'JOSE DA CONCEICAO', 'normalização de nome');
$v = new Validator(['email' => 'x@gmail.com', 'cpf' => '123', 'motivo' => 'curto']);
$v->scsEducaEmail('email', 'E-mail')->cpf('cpf')->minReason('motivo');
ok($v->fails() && count($v->errors()) === 3, 'erros em pt-BR: ' . implode(' | ', $v->errors()));

echo "== Masker\n";
ok(Masker::cpf('529.982.247-25') === '***.***.247-**', 'CPF mascarado');
ok(Masker::email('ana.souza@scseduca.com.br') === 'a***@scseduca.com.br', 'e-mail mascarado');
ok(Masker::phone('(11) 98765-4321') === '(**) *****-4321', 'telefone mascarado');
$d = Masker::scrubArray(['full_name' => ['de' => 'Ana', 'para' => 'Ana S.'], 'cpf' => ['de' => '52998224725', 'para' => '12345678909'], 'guardian_phone' => '11987654321', 'obs' => 'contato 529.982.247-25']);
ok($d['cpf']['de'] === '***.***.247-**' && $d['guardian_phone'] === '(**) *****-4321' && $d['full_name']['de'] === 'Ana' && str_contains($d['obs'], '***.***.247-**'), 'diff mascarado por chave e por padrão no texto');

echo "== Sessão e CSRF\n";
$t = $csrfToken;
$_SERVER['HTTP_ORIGIN'] = 'http://127.0.0.1:8088';
ok(strlen($t) === 64 && Csrf::validate($t), 'token válido com Origin correto');
$_SERVER['HTTP_ORIGIN'] = 'https://atacante.exemplo';
ok(!Csrf::validate($t), 'token válido mas Origin estranho → negado');
unset($_SERVER['HTTP_ORIGIN']);
ok(!Csrf::validate($t), 'sem Origin/Referer → negado');
$_SERVER['HTTP_REFERER'] = 'http://127.0.0.1:8088/pagina';
ok(Csrf::validate($t) && !Csrf::validate(strrev($t)) && !Csrf::validate(null), 'Referer aceito; token errado/ausente negado');

echo "== Banco e contexto\n";
Database::setActor(1, 'APP');
AuditLog::setActor(1, 'flaviospina@scseduca.com.br', 'SUPER_ADMIN');
ok(Database::value('SELECT @app_user_id') === 1 && Database::value('SELECT @app_origin') === 'APP', '@app_user_id/@app_origin definidos na conexão');
$sid = Database::insert('students', ['full_name' => 'Teste Fase Dois', 'full_name_norm' => 'TESTE FASE DOIS',
    'cpf_enc' => Crypto::encrypt('529.982.247-25', 'students.cpf'), 'cpf_bidx' => Crypto::blindIndex('52998224725'), 'key_version' => Crypto::currentVersion()]);
$found = Database::row('SELECT id, cpf_enc FROM students WHERE cpf_bidx = :b', ['b' => Crypto::blindIndex('52998224725')]);
ok($found !== null && (int) $found['id'] === $sid && Crypto::decrypt($found['cpf_enc'], 'students.cpf') === '529.982.247-25', 'busca por blind index e decifra');
ok(Database::updateVersioned('students', $sid, 1, ['group_name' => 'G1']) === true, 'update com versão correta grava');
ok(Database::updateVersioned('students', $sid, 1, ['group_name' => 'G2']) === false, 'update com versão antiga é recusado (lock otimista)');
ok((int) Database::value('SELECT version FROM students WHERE id = :id', ['id' => $sid]) === 2, 'version = 2');

echo "== AuditLog\n";
$before = (int) Database::value('SELECT COUNT(*) FROM audit_log');
$id1 = AuditLog::log('EDITAR', 'students', $sid, 'Editou aluno Teste', ['group_name' => ['de' => null, 'para' => 'G1'], 'cpf' => ['de' => '52998224725', 'para' => '52998224725']]);
$row = Database::row('SELECT * FROM audit_log WHERE id = :id', ['id' => $id1]);
ok($row['user_email'] === 'flaviospina@scseduca.com.br' && $row['origin'] === 'APP' && strlen($row['hash']) === 64, 'linha gravada com autor, origem e hash');
ok(str_contains((string) $row['diff_json'], '***.***.247-**') && !str_contains((string) $row['diff_json'], '52998224725'), 'diff_json mascarado');
ok($row['diff_json'] === '{"cpf":{"de":"***.***.247-**","para":"***.***.247-**"},"group_name":{"de":null,"para":"G1"}}', 'JSON canônico (chaves ordenadas)');
$q = Database::row('SELECT tab_name, row_values_json FROM sheet_log_outbox WHERE audit_log_id = :id', ['id' => $id1]);
ok($q !== null && $q['tab_name'] === 'AUDITORIA' && !str_contains($q['row_values_json'], '247'), 'linha enfileirada para a planilha de logs, sem dado sensível');
fails(fn() => AuditLog::log('INVENTADA'), 'ação desconhecida é rejeitada');
$chain = AuditLog::verifyChain();
ok($chain['ok'] && $chain['checked'] >= $before + 1, "cadeia íntegra ({$chain['checked']} linhas)");
$tampered = $row; $tampered['summary'] = 'x'; $tampered['occurred_at'] = Database::value("SELECT DATE_FORMAT(occurred_at,'%Y-%m-%d %H:%i:%s.%f') FROM audit_log WHERE id = :id", ['id' => $id1]);
ok(AuditLog::computeHash($tampered) !== $row['hash'], 'alteração de conteúdo muda o hash recalculado');
ok(AuditLog::missingTriggers() === [], 'sonda de triggers: tudo ativo');
// concorrência: 2 processos inserindo ao mesmo tempo não bifurcam a cadeia
$procs = [];
for ($i = 0; $i < 2; $i++) {
    $procs[] = proc_open([PHP_BINARY, '-r', 'define("APP_ROOT","' . APP_ROOT . '"); require APP_ROOT."/app/bootstrap.php"; App\Database::setActor(1,"APP"); App\Security\AuditLog::setActor(1,"flaviospina@scseduca.com.br","SUPER_ADMIN"); for($j=0;$j<15;$j++){ App\Security\AuditLog::log("VER","students",1,"concorrência ' . $i . ' $j"); }'], [], $pipes);
}
foreach ($procs as $p) { proc_close($p); }
$chain = AuditLog::verifyChain();
ok($chain['ok'], "cadeia íntegra após 30 inserções concorrentes em 2 processos ({$chain['checked']} linhas)", (string) $chain['detail']);

echo "== SecurityEvents\n";
$ev = SecurityEvents::record('LEITURA_MASSIVA', SecurityEvents::AVISO, 'Usuário leu 60 fichas em 1 hora', ['fichas' => 60, 'cpf' => '52998224725'], 'users', 1);
$alert = Database::row('SELECT recipients_json, subject, body_text FROM alert_outbox WHERE security_event_id = :id', ['id' => $ev]);
ok($alert !== null && str_contains($alert['recipients_json'], 'flaviospina@scseduca.com.br') && str_contains($alert['subject'], 'LEITURA_MASSIVA'), 'alerta enfileirado para os administradores');
ok(!str_contains($alert['body_text'], '52998224725'), 'corpo do alerta sem CPF em claro');

echo "== RateLimiter\n";
$k = 'teste:' . bin2hex(random_bytes(4));
$r1 = RateLimiter::hit($k, 2, 60); $r2 = RateLimiter::hit($k, 2, 60); $r3 = RateLimiter::hit($k, 2, 60, 120);
ok($r1['allowed'] && $r2['allowed'] && !$r3['allowed'] && $r3['retry_after'] === 120, '3ª ocorrência bloqueada por 120 s');
ok(!RateLimiter::hit($k, 2, 60)['allowed'], 'segue bloqueado enquanto durar o bloqueio');

echo "\nRESULTADO: $pass ok, $fail falhas\n";
exit($fail === 0 ? 0 : 1);
