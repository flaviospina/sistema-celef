<?php
// tools/mock_google.php — emulador MÍNIMO do OpenID Connect do Google para testes locais (NUNCA em produção).
// Uso: php -S 127.0.0.1:8090 tools/mock_google.php   (e GOOGLE_DISCOVERY_URL=http://127.0.0.1:8090/.well-known/openid-configuration no .env)
// O "usuário que faz login" vem do arquivo /dev/shm/mock_google/user.json: {"email":..., "sub":..., "hd":..., "email_verified":true}
declare(strict_types=1);

$dir = '/dev/shm/mock_google';
@mkdir($dir, 0700, true);
$base = 'http://' . $_SERVER['HTTP_HOST'];
$path = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);

if (!is_file("$dir/key.pem")) {
    $k = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    openssl_pkey_export($k, $pem);
    file_put_contents("$dir/key.pem", $pem);
}
$priv = openssl_pkey_get_private((string) file_get_contents("$dir/key.pem"));
$det = openssl_pkey_get_details($priv);
$b64 = static fn(string $s) => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');

header('Content-Type: application/json');
switch (true) {
    case $path === '/.well-known/openid-configuration':
        echo json_encode(['issuer' => $base, 'authorization_endpoint' => "$base/auth", 'token_endpoint' => "$base/token", 'jwks_uri' => "$base/jwks", 'revocation_endpoint' => "$base/revoke"]);
        break;
    case $path === '/jwks':
        echo json_encode(['keys' => [['kty' => 'RSA', 'alg' => 'RS256', 'use' => 'sig', 'kid' => 'mock-k1', 'n' => $b64($det['rsa']['n']), 'e' => $b64($det['rsa']['e'])]]]);
        break;
    case $path === '/auth':
        // guarda o pedido e devolve o "code" para o redirect_uri (como o Google faria após o usuário consentir)
        $code = bin2hex(random_bytes(16));
        file_put_contents("$dir/code-$code.json", json_encode($_GET));
        file_put_contents("$dir/last_auth_request.json", json_encode($_GET));
        header('Content-Type: text/html');
        // como o Google real: acrescenta iss (URL) e scope, e devolve na QUERY mesmo que se peça response_mode=fragment
        $sep = '?';
        header('Location: ' . $_GET['redirect_uri'] . $sep . http_build_query(['state' => $_GET['state'], 'code' => $code, 'scope' => 'email profile openid https://www.googleapis.com/auth/userinfo.email', 'authuser' => '0', 'hd' => 'scseduca.com.br', 'prompt' => 'none', 'iss' => $base]), true, 302);
        break;
    case $path === '/revoke':
        $valid = json_decode((string) @file_get_contents("$dir/refresh.json"), true) ?: [];
        file_put_contents("$dir/refresh.json", json_encode(array_values(array_diff($valid, [(string) ($_POST['token'] ?? '')]))));
        echo '{}';
        break;
    case $path === '/token' && ($_POST['grant_type'] ?? '') === 'refresh_token':
        $valid = json_decode((string) @file_get_contents("$dir/refresh.json"), true) ?: [];
        if (!in_array((string) ($_POST['refresh_token'] ?? ''), $valid, true) || ($_POST['client_secret'] ?? '') !== 'test-secret') {
            http_response_code(400); echo json_encode(['error' => 'invalid_grant', 'error_description' => 'Token has been expired or revoked.']); break;
        }
        echo json_encode(['access_token' => mock_issue_access($dir), 'expires_in' => 3600, 'token_type' => 'Bearer', 'scope' => 'https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/drive.metadata.readonly']);
        break;
    case $path === '/token' && ($_POST['grant_type'] ?? '') === 'urn:ietf:params:oauth:grant-type:jwt-bearer':
        // Service Account: confere a assinatura RS256 com a chave pública que o teste deixou em sa_pub.pem
        $parts = explode('.', (string) ($_POST['assertion'] ?? ''));
        $pub = @file_get_contents("$dir/sa_pub.pem");
        $un = static fn(string $x) => base64_decode(strtr($x, '-_', '+/') . str_repeat('=', (4 - strlen($x) % 4) % 4));
        $claims = count($parts) === 3 ? json_decode($un($parts[1]), true) : null;
        if ($pub === false || !is_array($claims) || openssl_verify($parts[0] . '.' . $parts[1], $un($parts[2]), $pub, OPENSSL_ALGO_SHA256) !== 1
            || !str_ends_with((string) $claims['iss'], '.iam.gserviceaccount.com') || $claims['aud'] !== "$base/token" || $claims['exp'] < time()) {
            http_response_code(400); echo json_encode(['error' => 'invalid_grant', 'error_description' => 'Invalid JWT Signature.']); break;
        }
        file_put_contents("$dir/last_sa_claims.json", json_encode($claims));
        echo json_encode(['access_token' => mock_issue_access($dir), 'expires_in' => 3600, 'token_type' => 'Bearer']);
        break;
    case $path === '/token':
        $code = (string) ($_POST['code'] ?? '');
        $file = "$dir/code-" . preg_replace('/[^a-f0-9]/', '', $code) . '.json';
        if (!is_file($file)) { http_response_code(400); echo json_encode(['error' => 'invalid_grant']); break; }
        $req = json_decode((string) file_get_contents($file), true);
        unlink($file); // código de uso único
        $challenge = rtrim(strtr(base64_encode(hash('sha256', (string) ($_POST['code_verifier'] ?? ''), true)), '+/', '-_'), '=');
        if ($challenge !== ($req['code_challenge'] ?? '') || ($_POST['client_id'] ?? '') !== $req['client_id'] || ($_POST['client_secret'] ?? '') !== 'test-secret') {
            http_response_code(400); echo json_encode(['error' => 'invalid_grant', 'detail' => 'pkce/client']); break;
        }
        $user = json_decode((string) @file_get_contents("$dir/user.json"), true) ?: ['email' => 'flaviospina@scseduca.com.br', 'sub' => '1001', 'hd' => 'scseduca.com.br', 'email_verified' => true];
        $now = time();
        $payload = ['iss' => $base, 'aud' => $req['client_id'], 'azp' => $req['client_id'], 'sub' => $user['sub'], 'email' => $user['email'], 'email_verified' => $user['email_verified'],
                    'nonce' => $req['nonce'], 'iat' => $now, 'exp' => $now + 3600, 'auth_time' => $now, 'name' => $user['name'] ?? 'Usuário Teste', 'picture' => 'https://lh3.googleusercontent.com/x'];
        if (isset($user['hd'])) { $payload['hd'] = $user['hd']; }
        if (!empty($user['tamper'])) { $payload['email'] = 'outro@scseduca.com.br'; }
        $h = $b64(json_encode(['alg' => 'RS256', 'typ' => 'JWT', 'kid' => 'mock-k1']));
        $p = $b64(json_encode($payload));
        openssl_sign("$h.$p", $sig, $priv, OPENSSL_ALGO_SHA256);
        $jwt = "$h.$p." . $b64($sig);
        if (!empty($user['tamper'])) { $jwt = "$h.$p." . $b64(str_repeat("\0", strlen($sig))); } // assinatura inválida
        $resp = ['access_token' => mock_issue_access($dir), 'id_token' => $jwt, 'expires_in' => 3600, 'token_type' => 'Bearer', 'scope' => (string) ($req['scope'] ?? '')];
        if (($req['access_type'] ?? '') === 'offline' && empty($user['no_refresh'])) {       // conta técnica: devolve refresh token
            $rt = 'mock-refresh-' . bin2hex(random_bytes(12));
            $valid = json_decode((string) @file_get_contents("$dir/refresh.json"), true) ?: [];
            $valid[] = $rt; file_put_contents("$dir/refresh.json", json_encode($valid));
            $resp['refresh_token'] = $rt;
        }
        echo json_encode($resp);
        break;
    case str_starts_with($path, '/v4/spreadsheets/') || str_starts_with($path, '/drive/v3/files/'):
        mock_api($dir, $path);
        break;
    default:
        http_response_code(404); echo json_encode(['error' => 'not_found']);
}


// ====================================================================================================
// Emulação das APIs Google Sheets v4 e Drive v3 (o suficiente para os testes do Sistema CELEF)
// Planilhas ficam em /dev/shm/mock_google/sheets/<id>.json:
//   {"title":..,"shared":"editor"|"reader"|false,"owner":..,"tabs":[{"gid":1,"title":"..","frozen":0,"protected":[],"values":[[..]]}],"revisions":[..]}
// ====================================================================================================
function mock_issue_access(string $dir): string
{
    $t = 'mock-access-' . bin2hex(random_bytes(8));
    $list = json_decode((string) @file_get_contents("$dir/access.json"), true) ?: [];
    $list[] = $t; file_put_contents("$dir/access.json", json_encode(array_slice($list, -50)));
    return $t;
}

function mock_err(int $status, string $reason, string $msg): void
{
    http_response_code($status);
    echo json_encode(['error' => ['code' => $status, 'message' => $msg, 'status' => $reason]]);
}

function mock_parse_range(string $range): array
{
    $tab = $range; $cells = '';
    if (($p = strrpos($range, '!')) !== false) { $tab = substr($range, 0, $p); $cells = substr($range, $p + 1); }
    if (strlen($tab) >= 2 && $tab[0] === "'" && substr($tab, -1) === "'") { $tab = str_replace("''", "'", substr($tab, 1, -1)); }
    preg_match('/^([A-Z]*)(\d*)(?::([A-Z]*)(\d*))?$/', $cells, $m);
    $col = static function (string $l): int { $n = 0; foreach (str_split($l) as $c) { $n = $n * 26 + ord($c) - 64; } return $n; };
    $hasEnd = str_contains($cells, ':');
    return ['tab' => $tab, 'r1' => ($m[2] ?? '') !== '' ? (int) $m[2] : 1, 'r2' => $hasEnd ? ((($m[4] ?? '') !== '') ? (int) $m[4] : PHP_INT_MAX) : ((($m[2] ?? '') !== '') ? (int) $m[2] : PHP_INT_MAX),
            'c1' => ($m[1] ?? '') !== '' ? $col($m[1]) : 1, 'c2' => $hasEnd && ($m[3] ?? '') !== '' ? $col($m[3]) : PHP_INT_MAX];
}

function mock_read_values(array $sheet, string $range): array
{
    $r = mock_parse_range($range);
    foreach ($sheet['tabs'] as $t) {
        if ($t['title'] !== $r['tab']) { continue; }
        $out = [];
        foreach ($t['values'] as $i => $row) {
            $n = $i + 1;
            if ($n < $r['r1'] || $n > $r['r2']) { continue; }
            $slice = array_slice($row, $r['c1'] - 1, $r['c2'] === PHP_INT_MAX ? null : $r['c2'] - $r['c1'] + 1);
            while ($slice !== [] && end($slice) === '') { array_pop($slice); }
            $out[] = array_values($slice);
        }
        while ($out !== [] && end($out) === []) { array_pop($out); }
        return $out;
    }
    return [];
}

function mock_api(string $dir, string $path): void
{
    // falhas injetadas pelo teste (para exercitar a retentativa exponencial)
    $ff = "$dir/fail_next.json";
    if (is_file($ff) && ($f = json_decode((string) file_get_contents($ff), true)) && $f['count'] > 0) {
        $f['count']--; file_put_contents($ff, json_encode($f));
        mock_err((int) $f['status'], $f['status'] === 429 ? 'RESOURCE_EXHAUSTED' : 'UNAVAILABLE', 'falha injetada'); return;
    }
    $auth = $_SERVER['HTTP_AUTHORIZATION'] ?? '';
    $valid = json_decode((string) @file_get_contents("$dir/access.json"), true) ?: [];
    if (!str_starts_with($auth, 'Bearer ') || !in_array(substr($auth, 7), $valid, true)) { mock_err(401, 'UNAUTHENTICATED', 'Invalid Credentials'); return; }

    if (!preg_match('~^/(?:v4/spreadsheets|drive/v3/files)/([A-Za-z0-9_-]+)(.*)$~', $path, $m)) { mock_err(404, 'NOT_FOUND', 'rota'); return; }
    [$all, $id, $rest] = $m;
    $rest = rawurldecode($rest);
    $file = "$dir/sheets/$id.json";
    if (!is_file($file)) { mock_err(404, 'NOT_FOUND', 'Requested entity was not found.'); return; }
    $sheet = json_decode((string) file_get_contents($file), true);
    if (($sheet['shared'] ?? false) === false) { mock_err(403, 'PERMISSION_DENIED', 'The caller does not have permission'); return; }
    $method = $_SERVER['REQUEST_METHOD'];
    $body = json_decode((string) file_get_contents('php://input'), true) ?: [];
    $save = static function () use (&$sheet, $file): void {
        $sheet['version'] = ($sheet['version'] ?? 1) + 1;
        $sheet['revisions'][] = ['id' => (string) $sheet['version'], 'modifiedTime' => gmdate('Y-m-d\TH:i:s.000\Z'), 'lastModifyingUser' => ['emailAddress' => 'celef@scseduca.com.br', 'displayName' => 'CELEF']];
        file_put_contents($file, json_encode($sheet, JSON_UNESCAPED_UNICODE));
    };
    $needEdit = static function () use ($sheet): bool { if ($sheet['shared'] !== 'editor') { mock_err(403, 'PERMISSION_DENIED', 'The caller does not have permission'); return false; } return true; };
    // ranges repetidos (ranges=a&ranges=b): o PHP guarda só o último, então lemos a query crua
    $ranges = [];
    foreach (explode('&', (string) ($_SERVER['QUERY_STRING'] ?? '')) as $kv) { if (str_starts_with($kv, 'ranges=')) { $ranges[] = rawurldecode(substr($kv, 7)); } }

    if (str_starts_with($path, '/drive/')) {
        if ($rest === '/revisions') { echo json_encode(['revisions' => $sheet['revisions'] ?? []]); return; }
        $last = end($sheet['revisions']) ?: ['modifiedTime' => gmdate('Y-m-d\TH:i:s.000\Z'), 'lastModifyingUser' => ['emailAddress' => $sheet['owner'] ?? 'celef@scseduca.com.br', 'displayName' => 'Dono']];
        echo json_encode(['id' => $id, 'name' => $sheet['title'], 'owners' => [['emailAddress' => $sheet['owner'] ?? 'celef@scseduca.com.br']], 'modifiedTime' => $last['modifiedTime'],
            'lastModifyingUser' => $last['lastModifyingUser'], 'capabilities' => ['canEdit' => $sheet['shared'] === 'editor'], 'webViewLink' => "https://docs.google.com/spreadsheets/d/$id/edit", 'version' => (string) ($sheet['version'] ?? 1)]);
        return;
    }
    if ($method === 'GET' && $rest === '') {
        echo json_encode(['properties' => ['title' => $sheet['title']], 'sheets' => array_map(static fn($t) => [
            'properties' => ['sheetId' => $t['gid'], 'title' => $t['title'], 'gridProperties' => ['rowCount' => max(1000, count($t['values'])), 'columnCount' => 26, 'frozenRowCount' => $t['frozen'] ?? 0]],
            'protectedRanges' => array_map(static fn($p) => ['protectedRangeId' => $p['id'], 'description' => $p['description']], $t['protected'] ?? [])], $sheet['tabs'])]);
        return;
    }
    if ($method === 'GET' && $rest === '/values:batchGet') {
        echo json_encode(['valueRanges' => array_map(static fn($r) => ['range' => $r, 'values' => mock_read_values($sheet, $r)], $ranges)]);
        return;
    }
    if ($method === 'GET' && str_starts_with($rest, '/values/')) {
        echo json_encode(['range' => substr($rest, 8), 'values' => mock_read_values($sheet, substr($rest, 8))]);
        return;
    }
    if ($method === 'POST' && preg_match('~^/values/(.+):append$~', $rest, $mm)) {
        if (!$needEdit()) { return; }
        if (($_GET['valueInputOption'] ?? '') !== 'RAW') { mock_err(400, 'INVALID_ARGUMENT', 'esperado valueInputOption=RAW'); return; }
        $r = mock_parse_range($mm[1]);
        foreach ($sheet['tabs'] as &$t) {
            if ($t['title'] !== $r['tab']) { continue; }
            $first = count($t['values']) + 1;
            foreach ($body['values'] as $row) { $t['values'][] = array_map('strval', $row); }
            $save();
            echo json_encode(['updates' => ['updatedRange' => "'{$t['title']}'!A{$first}:J" . count($t['values']), 'updatedRows' => count($body['values'])]]);
            return;
        }
        mock_err(400, 'INVALID_ARGUMENT', 'Unable to parse range'); return;
    }
    if ($method === 'POST' && $rest === '/values:batchUpdate') {
        if (!$needEdit()) { return; }
        if (($body['valueInputOption'] ?? '') !== 'RAW') { mock_err(400, 'INVALID_ARGUMENT', 'esperado valueInputOption=RAW'); return; }
        $cells = 0;
        foreach ($body['data'] as $d) {
            $r = mock_parse_range($d['range']);
            foreach ($sheet['tabs'] as &$t) {
                if ($t['title'] !== $r['tab']) { continue; }
                foreach ($d['values'] as $i => $row) {
                    $n = $r['r1'] - 1 + $i;
                    while (count($t['values']) <= $n) { $t['values'][] = []; }
                    foreach ($row as $j => $v) { $c = $r['c1'] - 1 + $j; while (count($t['values'][$n]) <= $c) { $t['values'][$n][] = ''; } $t['values'][$n][$c] = (string) $v; $cells++; }
                }
            }
            unset($t);
        }
        $save();
        echo json_encode(['totalUpdatedCells' => $cells]);
        return;
    }
    if ($method === 'POST' && $rest === ':batchUpdate') {
        if (!$needEdit()) { return; }
        $replies = [];
        foreach ($body['requests'] as $req) {
            if (isset($req['addSheet'])) {
                $gid = random_int(1000, 999999999);
                $p = $req['addSheet']['properties'];
                $sheet['tabs'][] = ['gid' => $gid, 'title' => $p['title'], 'frozen' => $p['gridProperties']['frozenRowCount'] ?? 0, 'protected' => [], 'values' => []];
                $replies[] = ['addSheet' => ['properties' => ['sheetId' => $gid, 'title' => $p['title']]]];
            } elseif (isset($req['updateSheetProperties'])) {
                foreach ($sheet['tabs'] as &$t) { if ($t['gid'] === $req['updateSheetProperties']['properties']['sheetId']) { $t['frozen'] = $req['updateSheetProperties']['properties']['gridProperties']['frozenRowCount']; } } unset($t);
                $replies[] = new stdClass();
            } elseif (isset($req['addProtectedRange'])) {
                $pr = $req['addProtectedRange']['protectedRange'];
                foreach ($sheet['tabs'] as &$t) { if ($t['gid'] === $pr['range']['sheetId']) { $t['protected'][] = ['id' => random_int(1, 999999), 'description' => $pr['description'], 'editors' => $pr['editors']['users'] ?? [], 'warningOnly' => $pr['warningOnly'] ?? false]; } } unset($t);
                $replies[] = new stdClass();
            } else {
                $replies[] = new stdClass();
            }
        }
        $save();
        echo json_encode(['replies' => $replies]);
        return;
    }
    mock_err(404, 'NOT_FOUND', 'rota não emulada: ' . $method . ' ' . $rest);
}
