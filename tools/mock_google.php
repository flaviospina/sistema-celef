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
        echo json_encode(['issuer' => $base, 'authorization_endpoint' => "$base/auth", 'token_endpoint' => "$base/token", 'jwks_uri' => "$base/jwks"]);
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
        header('Location: ' . $_GET['redirect_uri'] . '?' . http_build_query(['code' => $code, 'state' => $_GET['state']]), true, 302);
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
        echo json_encode(['access_token' => 'mock-access', 'id_token' => $jwt, 'expires_in' => 3600, 'token_type' => 'Bearer']);
        break;
    default:
        http_response_code(404); echo json_encode(['error' => 'not_found']);
}
