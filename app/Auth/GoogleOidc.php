<?php
// app/Auth/GoogleOidc.php — OpenID Connect com o Google (Workspace scseduca.com.br), sem bibliotecas:
// discovery, PKCE, troca do código via cURL, validação do ID Token (RS256 via JWKS + openssl_verify).
declare(strict_types=1);

namespace App\Auth;

use App\Config;
use App\Security\Logger;

final class GoogleOidc
{
    private const DISCOVERY_URL = 'https://accounts.google.com/.well-known/openid-configuration';
    private const DISCOVERY_TTL = 86400;
    private const JWKS_TTL = 21600;
    private const LEEWAY = 120; // segundos de tolerância de relógio

    /** @var array<string,mixed>|null */
    private static ?array $discovery = null;

    // ---- configuração --------------------------------------------------------------------------------------

    public static function clientId(): string
    {
        return Config::require('GOOGLE_CLIENT_ID');
    }

    public static function hostedDomain(): string
    {
        return strtolower(Config::get('GOOGLE_HOSTED_DOMAIN', 'scseduca.com.br') ?? 'scseduca.com.br');
    }

    /**
     * redirect_uri registrado no Google: a página ESTÁTICA public/auth/google/callback.html, que lê o fragmento
     * (response_mode=fragment) e encaminha code/state ao callback PHP (ver comentário na própria página).
     */
    public static function redirectUri(): string
    {
        return rtrim(Config::require('BASE_URL'), '/') . '/auth/google/callback.html';
    }

    public static function isConfigured(): bool
    {
        return Config::get('GOOGLE_CLIENT_ID') !== null && Config::get('GOOGLE_CLIENT_SECRET') !== null;
    }

    // ---- PKCE ------------------------------------------------------------------------------------------------

    public static function codeVerifier(): string
    {
        return rtrim(strtr(base64_encode(random_bytes(64)), '+/', '-_'), '=');
    }

    public static function codeChallenge(string $verifier): string
    {
        return rtrim(strtr(base64_encode(hash('sha256', $verifier, true)), '+/', '-_'), '=');
    }

    // ---- URL de autorização --------------------------------------------------------------------------------

    /**
     * @param array{state:string,nonce:string,code_verifier:string,prompt?:string,max_age?:int,login_hint?:string} $p
     */
    public static function authorizationUrl(array $p): string
    {
        $params = [
            'client_id'             => self::clientId(),
            'redirect_uri'          => self::redirectUri(),
            'response_type'         => 'code',
            'scope'                 => 'openid email profile',
            'state'                 => $p['state'],
            'nonce'                 => $p['nonce'],
            'code_challenge'        => self::codeChallenge($p['code_verifier']),
            'code_challenge_method' => 'S256',
            'hd'                    => self::hostedDomain(),
            // fragment: o retorno vem após "#" e não chega ao servidor (ver public/auth/google/callback.html)
            'response_mode'         => 'fragment',
            'access_type'           => 'online',
            'prompt'                => $p['prompt'] ?? 'select_account',
        ];
        if (isset($p['max_age'])) {
            $params['max_age'] = (string) $p['max_age'];
        }
        if (isset($p['login_hint'])) {
            $params['login_hint'] = $p['login_hint'];
        }
        return self::discovery()['authorization_endpoint'] . '?' . http_build_query($params, '', '&', PHP_QUERY_RFC3986);
    }

    // ---- troca do código -----------------------------------------------------------------------------------

    /** @return array{id_token:string,access_token?:string} */
    public static function exchangeCode(string $code, string $codeVerifier): array
    {
        $body = http_build_query([
            'code'          => $code,
            'client_id'     => self::clientId(),
            'client_secret' => Config::require('GOOGLE_CLIENT_SECRET'),
            'redirect_uri'  => self::redirectUri(),
            'grant_type'    => 'authorization_code',
            'code_verifier' => $codeVerifier,
        ], '', '&', PHP_QUERY_RFC3986);
        $resp = self::http('POST', self::discovery()['token_endpoint'], $body, ['Content-Type: application/x-www-form-urlencoded']);
        $data = json_decode($resp, true);
        if (!is_array($data) || empty($data['id_token']) || !is_string($data['id_token'])) {
            Logger::error('Troca de código OAuth falhou', ['resposta' => mb_substr($resp, 0, 300)]);
            throw new \RuntimeException('O Google não devolveu um token válido.');
        }
        return $data;
    }

    // ---- validação do ID Token ---------------------------------------------------------------------------

    /**
     * Verifica assinatura e claims. Retorna o payload. Lança RuntimeException com motivo (para o log).
     * @return array<string,mixed>
     */
    public static function verifyIdToken(string $jwt, string $expectedNonce): array
    {
        $parts = explode('.', $jwt);
        if (count($parts) !== 3) {
            throw new \RuntimeException('ID Token malformado.');
        }
        [$h64, $p64, $s64] = $parts;
        $header = json_decode(self::b64url($h64), true);
        $payload = json_decode(self::b64url($p64), true);
        $signature = self::b64url($s64);
        if (!is_array($header) || !is_array($payload) || $signature === '') {
            throw new \RuntimeException('ID Token ilegível.');
        }
        if (($header['alg'] ?? '') !== 'RS256' || empty($header['kid'])) {
            throw new \RuntimeException('Algoritmo do ID Token não aceito (esperado RS256).');
        }

        $pem = self::publicKeyPem((string) $header['kid']);
        $ok = openssl_verify($h64 . '.' . $p64, $signature, $pem, OPENSSL_ALGO_SHA256);
        if ($ok !== 1) {
            throw new \RuntimeException('Assinatura do ID Token inválida.');
        }

        $now = time();
        $issuer = (string) (self::discovery()['issuer'] ?? 'https://accounts.google.com');
        $iss = (string) ($payload['iss'] ?? '');
        if ($iss !== $issuer && $iss !== preg_replace('~^https://~', '', $issuer)) {
            throw new \RuntimeException('Emissor (iss) do ID Token inválido.');
        }
        $aud = $payload['aud'] ?? null;
        $audOk = is_array($aud) ? in_array(self::clientId(), $aud, true) : $aud === self::clientId();
        if (!$audOk) {
            throw new \RuntimeException('Audiência (aud) do ID Token não é este sistema.');
        }
        if (isset($payload['azp']) && $payload['azp'] !== self::clientId()) {
            throw new \RuntimeException('azp do ID Token não é este sistema.');
        }
        if (!isset($payload['exp']) || (int) $payload['exp'] < $now - self::LEEWAY) {
            throw new \RuntimeException('ID Token expirado.');
        }
        if (!isset($payload['iat']) || (int) $payload['iat'] > $now + self::LEEWAY) {
            throw new \RuntimeException('ID Token emitido no futuro (relógio).');
        }
        if (!isset($payload['nonce']) || !is_string($payload['nonce']) || !hash_equals($expectedNonce, $payload['nonce'])) {
            throw new \RuntimeException('nonce do ID Token não confere (possível replay).');
        }
        if (empty($payload['sub']) || !is_string($payload['sub'])) {
            throw new \RuntimeException('ID Token sem sub.');
        }
        return $payload;
    }

    /**
     * Regras do Workspace: hd obrigatório e igual ao domínio, e-mail verificado e do domínio.
     * @param array<string,mixed> $claims  @return string|null motivo da recusa (null = ok)
     */
    public static function workspaceDenialReason(array $claims): ?string
    {
        $domain = self::hostedDomain();
        $email = strtolower(trim((string) ($claims['email'] ?? '')));
        if (($claims['hd'] ?? null) !== $domain) {
            return 'DOMINIO_INVALIDO';
        }
        if (($claims['email_verified'] ?? false) !== true) {
            return 'TOKEN_INVALIDO';
        }
        if ($email === '' || !str_ends_with($email, '@' . $domain)) {
            return 'DOMINIO_INVALIDO';
        }
        return null;
    }

    // ---- discovery e JWKS (cache em storage/cache) ---------------------------------------------------------

    /** @return array<string,mixed> */
    public static function discovery(): array
    {
        if (self::$discovery !== null) {
            return self::$discovery;
        }
        $url = Config::get('GOOGLE_DISCOVERY_URL', self::DISCOVERY_URL) ?? self::DISCOVERY_URL;
        $data = self::cachedJson('google-oidc-discovery', $url, self::DISCOVERY_TTL);
        foreach (['issuer', 'authorization_endpoint', 'token_endpoint', 'jwks_uri'] as $k) {
            if (empty($data[$k])) {
                throw new \RuntimeException("Documento de descoberta do Google sem {$k}.");
            }
        }
        return self::$discovery = $data;
    }

    private static function publicKeyPem(string $kid): string
    {
        $jwks = self::cachedJson('google-oidc-jwks', (string) self::discovery()['jwks_uri'], self::JWKS_TTL);
        $key = self::findKey($jwks, $kid);
        if ($key === null) {
            // chave rotacionada: busca de novo ignorando o cache, uma única vez
            $jwks = self::cachedJson('google-oidc-jwks', (string) self::discovery()['jwks_uri'], 0);
            $key = self::findKey($jwks, $kid);
        }
        if ($key === null) {
            throw new \RuntimeException('Chave pública (kid) do ID Token não encontrada no JWKS do Google.');
        }
        return self::jwkToPem((string) $key['n'], (string) $key['e']);
    }

    /** @param array<string,mixed> $jwks @return array<string,mixed>|null */
    private static function findKey(array $jwks, string $kid): ?array
    {
        foreach ($jwks['keys'] ?? [] as $k) {
            if (is_array($k) && ($k['kid'] ?? null) === $kid && ($k['kty'] ?? '') === 'RSA' && !empty($k['n']) && !empty($k['e'])) {
                return $k;
            }
        }
        return null;
    }

    /** JWK (n, e em base64url) → PEM SubjectPublicKeyInfo, montando o DER à mão. */
    public static function jwkToPem(string $n, string $e): string
    {
        $mod = self::b64url($n);
        $exp = self::b64url($e);
        $der = self::derSequence(
            self::derSequence("\x06\x09\x2a\x86\x48\x86\xf7\x0d\x01\x01\x01" . "\x05\x00") // OID rsaEncryption + NULL
            . self::derBitString(self::derSequence(self::derInteger($mod) . self::derInteger($exp)))
        );
        return "-----BEGIN PUBLIC KEY-----\n" . chunk_split(base64_encode($der), 64, "\n") . "-----END PUBLIC KEY-----\n";
    }

    private static function derLength(int $len): string
    {
        if ($len < 0x80) {
            return chr($len);
        }
        $bytes = ltrim(pack('N', $len), "\0");
        return chr(0x80 | strlen($bytes)) . $bytes;
    }

    private static function derSequence(string $content): string { return "\x30" . self::derLength(strlen($content)) . $content; }
    private static function derBitString(string $content): string { return "\x03" . self::derLength(strlen($content) + 1) . "\0" . $content; }
    private static function derInteger(string $bytes): string
    {
        if ($bytes !== '' && (ord($bytes[0]) & 0x80)) {
            $bytes = "\0" . $bytes; // inteiro positivo
        }
        return "\x02" . self::derLength(strlen($bytes)) . $bytes;
    }

    public static function b64url(string $s): string
    {
        $d = base64_decode(strtr($s, '-_', '+/') . str_repeat('=', (4 - strlen($s) % 4) % 4), true);
        return $d === false ? '' : $d;
    }

    /** @return array<string,mixed> */
    private static function cachedJson(string $name, string $url, int $ttl): array
    {
        $file = STORAGE_PATH . '/cache/' . $name . '.json';
        if ($ttl > 0 && is_file($file) && (time() - filemtime($file)) < $ttl) {
            $data = json_decode((string) file_get_contents($file), true);
            if (is_array($data)) {
                return $data;
            }
        }
        $raw = self::http('GET', $url);
        $data = json_decode($raw, true);
        if (!is_array($data)) {
            throw new \RuntimeException("Resposta inválida de {$url}.");
        }
        @file_put_contents($file, $raw, LOCK_EX);
        @chmod($file, 0600);
        return $data;
    }

    /** cURL com verificação de certificado, sem redirecionamentos, timeout curto. @param list<string> $headers */
    public static function http(string $method, string $url, ?string $body = null, array $headers = []): string
    {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new \RuntimeException('cURL indisponível.');
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_FOLLOWLOCATION => false,
            CURLOPT_CONNECTTIMEOUT => 10,
            CURLOPT_TIMEOUT        => 15,
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
            CURLOPT_HTTPHEADER     => array_merge(['Accept: application/json', 'User-Agent: SistemaCELEF/' . APP_VERSION], $headers),
            CURLOPT_CUSTOMREQUEST  => $method,
        ]);
        if ($body !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
        }
        $resp = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        if ($resp === false || $status >= 400) {
            Logger::error('Falha HTTP com o Google', ['url' => preg_replace('~\?.*~', '', $url), 'status' => $status, 'erro' => $err, 'resposta' => is_string($resp) ? mb_substr($resp, 0, 300) : null]);
            throw new \RuntimeException('Não foi possível falar com o Google agora. Tente novamente em instantes.');
        }
        return (string) $resp;
    }
}
