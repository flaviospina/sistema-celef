<?php
// app/Google/GoogleJwt.php — Service Account: JWT RS256 assinado com openssl_sign e troca por access token
declare(strict_types=1);

namespace App\Google;

final class GoogleJwt
{
    /**
     * Monta e assina o JWT de asserção (RFC 7523).
     * @param array{client_email:string,private_key:string} $sa
     */
    public static function assertion(array $sa, string $scopes, string $audience, ?int $now = null): string
    {
        $now ??= time();
        $b64 = static fn(string $s): string => rtrim(strtr(base64_encode($s), '+/', '-_'), '=');
        $header = $b64(json_encode(['alg' => 'RS256', 'typ' => 'JWT'], JSON_THROW_ON_ERROR));
        $claims = $b64(json_encode(['iss' => $sa['client_email'], 'scope' => $scopes, 'aud' => $audience, 'iat' => $now, 'exp' => $now + 3600], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR));
        $key = openssl_pkey_get_private($sa['private_key']);
        if ($key === false) {
            throw new GoogleApiException('Chave privada da Service Account inválida.');
        }
        if (!openssl_sign($header . '.' . $claims, $signature, $key, OPENSSL_ALGO_SHA256)) {
            throw new GoogleApiException('Não foi possível assinar o JWT da Service Account.');
        }
        return $header . '.' . $claims . '.' . $b64($signature);
    }

    /**
     * Troca a asserção por um access token.
     * @param array{client_email:string,private_key:string} $sa
     * @return array{access_token:string,expires_in:int}
     */
    public static function accessToken(array $sa, string $scopes, string $tokenUrl): array
    {
        [$status, $data] = GoogleHttp::form($tokenUrl, [
            'grant_type' => 'urn:ietf:params:oauth:grant-type:jwt-bearer',
            'assertion'  => self::assertion($sa, $scopes, $tokenUrl),
        ]);
        if ($status !== 200 || empty($data['access_token'])) {
            throw new GoogleApiException((string) ($data['error_description'] ?? $data['error'] ?? "HTTP {$status}"), $status, (string) ($data['error'] ?? ''));
        }
        return ['access_token' => (string) $data['access_token'], 'expires_in' => (int) ($data['expires_in'] ?? 3600)];
    }

    /** Valida o conteúdo mínimo de uma Service Account (e-mail e chave PEM utilizável). */
    public static function validate(string $clientEmail, string $privateKey): ?string
    {
        if (!preg_match('/^[a-z0-9-]+@[a-z0-9-]+\.iam\.gserviceaccount\.com$/', $clientEmail)) {
            return 'O e-mail não parece ser de uma Service Account (…@<projeto>.iam.gserviceaccount.com).';
        }
        if (!str_contains($privateKey, 'BEGIN PRIVATE KEY') || openssl_pkey_get_private($privateKey) === false) {
            return 'A chave privada não é um PEM válido.';
        }
        return null;
    }
}
