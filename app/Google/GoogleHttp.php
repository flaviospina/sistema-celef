<?php
// app/Google/GoogleHttp.php — chamadas REST autenticadas às APIs do Google (cURL), com retentativa exponencial
declare(strict_types=1);

namespace App\Google;

use App\Config;
use App\Security\Logger;

final class GoogleHttp
{
    private const MAX_ATTEMPTS = 5;

    public static function sheetsBase(): string
    {
        return rtrim(Config::get('GOOGLE_SHEETS_BASE', 'https://sheets.googleapis.com') ?? '', '/');
    }

    public static function driveBase(): string
    {
        return rtrim(Config::get('GOOGLE_DRIVE_BASE', 'https://www.googleapis.com') ?? '', '/');
    }

    /**
     * Requisição JSON autenticada com o token da conta técnica.
     * Retenta 429/5xx com espera exponencial (1, 2, 4, 8 s + variação), respeitando $deadline (timestamp).
     * Em 401, renova o access token uma vez.
     * @param array<string,mixed>|null $body  @param array<string,mixed|list<string>> $query
     * @return array<string,mixed>
     */
    public static function json(string $method, string $url, ?array $body = null, array $query = [], ?int $deadline = null): array
    {
        if ($query !== []) {
            $url .= (str_contains($url, '?') ? '&' : '?') . self::buildQuery($query);
        }
        $payload = $body === null ? null : json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $refreshed = false;

        for ($attempt = 1; ; $attempt++) {
            $token = GoogleOAuthToken::accessToken($refreshed);
            [$status, $raw, $err] = self::raw($method, $url, $payload, ['Authorization: Bearer ' . $token, 'Content-Type: application/json; charset=utf-8', 'Accept: application/json']);
            if ($status >= 200 && $status < 300) {
                $data = $raw === '' ? [] : json_decode($raw, true);
                return is_array($data) ? $data : [];
            }
            $decoded = json_decode($raw, true);
            $reason = is_array($decoded) ? (string) ($decoded['error']['status'] ?? ($decoded['error']['errors'][0]['reason'] ?? '')) : '';
            $message = is_array($decoded) ? (string) ($decoded['error']['message'] ?? '') : ($err !== '' ? $err : 'resposta inválida');

            if ($status === 401 && !$refreshed) {       // token expirou no caminho: renova uma vez
                $refreshed = true;
                continue;
            }
            $retryable = $status === 0 || $status === 429 || $status >= 500 || in_array($reason, ['rateLimitExceeded', 'userRateLimitExceeded'], true);
            $wait = min(16, 2 ** ($attempt - 1)) + random_int(0, 500) / 1000;
            if ($retryable && $attempt < self::MAX_ATTEMPTS && ($deadline === null || time() + $wait < $deadline)) {
                Logger::warning('Google API: nova tentativa', ['status' => $status, 'motivo' => $reason, 'tentativa' => $attempt, 'espera_s' => round($wait, 1)]);
                usleep((int) ($wait * 1_000_000));
                continue;
            }
            Logger::error('Google API falhou', ['metodo' => $method, 'url' => preg_replace('~\?.*~', '', $url), 'status' => $status, 'motivo' => $reason, 'msg' => mb_substr($message, 0, 300)]);
            throw new GoogleApiException($message !== '' ? $message : "HTTP {$status}", $status, $reason, $retryable);
        }
    }

    /**
     * POST application/x-www-form-urlencoded sem autenticação por token (endpoints de token/revogação).
     * @param array<string,string> $fields @return array{0:int,1:array<string,mixed>}
     */
    public static function form(string $url, array $fields): array
    {
        [$status, $raw] = self::raw('POST', $url, http_build_query($fields, '', '&', PHP_QUERY_RFC3986), ['Content-Type: application/x-www-form-urlencoded', 'Accept: application/json']);
        $data = json_decode($raw, true);
        return [$status, is_array($data) ? $data : []];
    }

    /** @param list<string> $headers @return array{0:int,1:string,2:string} status, corpo, erro cURL */
    private static function raw(string $method, string $url, ?string $payload, array $headers): array
    {
        $ch = curl_init($url);
        if ($ch === false) {
            throw new GoogleApiException('cURL indisponível.');
        }
        curl_setopt_array($ch, [
            CURLOPT_RETURNTRANSFER => true, CURLOPT_FOLLOWLOCATION => false, CURLOPT_CONNECTTIMEOUT => 10, CURLOPT_TIMEOUT => 30,
            CURLOPT_SSL_VERIFYPEER => true, CURLOPT_SSL_VERIFYHOST => 2, CURLOPT_CUSTOMREQUEST => $method,
            CURLOPT_HTTPHEADER => array_merge($headers, ['User-Agent: SistemaCELEF/' . APP_VERSION]),
        ]);
        if ($payload !== null) {
            curl_setopt($ch, CURLOPT_POSTFIELDS, $payload);
        }
        $resp = curl_exec($ch);
        $status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE);
        $err = curl_error($ch);
        curl_close($ch);
        return [$status, is_string($resp) ? $resp : '', $err];
    }

    /** ranges=a&ranges=b (o Google não aceita ranges[]=). @param array<string,mixed|list<string>> $query */
    private static function buildQuery(array $query): string
    {
        $parts = [];
        foreach ($query as $k => $v) {
            foreach ((array) $v as $item) {
                $parts[] = rawurlencode((string) $k) . '=' . rawurlencode(is_bool($item) ? ($item ? 'true' : 'false') : (string) $item);
            }
        }
        return implode('&', $parts);
    }
}
