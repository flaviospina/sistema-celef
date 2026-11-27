<?php
// app/Google/GoogleOAuthToken.php — access token da conta técnica (refresh token OAuth da celef@ ou Service Account),
// com cache cifrado em storage/cache até pouco antes de expirar
declare(strict_types=1);

namespace App\Google;

use App\Auth\GoogleOidc;
use App\Config;
use App\Database;
use App\Security\Crypto;
use App\Security\Logger;
use App\Security\SecurityEvents;

final class GoogleOAuthToken
{
    public const SCOPES = 'https://www.googleapis.com/auth/spreadsheets https://www.googleapis.com/auth/drive.metadata.readonly';
    private const CACHE_FILE = '/cache/google-access-token.bin';
    private const CTX_SECRET = 'google_credentials.secret';

    /** @var array{token:string,exp:int,cred:int}|null */
    private static ?array $memo = null;

    /** Credencial ativa (ou null). @return array<string,mixed>|null */
    public static function activeCredential(): ?array
    {
        return Database::row("SELECT * FROM google_credentials WHERE is_active = 1 AND deleted_at IS NULL LIMIT 1");
    }

    public static function tokenUrl(): string
    {
        return Config::get('GOOGLE_TOKEN_URL') ?? (string) GoogleOidc::discovery()['token_endpoint'];
    }

    public static function revokeUrl(): string
    {
        return Config::get('GOOGLE_REVOKE_URL') ?? (string) (GoogleOidc::discovery()['revocation_endpoint'] ?? 'https://oauth2.googleapis.com/revoke');
    }

    /** Access token válido. $forceRefresh ignora o cache (usado após um 401). */
    public static function accessToken(bool $forceRefresh = false): string
    {
        $cred = self::activeCredential();
        if ($cred === null || $cred['status'] !== 'CONNECTED' || $cred['secret_enc'] === null) {
            throw new GoogleApiException('Conta técnica Google não conectada.', 401, 'not_connected');
        }
        $credId = (int) $cred['id'];
        if (!$forceRefresh) {
            $cached = self::$memo ?? self::readCache();
            if ($cached !== null && $cached['cred'] === $credId && $cached['exp'] > time() + 60) {
                return (self::$memo = $cached)['token'];
            }
        }
        $secret = (string) Crypto::decrypt($cred['secret_enc'], self::CTX_SECRET);
        try {
            if ($cred['kind'] === 'SERVICE_ACCOUNT') {
                $sa = json_decode($secret, true);
                $res = GoogleJwt::accessToken(['client_email' => (string) $sa['client_email'], 'private_key' => (string) $sa['private_key']], self::SCOPES, self::tokenUrl());
            } else {
                [$status, $data] = GoogleHttp::form(self::tokenUrl(), [
                    'grant_type' => 'refresh_token', 'refresh_token' => $secret,
                    'client_id' => GoogleOidc::techClientId(), 'client_secret' => GoogleOidc::techClientSecret(),
                ]);
                if ($status !== 200 || empty($data['access_token'])) {
                    throw new GoogleApiException((string) ($data['error_description'] ?? $data['error'] ?? "HTTP {$status}"), $status, (string) ($data['error'] ?? ''));
                }
                $res = ['access_token' => (string) $data['access_token'], 'expires_in' => (int) ($data['expires_in'] ?? 3600)];
            }
        } catch (GoogleApiException $e) {
            self::onRefreshFailure($cred, $e);
            throw $e;
        } finally {
            sodium_memzero($secret);
        }
        self::$memo = ['token' => $res['access_token'], 'exp' => time() + $res['expires_in'], 'cred' => $credId];
        self::writeCache(self::$memo);
        // no máximo 1 gravação por dia (a tabela é versionada: cada UPDATE gera uma linha de histórico)
        Database::run('UPDATE google_credentials SET last_refresh_at = NOW(3), last_error = NULL WHERE id = :id AND (last_refresh_at IS NULL OR last_refresh_at < NOW() - INTERVAL 1 DAY OR last_error IS NOT NULL)', ['id' => $credId]);
        return $res['access_token'];
    }

    /** invalid_grant = senha trocada/acesso revogado: marca ERRO, alerta e as filas passam a aguardar "Reconectar". */
    private static function onRefreshFailure(array $cred, GoogleApiException $e): void
    {
        self::clearCache();
        $permanent = in_array($e->reason, ['invalid_grant', 'invalid_client', 'unauthorized_client'], true);
        Database::run('UPDATE google_credentials SET last_error = :e' . ($permanent ? ", status = 'ERROR'" : '') . ' WHERE id = :id',
            ['e' => mb_substr($e->reason . ': ' . $e->getMessage(), 0, 500), 'id' => (int) $cred['id']]);
        Logger::error('Falha ao renovar o token da conta técnica', ['motivo' => $e->reason, 'status' => $e->status]);
        if ($permanent && $cred['status'] === 'CONNECTED') {
            SecurityEvents::record('TOKEN_GOOGLE_INVALIDO', SecurityEvents::CRITICO,
                "A autorização da conta técnica {$cred['account_email']} deixou de valer ({$e->reason}). Sincronização e planilha de logs paradas até reconectar em Admin → Conta técnica.",
                ['conta' => $cred['account_email'], 'motivo' => $e->reason], 'google_credentials', (int) $cred['id']);
        }
    }

    /** Grava a credencial (desativando a anterior). $secret = refresh token ou JSON mínimo da Service Account. */
    public static function store(string $kind, string $accountEmail, string $secret, string $scopes, int $byUserId): int
    {
        return Database::transaction(function () use ($kind, $accountEmail, $secret, $scopes, $byUserId): int {
            Database::run("UPDATE google_credentials SET is_active = 0, status = IF(status = 'CONNECTED', 'REVOKED', status), revoked_at = NOW(3), revoked_by = :u, updated_by = :u2 WHERE is_active = 1",
                ['u' => $byUserId, 'u2' => $byUserId]);
            self::clearCache();
            return Database::insert('google_credentials', [
                'kind' => $kind, 'account_email' => mb_strtolower($accountEmail), 'secret_enc' => Crypto::encrypt($secret, self::CTX_SECRET),
                'key_version' => Crypto::currentVersion(), 'scopes' => mb_substr($scopes, 0, 500), 'status' => 'CONNECTED', 'is_active' => 1,
                'connected_at' => date('Y-m-d H:i:s'), 'connected_by' => $byUserId, 'created_by' => $byUserId,
            ]);
        });
    }

    /** Revoga no Google (melhor esforço) e desativa localmente. O segredo cifrado é apagado da linha. */
    public static function revoke(int $byUserId): void
    {
        $cred = self::activeCredential();
        if ($cred === null) {
            return;
        }
        if ($cred['kind'] === 'OAUTH_USER_ACCOUNT' && $cred['secret_enc'] !== null) {
            try {
                $secret = (string) Crypto::decrypt($cred['secret_enc'], self::CTX_SECRET);
                GoogleHttp::form(self::revokeUrl(), ['token' => $secret]);
            } catch (\Throwable $e) {
                Logger::warning('Revogação no Google falhou (seguindo com a desativação local)', ['erro' => $e->getMessage()]);
            }
        }
        Database::run("UPDATE google_credentials SET is_active = 0, status = 'REVOKED', secret_enc = NULL, revoked_at = NOW(3), revoked_by = :u, updated_by = :u2 WHERE id = :id",
            ['u' => $byUserId, 'u2' => $byUserId, 'id' => (int) $cred['id']]);
        self::clearCache();
    }

    public static function accountEmail(): ?string
    {
        $cred = self::activeCredential();
        return $cred === null ? null : (string) $cred['account_email'];
    }

    public static function isConnected(): bool
    {
        $cred = self::activeCredential();
        return $cred !== null && $cred['status'] === 'CONNECTED' && $cred['secret_enc'] !== null;
    }

    // ---- cache cifrado -----------------------------------------------------------------------------------

    /** @return array{token:string,exp:int,cred:int}|null */
    private static function readCache(): ?array
    {
        $file = STORAGE_PATH . self::CACHE_FILE;
        if (!is_file($file)) {
            return null;
        }
        try {
            $data = json_decode((string) Crypto::decrypt((string) file_get_contents($file), 'cache.google_access_token'), true);
            return is_array($data) && isset($data['token'], $data['exp'], $data['cred']) ? ['token' => (string) $data['token'], 'exp' => (int) $data['exp'], 'cred' => (int) $data['cred']] : null;
        } catch (\Throwable) {
            return null;
        }
    }

    /** @param array{token:string,exp:int,cred:int} $data */
    private static function writeCache(array $data): void
    {
        $file = STORAGE_PATH . self::CACHE_FILE;
        @file_put_contents($file, (string) Crypto::encrypt(json_encode($data, JSON_THROW_ON_ERROR), 'cache.google_access_token'), LOCK_EX);
        @chmod($file, 0600);
    }

    public static function clearCache(): void
    {
        self::$memo = null;
        @unlink(STORAGE_PATH . self::CACHE_FILE);
    }
}
