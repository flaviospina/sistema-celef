<?php
// app/Auth/Auth.php — login/logout com Google, sessão vinculada ao banco (user_sessions), reautenticação, allowlist
declare(strict_types=1);

namespace App\Auth;

use App\Config;
use App\Database;
use App\Http\HttpException;
use App\Http\Response;
use App\Security\AuditLog;
use App\Security\Crypto;
use App\Security\Logger;
use App\Security\RateLimiter;
use App\Security\RequestContext;
use App\Security\SecureSession;
use App\Security\SecurityEvents;
use App\Settings;

final class Auth
{
    /** @var array<string,mixed>|null|false  false = ainda não carregado */
    private static array|null|false $user = false;
    /** @var array<string,mixed>|null */
    private static ?array $sessionRow = null;

    // ---- estado ------------------------------------------------------------------------------------------------

    /** Usuário logado (linha de users + role_code) ou null. Valida a sessão no banco a cada requisição. */
    public static function user(): ?array
    {
        if (self::$user !== false) {
            return self::$user ?: null;
        }
        self::$user = null;
        $userId = SecureSession::get('user_id');
        if (!is_int($userId)) {
            return null;
        }
        $hash = SecureSession::hash();
        $row = Database::row(
            'SELECT u.*, r.code AS role_code, r.name AS role_name, s.id AS session_hash, s.absolute_expires_at, s.google_auth_time,
                    s.last_reauth_at, s.ip AS session_ip, s.user_agent_hash AS session_ua, s.last_seen_at, s.revoked_at
             FROM users u JOIN roles r ON r.id = u.role_id
             LEFT JOIN user_sessions s ON s.id = :h AND s.user_id = u.id
             WHERE u.id = :id', ['h' => $hash, 'id' => $userId]);
        if ($row === null || $row['session_hash'] === null) {
            self::dropSession('SESSAO_INEXISTENTE');
            return null;
        }
        $now = time();
        if ($row['revoked_at'] !== null) {
            self::dropSession('REVOGADA');
            return null;
        }
        if (strtotime((string) $row['absolute_expires_at']) < $now) {
            self::revoke($hash, 'ABSOLUTA');
            self::dropSession('ABSOLUTA');
            return null;
        }
        if ((int) $row['is_active'] !== 1 || $row['deleted_at'] !== null) {
            self::revoke($hash, 'ADMIN');
            self::dropSession('INATIVO');
            return null;
        }
        if (Settings::bool('session.bind_user_agent', true) && !hash_equals((string) $row['session_ua'], RequestContext::userAgentHash())) {
            self::revoke($hash, 'TROCA_UA_IP');
            self::dropSession('TROCA_UA');
            SecurityEvents::record('SESSAO_TROCA_UA', SecurityEvents::AVISO, 'Sessão encerrada: navegador mudou no meio da sessão', ['usuario' => $row['email']], 'users', (int) $row['id'], false);
            return null;
        }
        if (Settings::bool('session.bind_ip', true) && (string) $row['session_ip'] !== RequestContext::ip()) {
            self::revoke($hash, 'TROCA_UA_IP');
            self::dropSession('TROCA_IP');
            SecurityEvents::record('SESSAO_TROCA_IP', SecurityEvents::AVISO, 'Sessão encerrada: endereço de rede mudou no meio da sessão', ['usuario' => $row['email']], 'users', (int) $row['id'], false);
            return null;
        }
        // last_seen_at com folga de 60 s para não gravar a cada clique
        if (strtotime((string) $row['last_seen_at']) < $now - 60) {
            Database::run('UPDATE user_sessions SET last_seen_at = NOW(3) WHERE id = :h', ['h' => $hash]);
        }
        self::$sessionRow = $row;
        self::$user = $row;
        self::applyActor($row);
        return $row;
    }

    private static function applyActor(array $user): void
    {
        Database::setActor((int) $user['id'], 'APP');
        AuditLog::setActor((int) $user['id'], (string) $user['email'], (string) $user['role_code']);
    }

    public static function check(): bool
    {
        return self::user() !== null;
    }

    public static function id(): ?int
    {
        $u = self::user();
        return $u === null ? null : (int) $u['id'];
    }

    /** Exige login; senão guarda o destino e manda para /login. */
    public static function requireLogin(string $intended = '/'): array
    {
        $u = self::user();
        if ($u === null) {
            SecureSession::set('intended', self::safePath($intended));
            Response::redirect('/login');
        }
        return $u;
    }

    public static function isSuperAdmin(): bool
    {
        $u = self::user();
        return $u !== null && $u['role_code'] === 'SUPER_ADMIN';
    }

    public static function isAdmin(): bool
    {
        $u = self::user();
        return $u !== null && in_array($u['role_code'], ['SUPER_ADMIN', 'ADMIN'], true);
    }

    /** E-mails protegidos pelo .env (não podem ser rebaixados/desativados pela interface). */
    public static function isProtectedEmail(string $email): bool
    {
        return in_array(strtolower($email), Config::list('SUPER_ADMIN_EMAILS'), true);
    }

    /** Segundos desde a última autenticação no Google (login ou reautenticação). */
    public static function authAgeSeconds(): int
    {
        $u = self::user();
        if ($u === null) {
            return PHP_INT_MAX;
        }
        $times = [strtotime((string) ($u['google_auth_time'] ?? '')) ?: 0, strtotime((string) ($u['last_reauth_at'] ?? '')) ?: 0];
        $loginAt = (int) (SecureSession::get('login_at') ?? 0);
        $last = max(max($times), $loginAt);
        return $last === 0 ? PHP_INT_MAX : time() - $last;
    }

    /** Exige autenticação recente (em minutos); senão redireciona para a reautenticação e volta para $returnTo. */
    public static function requireRecent(int $minutes, string $returnTo): void
    {
        if (self::authAgeSeconds() > $minutes * 60) {
            SecureSession::set('reauth_return', self::safePath($returnTo));
            Response::redirect('/reauth');
        }
    }

    // ---- fluxo OIDC ------------------------------------------------------------------------------------------

    /** Cria state/nonce/PKCE, grava em oauth_states e devolve a URL do Google. */
    public static function beginGoogleFlow(string $purpose, ?string $redirectTo = null): string
    {
        $state = Crypto::randomToken(32);
        $nonce = Crypto::randomToken(32);
        $verifier = GoogleOidc::codeVerifier();
        $stateHash = hash('sha256', $state);
        Database::insert('oauth_states', [
            'state_hash'        => $stateHash,
            'nonce_hash'        => hash('sha256', $nonce),
            'code_verifier_enc' => Crypto::encrypt($verifier, 'oauth_states.code_verifier'),
            'purpose'           => $purpose,
            'redirect_to'       => $redirectTo === null ? null : self::safePath($redirectTo),
            'user_id'           => self::id(),
            'ip'                => RequestContext::ip(),
            'expires_at'        => date('Y-m-d H:i:s', time() + 600),
        ]);
        // o navegador que iniciou é o único que pode concluir (anti login-CSRF)
        SecureSession::set('oauth_state_hash', $stateHash);
        SecureSession::set('oauth_nonce', $nonce);

        $params = ['state' => $state, 'nonce' => $nonce, 'code_verifier' => $verifier];
        if ($purpose === 'REAUTH') {
            $params['prompt'] = 'login';
            $params['max_age'] = 0;
            $u = self::user();
            if ($u !== null) {
                $params['login_hint'] = (string) $u['email'];
            }
        }
        return GoogleOidc::authorizationUrl($params);
    }

    /**
     * Conclui o retorno do Google. Retorna o caminho interno para onde redirecionar.
     * Qualquer recusa lança HttpException 403 com mensagem genérica (motivo real só no log/auditoria).
     */
    public static function completeGoogleFlow(?string $code, ?string $state, ?string $error): string
    {
        $ip = RequestContext::ip();
        if ($error !== null) {
            Logger::warning('Google devolveu erro no OAuth', ['erro' => $error]);
            throw HttpException::forbidden('O Google não autorizou o acesso. Tente novamente.');
        }
        if (!is_string($code) || $code === '' || !is_string($state) || $state === '') {
            throw HttpException::forbidden('Resposta do Google incompleta.');
        }
        $stateHash = hash('sha256', $state);
        $expected = SecureSession::get('oauth_state_hash');
        $nonce = SecureSession::get('oauth_nonce');
        SecureSession::forget('oauth_state_hash');
        SecureSession::forget('oauth_nonce');
        if (!is_string($expected) || !hash_equals($expected, $stateHash) || !is_string($nonce)) {
            self::deny(null, 'TOKEN_INVALIDO', 'state não pertence a esta sessão');
        }
        $row = Database::row('SELECT * FROM oauth_states WHERE state_hash = :h', ['h' => $stateHash]);
        if ($row === null || $row['used_at'] !== null || strtotime((string) $row['expires_at']) < time()) {
            self::deny(null, 'TOKEN_INVALIDO', 'state inexistente, usado ou expirado');
        }
        Database::run('UPDATE oauth_states SET used_at = NOW(3) WHERE state_hash = :h', ['h' => $stateHash]);
        if (!hash_equals((string) $row['nonce_hash'], hash('sha256', $nonce))) {
            self::deny(null, 'TOKEN_INVALIDO', 'nonce da sessão não confere com o state');
        }

        $verifier = (string) Crypto::decrypt($row['code_verifier_enc'], 'oauth_states.code_verifier');
        try {
            $tokens = GoogleOidc::exchangeCode($code, $verifier);
            $claims = GoogleOidc::verifyIdToken($tokens['id_token'], $nonce);
        } catch (\RuntimeException $e) {
            self::deny(null, 'TOKEN_INVALIDO', $e->getMessage());
        }

        $email = strtolower(trim((string) ($claims['email'] ?? '')));
        if (($reason = GoogleOidc::workspaceDenialReason($claims)) !== null) {
            self::deny($email, $reason, 'claims hd/email_verified/domínio');
        }

        return $row['purpose'] === 'REAUTH'
            ? self::finishReauth($claims, $email)
            : self::finishLogin($claims, $email, (string) ($row['redirect_to'] ?? ''));
    }

    /** @param array<string,mixed> $claims */
    private static function finishLogin(array $claims, string $email, string $redirectTo): string
    {
        $ip = RequestContext::ip();
        // contas genéricas/compartilhadas (padrões LIKE configuráveis)
        $blocked = Database::value(
            "SELECT pattern FROM blocked_email_patterns WHERE is_active = 1 AND deleted_at IS NULL AND :e LIKE pattern LIMIT 1", ['e' => $email]);
        if ($blocked !== null) {
            self::deny($email, 'CONTA_GENERICA', "padrão {$blocked}");
        }
        $user = Database::row('SELECT u.*, r.code AS role_code FROM users u JOIN roles r ON r.id = u.role_id WHERE u.email = :e', ['e' => $email]);
        if ($user === null || $user['deleted_at'] !== null) {
            self::deny($email, 'NAO_CADASTRADO', 'e-mail fora da allowlist');
        }
        if ((int) $user['is_active'] !== 1) {
            self::deny($email, 'INATIVO', 'usuário desativado');
        }
        if ($user['google_sub'] !== null && $user['google_sub'] !== $claims['sub']) {
            SecurityEvents::record('SUB_DIVERGENTE', SecurityEvents::CRITICO, "Conta Google diferente da registrada para {$email}", ['email' => $email], 'users', (int) $user['id']);
            self::deny($email, 'TOKEN_INVALIDO', 'google_sub divergente');
        }

        // sessão nova (evita fixação) e vínculo no banco
        SecureSession::regenerate();
        $hash = (string) SecureSession::hash();
        $absolute = time() + Settings::int('session.absolute_hours', 8) * 3600;
        $authTime = isset($claims['auth_time']) ? date('Y-m-d H:i:s', (int) $claims['auth_time']) : date('Y-m-d H:i:s');
        Database::insert('user_sessions', [
            'id' => $hash, 'user_id' => (int) $user['id'], 'absolute_expires_at' => date('Y-m-d H:i:s', $absolute),
            'google_auth_time' => $authTime, 'ip' => $ip, 'user_agent_hash' => RequestContext::userAgentHash(),
            'user_agent' => RequestContext::userAgent(),
        ]);
        SecureSession::set('user_id', (int) $user['id']);
        SecureSession::set('login_at', time());
        SecureSession::forget('intended');

        Database::setActor((int) $user['id'], 'APP');
        AuditLog::setActor((int) $user['id'], $email, (string) $user['role_code']);
        $amr = isset($claims['amr']) && is_array($claims['amr']) ? implode(',', array_map('strval', $claims['amr'])) : null;
        Database::run('UPDATE users SET google_sub = COALESCE(google_sub, :sub), last_login_at = NOW(3), last_login_ip = :ip, amr_last = :amr,
                       picture_url = :pic, updated_by = :uid WHERE id = :id',
            ['sub' => (string) $claims['sub'], 'ip' => $ip, 'amr' => $amr, 'pic' => isset($claims['picture']) ? mb_substr((string) $claims['picture'], 0, 500) : null,
             'uid' => (int) $user['id'], 'id' => (int) $user['id']]);
        Database::insert('login_attempts', ['email' => $email, 'google_sub' => (string) $claims['sub'], 'ip' => $ip, 'user_agent' => RequestContext::userAgent(), 'outcome' => 'OK']);
        AuditLog::log('LOGIN', 'users', (int) $user['id'], "Login com Google ({$user['role_code']})" . ($amr ? " amr={$amr}" : ''));
        self::$user = false; // força recarga
        return $redirectTo !== '' ? $redirectTo : '/';
    }

    /** @param array<string,mixed> $claims */
    private static function finishReauth(array $claims, string $email): string
    {
        $u = self::user();
        if ($u === null) {
            Response::redirect('/login');
        }
        if ($email !== strtolower((string) $u['email']) || ($u['google_sub'] !== null && $u['google_sub'] !== $claims['sub'])) {
            SecurityEvents::record('REAUTH_OUTRA_CONTA', SecurityEvents::CRITICO, 'Reautenticação feita com outra conta Google', ['sessao' => $u['email'], 'google' => $email], 'users', (int) $u['id']);
            self::logout('REAUTH_OUTRA_CONTA');
            throw HttpException::forbidden('A conta usada na confirmação não é a mesma da sessão. Faça login novamente.');
        }
        $authTime = isset($claims['auth_time']) ? date('Y-m-d H:i:s', (int) $claims['auth_time']) : date('Y-m-d H:i:s');
        Database::run('UPDATE user_sessions SET last_reauth_at = NOW(3), google_auth_time = :t WHERE id = :h', ['t' => $authTime, 'h' => (string) $u['session_hash']]);
        SecureSession::set('login_at', time());
        AuditLog::log('REAUTH', 'users', (int) $u['id'], 'Reautenticação no Google confirmada');
        $return = SecureSession::get('reauth_return', '/');
        SecureSession::forget('reauth_return');
        self::$user = false;
        return is_string($return) ? $return : '/';
    }

    /** Registra a recusa (login_attempts + auditoria), alerta se repetida, e interrompe com 403 genérico. */
    private static function deny(?string $email, string $outcome, string $detail): never
    {
        $ip = RequestContext::ip();
        Database::insert('login_attempts', ['email' => $email, 'ip' => $ip, 'user_agent' => RequestContext::userAgent(), 'outcome' => $outcome, 'detail' => mb_substr($detail, 0, 300)]);
        AuditLog::setActor(null, $email, null);
        AuditLog::log('LOGIN_NEGADO', 'users', null, "Login negado ({$outcome}): {$detail}");
        $limit = Settings::int('security.login_fail_limit', 10);
        $recent = (int) Database::value("SELECT COUNT(*) FROM login_attempts WHERE ip = :ip AND outcome <> 'OK' AND occurred_at > NOW() - INTERVAL 15 MINUTE", ['ip' => $ip]);
        if ($recent === $limit || ($recent > $limit && $recent % 50 === 0)) {
            SecurityEvents::record('LOGIN_NEGADO_REPETIDO', SecurityEvents::AVISO, "{$recent} logins negados do IP {$ip} em 15 minutos", ['ip' => $ip, 'ultimo_email' => $email, 'motivo' => $outcome]);
        }
        if ($outcome === 'NAO_CADASTRADO' || $outcome === 'CONTA_GENERICA') {
            SecurityEvents::record('LOGIN_FORA_ALLOWLIST', SecurityEvents::INFO, "Tentativa de login de conta não autorizada ({$outcome})", ['email' => $email, 'ip' => $ip], null, null, true);
        }
        Logger::warning('Login negado', ['email' => $email, 'motivo' => $outcome, 'detalhe' => $detail]);
        throw HttpException::forbidden('Acesso negado. Somente contas @' . GoogleOidc::hostedDomain() . ' cadastradas e ativas podem entrar. Procure a direção do CELEF.');
    }

    // ---- logout e sessões ----------------------------------------------------------------------------------

    public static function logout(string $reason = 'LOGOUT'): void
    {
        $u = self::user();
        if ($u !== null) {
            self::revoke((string) $u['session_hash'], $reason);
            AuditLog::log('LOGOUT', 'users', (int) $u['id'], 'Logout (' . $reason . ')');
        }
        self::dropSession($reason);
    }

    public static function revoke(string $sessionHash, string $reason, ?int $byUserId = null): void
    {
        Database::run('UPDATE user_sessions SET revoked_at = NOW(3), revoked_by = :by, revoke_reason = :r WHERE id = :h AND revoked_at IS NULL',
            ['by' => $byUserId, 'r' => substr($reason, 0, 30), 'h' => $sessionHash]);
    }

    /** Encerra todas as outras sessões ativas do usuário atual. */
    public static function revokeOthers(): int
    {
        $u = self::user();
        if ($u === null) {
            return 0;
        }
        $n = Database::run('UPDATE user_sessions SET revoked_at = NOW(3), revoked_by = :by, revoke_reason = :r WHERE user_id = :u AND id <> :h AND revoked_at IS NULL',
            ['by' => (int) $u['id'], 'r' => 'OUTRAS_SESSOES', 'u' => (int) $u['id'], 'h' => (string) $u['session_hash']])->rowCount();
        if ($n > 0) {
            AuditLog::log('SESSAO_ENCERRADA', 'users', (int) $u['id'], "Encerrou {$n} outra(s) sessão(ões) própria(s)");
        }
        return $n;
    }

    private static function dropSession(string $reason): void
    {
        self::$user = null;
        SecureSession::destroy($reason);
        SecureSession::start();
        if (!in_array($reason, ['LOGOUT', 'SESSAO_INEXISTENTE'], true)) {
            SecureSession::set('_expired_reason', $reason); // a tela de login explica o motivo
        }
    }

    /** Só caminhos internos relativos à aplicação. */
    public static function safePath(string $path): string
    {
        return (preg_match('~^/(?![/\\\\])[^\s]*$~', $path) && !str_contains($path, '..')) ? $path : '/';
    }
}
