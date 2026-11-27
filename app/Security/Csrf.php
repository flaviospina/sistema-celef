<?php
// app/Security/Csrf.php — token CSRF por sessão + verificação de origem
declare(strict_types=1);

namespace App\Security;

use App\Config;

final class Csrf
{
    public const FIELD = '_csrf';
    public const HEADER = 'X-CSRF-Token';

    public static function token(): string
    {
        $token = SecureSession::get('_csrf');
        if (!is_string($token) || strlen($token) !== 64) {
            $token = bin2hex(random_bytes(32));
            SecureSession::set('_csrf', $token);
        }
        return $token;
    }

    /** Campo oculto pronto para o formulário. */
    public static function field(): string
    {
        return '<input type="hidden" name="' . self::FIELD . '" value="' . htmlspecialchars(self::token(), ENT_QUOTES, 'UTF-8') . '">';
    }

    /** Diagnóstico da última validação (sem valores de token), para o log e para APP_DEBUG_ERRORS. */
    public static ?string $lastFailure = null;

    /** Valida o token enviado (POST ou cabeçalho) e, em profundidade, o Origin/Referer. */
    public static function validate(?string $sent): bool
    {
        self::$lastFailure = null;
        $expected = SecureSession::get('_csrf');
        $cookieName = session_name();
        $ctx = sprintf('cookie_de_sessao_recebido=%s; sessao_tem_token=%s; formulario_tem_token=%s; sec-fetch-site=%s; origin=%s; referer=%s; https=%s',
            isset($_COOKIE[$cookieName]) ? 'sim' : "não ({$cookieName})", is_string($expected) ? 'sim' : 'não', is_string($sent) ? 'sim' : 'não',
            $_SERVER['HTTP_SEC_FETCH_SITE'] ?? '-', $_SERVER['HTTP_ORIGIN'] ?? '-', isset($_SERVER['HTTP_REFERER']) ? 'sim' : '-', SecureSession::isHttps() ? 'sim' : 'não');
        if (!is_string($expected) || !is_string($sent) || strlen($sent) !== 64) {
            self::$lastFailure = 'token ausente: ' . $ctx;
            return false;
        }
        if (!hash_equals($expected, $sent)) {
            self::$lastFailure = 'token diferente do da sessão (página antiga ou cacheada): ' . $ctx;
            return false;
        }
        if (!self::originAllowed()) {
            self::$lastFailure = 'Origin/Referer não é este site: ' . $ctx;
            return false;
        }
        return true;
    }

    /** @deprecated mantido por compatibilidade interna */
    private static function validateLegacy(?string $sent): bool
    {
        $expected = SecureSession::get('_csrf');
        if (!is_string($expected) || !is_string($sent) || strlen($sent) !== 64) {
            return false;
        }
        if (!hash_equals($expected, $sent)) {
            return false;
        }
        return self::originAllowed();
    }

    /** Lê o token da requisição: campo do formulário ou cabeçalho (fetch/AJAX). */
    public static function fromRequest(): ?string
    {
        $v = $_POST[self::FIELD] ?? $_SERVER['HTTP_X_CSRF_TOKEN'] ?? null;
        return is_string($v) ? $v : null;
    }

    /**
     * A requisição deve vir do próprio site. Ordem: Sec-Fetch-Site (enviado por todos os navegadores atuais),
     * depois Origin, depois Referer. Sem nenhum deles → negar.
     */
    public static function originAllowed(): bool
    {
        $sfs = $_SERVER['HTTP_SEC_FETCH_SITE'] ?? null;
        if (is_string($sfs) && $sfs !== '') {
            return $sfs === 'same-origin';
        }
        $base = Config::get('BASE_URL');
        $expectedHost = $base ? (parse_url($base, PHP_URL_HOST) ?: null) : null;
        $expectedHost ??= $_SERVER['HTTP_HOST'] ?? null;
        $candidate = $_SERVER['HTTP_ORIGIN'] ?? null;
        if (!is_string($candidate) || $candidate === 'null') {
            $candidate = $_SERVER['HTTP_REFERER'] ?? null;
        }
        if (!is_string($candidate) || $expectedHost === null) {
            return false;
        }
        $host = parse_url($candidate, PHP_URL_HOST);
        return is_string($host) && strcasecmp($host, (string) $expectedHost) === 0;
    }

    public static function rotate(): void
    {
        SecureSession::set('_csrf', bin2hex(random_bytes(32)));
    }
}
