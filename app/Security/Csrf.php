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

    /** Valida o token enviado (POST ou cabeçalho) e, em profundidade, o Origin/Referer. */
    public static function validate(?string $sent): bool
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

    /** Origin (ou Referer, na ausência) deve ser o próprio site. Sem nenhum dos dois → negar. */
    public static function originAllowed(): bool
    {
        $base = Config::get('BASE_URL');
        $expectedHost = $base ? (parse_url($base, PHP_URL_HOST) ?: null) : null;
        $expectedHost ??= $_SERVER['HTTP_HOST'] ?? null;
        $candidate = $_SERVER['HTTP_ORIGIN'] ?? $_SERVER['HTTP_REFERER'] ?? null;
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
