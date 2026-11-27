<?php
// app/Security/Headers.php — cabeçalhos de segurança e Content-Security-Policy com nonce por requisição
declare(strict_types=1);

namespace App\Security;

final class Headers
{
    private static ?string $nonce = null;

    public static function nonce(): string
    {
        return self::$nonce ??= rtrim(strtr(base64_encode(random_bytes(18)), '+/', '-_'), '=');
    }

    /** Envia todos os cabeçalhos. Chamar antes de qualquer saída. */
    public static function apply(bool $noStore = true): void
    {
        if (headers_sent()) {
            return;
        }
        $nonce = self::nonce();
        $csp = implode('; ', [
            "default-src 'self'",
            "script-src 'self' 'nonce-{$nonce}'",
            "style-src 'self' 'nonce-{$nonce}'",
            "img-src 'self' data: blob:",
            "font-src 'self'",
            "connect-src 'self'",
            "frame-src 'none'",
            "frame-ancestors 'none'",
            "object-src 'none'",
            "base-uri 'self'",
            "form-action 'self' https://accounts.google.com",
            "upgrade-insecure-requests",
        ]);
        header('Content-Security-Policy: ' . $csp);
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        header('Referrer-Policy: no-referrer');
        header('Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=()');
        header('Cross-Origin-Opener-Policy: same-origin');
        header('Cross-Origin-Resource-Policy: same-origin');
        header_remove('X-Powered-By');
        if (SecureSession::isHttps()) {
            header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
        }
        if ($noStore) {
            header('Cache-Control: no-store, no-cache, must-revalidate, private');
            header('Pragma: no-cache');
        }
    }
}
