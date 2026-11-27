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
        // form-action precisa incluir o destino do redirecionamento pós-POST (o navegador aplica a diretiva também
        // ao redirect): o Google e, se configurado para testes, o emulador em GOOGLE_DISCOVERY_URL.
        $formAction = "'self' https://accounts.google.com";
        $disc = \App\Config::get('GOOGLE_DISCOVERY_URL');
        if ($disc !== null && ($u = parse_url($disc)) && isset($u['scheme'], $u['host'])) {
            $formAction .= ' ' . $u['scheme'] . '://' . $u['host'] . (isset($u['port']) ? ':' . $u['port'] : '');
        }
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
            "form-action {$formAction}",
            "upgrade-insecure-requests",
        ]);
        header('Content-Security-Policy: ' . $csp);
        header('X-Content-Type-Options: nosniff');
        header('X-Frame-Options: DENY');
        // same-origin (e não no-referrer): com no-referrer o navegador envia Origin: null até em POST do próprio site,
        // o que inviabiliza a verificação de origem do CSRF. Para outros sites nada é enviado, como antes.
        header('Referrer-Policy: same-origin');
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
            header('Expires: 0');
            // LiteSpeed (HostGator Turbo): nunca guardar páginas dinâmicas no cache do servidor
            header('X-LiteSpeed-Cache-Control: no-cache');
        }
    }
}
