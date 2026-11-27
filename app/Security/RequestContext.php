<?php
// app/Security/RequestContext.php — IP, user-agent e request_id da requisição atual (web ou cron)
declare(strict_types=1);

namespace App\Security;

final class RequestContext
{
    /**
     * HostGator compartilhado: Apache atende direto, sem proxy reverso confiável.
     * Por isso usamos SÓ REMOTE_ADDR (X-Forwarded-For é forjável). Se um dia houver Cloudflare,
     * trocar aqui por CF-Connecting-IP validando o IP de origem.
     */
    public static function ip(): string
    {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '';
        return filter_var($ip, FILTER_VALIDATE_IP) ? $ip : (PHP_SAPI === 'cli' ? 'cli' : '0.0.0.0');
    }

    public static function userAgent(): ?string
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;
        return is_string($ua) ? mb_substr($ua, 0, 300) : (PHP_SAPI === 'cli' ? 'cli' : null);
    }

    public static function userAgentHash(): string
    {
        return hash('sha256', (string) self::userAgent());
    }

    public static function requestId(): string
    {
        return Logger::requestId();
    }

    public static function isCli(): bool
    {
        return PHP_SAPI === 'cli';
    }
}
