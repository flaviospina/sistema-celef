<?php
// app/Http/Request.php — leitura segura da requisição HTTP
declare(strict_types=1);

namespace App\Http;

final class Request
{
    public readonly string $method;
    public readonly string $path;

    public function __construct()
    {
        $this->method = strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
        $uri = (string) ($_SERVER['REQUEST_URI'] ?? '/');
        $path = parse_url($uri, PHP_URL_PATH) ?: '/';
        $path = '/' . trim(preg_replace('~/+~', '/', $path) ?? '/', '/');
        // remove prefixo de subpasta, se BASE_URL tiver caminho (ex.: https://dominio/celef)
        $basePath = parse_url(\App\Config::get('BASE_URL', '') ?? '', PHP_URL_PATH);
        if (is_string($basePath) && $basePath !== '/' && $basePath !== '' && str_starts_with($path, $basePath)) {
            $path = '/' . ltrim(substr($path, strlen($basePath)), '/');
        }
        $this->path = $path === '' ? '/' : $path;
    }

    public function isPost(): bool { return $this->method === 'POST'; }
    public function isGet(): bool { return $this->method === 'GET'; }

    /** Valor de query string, sempre string (ou null). */
    public function query(string $key, ?string $default = null): ?string
    {
        $v = $_GET[$key] ?? null;
        return is_string($v) ? trim($v) : $default;
    }

    /** Valor de formulário POST, sempre string (ou null). */
    public function input(string $key, ?string $default = null): ?string
    {
        $v = $_POST[$key] ?? null;
        return is_string($v) ? trim($v) : $default;
    }

    public function int(string $key, ?int $default = null): ?int
    {
        $v = $this->input($key) ?? $this->query($key);
        return ($v !== null && preg_match('/^-?\d{1,18}$/', $v)) ? (int) $v : $default;
    }

    /** @return array<string,string> todos os campos POST escalares, aparados */
    public function all(): array
    {
        $out = [];
        foreach ($_POST as $k => $v) {
            if (is_string($v)) {
                $out[(string) $k] = trim($v);
            }
        }
        return $out;
    }

    public function wantsJson(): bool
    {
        $accept = $_SERVER['HTTP_ACCEPT'] ?? '';
        return str_contains($accept, 'application/json') || ($_SERVER['HTTP_X_REQUESTED_WITH'] ?? '') === 'fetch';
    }
}
