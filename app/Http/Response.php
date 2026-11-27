<?php
// app/Http/Response.php — respostas HTML, JSON e redirecionamentos
declare(strict_types=1);

namespace App\Http;

use App\Config;

final class Response
{
    public static function html(string $body, int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: text/html; charset=utf-8');
        echo $body;
        exit;
    }

    /** Padrão { ok, data, mensagem }. Erros de validação: 422. Não autenticado: 401. */
    public static function json(bool $ok, mixed $data = null, string $message = '', int $status = 200): never
    {
        http_response_code($status);
        header('Content-Type: application/json; charset=utf-8');
        echo json_encode(['ok' => $ok, 'data' => $data, 'mensagem' => $message], JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
        exit;
    }

    /** Só redireciona para rotas internas (evita open redirect). */
    public static function redirect(string $path, int $status = 303): never
    {
        if (!preg_match('~^/[^/\\\\]~', $path) && $path !== '/') {
            $path = '/';
        }
        $base = rtrim(Config::get('BASE_URL', '') ?? '', '/');
        http_response_code($status);
        header('Location: ' . $base . $path);
        exit;
    }
}
