<?php
// app/Http/View.php — renderização de views PHP com layout, escape e nonce de CSP
declare(strict_types=1);

namespace App\Http;

use App\Config;
use App\Security\Csrf;
use App\Security\Headers;
use App\Security\SecureSession;

final class View
{
    /** @param array<string,mixed> $data */
    public function render(string $view, array $data = [], ?string $layout = 'layout/base'): string
    {
        $content = $this->partial($view, $data);
        if ($layout === null) {
            return $content;
        }
        return $this->partial($layout, $data + ['conteudo' => $content]);
    }

    /** @param array<string,mixed> $data */
    public function partial(string $view, array $data = []): string
    {
        $file = APP_PATH . '/views/' . str_replace(['..', "\0"], '', $view) . '.php';
        if (!is_file($file)) {
            throw new \RuntimeException("View não encontrada: {$view}");
        }
        $data += [
            'nonce'     => Headers::nonce(),
            'csrf'      => Csrf::field(),
            'baseUrl'   => rtrim(Config::get('BASE_URL', '') ?? '', '/'),
            'appName'   => Config::get('APP_NAME', 'Sistema CELEF'),
            'flashes'   => $data['flashes'] ?? (session_status() === PHP_SESSION_ACTIVE ? SecureSession::pullFlash() : []),
        ];
        $e = static fn(mixed $v): string => htmlspecialchars((string) ($v ?? ''), ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
        extract($data, EXTR_SKIP);
        ob_start();
        try {
            require $file;
        } catch (\Throwable $t) {
            ob_end_clean();
            throw $t;
        }
        return (string) ob_get_clean();
    }
}
