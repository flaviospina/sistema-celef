<?php
// app/Http/Controller.php — base dos controllers: view, json, validação de entrada
declare(strict_types=1);

namespace App\Http;

abstract class Controller
{
    protected View $view;

    public function __construct(protected Request $request)
    {
        $this->view = new View();
    }

    /** @param array<string,mixed> $data */
    protected function render(string $view, array $data = [], ?string $layout = 'layout/base', int $status = 200): never
    {
        Response::html($this->view->render($view, $data, $layout), $status);
    }

    protected function json(bool $ok, mixed $data = null, string $message = '', int $status = 200): never
    {
        Response::json($ok, $data, $message, $status);
    }

    protected function redirect(string $path): never
    {
        Response::redirect($path);
    }
}
