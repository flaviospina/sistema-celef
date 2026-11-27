<?php
// app/Http/Kernel.php — ciclo da requisição: cabeçalhos, sessão, roteamento, CSRF, erros genéricos
declare(strict_types=1);

namespace App\Http;

use App\Config;
use App\Security\Csrf;
use App\Security\Headers;
use App\Security\Logger;
use App\Security\RateLimiter;
use App\Security\RequestContext;
use App\Security\SecureSession;

final class Kernel
{
    public static function handle(): void
    {
        Logger::setRequestId(bin2hex(random_bytes(16)));
        $request = new Request();
        try {
            Headers::apply();

            // Sem .env não há como seguir: mensagem clara (sem expor caminhos) para quem está instalando
            if (!is_file(APP_ROOT . '/.env')) {
                self::error($request, 500, 'Instalação incompleta',
                    'O arquivo .env não foi encontrado na pasta do projeto (a mesma pasta de app/ e public/). Copie .env.example para .env e preencha.');
            }

            SecureSession::start();

            // Limite global por IP (proteção básica contra abuso; limites específicos ficam nos controllers).
            // Páginas de diagnóstico (/status, /instalacao) continuam funcionando mesmo sem banco.
            $diagnostic = in_array($request->path, ['/status', '/instalacao'], true);
            try {
                $limit = RateLimiter::hit('ip:' . RequestContext::ip() . ':global', 300, 60);
                if (!$limit['allowed']) {
                    self::tooMany($request, $limit['retry_after']);
                }
            } catch (\RuntimeException $e) {
                if (!$diagnostic) {
                    throw $e;
                }
            }

            $router = new Router();
            require APP_PATH . '/routes.php';   // define as rotas em $router

            $match = $router->match($request->method, $request->path);
            if ($match === null) {
                self::error($request, 404, 'Página não encontrada', 'O endereço informado não existe neste sistema.');
            }
            if ($match === 'METHOD') {
                self::error($request, 405, 'Método não permitido', 'Esta página não aceita esse tipo de requisição.');
            }

            // Todo POST exige token CSRF válido (fail-closed)
            if ($request->isPost() && !Csrf::validate(Csrf::fromRequest())) {
                Logger::warning('CSRF inválido', ['rota' => $request->path, 'ip' => RequestContext::ip()]);
                self::error($request, 419, 'Sessão expirada', 'Sua sessão expirou ou o formulário é inválido. Volte e tente novamente.');
            }

            [$class, $method] = $match['handler'];
            $controller = new $class($request);
            $controller->$method(...array_values($match['params']));
        } catch (HttpException $e) {
            self::error($request, $e->status, $e->title, $e->getMessage());
        } catch (\Throwable $e) {
            Logger::exception($e);
            $showDetail = !Config::isProduction() || Config::bool('APP_DEBUG_ERRORS', false);
            $detail = $showDetail ? $e::class . ': ' . $e->getMessage() . ' em ' . str_replace(APP_ROOT, '', $e->getFile()) . ':' . $e->getLine() : null;
            if ($showDetail && $e->getPrevious() !== null) {
                $detail .= "\nCausa: " . $e->getPrevious()->getMessage();
            }
            self::error($request, 500, 'Erro interno', 'Ocorreu um erro inesperado. Informe o código abaixo ao administrador.', $detail);
        }
    }

    private static function tooMany(Request $request, int $retryAfter): never
    {
        header('Retry-After: ' . max(1, $retryAfter));
        self::error($request, 429, 'Muitas requisições', 'Aguarde alguns instantes antes de tentar novamente.');
    }

    public static function error(Request $request, int $status, string $title, string $message, ?string $detail = null): never
    {
        if ($request->wantsJson()) {
            Response::json(false, ['codigo' => Logger::requestId()], $message, $status);
        }
        $view = new View();
        Response::html($view->render('errors/erro', [
            'titulo' => $title, 'mensagem' => $message, 'status' => $status,
            'codigo' => Logger::requestId(), 'detalhe' => $detail,
        ], 'layout/minimo'), $status);
    }
}
