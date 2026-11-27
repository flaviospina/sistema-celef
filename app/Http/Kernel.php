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

            // Retorno do Google: página-ponte servida ANTES de iniciar a sessão (ver googleReturnPage)
            if ($request->path === \App\Auth\GoogleOidc::RETURN_PATH && in_array($request->method, ['GET', 'HEAD'], true)) {
                self::googleReturnPage();
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
                Logger::warning('CSRF inválido', ['rota' => $request->path, 'ip' => RequestContext::ip(), 'motivo' => Csrf::$lastFailure]);
                $detail = (!Config::isProduction() || Config::bool('APP_DEBUG_ERRORS', false)) ? (string) Csrf::$lastFailure : null;
                self::error($request, 419, 'Sessão expirada', 'Sua sessão expirou ou o formulário é inválido. Volte e tente novamente.', $detail);
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

    /**
     * Página-ponte do retorno do Google (redirect_uri). Não toca em sessão nem em banco, por dois motivos:
     *  1) este pedido chega por navegação vinda de outro site, então o cookie de sessão SameSite=Strict NÃO vem junto;
     *     se a sessão fosse iniciada aqui, um cookie novo sobrescreveria o do usuário e o "state" se perderia;
     *  2) a navegação seguinte, feita pelo script abaixo, parte do próprio site: o cookie é enviado normalmente.
     * O script encaminha SOMENTE code, state e error (os demais parâmetros, como iss e scope, contêm URLs e são barrados
     * pelo firewall da hospedagem em qualquer rota sem extensão de arquivo estático).
     */
    private static function googleReturnPage(): never
    {
        $nonce = Headers::nonce();
        header('Content-Type: text/html; charset=utf-8');
        echo '<!DOCTYPE html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">'
           . '<meta name="robots" content="noindex, nofollow"><title>Concluindo o login…</title>'
           . '<style nonce="' . $nonce . '">body{font-family:system-ui,Segoe UI,Roboto,sans-serif;background:#163a5a;color:#fff;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0;text-align:center;padding:1rem}a{color:#fff}</style>'
           . '</head><body><p id="msg">Concluindo o login…</p>'
           . '<noscript><p>Este sistema precisa de JavaScript habilitado para concluir o login.</p></noscript>'
           . '<script nonce="' . $nonce . '">(function(){"use strict";'
           . 'var bruto=window.location.search.length>1?window.location.search.substring(1):window.location.hash.substring(1);'
           . 'var e=new URLSearchParams(bruto),s=new URLSearchParams();'
           . '["code","state","error"].forEach(function(k){if(e.has(k)){s.set(k,e.get(k));}});'
           . 'if(!s.has("state")){document.getElementById("msg").innerHTML=\'Retorno do Google incompleto. <a href="../../login">Volte ao sistema</a> e tente entrar novamente.\';return;}'
           . 'window.location.replace("callback?"+s.toString());'   // relativo: …/auth/google/retorno.css → …/auth/google/callback
           . '})();</script></body></html>';
        exit;
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
