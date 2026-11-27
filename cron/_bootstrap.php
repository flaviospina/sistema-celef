<?php
// cron/_bootstrap.php — inicialização comum dos scripts de cron. Recusa execução via web.
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(403);
    header('Content-Type: text/plain; charset=utf-8');
    exit('Acesso negado.');
}

define('APP_ROOT', dirname(__DIR__));
require APP_ROOT . '/app/bootstrap.php';

App\Database::setActor(null, 'CRON');
App\Security\AuditLog::setActor(null, null, null);
