<?php
// app/bootstrap.php — inicialização comum (web e cron): autoload, configuração, erros, fuso, logs
declare(strict_types=1);

if (!defined('APP_ROOT')) {
    http_response_code(500);
    exit('APP_ROOT não definido.');
}

define('APP_PATH', APP_ROOT . '/app');
define('STORAGE_PATH', APP_ROOT . '/storage');
define('APP_VERSION', '0.2.0'); // Fase 2
define('APP_START', microtime(true));

// ---- Autoload PSR-4 simples: App\Security\Crypto → app/Security/Crypto.php ------------------------
spl_autoload_register(static function (string $class): void {
    if (!str_starts_with($class, 'App\\')) {
        return;
    }
    $relative = str_replace('\\', '/', substr($class, 4));
    $candidates = [
        APP_PATH . '/' . $relative . '.php',
        // controllers/models ficam em pastas minúsculas, conforme a estrutura do projeto
        APP_PATH . '/' . lcfirst($relative) . '.php',
    ];
    foreach ($candidates as $file) {
        if (is_file($file)) {
            require $file;
            return;
        }
    }
});

require APP_PATH . '/config.php';
App\Config::load(APP_ROOT);

// ---- Fuso horário, charset e erros ----------------------------------------------------------------------
date_default_timezone_set(App\Config::get('APP_TIMEZONE', 'America/Sao_Paulo'));
mb_internal_encoding('UTF-8');
ini_set('log_errors', '1');
ini_set('error_log', STORAGE_PATH . '/logs/php-error.log');
ini_set('display_errors', App\Config::isProduction() ? '0' : '1');
ini_set('expose_php', '0');
error_reporting(E_ALL);

// Erros de PHP viram exceções (tratadas pelo Kernel ou pelo cron). Avisos de obsolescência só vão para o log:
// não podem derrubar o sistema quando a hospedagem muda a versão do PHP.
set_error_handler(static function (int $severity, string $message, string $file, int $line): bool {
    if (!(error_reporting() & $severity)) {
        return false;
    }
    if ($severity === E_DEPRECATED || $severity === E_USER_DEPRECATED) {
        App\Security\Logger::warning('PHP obsoleto', ['msg' => $message, 'arquivo' => str_replace(APP_ROOT, '', $file) . ':' . $line]);
        return true;
    }
    throw new \ErrorException($message, 0, $severity, $file, $line);
});

// ---- Verificações de ambiente (falham cedo, com mensagem clara no log) -----------------------------
foreach (['pdo_mysql', 'openssl', 'curl', 'sodium', 'mbstring', 'json'] as $ext) {
    if (!extension_loaded($ext)) {
        App\Security\Logger::critical('Extensão PHP ausente', ['extensao' => $ext]);
    }
}
