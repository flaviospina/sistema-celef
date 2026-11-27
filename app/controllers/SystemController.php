<?php
// app/controllers/SystemController.php — página inicial provisória, status da instalação e geração de chaves
declare(strict_types=1);

namespace App\controllers;

use App\Config;
use App\Database;
use App\Http\Controller;
use App\Http\HttpException;
use App\Security\Crypto;
use App\Security\Logger;
use App\Security\RateLimiter;
use App\Security\RequestContext;
use App\Settings;

final class SystemController extends Controller
{
    /** Até a Fase 3 (login), a página inicial só apresenta o sistema. */
    public function home(): never
    {
        $this->render('system/home', ['titulo' => 'Sistema CELEF']);
    }

    /**
     * /status → "OK" genérico. Com ?token=<STATUS_TOKEN> mostra o diagnóstico completo.
     * Limitado por IP para não servir de sonda.
     */
    public function status(): never
    {
        if (!RateLimiter::hit('ip:' . RequestContext::ip() . ':status', 20, 300)['allowed']) {
            throw new HttpException(429, 'Muitas requisições', 'Aguarde alguns minutos.');
        }
        $checks = $this->checks();
        $allOk = !in_array(false, array_column($checks, 'ok'), true);

        $token = Config::get('STATUS_TOKEN');
        $sent = $this->request->query('token');
        $detailed = $token !== null && is_string($sent) && hash_equals($token, $sent);
        if (!$detailed) {
            $this->render('system/status', ['titulo' => 'Status', 'allOk' => $allOk, 'checks' => null], 'layout/minimo', $allOk ? 200 : 503);
        }
        $this->render('system/status', ['titulo' => 'Status detalhado', 'allOk' => $allOk, 'checks' => $checks], 'layout/minimo', $allOk ? 200 : 503);
    }

    /**
     * /instalacao → gera APP_KEY_V1 e BLIND_INDEX_KEY para colar no .env.
     * Só existe enquanto as chaves NÃO estiverem configuradas; depois responde 404.
     * As chaves são geradas no servidor e exibidas uma única vez; nada é gravado.
     */
    public function install(): never
    {
        if (!Config::cryptoKeysMissing()) {
            throw HttpException::notFound();
        }
        if (!RateLimiter::hit('ip:' . RequestContext::ip() . ':instalacao', 5, 600)['allowed']) {
            throw new HttpException(429, 'Muitas requisições', 'Aguarde alguns minutos.');
        }
        Logger::warning('Página de instalação acessada (chaves ainda não configuradas)', ['ip' => RequestContext::ip()]);
        $keys = Crypto::generateKeys();
        $this->render('system/instalacao', [
            'titulo'   => 'Instalação — chaves de criptografia',
            'appKey'   => $keys['app_key'],
            'blindKey' => $keys['blind_key'],
            'statusToken' => Crypto::randomToken(24),
            'checks'   => $this->checks(),
        ], 'layout/minimo');
    }

    public function privacy(): never
    {
        $this->render('system/privacidade', [
            'titulo' => 'Aviso de privacidade',
            'texto'  => (string) Settings::get('privacy.notice_text', ''),
            'versao' => (string) Settings::get('privacy.notice_version', '1.0'),
        ]);
    }

    /** @return list<array{item:string,ok:bool,info:string}> */
    private function checks(): array
    {
        $checks = [];
        $checks[] = ['item' => 'PHP', 'ok' => version_compare(PHP_VERSION, '8.2.0', '>='), 'info' => PHP_VERSION];
        foreach (['pdo_mysql', 'openssl', 'curl', 'sodium', 'mbstring', 'fileinfo', 'gd', 'json'] as $ext) {
            $checks[] = ['item' => "Extensão {$ext}", 'ok' => extension_loaded($ext), 'info' => extension_loaded($ext) ? 'carregada' : 'AUSENTE'];
        }
        $checks[] = ['item' => 'HTTPS', 'ok' => \App\Security\SecureSession::isHttps() || !Config::isProduction(), 'info' => \App\Security\SecureSession::isHttps() ? 'sim' : 'não'];
        $checks[] = ['item' => '.env encontrado', 'ok' => is_file(APP_ROOT . '/.env'), 'info' => is_file(APP_ROOT . '/.env') ? 'sim' : 'copie .env.example para .env'];
        $checks[] = ['item' => '.env fora da pasta pública', 'ok' => !is_file(APP_ROOT . '/public/.env'), 'info' => is_file(APP_ROOT . '/public/.env') ? 'ARQUIVO .env DENTRO DE public/ — remover!' : 'ok'];
        $perm = is_file(APP_ROOT . '/.env') ? substr(sprintf('%o', fileperms(APP_ROOT . '/.env')), -3) : '-';
        $checks[] = ['item' => 'Permissão do .env', 'ok' => $perm === '-' || in_array($perm, ['600', '400', '640'], true), 'info' => $perm . ($perm === '-' ? '' : ' (recomendado 600)')];
        foreach (['logs', 'uploads', 'sessions', 'cache', 'tmp'] as $dir) {
            $path = STORAGE_PATH . '/' . $dir;
            if (!is_dir($path)) {
                @mkdir($path, 0750, true);
            }
            $checks[] = ['item' => "storage/{$dir} gravável", 'ok' => is_writable($path), 'info' => is_writable($path) ? 'sim' : 'ajustar permissão (750)'];
        }
        $checks[] = ['item' => 'Chaves de criptografia', 'ok' => !Config::cryptoKeysMissing(), 'info' => Config::cryptoKeysMissing() ? 'não configuradas — acesse /instalacao' : 'versão ' . Crypto::currentVersion()];
        if (!Config::cryptoKeysMissing()) {
            try {
                $ok = Crypto::decrypt(Crypto::encrypt('teste', 'status'), 'status') === 'teste' && Crypto::blindIndex('x') !== null;
                $checks[] = ['item' => 'Cifrar/decifrar', 'ok' => $ok, 'info' => $ok ? 'ok' : 'falhou'];
            } catch (\Throwable $e) {
                $checks[] = ['item' => 'Cifrar/decifrar', 'ok' => false, 'info' => 'chave inválida'];
            }
        }
        try {
            $version = (string) Database::value('SELECT VERSION()');
            $tables = (int) Database::value('SELECT COUNT(*) FROM information_schema.tables WHERE table_schema = DATABASE()');
            $checks[] = ['item' => 'Banco de dados', 'ok' => true, 'info' => $version];
            $checks[] = ['item' => 'Tabelas (esperado 72)', 'ok' => $tables >= 72, 'info' => (string) $tables];
            $missing = \App\Security\AuditLog::missingTriggers();
            $checks[] = ['item' => 'Triggers de proteção (sonda funcional)', 'ok' => $missing === [], 'info' => $missing === [] ? 'ativos: hash no INSERT, bloqueio de UPDATE, versionamento' : 'FALHOU: ' . implode('; ', $missing)];
            $grants = array_map(static fn($r) => (string) array_values($r)[0], Database::rows('SHOW GRANTS FOR CURRENT_USER()'));
            $tooMuch = (bool) preg_grep('/\b(DELETE|DROP|ALTER|CREATE|ALL PRIVILEGES|TRIGGER|INDEX)\b/', $grants);
            $checks[] = ['item' => 'Privilégios do usuário da app', 'ok' => !$tooMuch, 'info' => $tooMuch ? 'EXCESSIVOS: só SELECT, INSERT, UPDATE, EXECUTE' : 'mínimos'];
            $super = (int) Database::value("SELECT COUNT(*) FROM users u JOIN roles r ON r.id = u.role_id WHERE r.code = 'SUPER_ADMIN' AND u.is_active = 1 AND u.deleted_at IS NULL");
            $checks[] = ['item' => 'Super Administrador ativo', 'ok' => $super > 0, 'info' => (string) $super];
        } catch (\Throwable $e) {
            $checks[] = ['item' => 'Banco de dados', 'ok' => false, 'info' => 'sem conexão (verifique DB_* no .env)'];
        }
        return $checks;
    }
}
