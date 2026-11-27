<?php
// app/Security/SecureSession.php — sessão PHP endurecida (cookie __Host-, strict mode, regeneração, expirações)
// A Fase 3 acrescenta o vínculo com users/user_sessions (encerramento remoto e reautenticação Google).
declare(strict_types=1);

namespace App\Security;

use App\Config;
use App\Settings;

final class SecureSession
{
    public const COOKIE = '__Host-celef';
    private static bool $started = false;

    public static function start(): void
    {
        if (self::$started || session_status() === PHP_SESSION_ACTIVE) {
            self::$started = true;
            return;
        }
        $secure = self::isHttps();
        // Em desenvolvimento local sem HTTPS o prefixo __Host- não é aceito pelo navegador.
        $name = $secure ? self::COOKIE : 'celef_dev';

        ini_set('session.use_strict_mode', '1');
        ini_set('session.use_only_cookies', '1');
        ini_set('session.use_trans_sid', '0');
        ini_set('session.cookie_httponly', '1');
        ini_set('session.cookie_secure', $secure ? '1' : '0');
        ini_set('session.cookie_samesite', 'Strict');
        ini_set('session.sid_length', '48');
        ini_set('session.sid_bits_per_character', '6');
        ini_set('session.gc_maxlifetime', (string) (Settings::int('session.absolute_hours', 8) * 3600));
        ini_set('session.save_path', self::savePath());

        session_name($name);
        session_set_cookie_params([
            'lifetime' => 0,          // cookie de sessão (morre ao fechar o navegador)
            'path'     => '/',
            'domain'   => '',         // obrigatório vazio para __Host-
            'secure'   => $secure,
            'httponly' => true,
            'samesite' => 'Strict',
        ]);
        session_start();
        self::$started = true;

        $now = time();
        $idle = Settings::int('session.idle_minutes', 15) * 60;
        $absolute = Settings::int('session.absolute_hours', 8) * 3600;

        if (isset($_SESSION['_created']) && ($now - (int) $_SESSION['_created']) > $absolute) {
            self::destroy('ABSOLUTA');
            session_start();
        } elseif (isset($_SESSION['_last']) && ($now - (int) $_SESSION['_last']) > $idle) {
            self::destroy('INATIVIDADE');
            session_start();
        }
        $_SESSION['_created'] ??= $now;
        $_SESSION['_last'] = $now;
        $_SESSION['_expired_reason'] ??= null;
    }

    /** Novo id (login, elevação de privilégio). Mantém os dados. */
    public static function regenerate(): void
    {
        self::start();
        session_regenerate_id(true);
    }

    /** Encerra a sessão atual e apaga o cookie. */
    public static function destroy(string $reason = 'LOGOUT'): void
    {
        if (session_status() !== PHP_SESSION_ACTIVE) {
            return;
        }
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $p = session_get_cookie_params();
            setcookie(session_name(), '', [
                'expires' => time() - 42000, 'path' => $p['path'], 'domain' => $p['domain'],
                'secure' => $p['secure'], 'httponly' => $p['httponly'], 'samesite' => $p['samesite'],
            ]);
        }
        session_destroy();
        self::$started = false;
        Logger::info('Sessão encerrada', ['motivo' => $reason]);
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        self::start();
        return $_SESSION[$key] ?? $default;
    }

    public static function set(string $key, mixed $value): void
    {
        self::start();
        $_SESSION[$key] = $value;
    }

    public static function forget(string $key): void
    {
        self::start();
        unset($_SESSION[$key]);
    }

    /** Mensagem única para a próxima requisição (padrão flash). */
    public static function flash(string $type, string $message): void
    {
        self::start();
        $_SESSION['_flash'][] = ['tipo' => $type, 'msg' => $message];
    }

    /** @return list<array{tipo:string,msg:string}> */
    public static function pullFlash(): array
    {
        self::start();
        $f = $_SESSION['_flash'] ?? [];
        unset($_SESSION['_flash']);
        return $f;
    }

    /** SHA-256 do id de sessão: é o que vai para user_sessions.id e audit_log.session_hash. */
    public static function hash(): ?string
    {
        $id = session_id();
        return $id === '' ? null : hash('sha256', $id);
    }

    public static function isHttps(): bool
    {
        return (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off') || (int) ($_SERVER['SERVER_PORT'] ?? 0) === 443;
    }

    private static function savePath(): string
    {
        // Sessões fora do /tmp compartilhado da hospedagem (outras contas não enxergam)
        $dir = STORAGE_PATH . '/sessions';
        if (!is_dir($dir)) {
            @mkdir($dir, 0700, true);
        }
        return $dir;
    }
}
