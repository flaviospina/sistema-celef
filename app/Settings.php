<?php
// app/Settings.php — leitura das configurações da tabela settings (cache por requisição)
declare(strict_types=1);

namespace App;

final class Settings
{
    /** @var array<string,mixed>|null */
    private static ?array $cache = null;

    private static function load(): void
    {
        if (self::$cache !== null) {
            return;
        }
        self::$cache = [];
        try {
            foreach (Database::rows('SELECT setting_key, value_json FROM settings WHERE deleted_at IS NULL') as $row) {
                self::$cache[$row['setting_key']] = json_decode((string) $row['value_json'], true);
            }
        } catch (\Throwable $e) {
            // sem banco (ex.: página de instalação): usa só os padrões informados pelos chamadores
            Security\Logger::warning('Settings indisponível', ['erro' => $e->getMessage()]);
        }
    }

    public static function get(string $key, mixed $default = null): mixed
    {
        self::load();
        return array_key_exists($key, self::$cache ?? []) ? self::$cache[$key] : $default;
    }

    public static function int(string $key, int $default): int
    {
        $v = self::get($key, $default);
        return is_numeric($v) ? (int) $v : $default;
    }

    public static function bool(string $key, bool $default): bool
    {
        $v = self::get($key, $default);
        return is_bool($v) ? $v : (bool) $v;
    }

    /** @return list<string> */
    public static function list(string $key): array
    {
        $v = self::get($key, []);
        return is_array($v) ? array_values(array_filter(array_map('strval', $v))) : [];
    }

    /** Gravação auditada (quem/por quê ficam no AuditLog, chamado pelo controller). */
    public static function set(string $key, mixed $value): void
    {
        $json = json_encode($value, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        $row = Database::row('SELECT id, version FROM settings WHERE setting_key = :k', ['k' => $key]);
        if ($row === null) {
            Database::insert('settings', [
                'setting_key' => $key, 'value_json' => $json, 'value_type' => 'json',
                'group_name' => 'geral', 'created_by' => Database::actorUserId(),
            ]);
        } else {
            Database::updateVersioned('settings', (int) $row['id'], (int) $row['version'], [
                'value_json' => $json, 'updated_by' => Database::actorUserId(),
            ]);
        }
        self::$cache = null;
    }
}
