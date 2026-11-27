<?php
// app/config.php — leitura do .env e constantes globais (sem bibliotecas externas)
declare(strict_types=1);

namespace App;

final class Config
{
    /** @var array<string,string> */
    private static array $values = [];
    private static bool $loaded = false;

    /**
     * Lê APP_ROOT/.env (formato CHAVE=valor, aceita aspas e comentários com #).
     * Valores do ambiente do servidor ($_SERVER / getenv) têm prioridade sobre o arquivo.
     */
    public static function load(string $root): void
    {
        if (self::$loaded) {
            return;
        }
        $file = $root . '/.env';
        if (is_file($file) && is_readable($file)) {
            foreach (file($file, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES) as $line) {
                $line = trim($line);
                if ($line === '' || str_starts_with($line, '#') || !str_contains($line, '=')) {
                    continue;
                }
                [$key, $value] = explode('=', $line, 2);
                $key = trim($key);
                $value = trim($value);
                // remove comentário no fim da linha (só fora de aspas)
                if ($value !== '' && $value[0] !== '"' && $value[0] !== "'") {
                    $hash = strpos($value, ' #');
                    if ($hash !== false) {
                        $value = rtrim(substr($value, 0, $hash));
                    }
                } elseif ($value !== '') {
                    $quote = $value[0];
                    $end = strrpos($value, $quote, 1);
                    $value = $end !== false ? substr($value, 1, $end - 1) : substr($value, 1);
                }
                self::$values[$key] = $value;
            }
        }
        self::$loaded = true;
    }

    public static function get(string $key, ?string $default = null): ?string
    {
        $env = $_SERVER[$key] ?? getenv($key);
        if (is_string($env) && $env !== '') {
            return $env;
        }
        $value = self::$values[$key] ?? null;
        return ($value === null || $value === '') ? $default : $value;
    }

    public static function require(string $key): string
    {
        $value = self::get($key);
        if ($value === null) {
            throw new \RuntimeException("Configuração obrigatória ausente no .env: {$key}");
        }
        return $value;
    }

    public static function bool(string $key, bool $default = false): bool
    {
        $value = self::get($key);
        if ($value === null) {
            return $default;
        }
        return in_array(strtolower($value), ['1', 'true', 'sim', 'yes', 'on'], true);
    }

    public static function int(string $key, int $default): int
    {
        $value = self::get($key);
        return ($value === null || !is_numeric($value)) ? $default : (int) $value;
    }

    /** @return string[] lista separada por vírgula, minúscula, sem vazios */
    public static function list(string $key): array
    {
        $value = self::get($key, '') ?? '';
        $items = array_map(static fn(string $v): string => strtolower(trim($v)), explode(',', $value));
        return array_values(array_filter($items, static fn(string $v): bool => $v !== ''));
    }

    public static function isProduction(): bool
    {
        return (self::get('APP_ENV', 'production') ?? 'production') !== 'development';
    }

    /** Verdadeiro quando as chaves de criptografia ainda não foram configuradas (libera /instalacao). */
    public static function cryptoKeysMissing(): bool
    {
        return self::get('APP_KEY_V' . self::int('APP_KEY_VERSION', 1)) === null
            || self::get('BLIND_INDEX_KEY') === null;
    }
}
