<?php
// app/Security/RateLimiter.php — limite de requisições por chave (IP, usuário, ação) na tabela rate_limits
declare(strict_types=1);

namespace App\Security;

use App\Database;

final class RateLimiter
{
    /**
     * Registra uma ocorrência e informa se ainda está dentro do limite.
     * Janela fixa: ao expirar, o contador zera. Se exceder, bloqueia por $blockSeconds (padrão = janela).
     * @return array{allowed:bool,remaining:int,retry_after:int}
     */
    public static function hit(string $key, int $limit, int $windowSeconds, ?int $blockSeconds = null): array
    {
        $key = substr($key, 0, 190);
        $blockSeconds ??= $windowSeconds;
        $row = Database::row('SELECT window_start, hit_count, blocked_until FROM rate_limits WHERE bucket_key = :k', ['k' => $key]);
        $now = time();

        if ($row !== null && $row['blocked_until'] !== null && strtotime((string) $row['blocked_until']) > $now) {
            return ['allowed' => false, 'remaining' => 0, 'retry_after' => strtotime((string) $row['blocked_until']) - $now];
        }

        $windowStart = $row === null ? null : strtotime((string) $row['window_start']);
        if ($row === null || $windowStart === false || ($now - $windowStart) >= $windowSeconds) {
            // nova janela (INSERT ... ON DUPLICATE KEY UPDATE usa só INSERT/UPDATE: privilégios da app)
            Database::run(
                'INSERT INTO rate_limits (bucket_key, window_start, hit_count, blocked_until) VALUES (:k, :w, 1, NULL)
                 ON DUPLICATE KEY UPDATE window_start = VALUES(window_start), hit_count = 1, blocked_until = NULL',
                ['k' => $key, 'w' => date('Y-m-d H:i:s', $now)]
            );
            return ['allowed' => true, 'remaining' => max(0, $limit - 1), 'retry_after' => 0];
        }

        $count = (int) $row['hit_count'] + 1;
        if ($count > $limit) {
            Database::run('UPDATE rate_limits SET hit_count = :c, blocked_until = :b WHERE bucket_key = :k',
                ['c' => $count, 'b' => date('Y-m-d H:i:s', $now + $blockSeconds), 'k' => $key]);
            Logger::warning('Rate limit excedido', ['chave' => $key, 'limite' => $limit]);
            return ['allowed' => false, 'remaining' => 0, 'retry_after' => $blockSeconds];
        }
        Database::run('UPDATE rate_limits SET hit_count = :c WHERE bucket_key = :k', ['c' => $count, 'k' => $key]);
        return ['allowed' => true, 'remaining' => $limit - $count, 'retry_after' => 0];
    }

    /** Só consulta (sem contar): quantas ocorrências na janela atual. */
    public static function count(string $key): int
    {
        $row = Database::row('SELECT hit_count FROM rate_limits WHERE bucket_key = :k', ['k' => substr($key, 0, 190)]);
        return $row === null ? 0 : (int) $row['hit_count'];
    }

    public static function reset(string $key): void
    {
        Database::run('UPDATE rate_limits SET hit_count = 0, blocked_until = NULL WHERE bucket_key = :k', ['k' => substr($key, 0, 190)]);
    }
}
