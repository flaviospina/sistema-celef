<?php
// app/Security/Logger.php — log da aplicação em storage/logs (JSON por linha, arquivo diário, sem dado sensível)
declare(strict_types=1);

namespace App\Security;

final class Logger
{
    private static ?string $requestId = null;

    public static function setRequestId(string $id): void
    {
        self::$requestId = $id;
    }

    public static function requestId(): string
    {
        if (self::$requestId === null) {
            self::$requestId = bin2hex(random_bytes(16));
        }
        return self::$requestId;
    }

    /** @param array<string,mixed> $context */
    public static function debug(string $message, array $context = []): void { self::write('DEBUG', $message, $context); }
    /** @param array<string,mixed> $context */
    public static function info(string $message, array $context = []): void { self::write('INFO', $message, $context); }
    /** @param array<string,mixed> $context */
    public static function warning(string $message, array $context = []): void { self::write('AVISO', $message, $context); }
    /** @param array<string,mixed> $context */
    public static function error(string $message, array $context = []): void { self::write('ERRO', $message, $context); }
    /** @param array<string,mixed> $context */
    public static function critical(string $message, array $context = []): void { self::write('CRITICO', $message, $context); }

    /** Registra uma exceção com stack resumido (caminhos relativos a APP_ROOT). */
    public static function exception(\Throwable $e, string $message = 'Exceção não tratada'): void
    {
        self::write('ERRO', $message, [
            'classe'  => $e::class,
            'erro'    => $e->getMessage(),
            'arquivo' => str_replace(APP_ROOT, '', $e->getFile()) . ':' . $e->getLine(),
            'pilha'   => array_slice(array_map(static fn($f) => str_replace(APP_ROOT, '', ($f['file'] ?? '?') . ':' . ($f['line'] ?? '?')), $e->getTrace()), 0, 8),
        ]);
    }

    /** @param array<string,mixed> $context */
    private static function write(string $level, string $message, array $context): void
    {
        if ($level === 'DEBUG' && \App\Config::isProduction()) {
            return;
        }
        $dir = STORAGE_PATH . '/logs';
        if (!is_dir($dir)) {
            @mkdir($dir, 0750, true);
        }
        $line = [
            'ts'      => (new \DateTimeImmutable('now'))->format('Y-m-d\TH:i:s.vP'),
            'nivel'   => $level,
            'req'     => self::requestId(),
            'msg'     => Masker::scrubText($message),
            'ctx'     => Masker::scrubArray($context),
        ];
        $json = json_encode($line, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PARTIAL_OUTPUT_ON_ERROR);
        @file_put_contents($dir . '/app-' . date('Y-m-d') . '.log', $json . PHP_EOL, FILE_APPEND | LOCK_EX);
    }

    /** Remove arquivos de log mais antigos que a retenção (chamado pelo cron). */
    public static function rotate(int $retentionDays): int
    {
        $removed = 0;
        $limit = time() - $retentionDays * 86400;
        foreach (glob(STORAGE_PATH . '/logs/app-*.log') ?: [] as $file) {
            if (filemtime($file) < $limit && @unlink($file)) {
                $removed++;
            }
        }
        return $removed;
    }
}
