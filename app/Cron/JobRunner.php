<?php
// app/Cron/JobRunner.php — executa um job de cron com lock (sem sobreposição), registro em cron_runs e tempo máximo
declare(strict_types=1);

namespace App\Cron;

use App\Database;
use App\Security\Logger;
use App\Settings;

final class JobRunner
{
    /**
     * @param callable(int $deadline): string $job  recebe o timestamp limite e devolve um resumo
     */
    public static function run(string $jobName, callable $job, ?int $maxSeconds = null): int
    {
        $maxSeconds ??= Settings::int('sync.max_seconds', 60);
        $started = microtime(true);
        if (!Database::lock('cron_' . $jobName, 0)) {
            echo "[{$jobName}] já em execução, saindo.\n";
            return 0;
        }
        $runId = Database::insert('cron_runs', ['job_name' => $jobName, 'status' => 'RUNNING']);
        Logger::setRequestId('cron-' . $runId);
        try {
            $summary = (string) $job(time() + $maxSeconds);
            Database::run('UPDATE cron_runs SET finished_at = NOW(3), status = :s, summary = :m WHERE id = :id',
                ['s' => 'OK', 'm' => mb_substr($summary, 0, 500), 'id' => $runId]);
            printf("[%s] OK em %.1fs — %s\n", $jobName, microtime(true) - $started, $summary);
            return 0;
        } catch (\Throwable $e) {
            Logger::exception($e, "Falha no job {$jobName}");
            Database::run('UPDATE cron_runs SET finished_at = NOW(3), status = :s, error = :e WHERE id = :id',
                ['s' => 'ERROR', 'e' => mb_substr($e->getMessage(), 0, 1000), 'id' => $runId]);
            fwrite(STDERR, "[{$jobName}] ERRO: " . $e->getMessage() . "\n");
            return 1;
        } finally {
            Database::unlock('cron_' . $jobName);
        }
    }
}
