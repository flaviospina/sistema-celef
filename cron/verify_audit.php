<?php
// cron/verify_audit.php — verifica a cadeia de hash da auditoria, confere os triggers e grava a âncora diária.
// cPanel → Cron Jobs (1x por dia, ex.: 00:20):  /usr/local/bin/php /home/<usuario>/<dominio>/cron/verify_audit.php
declare(strict_types=1);

require __DIR__ . '/_bootstrap.php';

use App\Cron\JobRunner;
use App\Database;
use App\Security\AuditLog;
use App\Security\Logger;
use App\Security\SecurityEvents;
use App\Settings;

exit(JobRunner::run('verify_audit', static function (int $deadline): string {
    $runId = Database::insert('audit_verification_runs', [
        'started_at' => date('Y-m-d H:i:s.v'), 'from_id' => 1,
        'to_id' => (int) (Database::value('SELECT MAX(id) FROM audit_log') ?? 0), 'result' => 'ERRO',
    ]);

    // 1. cadeia completa (em lotes; a tabela cresce devagar o bastante para verificar tudo diariamente)
    $result = AuditLog::verifyChain(1, null, 2000);
    // 2. triggers de proteção
    $missing = AuditLog::missingTriggers();

    Database::run('UPDATE audit_verification_runs SET finished_at = NOW(3), rows_checked = :n, result = :r, first_broken_id = :b, triggers_ok = :t, detail = :d WHERE id = :id', [
        'n' => $result['checked'], 'r' => $result['ok'] ? 'OK' : 'QUEBRA', 'b' => $result['first_broken_id'],
        't' => $missing === [] ? 1 : 0, 'd' => mb_substr((string) ($result['detail'] ?? ($missing === [] ? '' : 'Triggers ausentes: ' . implode(', ', $missing))), 0, 1000), 'id' => $runId,
    ]);

    if (!$result['ok']) {
        SecurityEvents::record('QUEBRA_HASH', SecurityEvents::CRITICO,
            "Cadeia de hash da auditoria QUEBRADA na linha {$result['first_broken_id']}: {$result['detail']}",
            ['linha' => $result['first_broken_id'], 'verificadas' => $result['checked']], 'audit_log', $result['first_broken_id']);
    }
    if ($missing !== []) {
        SecurityEvents::record('TRIGGER_AUSENTE', SecurityEvents::CRITICO,
            'Triggers de proteção removidos do banco: ' . implode(', ', $missing), ['ausentes' => $missing], 'audit_log', null);
    }

    // 3. âncora do dia anterior
    $anchor = AuditLog::anchorYesterday();
    $anchorMsg = $anchor === null ? 'sem linhas para ancorar' : ($anchor['created'] ? "âncora {$anchor['anchor_date']} criada ({$anchor['row_count']} linhas)" : "âncora {$anchor['anchor_date']} já existia");
    if ($anchor !== null && $anchor['created']) {
        // e-mail da âncora aos administradores (enviado pelo cron de alertas, Fase 10)
        Database::insert('alert_outbox', [
            'kind' => 'ANCORA_DIARIA',
            'recipients_json' => json_encode(SecurityEvents::recipients(), JSON_THROW_ON_ERROR),
            'subject' => "[CELEF] Âncora da auditoria {$anchor['anchor_date']}",
            'body_text' => "Âncora diária da trilha de auditoria do Sistema CELEF\n\nData: {$anchor['anchor_date']}\nLinhas até a âncora: {$anchor['row_count']}\nHash: {$anchor['last_hash']}\n\nGuarde este e-mail: ele prova, de forma independente do servidor, o estado da auditoria neste dia.",
            'status' => 'PENDING', 'next_attempt_at' => date('Y-m-d H:i:s'),
        ]);
    }

    // 4. eventos FORA_DA_APLICACAO criados por trigger ainda sem alerta
    $alerted = SecurityEvents::alertPendingTriggerEvents();

    // 5. rotação de logs
    $removed = Logger::rotate(\App\Config::int('LOG_RETENTION_DAYS', 180));

    return sprintf('cadeia %s (%d linhas), triggers %s, %s, %d alertas de trigger, %d logs antigos removidos',
        $result['ok'] ? 'íntegra' : 'QUEBRADA', $result['checked'], $missing === [] ? 'ok' : 'AUSENTES', $anchorMsg, $alerted, $removed);
}, 300));
