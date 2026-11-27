<?php
// app/Security/SecurityEvents.php — eventos de segurança + fila de alertas por e-mail aos administradores
declare(strict_types=1);

namespace App\Security;

use App\Config;
use App\Database;
use App\Settings;

final class SecurityEvents
{
    public const INFO = 'INFO';
    public const AVISO = 'AVISO';
    public const CRITICO = 'CRITICO';

    /**
     * Registra o evento, grava na auditoria (SEGURANCA) e enfileira o e-mail de alerta.
     * @param array<string,mixed> $detail
     */
    public static function record(string $kind, string $severity, string $summary, array $detail = [], ?string $entity = null, ?int $entityId = null, bool $alert = true): int
    {
        $detail = Masker::scrubArray($detail);
        $auditId = AuditLog::log('SEGURANCA', $entity, $entityId, "[{$kind}] {$summary}", $detail === [] ? null : $detail);
        $eventId = Database::insert('security_events', [
            'severity'     => $severity,
            'kind'         => substr($kind, 0, 40),
            'user_id'      => Database::actorUserId(),
            'entity'       => $entity,
            'entity_id'    => $entityId,
            'detail_json'  => json_encode($detail, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            'audit_log_id' => $auditId,
        ]);
        if ($alert) {
            self::enqueueAlert($kind, $severity, $summary, $detail, $eventId);
        }
        return $eventId;
    }

    /**
     * Eventos criados por TRIGGER (FORA_DA_APLICACAO) ainda sem alerta: gera o e-mail e marca alert_sent_at
     * quando a fila receber. Chamado pelo cron e, oportunisticamente, no acesso ao admin.
     */
    public static function alertPendingTriggerEvents(): int
    {
        $rows = Database::rows("SELECT id, kind, severity, entity, entity_id, detail_json, occurred_at
                                FROM security_events WHERE alert_sent_at IS NULL AND audit_log_id IS NULL ORDER BY id LIMIT 50");
        foreach ($rows as $r) {
            $detail = json_decode((string) ($r['detail_json'] ?? '{}'), true) ?: [];
            $summary = sprintf('Alteração direta no banco (fora da aplicação) em %s%s em %s',
                $r['entity'], $r['entity_id'] !== null ? " #{$r['entity_id']}" : '', $r['occurred_at']);
            $auditId = AuditLog::log('SEGURANCA', (string) $r['entity'], $r['entity_id'] === null ? null : (int) $r['entity_id'], "[{$r['kind']}] {$summary}", $detail);
            self::enqueueAlert((string) $r['kind'], (string) $r['severity'], $summary, $detail, (int) $r['id']);
            Database::run('UPDATE security_events SET audit_log_id = :a, alert_sent_at = NOW(3) WHERE id = :id', ['a' => $auditId, 'id' => (int) $r['id']]);
        }
        return count($rows);
    }

    /** @param array<string,mixed> $detail */
    private static function enqueueAlert(string $kind, string $severity, string $summary, array $detail, int $eventId): void
    {
        $recipients = self::recipients();
        if ($recipients === []) {
            Logger::warning('Alerta sem destinatários (nenhum administrador ativo e alerts.emails vazio)', ['kind' => $kind]);
            return;
        }
        $when = date('d/m/Y H:i:s');
        $lines = ["Sistema CELEF — alerta de segurança", "", "Tipo: {$kind}", "Gravidade: {$severity}", "Quando: {$when}", "", $summary];
        if ($detail !== []) {
            $lines[] = '';
            $lines[] = 'Detalhes: ' . json_encode($detail, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_PRETTY_PRINT);
        }
        $lines[] = '';
        $lines[] = 'Acesse Admin → Segurança para mais informações. Esta mensagem é automática.';
        Database::insert('alert_outbox', [
            'kind'              => substr($kind, 0, 40),
            'recipients_json'   => json_encode($recipients, JSON_THROW_ON_ERROR),
            'subject'           => "[CELEF] {$severity}: {$kind}",
            'body_text'         => implode("\n", $lines),
            'security_event_id' => $eventId,
            'status'            => 'PENDING',
            'next_attempt_at'   => date('Y-m-d H:i:s'),
        ]);
        Database::run('UPDATE security_events SET alert_sent_at = NOW(3) WHERE id = :id AND alert_sent_at IS NULL', ['id' => $eventId]);
    }

    /** alerts.emails (settings) ou, se vazio, todos os administradores ativos; sempre inclui SUPER_ADMIN_EMAILS. @return list<string> */
    public static function recipients(): array
    {
        $list = Settings::list('alerts.emails');
        if ($list === []) {
            $list = array_column(Database::rows(
                "SELECT u.email FROM users u JOIN roles r ON r.id = u.role_id
                 WHERE u.is_active = 1 AND u.deleted_at IS NULL AND r.code IN ('SUPER_ADMIN', 'ADMIN')"), 'email');
        }
        $list = array_merge($list, Config::list('SUPER_ADMIN_EMAILS'));
        $list = array_values(array_unique(array_filter(array_map('strtolower', $list), static fn($e) => str_ends_with($e, '@scseduca.com.br'))));
        return $list;
    }
}
