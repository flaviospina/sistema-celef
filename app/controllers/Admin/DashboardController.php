<?php
// app/controllers/Admin/DashboardController.php — painel inicial da área administrativa
declare(strict_types=1);

namespace App\controllers\Admin;

use App\Auth\GoogleOidc;
use App\Database;
use App\Security\SecurityEvents;

final class DashboardController extends AdminController
{
    public function index(): never
    {
        // disparo oportunista: eventos criados por trigger (FORA_DA_APLICACAO) ganham alerta ao abrir o painel
        try {
            SecurityEvents::alertPendingTriggerEvents();
        } catch (\Throwable $e) {
            \App\Security\Logger::exception($e, 'Falha ao processar eventos pendentes');
        }
        $stats = [
            'usuarios_ativos'   => (int) Database::value('SELECT COUNT(*) FROM users WHERE is_active = 1 AND deleted_at IS NULL'),
            'sessoes_ativas'    => (int) Database::value('SELECT COUNT(*) FROM user_sessions WHERE revoked_at IS NULL AND absolute_expires_at > NOW()'),
            'eventos_24h'       => (int) Database::value('SELECT COUNT(*) FROM security_events WHERE occurred_at > NOW() - INTERVAL 1 DAY'),
            'criticos_7d'       => (int) Database::value("SELECT COUNT(*) FROM security_events WHERE severity = 'CRITICO' AND occurred_at > NOW() - INTERVAL 7 DAY AND acknowledged_at IS NULL"),
            'logins_negados_24h'=> (int) Database::value("SELECT COUNT(*) FROM login_attempts WHERE outcome <> 'OK' AND occurred_at > NOW() - INTERVAL 1 DAY"),
            'auditoria_total'   => (int) Database::value('SELECT COUNT(*) FROM audit_log'),
            'alertas_pendentes' => (int) Database::value("SELECT COUNT(*) FROM alert_outbox WHERE status = 'PENDING'"),
            'logs_planilha_pend'=> (int) Database::value("SELECT COUNT(*) FROM sheet_log_outbox WHERE status = 'PENDING'"),
        ];
        $lastVerify = Database::row('SELECT started_at, result, rows_checked, triggers_ok FROM audit_verification_runs ORDER BY id DESC LIMIT 1');
        $lastAnchor = Database::row('SELECT anchor_date, row_count, last_hash FROM audit_anchor ORDER BY id DESC LIMIT 1');
        $avisos = [];
        if (!GoogleOidc::isConfigured()) {
            $avisos[] = 'Login com Google não configurado (GOOGLE_CLIENT_ID/GOOGLE_CLIENT_SECRET no .env).';
        }
        if (Database::value("SELECT 1 FROM google_credentials WHERE is_active = 1 AND status = 'CONNECTED'") === null) {
            $avisos[] = 'Conta técnica Google não conectada (Fase 4): sincronização e planilha de logs inativas.';
        }
        if (Database::value("SELECT 1 FROM connected_sheets WHERE sheet_role = 'LOGS' AND deleted_at IS NULL") === null) {
            $avisos[] = 'Nenhuma planilha de logs configurada: os registros ficam apenas no banco.';
        }
        $this->render('admin/dashboard', ['titulo' => 'Administração', 'secaoAdmin' => 'inicio', 'stats' => $stats, 'ultimaVerificacao' => $lastVerify, 'ultimaAncora' => $lastAnchor, 'avisos' => $avisos]);
    }
}
