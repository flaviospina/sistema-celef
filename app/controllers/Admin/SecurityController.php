<?php
// app/controllers/Admin/SecurityController.php — Admin → Segurança: eventos, sessões ativas, logins negados, alertas
declare(strict_types=1);

namespace App\controllers\Admin;

use App\Auth\Auth;
use App\Auth\Rbac;
use App\Database;
use App\Http\HttpException;
use App\Security\SecureSession;

final class SecurityController extends AdminController
{
    public function index(): never
    {
        Rbac::require('admin.seguranca');
        $period = $this->request->query('periodo') === '7d' ? 7 : 1;
        $events = Database::rows('SELECT e.*, u.email AS user_email FROM security_events e LEFT JOIN users u ON u.id = e.user_id
                                  WHERE e.occurred_at > NOW() - INTERVAL :d DAY ORDER BY e.id DESC LIMIT 200', ['d' => $period]);
        $sessions = Database::rows('SELECT s.id, s.user_id, s.created_at, s.last_seen_at, s.ip, s.user_agent, s.last_reauth_at, u.email, u.full_name
                                    FROM user_sessions s JOIN users u ON u.id = s.user_id
                                    WHERE s.revoked_at IS NULL AND s.absolute_expires_at > NOW() ORDER BY s.last_seen_at DESC LIMIT 200');
        $denied = Database::rows("SELECT email, ip, outcome, detail, occurred_at FROM login_attempts WHERE outcome <> 'OK' AND occurred_at > NOW() - INTERVAL :d DAY ORDER BY id DESC LIMIT 100", ['d' => $period]);
        $alerts = Database::rows('SELECT id, kind, subject, status, attempts, last_error, created_at, sent_at FROM alert_outbox ORDER BY id DESC LIMIT 50');
        $this->render('admin/seguranca', ['titulo' => 'Segurança', 'secaoAdmin' => 'seguranca', 'periodo' => $period, 'eventos' => $events,
            'sessoes' => $sessions, 'negados' => $denied, 'alertas' => $alerts, 'sessaoAtual' => $this->user['session_hash']]);
    }

    /** POST /admin/seguranca/sessoes/{hash}/encerrar */
    public function revokeSession(string $hash): never
    {
        Rbac::require('admin.seguranca');
        if (!preg_match('/^[a-f0-9]{64}$/', $hash)) {
            throw HttpException::notFound();
        }
        $row = Database::row('SELECT s.id, s.user_id, u.email FROM user_sessions s JOIN users u ON u.id = s.user_id WHERE s.id = :h AND s.revoked_at IS NULL', ['h' => $hash]) ?? throw HttpException::notFound('Sessão não encontrada ou já encerrada.');
        Auth::revoke($hash, 'ADMIN', (int) $this->user['id']);
        \App\Security\AuditLog::log('SESSAO_ENCERRADA', 'users', (int) $row['user_id'], "Encerrou remotamente uma sessão de {$row['email']}");
        $this->adminAction("encerrou remotamente uma sessão de {$row['email']}", 'users', (int) $row['user_id']);
        SecureSession::flash('success', "Sessão de {$row['email']} encerrada.");
        $this->redirect('/admin/seguranca');
    }

    /** POST /admin/seguranca/eventos/{id}/ciente */
    public function acknowledge(string $id): never
    {
        Rbac::require('admin.seguranca');
        $n = Database::run('UPDATE security_events SET acknowledged_at = NOW(3), acknowledged_by = :u WHERE id = :id AND acknowledged_at IS NULL', ['u' => (int) $this->user['id'], 'id' => (int) $id])->rowCount();
        if ($n === 1) {
            \App\Security\AuditLog::log('SEGURANCA', 'security_events', (int) $id, 'Marcou evento de segurança como ciente');
        }
        $this->redirect('/admin/seguranca');
    }
}
