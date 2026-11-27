<?php
// app/controllers/Admin/AuditController.php — Auditoria: busca na trilha e verificação da cadeia (perfis com auditoria.ver)
declare(strict_types=1);

namespace App\controllers\Admin;

use App\Auth\Auth;
use App\Auth\Rbac;
use App\Database;
use App\Http\AuthenticatedController;
use App\Http\Request;
use App\Security\AuditLog;
use App\Security\SecureSession;
use App\Security\SecurityEvents;
use App\Settings;

final class AuditController extends AuthenticatedController
{
    public function __construct(Request $request)
    {
        parent::__construct($request);
        Rbac::require('auditoria.ver');
        // auditor não é admin, mas também confirma identidade com a mesma folga da área admin
        Auth::requireRecent(Settings::int('session.admin_reauth_minutes', 10), $request->path);
    }

    public function index(): never
    {
        $f = [
            'usuario' => $this->request->query('usuario', ''), 'acao' => $this->request->query('acao', ''), 'entidade' => $this->request->query('entidade', ''),
            'entity_id' => $this->request->query('entity_id', ''), 'de' => $this->request->query('de', ''), 'ate' => $this->request->query('ate', ''),
        ];
        $where = ['1 = 1'];
        $params = [];
        if ($f['usuario'] !== '') { $where[] = 'a.user_email LIKE :u'; $params['u'] = '%' . $f['usuario'] . '%'; }
        if ($f['acao'] !== '' && in_array($f['acao'], AuditLog::ACTIONS, true)) { $where[] = 'a.action = :ac'; $params['ac'] = $f['acao']; }
        if ($f['entidade'] !== '') { $where[] = 'a.entity = :en'; $params['en'] = $f['entidade']; }
        if ($f['entity_id'] !== '' && ctype_digit($f['entity_id'])) { $where[] = 'a.entity_id = :eid'; $params['eid'] = (int) $f['entity_id']; }
        $tz = new \DateTimeZone(date_default_timezone_get());
        if ($f['de'] !== '' && ($d = \DateTimeImmutable::createFromFormat('!Y-m-d', $f['de'], $tz))) { $where[] = 'a.occurred_at >= :de'; $params['de'] = $d->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s'); }
        if ($f['ate'] !== '' && ($d = \DateTimeImmutable::createFromFormat('!Y-m-d', $f['ate'], $tz))) { $where[] = 'a.occurred_at < :ate'; $params['ate'] = $d->modify('+1 day')->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s'); }
        $w = implode(' AND ', $where);
        $page = max(1, (int) ($this->request->query('pagina', '1') ?? 1));
        $per = 25;
        $total = (int) Database::value("SELECT COUNT(*) FROM audit_log a WHERE {$w}", $params);
        $rows = Database::rows("SELECT a.id, a.occurred_at, a.user_email, a.role_code, a.action, a.entity, a.entity_id, a.summary, a.diff_json, a.ip, a.origin, a.hash, a.request_id
                                FROM audit_log a WHERE {$w} ORDER BY a.id DESC LIMIT {$per} OFFSET " . (($page - 1) * $per), $params);
        $this->render('admin/auditoria', ['titulo' => 'Auditoria', 'secaoAdmin' => 'auditoria', 'filtros' => $f, 'linhas' => $rows, 'total' => $total, 'pagina' => $page, 'porPagina' => $per,
            'acoes' => AuditLog::ACTIONS, 'ultimaVerificacao' => Database::row('SELECT * FROM audit_verification_runs ORDER BY id DESC LIMIT 1'),
            'ancoras' => Database::rows('SELECT anchor_date, row_count, last_hash FROM audit_anchor ORDER BY id DESC LIMIT 10'),
            'isSuperAdmin' => Auth::isSuperAdmin()], 'layout/admin');
    }

    /** POST /admin/auditoria/verificar */
    public function verify(): never
    {
        Rbac::require('auditoria.verificar');
        $runId = Database::insert('audit_verification_runs', ['started_at' => date('Y-m-d H:i:s.v'), 'from_id' => 1, 'to_id' => (int) (Database::value('SELECT MAX(id) FROM audit_log') ?? 0), 'result' => 'ERRO']);
        $r = AuditLog::verifyChain();
        $missing = AuditLog::missingTriggers();
        Database::run('UPDATE audit_verification_runs SET finished_at = NOW(3), rows_checked = :n, result = :res, first_broken_id = :b, triggers_ok = :t, detail = :d WHERE id = :id',
            ['n' => $r['checked'], 'res' => $r['ok'] ? 'OK' : 'QUEBRA', 'b' => $r['first_broken_id'], 't' => $missing === [] ? 1 : 0,
             'd' => mb_substr((string) ($r['detail'] ?? implode('; ', $missing)), 0, 1000), 'id' => $runId]);
        AuditLog::log('SEGURANCA', 'audit_log', null, 'Verificação manual da cadeia: ' . ($r['ok'] ? 'íntegra' : 'QUEBRADA') . " ({$r['checked']} linhas)" . ($missing === [] ? '' : '; proteções ausentes'));
        if (!$r['ok']) {
            SecurityEvents::record('QUEBRA_HASH', SecurityEvents::CRITICO, "Cadeia de hash QUEBRADA na linha {$r['first_broken_id']}: {$r['detail']}", ['linha' => $r['first_broken_id']], 'audit_log', $r['first_broken_id']);
        }
        if ($missing !== []) {
            SecurityEvents::record('TRIGGER_AUSENTE', SecurityEvents::CRITICO, 'Proteções do banco ausentes: ' . implode('; ', $missing), ['ausentes' => $missing]);
        }
        SecureSession::flash($r['ok'] && $missing === [] ? 'success' : 'danger',
            ($r['ok'] ? "Cadeia íntegra: {$r['checked']} linhas verificadas." : "CADEIA QUEBRADA na linha {$r['first_broken_id']}: {$r['detail']}") . ($missing === [] ? '' : ' Proteções ausentes: ' . implode('; ', $missing)));
        $this->redirect('/admin/auditoria');
    }
}
