<?php
// app/controllers/Admin/LogSheetController.php — Admin → Planilha de logs e segurança (configurar, testar escrita, fila, conferência)
declare(strict_types=1);

namespace App\controllers\Admin;

use App\Auth\Rbac;
use App\Database;
use App\Google\GoogleApiException;
use App\Google\GoogleOAuthToken;
use App\Google\SheetLogger;
use App\Google\SheetsClient;
use App\Google\TechAccount;
use App\Http\Request;
use App\Security\AuditLog;
use App\Security\SecureSession;
use App\Security\SecurityEvents;

final class LogSheetController extends AdminController
{
    public function __construct(Request $request)
    {
        parent::__construct($request);
        Rbac::require('admin.planilha_logs');
    }

    public function index(): never
    {
        $result = SecureSession::get('conferencia_logs');
        SecureSession::forget('conferencia_logs');
        $this->render('admin/planilha-logs', ['titulo' => 'Planilha de logs e segurança', 'secaoAdmin' => 'planilha_logs', 'planilha' => SheetLogger::sheet(),
            'fila' => SheetLogger::queueStats(), 'conectada' => GoogleOAuthToken::isConnected(), 'contaTecnica' => GoogleOAuthToken::accountEmail() ?? TechAccount::expectedEmail(),
            'abas' => SheetLogger::TABS, 'conferencia' => is_array($result) ? $result : null,
            'ultimoCron' => Database::row("SELECT started_at, status, summary FROM cron_runs WHERE job_name = 'flush_sheet_log' ORDER BY id DESC LIMIT 1")]);
    }

    /** POST /admin/planilha-logs — define a planilha (ID já extraído do link pelo navegador) */
    public function save(): never
    {
        $id = SheetsClient::parseId((string) $this->request->input('spreadsheet_id'));
        if ($id === null) {
            SecureSession::flash('danger', 'Informe o link ou o ID da planilha de logs.');
            $this->redirect('/admin/planilha-logs');
        }
        $other = Database::row('SELECT id, sheet_role, deleted_at, version FROM connected_sheets WHERE spreadsheet_id = :s', ['s' => $id]);
        if ($other !== null && $other['sheet_role'] !== 'LOGS') {
            SecureSession::flash('danger', 'Esta planilha já está cadastrada como planilha de dados. A planilha de logs precisa ser um arquivo separado.');
            $this->redirect('/admin/planilha-logs');
        }
        $current = SheetLogger::sheet();
        Database::transaction(function () use ($id, $other, $current): void {
            if ($current !== null && $current['spreadsheet_id'] !== $id) {
                Database::updateVersioned('connected_sheets', (int) $current['id'], (int) $current['version'], ['sync_enabled' => 0, 'deleted_at' => date('Y-m-d H:i:s.v'),
                    'deleted_by' => (int) $this->user['id'], 'delete_reason' => 'Substituída por outra planilha de logs', 'updated_by' => (int) $this->user['id']]);
            }
            if ($other !== null) {
                Database::updateVersioned('connected_sheets', (int) $other['id'], (int) $other['version'], ['deleted_at' => null, 'sync_enabled' => 1, 'write_enabled' => 1, 'updated_by' => (int) $this->user['id']]);
                $rowId = (int) $other['id'];
            } else {
                $rowId = Database::insert('connected_sheets', ['name' => 'Planilha de logs e segurança', 'spreadsheet_id' => $id, 'sheet_role' => 'LOGS', 'direction' => 'APPEND_ONLY',
                    'write_enabled' => 1, 'sync_enabled' => 1, 'created_by' => (int) $this->user['id']]);
            }
            $this->adminAction('definiu a planilha de logs e segurança', 'connected_sheets', $rowId, ['id_planilha' => $id]);
        });
        SecureSession::flash('success', 'Planilha de logs definida. Use "Testar escrita" para criar as abas e gravar a primeira linha.');
        $this->redirect('/admin/planilha-logs');
    }

    /** POST /admin/planilha-logs/testar — cria abas (se faltarem), grava uma linha de teste e envia a fila */
    public function test(): never
    {
        $sheet = SheetLogger::sheet();
        if ($sheet === null) {
            SecureSession::flash('danger', 'Defina a planilha de logs primeiro.');
            $this->redirect('/admin/planilha-logs');
        }
        try {
            $r = SheetLogger::ensureTabs((string) $sheet['spreadsheet_id'], time() + 25);
            AuditLog::log('ADMIN', 'connected_sheets', (int) $sheet['id'], 'Teste de escrita na planilha de logs');
            $f = SheetLogger::flush(time() + 25);
            $msg = 'Escrita OK. ' . ($r['criadas'] === [] ? 'As 7 abas já existiam.' : 'Abas criadas: ' . implode(', ', $r['criadas']) . '.')
                 . ($r['protegidas'] === [] ? '' : ' Proteção aplicada em: ' . implode(', ', $r['protegidas']) . '.') . ' ' . $f['mensagem'];
            Database::run('UPDATE connected_sheets SET last_test_at = NOW(3), last_test_result = :r WHERE id = :id', ['r' => mb_substr($msg, 0, 500), 'id' => (int) $sheet['id']]);
            SecureSession::flash($f['falhas'] === 0 ? 'success' : 'warning', $msg);
        } catch (GoogleApiException $e) {
            $msg = $e->friendly(GoogleOAuthToken::accountEmail() ?? TechAccount::expectedEmail());
            Database::run('UPDATE connected_sheets SET last_test_at = NOW(3), last_test_result = :r WHERE id = :id', ['r' => mb_substr($msg, 0, 500), 'id' => (int) $sheet['id']]);
            SecureSession::flash('danger', $msg);
        }
        $this->redirect('/admin/planilha-logs');
    }

    /** POST /admin/planilha-logs/enviar — envia a fila agora */
    public function flush(): never
    {
        $f = SheetLogger::flush(time() + 25);
        SecureSession::flash($f['falhas'] === 0 ? 'success' : 'warning', $f['mensagem']);
        $this->redirect('/admin/planilha-logs');
    }

    /** POST /admin/planilha-logs/conferir — compara planilha × banco */
    public function compare(): never
    {
        Rbac::require('auditoria.conferir_planilha');
        $sheet = SheetLogger::sheet();
        if ($sheet === null) {
            SecureSession::flash('danger', 'Não há planilha de logs configurada.');
            $this->redirect('/admin/planilha-logs');
        }
        try {
            $r = SheetLogger::compare((string) $sheet['spreadsheet_id'], time() + 25);
            $n = count($r['apagadas']) + count($r['alteradas']) + count($r['estranhas']);
            AuditLog::log('SEGURANCA', 'connected_sheets', (int) $sheet['id'], "Conferência da planilha de logs: {$r['conferidas']} linhas, {$n} divergência(s)");
            if (!$r['ok']) {
                SecurityEvents::record('PLANILHA_LOGS_ADULTERADA', SecurityEvents::CRITICO,
                    'A planilha de logs diverge do banco: ' . count($r['apagadas']) . ' linha(s) apagada(s), ' . count($r['alteradas']) . ' alterada(s), ' . count($r['estranhas']) . ' estranha(s). O banco permanece íntegro.',
                    ['apagadas' => count($r['apagadas']), 'alteradas' => count($r['alteradas']), 'estranhas' => count($r['estranhas'])], 'connected_sheets', (int) $sheet['id']);
            }
            // guarda só uma amostra para a tela
            SecureSession::set('conferencia_logs', ['ok' => $r['ok'], 'conferidas' => $r['conferidas'], 'apagadas' => array_slice($r['apagadas'], 0, 30),
                'alteradas' => array_slice($r['alteradas'], 0, 30), 'estranhas' => array_slice($r['estranhas'], 0, 30),
                'totais' => ['apagadas' => count($r['apagadas']), 'alteradas' => count($r['alteradas']), 'estranhas' => count($r['estranhas'])]]);
        } catch (GoogleApiException $e) {
            SecureSession::flash('danger', $e->friendly(GoogleOAuthToken::accountEmail() ?? TechAccount::expectedEmail()));
        }
        $this->redirect('/admin/planilha-logs');
    }
}
