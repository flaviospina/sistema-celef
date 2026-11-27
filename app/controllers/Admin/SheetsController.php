<?php
// app/controllers/Admin/SheetsController.php — Admin → Planilhas conectadas (cadastro, teste de conexão, abas e cabeçalhos)
declare(strict_types=1);

namespace App\controllers\Admin;

use App\Auth\Rbac;
use App\Database;
use App\Google\DriveClient;
use App\Google\GoogleApiException;
use App\Google\GoogleOAuthToken;
use App\Google\SheetsClient;
use App\Google\TechAccount;
use App\Http\HttpException;
use App\Http\Request;
use App\Security\SecureSession;
use App\Security\Validator;

final class SheetsController extends AdminController
{
    private const ROLES = ['FONTE_SECRETARIA' => 'Fonte Secretaria (nomes dos alunos)', 'ESPELHO_ESCOLA' => 'Espelho da escola'];
    private const DIRECTIONS = ['IN' => 'Leitura (Planilha → Sistema)', 'OUT' => 'Escrita (Sistema → Planilha)', 'BOTH' => 'Leitura e escrita'];

    public function __construct(Request $request)
    {
        parent::__construct($request);
        Rbac::require('admin.planilhas');
    }

    public function index(): never
    {
        $sheets = Database::rows("SELECT s.*, (SELECT COUNT(*) FROM connected_sheet_tabs t WHERE t.connected_sheet_id = s.id AND t.deleted_at IS NULL) AS abas
                                  FROM connected_sheets s WHERE s.deleted_at IS NULL AND s.sheet_role <> 'LOGS' ORDER BY s.school_year DESC, s.name");
        $this->render('admin/planilhas/lista', ['titulo' => 'Planilhas conectadas', 'secaoAdmin' => 'planilhas', 'planilhas' => $sheets, 'papeis' => self::ROLES,
            'sentidos' => self::DIRECTIONS, 'contaTecnica' => GoogleOAuthToken::accountEmail(), 'conectada' => GoogleOAuthToken::isConnected(), 'emailEsperado' => TechAccount::expectedEmail()]);
    }

    /** POST /admin/planilhas — o ID chega já extraído do link pelo navegador (campo spreadsheet_id) */
    public function store(): never
    {
        $in = $this->request->all();
        $v = new Validator($in);
        $v->required('name', 'Nome')->length('name', 'Nome', 3, 120)->required('sheet_role', 'Papel')->in('sheet_role', 'Papel', array_keys(self::ROLES))
          ->integer('school_year', 'Ano letivo', 2020, 2100);
        $errors = $v->errors();
        $id = SheetsClient::parseId($in['spreadsheet_id'] ?? '');
        if ($id === null) {
            $errors['spreadsheet_id'] = 'Informe o link ou o ID da planilha (o trecho entre /d/ e /edit no endereço).';
        } elseif (Database::value('SELECT 1 FROM connected_sheets WHERE spreadsheet_id = :s', ['s' => $id]) !== null) {
            $errors['spreadsheet_id'] = 'Esta planilha já está cadastrada (verifique também a lixeira e a planilha de logs).';
        }
        if ($errors !== []) {
            SecureSession::flash('danger', implode(' ', $errors));
            $this->redirect('/admin/planilhas');
        }
        $role = $in['sheet_role'];
        // a fonte da Secretaria nasce somente leitura; só o Super Admin habilita escrita depois, explicitamente
        $rowId = Database::insert('connected_sheets', [
            'name' => $in['name'], 'spreadsheet_id' => $id, 'sheet_role' => $role, 'direction' => $role === 'FONTE_SECRETARIA' ? 'IN' : 'BOTH',
            'school_year' => ($in['school_year'] ?? '') === '' ? null : (int) $in['school_year'], 'write_enabled' => $role === 'FONTE_SECRETARIA' ? 0 : 1,
            'sync_enabled' => 0, 'created_by' => (int) $this->user['id'],
        ]);
        $this->adminAction("cadastrou a planilha \"{$in['name']}\" ({$role})", 'connected_sheets', $rowId, ['papel' => $role, 'id_planilha' => $id]);
        SecureSession::flash('success', 'Planilha cadastrada. Use "Testar conexão" para ler as abas. A sincronização fica desligada até o mapeamento de colunas (Fase 5).');
        $this->redirect('/admin/planilhas/' . $rowId);
    }

    public function show(string $id): never
    {
        $sheet = $this->find((int) $id);
        $tabs = Database::rows('SELECT t.*, c.code AS class_code FROM connected_sheet_tabs t LEFT JOIN classes c ON c.id = t.class_id WHERE t.connected_sheet_id = :s AND t.deleted_at IS NULL ORDER BY t.id', ['s' => (int) $sheet['id']]);
        $result = SecureSession::get('teste_planilha_' . $sheet['id']);
        SecureSession::forget('teste_planilha_' . $sheet['id']);
        $this->render('admin/planilhas/detalhe', ['titulo' => $sheet['name'], 'secaoAdmin' => 'planilhas', 'planilha' => $sheet, 'abas' => $tabs, 'papeis' => self::ROLES,
            'sentidos' => self::DIRECTIONS, 'resultado' => is_array($result) ? $result : null, 'contaTecnica' => GoogleOAuthToken::accountEmail() ?? TechAccount::expectedEmail()]);
    }

    /** POST /admin/planilhas/{id}/testar — verifica acesso, lista abas e cabeçalhos, grava as abas */
    public function test(string $id): never
    {
        $sheet = $this->find((int) $id);
        $tech = GoogleOAuthToken::accountEmail() ?? TechAccount::expectedEmail();
        $deadline = time() + 25;
        $result = ['ok' => false, 'mensagem' => '', 'arquivo' => null, 'abas' => []];
        try {
            $meta = SheetsClient::metadata((string) $sheet['spreadsheet_id'], $deadline);
            try {
                $file = DriveClient::file((string) $sheet['spreadsheet_id'], $deadline);
            } catch (GoogleApiException $e) {
                $file = null; // sem a API do Drive ativada o teste segue só com o Sheets
            }
            $ranges = array_map(static fn(array $t) => SheetsClient::range($t['title'], '1:1'), $meta['tabs']);
            $headers = [];
            foreach (array_chunk($ranges, 60) as $chunk) {
                $headers += SheetsClient::batchGet((string) $sheet['spreadsheet_id'], $chunk, $deadline);
            }
            $needsEdit = $sheet['sheet_role'] !== 'FONTE_SECRETARIA' || (int) $sheet['write_enabled'] === 1;
            $canEdit = $file['can_edit'] ?? null;
            $result['ok'] = !($needsEdit && $canEdit === false);
            $result['arquivo'] = $file;
            $result['mensagem'] = "Planilha \"{$meta['title']}\" acessível pela conta técnica {$tech}: " . count($meta['tabs']) . ' aba(s).'
                . ($needsEdit && $canEdit === false ? " ATENÇÃO: a conta técnica só tem leitura; para esta planilha é preciso compartilhar com {$tech} como EDITOR." : '')
                . ($file === null ? ' (Metadados do Drive indisponíveis: ative a API Google Drive no projeto para registrar dono e último editor.)' : '');
            Database::transaction(function () use ($sheet, $meta, $headers, $ranges, &$result, $file): void {
                foreach ($meta['tabs'] as $i => $t) {
                    $header = $headers[$ranges[$i]][0] ?? [];
                    $kind = self::guessKind($t['title']);
                    $result['abas'][] = ['titulo' => $t['title'], 'tipo' => $kind, 'linhas' => $t['rows'], 'cabecalho' => $header];
                    $existing = Database::row('SELECT id, version, tab_title FROM connected_sheet_tabs WHERE connected_sheet_id = :s AND sheet_gid = :g', ['s' => (int) $sheet['id'], 'g' => $t['gid']]);
                    if ($existing === null) {
                        Database::insert('connected_sheet_tabs', ['connected_sheet_id' => (int) $sheet['id'], 'tab_title' => $t['title'], 'sheet_gid' => $t['gid'], 'tab_kind' => $kind,
                            'key_field' => 'ra', 'created_by' => (int) $this->user['id']]);
                    } elseif ($existing['tab_title'] !== $t['title']) {
                        Database::updateVersioned('connected_sheet_tabs', (int) $existing['id'], (int) $existing['version'], ['tab_title' => $t['title'], 'updated_by' => (int) $this->user['id']]);
                    }
                }
                Database::updateVersioned('connected_sheets', (int) $sheet['id'], (int) $sheet['version'], [
                    'last_test_at' => date('Y-m-d H:i:s.v'), 'last_test_result' => mb_substr($result['mensagem'], 0, 500), 'owner_email' => $file['owner'] ?? $sheet['owner_email'],
                    'last_drive_modified_at' => $file['modified_at'] ?? null, 'last_drive_revision_id' => isset($file['head_revision']) ? mb_substr((string) $file['head_revision'], 0, 64) : null,
                    'updated_by' => (int) $this->user['id'],
                ]);
            });
        } catch (GoogleApiException $e) {
            $result['mensagem'] = $e->friendly($tech);
            Database::run('UPDATE connected_sheets SET last_test_at = NOW(3), last_test_result = :r, updated_by = :u WHERE id = :id', ['r' => mb_substr($result['mensagem'], 0, 500), 'u' => (int) $this->user['id'], 'id' => (int) $sheet['id']]);
        }
        \App\Security\AuditLog::log('ADMIN', 'connected_sheets', (int) $sheet['id'], "Testou a conexão com a planilha \"{$sheet['name']}\": " . ($result['ok'] ? 'ok' : 'falhou'));
        SecureSession::set('teste_planilha_' . $sheet['id'], $result);
        $this->redirect('/admin/planilhas/' . $sheet['id']);
    }

    /** POST /admin/planilhas/{id} — nome, papel, ano, sentido; escrita na fonte da Secretaria só pelo Super Admin */
    public function update(string $id): never
    {
        $sheet = $this->find((int) $id);
        $in = $this->request->all();
        $v = new Validator($in);
        $v->required('name', 'Nome')->length('name', 'Nome', 3, 120)->in('sheet_role', 'Papel', array_keys(self::ROLES))->in('direction', 'Sentido', array_keys(self::DIRECTIONS))
          ->integer('school_year', 'Ano letivo', 2020, 2100);
        if ($v->fails()) {
            SecureSession::flash('danger', implode(' ', $v->errors()));
            $this->redirect('/admin/planilhas/' . $sheet['id']);
        }
        $role = $in['sheet_role'] ?? $sheet['sheet_role'];
        $direction = $in['direction'] ?? $sheet['direction'];
        $write = $direction !== 'IN';
        if ($role === 'FONTE_SECRETARIA' && $write) {
            $this->requireSuperAdmin();
            if (($in['confirmar_escrita_secretaria'] ?? '') !== 'SIM') {
                SecureSession::flash('danger', 'Para permitir escrita na planilha da Secretaria, digite SIM no campo de confirmação. O padrão é somente leitura.');
                $this->redirect('/admin/planilhas/' . $sheet['id']);
            }
        }
        $new = ['name' => $in['name'], 'sheet_role' => $role, 'direction' => $direction, 'write_enabled' => $write ? 1 : 0,
                'school_year' => ($in['school_year'] ?? '') === '' ? null : (int) $in['school_year']];
        $diff = [];
        foreach ($new as $k => $val) {
            $old = in_array($k, ['write_enabled', 'school_year'], true) && $sheet[$k] !== null ? (int) $sheet[$k] : $sheet[$k];
            if ($old !== $val) {
                $diff[$k] = ['de' => $old, 'para' => $val];
            }
        }
        if ($diff !== []) {
            if (!Database::updateVersioned('connected_sheets', (int) $sheet['id'], (int) $sheet['version'], $new + ['updated_by' => (int) $this->user['id']])) {
                throw new HttpException(409, 'Conflito', 'A planilha foi alterada por outra pessoa. Recarregue.');
            }
            $this->adminAction("alterou a planilha conectada \"{$sheet['name']}\"", 'connected_sheets', (int) $sheet['id'], $diff);
        }
        SecureSession::flash('success', 'Planilha atualizada.');
        $this->redirect('/admin/planilhas/' . $sheet['id']);
    }

    /** POST /admin/planilhas/{id}/excluir — exclusão lógica (a planilha no Google não é tocada) */
    public function delete(string $id): never
    {
        $sheet = $this->find((int) $id);
        $v = new Validator($this->request->all());
        $v->minReason('motivo');
        if ($v->fails()) {
            SecureSession::flash('danger', $v->errors()['motivo']);
            $this->redirect('/admin/planilhas/' . $sheet['id']);
        }
        $reason = trim((string) $this->request->input('motivo'));
        Database::updateVersioned('connected_sheets', (int) $sheet['id'], (int) $sheet['version'], ['deleted_at' => date('Y-m-d H:i:s.v'), 'deleted_by' => (int) $this->user['id'],
            'delete_reason' => $reason, 'sync_enabled' => 0, 'updated_by' => (int) $this->user['id']]);
        \App\Security\AuditLog::log('EXCLUIR', 'connected_sheets', (int) $sheet['id'], "Desconectou a planilha \"{$sheet['name']}\": {$reason}");
        $this->adminAction("desconectou a planilha \"{$sheet['name']}\" (motivo: {$reason})", 'connected_sheets', (int) $sheet['id']);
        SecureSession::flash('success', 'Planilha desconectada do sistema. O arquivo no Google não foi alterado.');
        $this->redirect('/admin/planilhas');
    }

    /** Palpite do tipo da aba pelo título (confirmado no mapeamento da Fase 5). */
    public static function guessKind(string $title): string
    {
        $t = mb_strtoupper(trim($title));
        return match (true) {
            (bool) preg_match('/^[1-9]\s*º?\s*[A-M]$/u', $t)   => 'TURMA',
            str_contains($t, 'REMANEJ')                       => 'REMANEJAMENTOS',
            str_contains($t, 'DESIST')                        => 'DESISTENTES',
            str_contains($t, 'TOTAL')                         => 'TOTAIS',
            str_contains($t, 'EXCLU')                         => 'EXCLUIDOS',
            default                                           => 'ALUNOS',
        };
    }

    /** @return array<string,mixed> */
    private function find(int $id): array
    {
        return Database::row("SELECT * FROM connected_sheets WHERE id = :id AND deleted_at IS NULL AND sheet_role <> 'LOGS'", ['id' => $id]) ?? throw HttpException::notFound();
    }
}
