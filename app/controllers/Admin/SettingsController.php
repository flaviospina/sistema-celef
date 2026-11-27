<?php
// app/controllers/Admin/SettingsController.php — Admin → Configurações (settings) e padrões de e-mail bloqueados
declare(strict_types=1);

namespace App\controllers\Admin;

use App\Auth\Rbac;
use App\Database;
use App\Http\HttpException;
use App\Security\SecureSession;
use App\Security\Validator;
use App\Settings;

final class SettingsController extends AdminController
{
    /** Campos editáveis: chave → [rótulo, tipo, min, max] (o que não está aqui não é editável pela tela) */
    private const FIELDS = [
        'sessao' => [
            'session.idle_minutes'          => ['Expiração por inatividade (minutos)', 'int', 5, 120],
            'session.absolute_hours'        => ['Expiração absoluta (horas)', 'int', 1, 24],
            'session.admin_reauth_minutes'  => ['Área admin: reautenticar após (minutos)', 'int', 1, 120],
            'session.bind_user_agent'       => ['Encerrar sessão se o navegador mudar', 'bool', 0, 1],
            'session.bind_ip'               => ['Encerrar sessão se o IP mudar', 'bool', 0, 1],
        ],
        'seguranca' => [
            'security.login_fail_limit'       => ['Logins negados por IP em 15 min antes de alertar', 'int', 3, 100],
            'security.sensitive_hourly_limit' => ['Leituras de dados sensíveis por usuário/hora antes de alertar', 'int', 5, 1000],
            'security.export_max_rows'        => ['Limite de registros por exportação', 'int', 10, 10000],
            'security.mass_export_threshold'  => ['Exportação exige aprovação a partir de (registros)', 'int', 10, 10000],
            'backup.retention_days'           => ['Retenção dos backups (dias)', 'int', 7, 3650],
        ],
        'alertas' => [
            'alerts.emails'                => ['E-mails que recebem alertas (um por linha; vazio = todos os administradores)', 'emails', 0, 20],
            'alerts.from_email'            => ['Remetente dos e-mails', 'email', 0, 190],
            'alerts.sync_failure_minutes'  => ['Alertar se sincronização falhar por mais de (minutos)', 'int', 5, 1440],
        ],
        'sync' => [
            'sync.batch_rows'        => ['Linhas por lote', 'int', 50, 5000],
            'sync.max_seconds'       => ['Tempo máximo por execução (s)', 'int', 10, 600],
            'sync.cron_minutes'      => ['Intervalo do cron (min, informativo)', 'int', 1, 60],
            'sync.opportunistic'     => ['Sincronizar quando um admin abre o painel', 'bool', 0, 1],
            'sync.log_flush_minutes' => ['Envio da fila para a planilha de logs (min)', 'int', 1, 60],
        ],
        'diario' => [
            'diary.edit_days' => ['Dias para o professor editar o diário sem aprovação', 'int', 0, 60],
        ],
        'lgpd' => [
            'lgpd.retention_years'      => ['Retenção após a saída do aluno (anos)', 'int', 1, 30],
            'lgpd.collect_social_media' => ['Coletar o campo REDES SOCIAIS', 'bool', 0, 1],
            'lgpd.image_term_version'   => ['Versão do termo de autorização de imagem', 'string', 1, 20],
            'privacy.notice_version'    => ['Versão do aviso de privacidade (mudar exige novo aceite de todos)', 'string', 1, 20],
            'privacy.notice_text'       => ['Texto do aviso de privacidade', 'text', 20, 4000],
        ],
        'marca' => [
            'branding.school_name' => ['Nome da instituição', 'string', 3, 160],
            'branding.org_name'    => ['Órgão', 'string', 3, 160],
        ],
    ];

    public function index(): never
    {
        Rbac::require('admin.configuracoes');
        $values = [];
        foreach (self::FIELDS as $group => $fields) {
            foreach ($fields as $key => $def) {
                $values[$key] = Settings::get($key);
            }
        }
        $patterns = Database::rows('SELECT id, pattern, description, is_active FROM blocked_email_patterns WHERE deleted_at IS NULL ORDER BY pattern');
        $this->render('admin/configuracoes', ['titulo' => 'Configurações', 'secaoAdmin' => 'configuracoes', 'grupos' => self::FIELDS, 'valores' => $values, 'padroes' => $patterns]);
    }

    /** POST /admin/configuracoes/{grupo} */
    public function update(string $group): never
    {
        Rbac::require('admin.configuracoes');
        $fields = self::FIELDS[$group] ?? throw HttpException::notFound();
        $errors = [];
        $diff = [];
        $new = [];
        foreach ($fields as $key => [$label, $type, $min, $max]) {
            // o PHP troca '.' por '_' nos nomes dos campos enviados por formulário
            $raw = $this->request->input(str_replace('.', '_', $key));
            $old = Settings::get($key);
            switch ($type) {
                case 'int':
                    if ($raw === null || !preg_match('/^\d+$/', $raw) || (int) $raw < $min || (int) $raw > $max) {
                        $errors[$key] = "{$label}: informe um número entre {$min} e {$max}.";
                        continue 2;
                    }
                    $value = (int) $raw;
                    break;
                case 'bool':
                    $value = $raw === '1';
                    break;
                case 'email':
                    $value = trim((string) $raw);
                    if ($value !== '' && !Validator::isEmail($value)) {
                        $errors[$key] = "{$label}: e-mail inválido.";
                        continue 2;
                    }
                    break;
                case 'emails':
                    $list = array_values(array_filter(array_map(static fn($l) => mb_strtolower(trim($l)), preg_split('/[\r\n,;]+/', (string) $raw) ?: [])));
                    foreach ($list as $e) {
                        if (!Validator::isEmail($e) || !str_ends_with($e, '@scseduca.com.br')) {
                            $errors[$key] = "{$label}: '{$e}' não é um e-mail @scseduca.com.br válido.";
                            continue 3;
                        }
                    }
                    $value = $list;
                    break;
                case 'text':
                case 'string':
                default:
                    $value = trim((string) $raw);
                    $len = mb_strlen($value);
                    if ($len < $min || $len > $max) {
                        $errors[$key] = "{$label}: entre {$min} e {$max} caracteres.";
                        continue 2;
                    }
            }
            $new[$key] = $value;
            if ($old !== $value) {
                $diff[$key] = ['de' => $old, 'para' => $value];
            }
        }
        if ($errors !== []) {
            SecureSession::flash('danger', implode(' ', $errors));
            $this->redirect('/admin/configuracoes#' . $group);
        }
        if ($diff !== []) {
            Database::transaction(function () use ($new, $diff, $group): void {
                foreach ($diff as $key => $_) {
                    Settings::set($key, $new[$key]);
                }
                $this->adminAction("alterou configurações do grupo {$group}", 'settings', null, $diff);
            });
            SecureSession::flash('success', 'Configurações salvas.');
        } else {
            SecureSession::flash('info', 'Nada foi alterado.');
        }
        $this->redirect('/admin/configuracoes#' . $group);
    }

    /** POST /admin/configuracoes/padroes — adiciona padrão de e-mail bloqueado */
    public function addPattern(): never
    {
        Rbac::require('admin.configuracoes');
        $pattern = mb_strtolower(trim((string) $this->request->input('pattern')));
        $desc = mb_substr(trim((string) $this->request->input('description')), 0, 300);
        if ($pattern === '' || mb_strlen($pattern) > 190 || !preg_match('/^[a-z0-9._%@-]+$/', $pattern)) {
            SecureSession::flash('danger', 'Padrão inválido. Use letras, números, ponto, hífen, @ e % (curinga). Ex.: celef%2028@%');
            $this->redirect('/admin/configuracoes#padroes');
        }
        $exists = Database::row('SELECT id, version, deleted_at FROM blocked_email_patterns WHERE pattern = :p', ['p' => $pattern]);
        if ($exists !== null) {
            Database::updateVersioned('blocked_email_patterns', (int) $exists['id'], (int) $exists['version'], ['deleted_at' => null, 'is_active' => 1, 'description' => $desc ?: null, 'updated_by' => (int) $this->user['id']]);
            $id = (int) $exists['id'];
        } else {
            $id = Database::insert('blocked_email_patterns', ['pattern' => $pattern, 'description' => $desc ?: null, 'created_by' => (int) $this->user['id']]);
        }
        $this->adminAction("adicionou o padrão de e-mail bloqueado {$pattern}", 'blocked_email_patterns', $id, ['pattern' => $pattern]);
        SecureSession::flash('success', 'Padrão adicionado.');
        $this->redirect('/admin/configuracoes#padroes');
    }

    /** POST /admin/configuracoes/padroes/{id}/alternar — ativa/desativa */
    public function togglePattern(string $id): never
    {
        Rbac::require('admin.configuracoes');
        $row = Database::row('SELECT id, pattern, is_active, version FROM blocked_email_patterns WHERE id = :id AND deleted_at IS NULL', ['id' => (int) $id]) ?? throw HttpException::notFound();
        $new = (int) $row['is_active'] === 1 ? 0 : 1;
        Database::updateVersioned('blocked_email_patterns', (int) $row['id'], (int) $row['version'], ['is_active' => $new, 'updated_by' => (int) $this->user['id']]);
        $this->adminAction(($new ? 'ativou' : 'desativou') . " o padrão bloqueado {$row['pattern']}", 'blocked_email_patterns', (int) $row['id'], ['is_active' => ['de' => (int) $row['is_active'], 'para' => $new]]);
        SecureSession::flash('success', 'Padrão atualizado.');
        $this->redirect('/admin/configuracoes#padroes');
    }
}
