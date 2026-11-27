<?php
// app/controllers/Admin/UsersController.php — Admin → Usuários (cadastro, perfil, turmas, ativação, exclusão lógica, restauração)
declare(strict_types=1);

namespace App\controllers\Admin;

use App\Auth\Rbac;
use App\Database;
use App\Http\HttpException;
use App\models\UserService;
use App\Security\SecureSession;
use App\Security\Validator;

final class UsersController extends AdminController
{
    public function index(): never
    {
        Rbac::require('admin.usuarios');
        $f = ['q' => $this->request->query('q', ''), 'role' => $this->request->query('perfil', ''), 'ativo' => $this->request->query('ativo', ''), 'lixeira' => $this->request->query('lixeira') === '1'];
        $page = max(1, (int) ($this->request->query('pagina', '1') ?? 1));
        $this->render('admin/usuarios/lista', ['titulo' => 'Usuários', 'secaoAdmin' => 'usuarios', 'filtros' => $f, 'lista' => UserService::search($f, $page), 'perfis' => UserService::roles()]);
    }

    public function create(): never
    {
        Rbac::require('admin.usuarios');
        $this->form(null, [], []);
    }

    public function store(): never
    {
        Rbac::require('admin.usuarios');
        $in = $this->request->all();
        $errors = UserService::validate($in, true);
        $roleCode = $in['role_code'] ?? '';
        if ($errors === [] && ($msg = UserService::guardChange(['id' => 0, 'email' => $in['email'], 'role_code' => $roleCode, 'is_active' => 1, 'deleted_at' => null], $this->user, $roleCode, true)) !== null) {
            $errors['role_code'] = $msg;
        }
        if ($errors !== []) {
            $this->form(null, $in, $errors);
        }
        $email = mb_strtolower(trim($in['email']));
        $classIds = $this->classIdsFromInput();
        $id = Database::transaction(function () use ($in, $email, $roleCode, $classIds): int {
            $id = Database::insert('users', [
                'email' => $email, 'full_name' => trim($in['full_name']), 'role_id' => UserService::roleIdByCode($roleCode),
                'is_active' => isset($in['is_active']) ? 1 : 0, 'notes' => mb_substr($in['notes'] ?? '', 0, 500) ?: null, 'created_by' => (int) $this->user['id'],
            ]);
            if (in_array($roleCode, ['PROFESSOR', 'COORDENACAO'], true) && $classIds !== []) {
                UserService::syncClasses($id, $roleCode, $classIds, (int) $this->user['id']);
            }
            $this->adminAction("cadastrou o usuário {$email} com perfil {$roleCode}", 'users', $id, ['email' => $email, 'perfil' => $roleCode, 'turmas' => $classIds]);
            return $id;
        });
        SecureSession::flash('success', "Usuário {$email} cadastrado.");
        $this->redirect('/admin/usuarios/' . $id);
    }

    public function edit(string $id): never
    {
        Rbac::require('admin.usuarios');
        $user = UserService::find((int) $id) ?? throw HttpException::notFound();
        $this->form($user, [], []);
    }

    public function update(string $id): never
    {
        Rbac::require('admin.usuarios');
        $target = UserService::find((int) $id) ?? throw HttpException::notFound();
        if ($target['deleted_at'] !== null) {
            throw HttpException::forbidden('Usuário na lixeira: restaure antes de editar.');
        }
        $in = $this->request->all();
        $errors = UserService::validate($in, false);
        $roleCode = $in['role_code'] ?? $target['role_code'];
        $active = isset($in['is_active']);
        $self = (int) $target['id'] === (int) $this->user['id'];
        if ($self) { // ninguém altera o próprio perfil/ativação
            $roleCode = $target['role_code'];
            $active = true;
        }
        if ($errors === [] && ($msg = UserService::guardChange($target, $this->user, $roleCode, $active)) !== null) {
            $errors['role_code'] = $msg;
        }
        if ($errors !== []) {
            $this->form($target, $in, $errors);
        }
        $classIds = $this->classIdsFromInput();
        $diff = [];
        foreach (['full_name' => trim($in['full_name']), 'role_code' => $roleCode, 'is_active' => $active ? 1 : 0, 'notes' => mb_substr($in['notes'] ?? '', 0, 500) ?: null] as $k => $v) {
            $old = $k === 'is_active' ? (int) $target[$k] : $target[$k];
            if ($old !== $v) {
                $diff[$k] = ['de' => $old, 'para' => $v];
            }
        }
        Database::transaction(function () use ($target, $in, $roleCode, $active, $classIds, &$diff): void {
            $ok = Database::updateVersioned('users', (int) $target['id'], (int) $target['version'], [
                'full_name' => trim($in['full_name']), 'role_id' => UserService::roleIdByCode($roleCode), 'is_active' => $active ? 1 : 0,
                'notes' => mb_substr($in['notes'] ?? '', 0, 500) ?: null, 'updated_by' => (int) $this->user['id'],
            ]);
            if (!$ok) {
                throw new HttpException(409, 'Conflito', 'Este usuário foi alterado por outra pessoa enquanto você editava. Recarregue e tente de novo.');
            }
            if (in_array($roleCode, ['PROFESSOR', 'COORDENACAO'], true)) {
                $r = UserService::syncClasses((int) $target['id'], $roleCode, $classIds, (int) $this->user['id']);
                if ($r['adicionadas'] !== [] || $r['removidas'] !== []) {
                    $diff['turmas'] = $r;
                }
            } elseif (UserService::assignedClassIds((int) $target['id']) !== []) {
                $r = UserService::syncClasses((int) $target['id'], 'PROFESSOR', [], (int) $this->user['id']);
                $diff['turmas'] = $r;
            }
            if (!$active && (int) $target['is_active'] === 1) {
                Database::run('UPDATE user_sessions SET revoked_at = NOW(3), revoked_by = :by, revoke_reason = :r WHERE user_id = :u AND revoked_at IS NULL', ['by' => (int) $this->user['id'], 'r' => 'ADMIN', 'u' => (int) $target['id']]);
            }
            $this->adminAction("alterou o usuário {$target['email']}", 'users', (int) $target['id'], $diff === [] ? null : $diff);
        });
        Rbac::flush();
        SecureSession::flash('success', 'Usuário atualizado.');
        $this->redirect('/admin/usuarios/' . $target['id']);
    }

    /** POST /admin/usuarios/{id}/excluir — exclusão lógica com motivo */
    public function delete(string $id): never
    {
        Rbac::require('admin.usuarios');
        $target = UserService::find((int) $id) ?? throw HttpException::notFound();
        $v = new Validator($this->request->all());
        $v->minReason('motivo');
        if ($v->fails()) {
            SecureSession::flash('danger', $v->errors()['motivo']);
            $this->redirect('/admin/usuarios/' . $target['id']);
        }
        if (($msg = UserService::guardChange($target, $this->user, null, null, true)) !== null) {
            SecureSession::flash('danger', $msg);
            $this->redirect('/admin/usuarios/' . $target['id']);
        }
        $reason = trim((string) $this->request->input('motivo'));
        Database::transaction(function () use ($target, $reason): void {
            Database::updateVersioned('users', (int) $target['id'], (int) $target['version'], ['deleted_at' => date('Y-m-d H:i:s.v'), 'deleted_by' => (int) $this->user['id'], 'delete_reason' => $reason, 'is_active' => 0, 'updated_by' => (int) $this->user['id']]);
            Database::run('UPDATE user_sessions SET revoked_at = NOW(3), revoked_by = :by, revoke_reason = :r WHERE user_id = :u AND revoked_at IS NULL', ['by' => (int) $this->user['id'], 'r' => 'ADMIN', 'u' => (int) $target['id']]);
            \App\Security\AuditLog::log('EXCLUIR', 'users', (int) $target['id'], "Excluiu (lixeira) o usuário {$target['email']}: {$reason}");
            $this->adminAction("excluiu o usuário {$target['email']} (motivo: {$reason})", 'users', (int) $target['id']);
        });
        SecureSession::flash('success', 'Usuário enviado para a lixeira.');
        $this->redirect('/admin/usuarios?lixeira=1');
    }

    /** POST /admin/usuarios/{id}/restaurar */
    public function restore(string $id): never
    {
        Rbac::require('admin.lixeira');
        $target = UserService::find((int) $id) ?? throw HttpException::notFound();
        if ($target['deleted_at'] === null) {
            $this->redirect('/admin/usuarios/' . $target['id']);
        }
        Database::updateVersioned('users', (int) $target['id'], (int) $target['version'], ['deleted_at' => null, 'updated_by' => (int) $this->user['id']]);
        \App\Security\AuditLog::log('RESTAURAR', 'users', (int) $target['id'], "Restaurou o usuário {$target['email']} da lixeira");
        $this->adminAction("restaurou o usuário {$target['email']}", 'users', (int) $target['id']);
        SecureSession::flash('success', 'Usuário restaurado (permanece desativado até você reativar).');
        $this->redirect('/admin/usuarios/' . $target['id']);
    }

    /** POST /admin/usuarios/{id}/encerrar-sessoes */
    public function revokeSessions(string $id): never
    {
        Rbac::require('admin.seguranca');
        $target = UserService::find((int) $id) ?? throw HttpException::notFound();
        $n = Database::run('UPDATE user_sessions SET revoked_at = NOW(3), revoked_by = :by, revoke_reason = :r WHERE user_id = :u AND revoked_at IS NULL', ['by' => (int) $this->user['id'], 'r' => 'ADMIN', 'u' => (int) $target['id']])->rowCount();
        \App\Security\AuditLog::log('SESSAO_ENCERRADA', 'users', (int) $target['id'], "Encerrou {$n} sessão(ões) de {$target['email']}");
        $this->adminAction("encerrou {$n} sessão(ões) de {$target['email']}", 'users', (int) $target['id']);
        SecureSession::flash('success', "{$n} sessão(ões) encerrada(s).");
        $this->redirect('/admin/usuarios/' . $target['id']);
    }

    /** @return list<int> */
    private function classIdsFromInput(): array
    {
        $ids = $_POST['turmas'] ?? [];
        if (!is_array($ids)) {
            return [];
        }
        return array_values(array_unique(array_map('intval', array_filter($ids, static fn($v) => is_string($v) && ctype_digit($v)))));
    }

    /** @param array<string,mixed>|null $user @param array<string,string> $in @param array<string,string> $errors */
    private function form(?array $user, array $in, array $errors): never
    {
        $values = $user === null ? ['email' => '', 'full_name' => '', 'role_code' => 'PROFESSOR', 'is_active' => 1, 'notes' => ''] : $user;
        $values = array_merge($values, $in);
        if ($in !== []) {
            $values['is_active'] = isset($in['is_active']) ? 1 : 0;
        }
        $assigned = $user === null ? ($in !== [] ? $this->classIdsFromInput() : []) : UserService::assignedClassIds((int) $user['id']);
        $sessions = $user === null ? [] : Database::rows('SELECT id, created_at, last_seen_at, ip, user_agent, revoked_at, revoke_reason FROM user_sessions WHERE user_id = :u ORDER BY created_at DESC LIMIT 10', ['u' => (int) $user['id']]);
        $this->render('admin/usuarios/form', [
            'titulo' => $user === null ? 'Novo usuário' : 'Usuário: ' . $user['full_name'], 'secaoAdmin' => 'usuarios',
            'usuarioAlvo' => $user, 'valores' => $values, 'erros' => $errors, 'perfis' => UserService::roles(),
            'turmas' => UserService::classesForAssignment(), 'turmasVinculadas' => $assigned, 'sessoes' => $sessions,
            'protegido' => $user !== null && \App\Auth\Auth::isProtectedEmail((string) $user['email']),
            'ehProprio' => $user !== null && (int) $user['id'] === (int) $this->user['id'],
        ], 'layout/admin', $errors === [] ? 200 : 422);
    }
}
