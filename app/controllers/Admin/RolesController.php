<?php
// app/controllers/Admin/RolesController.php — Admin → Perfis e permissões (matriz perfil × permissão)
declare(strict_types=1);

namespace App\controllers\Admin;

use App\Auth\Rbac;
use App\Database;
use App\Http\HttpException;
use App\Security\SecureSession;

final class RolesController extends AdminController
{
    public function index(): never
    {
        Rbac::require('admin.perfis');
        $roles = Database::rows('SELECT id, code, name, description FROM roles WHERE deleted_at IS NULL ORDER BY id');
        $perms = Database::rows('SELECT id, code, module, description, is_sensitive FROM permissions ORDER BY module, code');
        $granted = [];
        foreach (Database::rows('SELECT role_id, permission_id FROM role_permissions WHERE is_granted = 1') as $r) {
            $granted[(int) $r['role_id']][(int) $r['permission_id']] = true;
        }
        $byModule = [];
        foreach ($perms as $p) {
            $byModule[$p['module']][] = $p;
        }
        $this->render('admin/perfis', ['titulo' => 'Perfis e permissões', 'secaoAdmin' => 'perfis', 'perfis' => $roles, 'modulos' => $byModule, 'concedidas' => $granted]);
    }

    /** POST /admin/perfis/{roleId} — recebe perms[] (ids concedidos) */
    public function update(string $roleId): never
    {
        Rbac::require('admin.perfis');
        $role = Database::row('SELECT id, code, name FROM roles WHERE id = :id AND deleted_at IS NULL', ['id' => (int) $roleId]) ?? throw HttpException::notFound();
        if ($role['code'] === 'SUPER_ADMIN') {
            throw HttpException::forbidden('O Super Administrador sempre tem todas as permissões.');
        }
        if (in_array($role['code'], ['ADMIN'], true)) {
            $this->requireSuperAdmin();
        }
        $wanted = $_POST['perms'] ?? [];
        $wanted = is_array($wanted) ? array_map('intval', array_filter($wanted, static fn($v) => is_string($v) && ctype_digit($v))) : [];
        $all = Database::rows('SELECT id, code FROM permissions');
        $validIds = array_map('intval', array_column($all, 'id'));
        $wanted = array_values(array_intersect($wanted, $validIds));
        // ADMIN nunca recebe as permissões exclusivas do Super Admin
        if ($role['code'] === 'ADMIN') {
            $exclusive = array_map('intval', array_column(array_filter($all, static fn($p) => in_array($p['code'], ['admin.administradores', 'admin.conta_tecnica', 'admin.planilhas', 'admin.planilha_logs'], true)), 'id'));
            $wanted = array_values(array_diff($wanted, $exclusive));
        }
        $current = array_map('intval', array_column(Database::rows('SELECT permission_id FROM role_permissions WHERE role_id = :r AND is_granted = 1', ['r' => (int) $role['id']]), 'permission_id'));
        $add = array_diff($wanted, $current);
        $remove = array_diff($current, $wanted);
        $codes = array_column($all, 'code', 'id');
        Database::transaction(function () use ($role, $add, $remove): void {
            foreach ($add as $pid) {
                Database::run('INSERT INTO role_permissions (role_id, permission_id, is_granted, created_by) VALUES (:r, :p, 1, :u)
                               ON DUPLICATE KEY UPDATE is_granted = 1, updated_by = :u2', ['r' => (int) $role['id'], 'p' => $pid, 'u' => (int) $this->user['id'], 'u2' => (int) $this->user['id']]);
            }
            foreach ($remove as $pid) {
                Database::run('UPDATE role_permissions SET is_granted = 0, updated_by = :u WHERE role_id = :r AND permission_id = :p', ['u' => (int) $this->user['id'], 'r' => (int) $role['id'], 'p' => $pid]);
            }
        });
        if ($add !== [] || $remove !== []) {
            $diff = ['concedidas' => array_values(array_map(static fn($i) => $codes[$i], $add)), 'revogadas' => array_values(array_map(static fn($i) => $codes[$i], $remove))];
            \App\Security\AuditLog::log('PERMISSAO', 'roles', (int) $role['id'], "Permissões do perfil {$role['code']} alteradas", $diff);
            $this->adminAction("alterou as permissões do perfil {$role['code']}", 'roles', (int) $role['id'], $diff);
            Rbac::flush();
        }
        SecureSession::flash('success', "Permissões do perfil {$role['name']} salvas.");
        $this->redirect('/admin/perfis');
    }
}
