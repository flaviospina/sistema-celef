<?php
// app/controllers/Admin/AdministratorsController.php — Admin → Administradores (só Super Admin promove/rebaixa)
declare(strict_types=1);

namespace App\controllers\Admin;

use App\Auth\Auth;
use App\Auth\Rbac;
use App\Database;
use App\Http\HttpException;
use App\models\UserService;
use App\Security\SecureSession;

final class AdministratorsController extends AdminController
{
    public function index(): never
    {
        Rbac::require('admin.administradores');
        $admins = Database::rows("SELECT u.id, u.email, u.full_name, u.is_active, u.last_login_at, r.code AS role_code FROM users u JOIN roles r ON r.id = u.role_id
                                  WHERE r.code IN ('SUPER_ADMIN','ADMIN') AND u.deleted_at IS NULL ORDER BY r.id, u.full_name");
        $others = Database::rows("SELECT u.id, u.email, u.full_name, r.code AS role_code FROM users u JOIN roles r ON r.id = u.role_id
                                  WHERE r.code NOT IN ('SUPER_ADMIN','ADMIN') AND u.deleted_at IS NULL AND u.is_active = 1 ORDER BY u.full_name");
        $this->render('admin/administradores', ['titulo' => 'Administradores', 'secaoAdmin' => 'administradores', 'admins' => $admins, 'outros' => $others,
            'protegidos' => \App\Config::list('SUPER_ADMIN_EMAILS')]);
    }

    /** POST /admin/administradores/{id}/perfil  (role_code = SUPER_ADMIN | ADMIN | <outro perfil para rebaixar>) */
    public function changeRole(string $id): never
    {
        $this->requireSuperAdmin();
        $target = UserService::find((int) $id) ?? throw HttpException::notFound();
        $newRole = (string) $this->request->input('role_code', '');
        if (UserService::roleIdByCode($newRole) === null) {
            SecureSession::flash('danger', 'Perfil inválido.');
            $this->redirect('/admin/administradores');
        }
        if (($msg = UserService::guardChange($target, $this->user, $newRole, null)) !== null) {
            SecureSession::flash('danger', $msg);
            $this->redirect('/admin/administradores');
        }
        if ($newRole === $target['role_code']) {
            $this->redirect('/admin/administradores');
        }
        $ok = Database::updateVersioned('users', (int) $target['id'], (int) $target['version'], ['role_id' => UserService::roleIdByCode($newRole), 'updated_by' => (int) $this->user['id']]);
        if (!$ok) {
            throw new HttpException(409, 'Conflito', 'O usuário foi alterado por outra pessoa. Recarregue.');
        }
        \App\Security\AuditLog::log('PERMISSAO', 'users', (int) $target['id'], "Perfil de {$target['email']}: {$target['role_code']} → {$newRole}", ['perfil' => ['de' => $target['role_code'], 'para' => $newRole]]);
        $verb = in_array($newRole, ['SUPER_ADMIN', 'ADMIN'], true) ? 'promoveu' : 'rebaixou';
        $this->adminAction("{$verb} {$target['email']} para {$newRole}", 'users', (int) $target['id'], ['perfil' => ['de' => $target['role_code'], 'para' => $newRole]]);
        // perfil mudou: sessões abertas do alvo perdem validade (recarregam permissões no próximo acesso)
        Database::run('UPDATE user_sessions SET revoked_at = NOW(3), revoked_by = :by, revoke_reason = :r WHERE user_id = :u AND revoked_at IS NULL', ['by' => (int) $this->user['id'], 'r' => 'ADMIN', 'u' => (int) $target['id']]);
        Rbac::flush();
        SecureSession::flash('success', "{$target['email']} agora é {$newRole}.");
        $this->redirect('/admin/administradores');
    }
}
