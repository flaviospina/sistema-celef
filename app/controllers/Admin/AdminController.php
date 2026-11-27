<?php
// app/controllers/Admin/AdminController.php — base da área /admin: perfil ADMIN/SUPER_ADMIN + reautenticação recente
declare(strict_types=1);

namespace App\controllers\Admin;

use App\Auth\Auth;
use App\Auth\Rbac;
use App\Http\AuthenticatedController;
use App\Http\Request;
use App\Security\AuditLog;
use App\Security\SecurityEvents;
use App\Settings;

abstract class AdminController extends AuthenticatedController
{
    public function __construct(Request $request)
    {
        parent::__construct($request);
        Rbac::requireAdmin();
        // login/reautenticação com mais de N minutos → confirmar identidade no Google
        Auth::requireRecent(Settings::int('session.admin_reauth_minutes', 10), $request->path);
    }

    /** @param array<string,mixed> $data */
    protected function render(string $view, array $data = [], ?string $layout = 'layout/admin', int $status = 200): never
    {
        $data += ['isSuperAdmin' => Auth::isSuperAdmin(), 'secaoAdmin' => $data['secaoAdmin'] ?? ''];
        parent::render($view, $data, $layout, $status);
    }

    /**
     * Toda ação administrativa: auditoria (ADMIN) + alerta por e-mail aos demais administradores.
     * @param array<string,mixed>|null $diff
     */
    protected function adminAction(string $summary, ?string $entity = null, ?int $entityId = null, ?array $diff = null): void
    {
        AuditLog::log('ADMIN', $entity, $entityId, $summary, $diff);
        SecurityEvents::record('ACAO_ADMIN', SecurityEvents::INFO, $this->user['email'] . ' ' . $summary . ' em ' . date('d/m/Y H:i'),
            $diff ?? [], $entity, $entityId, true, [(string) $this->user['email']]);
    }

    protected function requireSuperAdmin(): void
    {
        Rbac::requireSuperAdmin();
    }
}
