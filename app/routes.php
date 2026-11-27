<?php
// app/routes.php — tabela de rotas ($router já instanciado pelo Kernel)
declare(strict_types=1);

use App\controllers\Admin\AdministratorsController;
use App\controllers\Admin\AuditController;
use App\controllers\Admin\DashboardController;
use App\controllers\Admin\LogSheetController;
use App\controllers\Admin\RolesController;
use App\controllers\Admin\SecurityController;
use App\controllers\Admin\SettingsController;
use App\controllers\Admin\SheetsController;
use App\controllers\Admin\TechAccountController;
use App\controllers\Admin\UsersController;
use App\controllers\AuthController;
use App\controllers\HomeController;
use App\controllers\SystemController;

/** @var App\Http\Router $router */

// ---- públicas ----------------------------------------------------------------------------------------------
$router->get('/status',      [SystemController::class, 'status']);
$router->get('/instalacao',  [SystemController::class, 'install']);
$router->get('/privacidade', [SystemController::class, 'privacy']);

// ---- autenticação --------------------------------------------------------------------------------------------
$router->get('/login',                 [AuthController::class, 'login']);
$router->post('/login/google',         [AuthController::class, 'startGoogle']);
$router->get('/auth/google/callback',  [AuthController::class, 'callback']);
$router->post('/logout',               [AuthController::class, 'logout']);
$router->get('/reauth',                [AuthController::class, 'reauthPage']);
$router->post('/reauth',               [AuthController::class, 'reauthStart']);
$router->get('/privacidade/aceite',    [AuthController::class, 'privacyPage']);
$router->post('/privacidade/aceite',   [AuthController::class, 'privacyAccept']);
$router->get('/minhas-sessoes',        [AuthController::class, 'sessions']);
$router->post('/minhas-sessoes/encerrar-outras', [AuthController::class, 'revokeOthers']);

// ---- menu --------------------------------------------------------------------------------------------------------
$router->get('/', [HomeController::class, 'index']);

// ---- administração ------------------------------------------------------------------------------------------
$router->get('/admin',                                   [DashboardController::class, 'index']);
$router->get('/admin/usuarios',                          [UsersController::class, 'index']);
$router->get('/admin/usuarios/novo',                     [UsersController::class, 'create']);
$router->post('/admin/usuarios',                         [UsersController::class, 'store']);
$router->get('/admin/usuarios/{id}',                     [UsersController::class, 'edit']);
$router->post('/admin/usuarios/{id}',                    [UsersController::class, 'update']);
$router->post('/admin/usuarios/{id}/excluir',            [UsersController::class, 'delete']);
$router->post('/admin/usuarios/{id}/restaurar',          [UsersController::class, 'restore']);
$router->post('/admin/usuarios/{id}/encerrar-sessoes',   [UsersController::class, 'revokeSessions']);
$router->get('/admin/administradores',                   [AdministratorsController::class, 'index']);
$router->post('/admin/administradores/{id}/perfil',      [AdministratorsController::class, 'changeRole']);
$router->get('/admin/perfis',                            [RolesController::class, 'index']);
$router->post('/admin/perfis/{id}',                      [RolesController::class, 'update']);
$router->get('/admin/configuracoes',                     [SettingsController::class, 'index']);
$router->post('/admin/configuracoes/padroes',            [SettingsController::class, 'addPattern']);
$router->post('/admin/configuracoes/padroes/{id}/alternar', [SettingsController::class, 'togglePattern']);
$router->post('/admin/configuracoes/{grupo}',            [SettingsController::class, 'update']);
$router->get('/admin/seguranca',                         [SecurityController::class, 'index']);
$router->post('/admin/seguranca/sessoes/{hash}/encerrar',[SecurityController::class, 'revokeSession']);
$router->post('/admin/seguranca/eventos/{id}/ciente',    [SecurityController::class, 'acknowledge']);
$router->get('/admin/auditoria',                         [AuditController::class, 'index']);
$router->post('/admin/auditoria/verificar',              [AuditController::class, 'verify']);

// ---- administração: Google (conta técnica, planilhas conectadas, planilha de logs) ------------------------
$router->get('/admin/conta-tecnica',                    [TechAccountController::class, 'index']);
$router->post('/admin/conta-tecnica/conectar',          [TechAccountController::class, 'connect']);
$router->post('/admin/conta-tecnica/testar',            [TechAccountController::class, 'test']);
$router->post('/admin/conta-tecnica/revogar',           [TechAccountController::class, 'revoke']);
$router->post('/admin/conta-tecnica/service-account',   [TechAccountController::class, 'storeServiceAccount']);
$router->get('/admin/planilhas',                        [SheetsController::class, 'index']);
$router->post('/admin/planilhas',                       [SheetsController::class, 'store']);
$router->get('/admin/planilhas/{id}',                   [SheetsController::class, 'show']);
$router->post('/admin/planilhas/{id}',                  [SheetsController::class, 'update']);
$router->post('/admin/planilhas/{id}/testar',           [SheetsController::class, 'test']);
$router->post('/admin/planilhas/{id}/excluir',          [SheetsController::class, 'delete']);
$router->get('/admin/planilha-logs',                    [LogSheetController::class, 'index']);
$router->post('/admin/planilha-logs',                   [LogSheetController::class, 'save']);
$router->post('/admin/planilha-logs/testar',            [LogSheetController::class, 'test']);
$router->post('/admin/planilha-logs/enviar',            [LogSheetController::class, 'flush']);
$router->post('/admin/planilha-logs/conferir',          [LogSheetController::class, 'compare']);
