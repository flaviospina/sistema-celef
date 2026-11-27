<?php
// app/routes.php — tabela de rotas ($router já instanciado pelo Kernel)
declare(strict_types=1);

use App\controllers\SystemController;

/** @var App\Http\Router $router */
$router->get('/',           [SystemController::class, 'home']);
$router->get('/status',     [SystemController::class, 'status']);
$router->get('/instalacao', [SystemController::class, 'install']);
$router->get('/privacidade',[SystemController::class, 'privacy']);
