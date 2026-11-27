<?php
// public/index.php — Front controller do Sistema CELEF
declare(strict_types=1);

/*
 | APP_ROOT: pasta que contém app/, sql/, cron/, storage/ e .env.
 | Cenário padrão (document root apontando para <dominio>/public): dirname(__DIR__).
 | Plano B (document root é a própria pasta do domínio): troque pela pasta privada, ex.:
 |     define('APP_ROOT', '/home/usuario/celef_privado');
 */
define('APP_ROOT', dirname(__DIR__));

require APP_ROOT . '/app/bootstrap.php';

App\Http\Kernel::handle();
