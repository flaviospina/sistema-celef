<?php
// app/controllers/HomeController.php — menu inicial: só os módulos do perfil do usuário
declare(strict_types=1);

namespace App\controllers;

use App\Http\AuthenticatedController;

final class HomeController extends AuthenticatedController
{
    /** Módulos do sistema: rótulo, rota, permissões que liberam, fase em que fica disponível. */
    public const MODULES = [
        ['label' => 'Alunos',          'icon' => '🎓', 'path' => '/alunos',         'perms' => ['aluno.ver'],                                   'phase' => 6],
        ['label' => 'Turmas',          'icon' => '🏫', 'path' => '/turmas',         'perms' => ['turma.ver'],                                   'phase' => 6],
        ['label' => 'Remanejamentos',  'icon' => '🔁', 'path' => '/remanejamentos', 'perms' => ['remanejamento.ver'],                           'phase' => 7],
        ['label' => 'Desistências',    'icon' => '📤', 'path' => '/desistencias',   'perms' => ['desistencia.ver'],                             'phase' => 7],
        ['label' => 'Transferências',  'icon' => '🚚', 'path' => '/transferencias', 'perms' => ['transferencia.ver'],                           'phase' => 7],
        ['label' => 'Diário',          'icon' => '📘', 'path' => '/diario',         'perms' => ['diario.ver'],                                  'phase' => 8],
        ['label' => 'Documentos',      'icon' => '📎', 'path' => '/documentos',     'perms' => ['documento.ver'],                               'phase' => 8],
        ['label' => 'Carômetro',       'icon' => '🪪', 'path' => '/carometro',      'perms' => ['carometro.ver'],                               'phase' => 9],
        ['label' => 'Declarações',     'icon' => '📄', 'path' => '/declaracoes',    'perms' => ['declaracao.emitir'],                           'phase' => 9],
        ['label' => 'Funcionários',    'icon' => '👥', 'path' => '/funcionarios',   'perms' => ['funcionario.ver'],                             'phase' => 9],
        ['label' => 'Indicadores',     'icon' => '📊', 'path' => '/indicadores',    'perms' => ['indicadores.ver'],                             'phase' => 10],
        ['label' => 'Auditoria',       'icon' => '🔍', 'path' => '/admin/auditoria','perms' => ['auditoria.ver'],                               'phase' => 3],
        ['label' => 'Administração',   'icon' => '⚙️', 'path' => '/admin',          'perms' => ['admin.usuarios', 'admin.configuracoes'],      'phase' => 3],
    ];

    public function index(): never
    {
        $modules = [];
        foreach (self::MODULES as $m) {
            $allowed = false;
            foreach ($m['perms'] as $p) {
                if ($this->can($p)) {
                    $allowed = true;
                    break;
                }
            }
            if ($allowed) {
                $m['disponivel'] = $m['phase'] <= 3;
                $modules[] = $m;
            }
        }
        $this->render('home/menu', ['titulo' => 'Início', 'modulos' => $modules]);
    }
}
