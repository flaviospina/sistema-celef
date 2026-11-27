<?php
// app/models/UserService.php — regras de negócio de usuários (cadastro, perfil, ativação, exclusão lógica, turmas)
declare(strict_types=1);

namespace App\models;

use App\Auth\Auth;
use App\Database;
use App\Security\Validator;

final class UserService
{
    /** @return list<array<string,mixed>> */
    public static function roles(): array
    {
        return Database::rows('SELECT id, code, name, description FROM roles WHERE deleted_at IS NULL ORDER BY id');
    }

    public static function roleIdByCode(string $code): ?int
    {
        $v = Database::value('SELECT id FROM roles WHERE code = :c', ['c' => $code]);
        return $v === null ? null : (int) $v;
    }

    /** @return array<string,mixed>|null */
    public static function find(int $id): ?array
    {
        return Database::row('SELECT u.*, r.code AS role_code, r.name AS role_name FROM users u JOIN roles r ON r.id = u.role_id WHERE u.id = :id', ['id' => $id]);
    }

    /**
     * Lista paginada com filtros. @param array{q?:string,role?:string,ativo?:string,lixeira?:bool} $f
     * @return array{itens:list<array<string,mixed>>,total:int,pagina:int,por_pagina:int}
     */
    public static function search(array $f, int $page = 1, int $perPage = 25): array
    {
        $where = ['1 = 1'];
        $params = [];
        $where[] = !empty($f['lixeira']) ? 'u.deleted_at IS NOT NULL' : 'u.deleted_at IS NULL';
        if (!empty($f['q'])) {
            $where[] = '(u.email LIKE :q OR u.full_name LIKE :q)';
            $params['q'] = '%' . str_replace(['%', '_'], ['\%', '\_'], $f['q']) . '%';
        }
        if (!empty($f['role'])) {
            $where[] = 'r.code = :role';
            $params['role'] = $f['role'];
        }
        if (isset($f['ativo']) && $f['ativo'] !== '') {
            $where[] = 'u.is_active = :ativo';
            $params['ativo'] = (int) ($f['ativo'] === '1');
        }
        $w = implode(' AND ', $where);
        $total = (int) Database::value("SELECT COUNT(*) FROM users u JOIN roles r ON r.id = u.role_id WHERE {$w}", $params);
        $page = max(1, $page);
        $offset = ($page - 1) * $perPage;
        $items = Database::rows("SELECT u.id, u.email, u.full_name, u.is_active, u.last_login_at, u.deleted_at, u.delete_reason, r.code AS role_code, r.name AS role_name,
                                        (SELECT COUNT(*) FROM user_class_assignments a WHERE a.user_id = u.id AND a.deleted_at IS NULL AND (a.ended_on IS NULL OR a.ended_on >= CURDATE())) AS turmas
                                 FROM users u JOIN roles r ON r.id = u.role_id WHERE {$w}
                                 ORDER BY u.full_name LIMIT " . (int) $perPage . ' OFFSET ' . (int) $offset, $params);
        return ['itens' => $items, 'total' => $total, 'pagina' => $page, 'por_pagina' => $perPage];
    }

    /** Validação comum de cadastro/edição. @param array<string,string> $in @return array<string,string> erros */
    public static function validate(array $in, bool $creating): array
    {
        $v = new Validator($in);
        $v->required('full_name', 'Nome')->length('full_name', 'Nome', 3, 160)
          ->required('role_code', 'Perfil')->in('role_code', 'Perfil', array_column(self::roles(), 'code'));
        if ($creating) {
            $v->required('email', 'E-mail')->scsEducaEmail('email', 'E-mail')->length('email', 'E-mail', 6, 190);
        }
        $errors = $v->errors();
        if ($creating && !isset($errors['email'])) {
            $email = mb_strtolower(trim($in['email']));
            if (Database::value('SELECT 1 FROM users WHERE email = :e', ['e' => $email]) !== null) {
                $errors['email'] = 'Já existe um usuário com este e-mail (verifique a lixeira).';
            }
            $blocked = Database::value('SELECT pattern FROM blocked_email_patterns WHERE is_active = 1 AND deleted_at IS NULL AND :e LIKE pattern LIMIT 1', ['e' => $email]);
            if ($blocked !== null) {
                $errors['email'] = "Este e-mail corresponde a um padrão de conta genérica bloqueada ({$blocked}). Só pessoas físicas podem ser cadastradas.";
            }
        }
        return $errors;
    }

    /**
     * Regras de proteção ao mudar perfil/ativação/exclusão. @return string|null mensagem de erro
     */
    public static function guardChange(array $target, array $actor, ?string $newRoleCode, ?bool $newActive, bool $deleting = false): ?string
    {
        $targetEmail = strtolower((string) $target['email']);
        $actorIsSuper = $actor['role_code'] === 'SUPER_ADMIN';
        if ((int) $target['id'] === (int) $actor['id'] && ($newRoleCode !== null && $newRoleCode !== $target['role_code'] || $newActive === false || $deleting)) {
            return 'Você não pode alterar o próprio perfil, desativar-se ou excluir-se.';
        }
        if (Auth::isProtectedEmail($targetEmail)) {
            if (($newRoleCode !== null && $newRoleCode !== 'SUPER_ADMIN') || $newActive === false || $deleting) {
                return 'Este e-mail está em SUPER_ADMIN_EMAILS (.env) e não pode ser rebaixado, desativado nem excluído pela interface.';
            }
        }
        $touchesSuper = $target['role_code'] === 'SUPER_ADMIN' || $newRoleCode === 'SUPER_ADMIN';
        if ($touchesSuper && !$actorIsSuper) {
            return 'Somente o Super Administrador pode gerenciar Super Administradores.';
        }
        $touchesAdmin = in_array($target['role_code'], ['ADMIN', 'SUPER_ADMIN'], true) || in_array($newRoleCode, ['ADMIN', 'SUPER_ADMIN'], true);
        if ($touchesAdmin && !$actorIsSuper && ($newRoleCode !== null && $newRoleCode !== $target['role_code'])) {
            return 'Somente o Super Administrador promove ou rebaixa administradores.';
        }
        if ($target['role_code'] === 'SUPER_ADMIN' && (int) $target['is_active'] === 1 && $target['deleted_at'] === null
            && (($newRoleCode !== null && $newRoleCode !== 'SUPER_ADMIN') || $newActive === false || $deleting)) {
            $others = (int) Database::value("SELECT COUNT(*) FROM users u JOIN roles r ON r.id = u.role_id WHERE r.code = 'SUPER_ADMIN' AND u.is_active = 1 AND u.deleted_at IS NULL AND u.id <> :id", ['id' => (int) $target['id']]);
            if ($others === 0) {
                return 'Não é possível remover, rebaixar ou desativar o último Super Administrador ativo.';
            }
        }
        return null;
    }

    /** @return list<array<string,mixed>> turmas disponíveis para vínculo (ano letivo corrente ou futuro) */
    public static function classesForAssignment(): array
    {
        return Database::rows("SELECT c.id, c.code, c.school_year, c.grade, c.letter FROM classes c WHERE c.deleted_at IS NULL AND c.status = 'ATIVA' ORDER BY c.school_year DESC, c.grade, c.letter");
    }

    /** @return list<int> */
    public static function assignedClassIds(int $userId): array
    {
        return array_map('intval', array_column(Database::rows(
            'SELECT class_id FROM user_class_assignments WHERE user_id = :u AND deleted_at IS NULL AND (ended_on IS NULL OR ended_on >= CURDATE())', ['u' => $userId]), 'class_id'));
    }

    /**
     * Sincroniza vínculos de turma: novos são inseridos; removidos recebem ended_on (nunca apagados).
     * @param list<int> $classIds @return array{adicionadas:list<int>,removidas:list<int>}
     */
    public static function syncClasses(int $userId, string $roleCode, array $classIds, int $actorId): array
    {
        $type = $roleCode === 'COORDENACAO' ? 'COORDENACAO' : 'PROFESSOR';
        $current = self::assignedClassIds($userId);
        $add = array_values(array_diff($classIds, $current));
        $remove = array_values(array_diff($current, $classIds));
        foreach ($add as $cid) {
            $class = Database::row('SELECT id, school_year FROM classes WHERE id = :id AND deleted_at IS NULL', ['id' => $cid]);
            if ($class === null) {
                continue;
            }
            $existing = Database::row('SELECT id, version FROM user_class_assignments WHERE user_id = :u AND class_id = :c AND assignment_type = :t', ['u' => $userId, 'c' => $cid, 't' => $type]);
            if ($existing !== null) {
                Database::updateVersioned('user_class_assignments', (int) $existing['id'], (int) $existing['version'], ['ended_on' => null, 'deleted_at' => null, 'started_on' => date('Y-m-d'), 'updated_by' => $actorId]);
            } else {
                Database::insert('user_class_assignments', ['user_id' => $userId, 'class_id' => $cid, 'assignment_type' => $type, 'school_year' => (int) $class['school_year'], 'started_on' => date('Y-m-d'), 'created_by' => $actorId]);
            }
        }
        if ($remove !== []) {
            foreach ($remove as $cid) {
                Database::run('UPDATE user_class_assignments SET ended_on = CURDATE(), updated_by = :a WHERE user_id = :u AND class_id = :c AND deleted_at IS NULL AND (ended_on IS NULL OR ended_on >= CURDATE())',
                    ['a' => $actorId, 'u' => $userId, 'c' => $cid]);
            }
        }
        return ['adicionadas' => $add, 'removidas' => $remove];
    }
}
