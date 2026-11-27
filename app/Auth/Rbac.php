<?php
// app/Auth/Rbac.php — permissões por perfil (role_permissions) e escopo de turmas aplicado no SQL
declare(strict_types=1);

namespace App\Auth;

use App\Database;
use App\Http\HttpException;
use App\Security\Logger;

final class Rbac
{
    /** @var array<int,array<string,true>> cache por usuário na requisição */
    private static array $perms = [];
    /** @var array<int,list<int>|null> */
    private static array $scope = [];

    /** @return array<string,true> códigos de permissão concedidos */
    public static function permissions(?array $user = null): array
    {
        $user ??= Auth::user();
        if ($user === null) {
            return [];
        }
        $uid = (int) $user['id'];
        if (!isset(self::$perms[$uid])) {
            if ($user['role_code'] === 'SUPER_ADMIN') {
                $codes = array_column(Database::rows('SELECT code FROM permissions'), 'code');
            } else {
                $codes = array_column(Database::rows(
                    'SELECT p.code FROM role_permissions rp JOIN permissions p ON p.id = rp.permission_id WHERE rp.role_id = :r AND rp.is_granted = 1',
                    ['r' => (int) $user['role_id']]), 'code');
            }
            self::$perms[$uid] = array_fill_keys($codes, true);
        }
        return self::$perms[$uid];
    }

    public static function can(string $code, ?array $user = null): bool
    {
        return isset(self::permissions($user)[$code]);
    }

    /** Qualquer uma das permissões. @param list<string> $codes */
    public static function canAny(array $codes, ?array $user = null): bool
    {
        foreach ($codes as $c) {
            if (self::can($c, $user)) {
                return true;
            }
        }
        return false;
    }

    /** Padrão = negar: sem a permissão, 403 (registrado no log). */
    public static function require(string $code): void
    {
        $u = Auth::requireLogin($_SERVER['REQUEST_URI'] ?? '/');
        if (!self::can($code, $u)) {
            Logger::warning('Permissão negada', ['usuario' => $u['email'], 'permissao' => $code]);
            throw HttpException::forbidden();
        }
    }

    public static function requireAdmin(): array
    {
        $u = Auth::requireLogin($_SERVER['REQUEST_URI'] ?? '/');
        if (!in_array($u['role_code'], ['SUPER_ADMIN', 'ADMIN'], true)) {
            Logger::warning('Área admin negada', ['usuario' => $u['email']]);
            throw HttpException::forbidden('A área administrativa é restrita aos administradores.');
        }
        return $u;
    }

    public static function requireSuperAdmin(): array
    {
        $u = self::requireAdmin();
        if ($u['role_code'] !== 'SUPER_ADMIN') {
            throw HttpException::forbidden('Somente o Super Administrador pode executar esta ação.');
        }
        return $u;
    }

    /**
     * Escopo de turmas: null = sem restrição (secretaria, coordenação, admin, auditor);
     * lista de ids = só estas turmas (PROFESSOR, via user_class_assignments ativas).
     * @return list<int>|null
     */
    public static function classScope(?array $user = null): ?array
    {
        $user ??= Auth::user();
        if ($user === null) {
            return [];
        }
        $uid = (int) $user['id'];
        if (!array_key_exists($uid, self::$scope)) {
            if ($user['role_code'] !== 'PROFESSOR') {
                self::$scope[$uid] = null;
            } else {
                self::$scope[$uid] = array_map('intval', array_column(Database::rows(
                    'SELECT class_id FROM user_class_assignments WHERE user_id = :u AND deleted_at IS NULL AND (ended_on IS NULL OR ended_on >= CURDATE())',
                    ['u' => $uid]), 'class_id'));
            }
        }
        return self::$scope[$uid];
    }

    /**
     * Fragmento SQL do escopo, para ser concatenado ao WHERE (sempre com AND). Padrão = negar: professor sem turma → 1=0.
     * @return array{0:string,1:array<string,int>}  ex.: [' AND e.class_id IN (:sc0,:sc1)', ['sc0'=>3,'sc1'=>9]]
     */
    public static function classScopeSql(string $column, ?array $user = null): array
    {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_.]*$/', $column)) {
            throw new \InvalidArgumentException('Coluna inválida para escopo.');
        }
        $ids = self::classScope($user);
        if ($ids === null) {
            return ['', []];
        }
        if ($ids === []) {
            return [' AND 1 = 0', []];
        }
        $params = [];
        $marks = [];
        foreach (array_values($ids) as $i => $id) {
            $params["sc{$i}"] = $id;
            $marks[] = ":sc{$i}";
        }
        return [" AND {$column} IN (" . implode(',', $marks) . ')', $params];
    }

    /** Verifica se uma turma está no escopo (para IDOR em rotas com {id}). */
    public static function classInScope(int $classId, ?array $user = null): bool
    {
        $ids = self::classScope($user);
        return $ids === null || in_array($classId, $ids, true);
    }

    public static function flush(): void
    {
        self::$perms = [];
        self::$scope = [];
    }
}
