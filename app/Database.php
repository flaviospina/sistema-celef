<?php
// app/Database.php — conexão PDO única por requisição, com o contexto exigido pelos triggers
declare(strict_types=1);

namespace App;

use PDO;
use PDOException;
use PDOStatement;

final class Database
{
    private static ?PDO $pdo = null;
    private static ?int $actorUserId = null;
    private static string $origin = 'APP';
    private static int $transactionDepth = 0;

    public static function get(): PDO
    {
        if (self::$pdo instanceof PDO) {
            return self::$pdo;
        }
        $dsn = sprintf('mysql:host=%s;port=%d;dbname=%s;charset=utf8mb4', Config::require('DB_HOST'), Config::int('DB_PORT', 3306), Config::require('DB_NAME'));
        try {
            self::$pdo = new PDO($dsn, Config::require('DB_USER'), Config::get('DB_PASS', '') ?? '', [
                PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
                PDO::ATTR_EMULATE_PREPARES   => false,   // prepared statements nativos: 100% das consultas
                PDO::ATTR_STRINGIFY_FETCHES  => false,
                PDO::MYSQL_ATTR_MULTI_STATEMENTS => false, // uma instrução por execute (anti-SQLi em profundidade)
            ]);
        } catch (PDOException $e) {
            // nunca expõe DSN/senha; detalhes só no log
            Security\Logger::critical('Falha ao conectar ao banco', ['erro' => $e->getMessage()]);
            throw new \RuntimeException('Banco de dados indisponível.');
        }

        // Horário de negócio em São Paulo (offset calculado para não depender das tabelas de fuso do MySQL)
        $offset = (new \DateTime('now', new \DateTimeZone(Config::get('APP_TIMEZONE', 'America/Sao_Paulo'))))->format('P');
        self::$pdo->exec("SET time_zone = " . self::$pdo->quote($offset));
        self::$pdo->exec("SET SESSION sql_mode = 'STRICT_ALL_TABLES,NO_ZERO_DATE,NO_ZERO_IN_DATE,ERROR_FOR_DIVISION_BY_ZERO,NO_ENGINE_SUBSTITUTION'");
        self::applyContext();
        return self::$pdo;
    }

    /**
     * Define quem está agindo. Os triggers leem @app_user_id e @app_origin em TODA alteração.
     * Chamado pelo Auth (usuário logado), pelo cron ('CRON') e pela sincronização ('PLANILHA:<nome>').
     */
    public static function setActor(?int $userId, string $origin = 'APP'): void
    {
        self::$actorUserId = $userId;
        self::$origin = substr($origin, 0, 60);
        if (self::$pdo instanceof PDO) {
            self::applyContext();
        }
    }

    public static function actorUserId(): ?int
    {
        return self::$actorUserId;
    }

    public static function origin(): string
    {
        return self::$origin;
    }

    private static function applyContext(): void
    {
        $stmt = self::$pdo->prepare('SET @app_user_id = :uid, @app_origin = :origin');
        $stmt->bindValue(':uid', self::$actorUserId, self::$actorUserId === null ? PDO::PARAM_NULL : PDO::PARAM_INT);
        $stmt->bindValue(':origin', self::$origin);
        $stmt->execute();
    }

    // ---- Atalhos ----------------------------------------------------------------------------------------

    /** @param array<string|int,mixed> $params */
    public static function run(string $sql, array $params = []): PDOStatement
    {
        $stmt = self::get()->prepare($sql);
        foreach ($params as $key => $value) {
            $name = is_int($key) ? $key + 1 : (str_starts_with($key, ':') ? $key : ':' . $key);
            $type = match (true) {
                $value === null  => PDO::PARAM_NULL,
                is_int($value)   => PDO::PARAM_INT,
                is_bool($value)  => PDO::PARAM_INT,
                default          => PDO::PARAM_STR,
            };
            $stmt->bindValue($name, is_bool($value) ? (int) $value : $value, $type);
        }
        $stmt->execute();
        return $stmt;
    }

    /** @param array<string|int,mixed> $params @return array<string,mixed>|null */
    public static function row(string $sql, array $params = []): ?array
    {
        $row = self::run($sql, $params)->fetch();
        return $row === false ? null : $row;
    }

    /** @param array<string|int,mixed> $params @return list<array<string,mixed>> */
    public static function rows(string $sql, array $params = []): array
    {
        return self::run($sql, $params)->fetchAll();
    }

    /** @param array<string|int,mixed> $params */
    public static function value(string $sql, array $params = []): mixed
    {
        $value = self::run($sql, $params)->fetchColumn();
        return $value === false ? null : $value;
    }

    /** @param array<string,mixed> $data */
    public static function insert(string $table, array $data): int
    {
        self::assertIdentifier($table);
        $cols = array_keys($data);
        foreach ($cols as $c) {
            self::assertIdentifier($c);
        }
        $sql = sprintf('INSERT INTO `%s` (%s) VALUES (%s)', $table,
            implode(', ', array_map(static fn($c) => "`$c`", $cols)),
            implode(', ', array_map(static fn($c) => ":$c", $cols)));
        self::run($sql, $data);
        return (int) self::get()->lastInsertId();
    }

    /**
     * UPDATE com lock otimista: só grava se a versão em banco for a esperada.
     * Retorna false quando outra pessoa (ou a sincronização) alterou o registro antes.
     * @param array<string,mixed> $data
     */
    public static function updateVersioned(string $table, int $id, int $expectedVersion, array $data): bool
    {
        self::assertIdentifier($table);
        unset($data['id'], $data['version']);
        $sets = [];
        foreach (array_keys($data) as $c) {
            self::assertIdentifier($c);
            $sets[] = "`$c` = :$c";
        }
        $sql = sprintf('UPDATE `%s` SET %s WHERE `id` = :_id AND `version` = :_version', $table, implode(', ', $sets));
        $stmt = self::run($sql, $data + ['_id' => $id, '_version' => $expectedVersion]);
        return $stmt->rowCount() === 1;
    }

    /** Transação reentrante (aninhamentos só participam da externa). */
    public static function transaction(callable $fn): mixed
    {
        $pdo = self::get();
        if (self::$transactionDepth === 0) {
            $pdo->beginTransaction();
        }
        self::$transactionDepth++;
        try {
            $result = $fn($pdo);
            self::$transactionDepth--;
            if (self::$transactionDepth === 0) {
                $pdo->commit();
            }
            return $result;
        } catch (\Throwable $e) {
            self::$transactionDepth--;
            if (self::$transactionDepth === 0 && $pdo->inTransaction()) {
                $pdo->rollBack();
            }
            throw $e;
        }
    }

    /** Lock nomeado do MySQL (serializa a cadeia de hash e impede dois crons simultâneos). */
    public static function lock(string $name, int $timeoutSeconds = 5): bool
    {
        return (int) self::value('SELECT GET_LOCK(:n, :t)', ['n' => 'celef_' . $name, 't' => $timeoutSeconds]) === 1;
    }

    public static function unlock(string $name): void
    {
        self::value('SELECT RELEASE_LOCK(:n)', ['n' => 'celef_' . $name]);
    }

    private static function assertIdentifier(string $name): void
    {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]{0,63}$/', $name)) {
            throw new \InvalidArgumentException('Identificador SQL inválido.');
        }
    }
}
