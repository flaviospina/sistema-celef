<?php
// app/Security/AuditLog.php — trilha de auditoria imutável: gravação encadeada, fila da planilha de logs, verificação
declare(strict_types=1);

namespace App\Security;

use App\Database;

final class AuditLog
{
    public const GENESIS = '0000000000000000000000000000000000000000000000000000000000000000';

    /** Ações reconhecidas (também listadas no comentário da coluna audit_log.action). */
    public const ACTIONS = [
        'LOGIN', 'LOGIN_NEGADO', 'LOGOUT', 'REAUTH', 'SESSAO_ENCERRADA',
        'VER', 'VER_SENSIVEL', 'CRIAR', 'EDITAR', 'EXCLUIR', 'RESTAURAR', 'EXPORTAR', 'IMPRIMIR',
        'PERMISSAO', 'ADMIN', 'SYNC_IN', 'SYNC_OUT', 'SYNC_CONFLITO', 'ALTERACAO_EXTERNA_PLANILHA',
        'SEGURANCA', 'INSTALACAO', 'ANCORA',
    ];

    /** Ação → aba da planilha de logs (null = não vai para a planilha). */
    private const SHEET_TAB = [
        'LOGIN' => 'ACESSOS', 'LOGIN_NEGADO' => 'ACESSOS', 'LOGOUT' => 'ACESSOS', 'REAUTH' => 'ACESSOS', 'SESSAO_ENCERRADA' => 'ACESSOS',
        'PERMISSAO' => 'ADMIN', 'ADMIN' => 'ADMIN',
        'SYNC_IN' => 'SINCRONIZACAO', 'SYNC_OUT' => 'SINCRONIZACAO', 'SYNC_CONFLITO' => 'SINCRONIZACAO',
        'ALTERACAO_EXTERNA_PLANILHA' => 'SEGURANCA', 'SEGURANCA' => 'SEGURANCA',
        'EXPORTAR' => 'EXPORTACOES', 'ANCORA' => 'ANCORAS',
    ];

    private static ?int $userId = null;
    private static ?string $userEmail = null;
    private static ?string $roleCode = null;

    /** Definido pelo Auth após o login (e pelo cron com null). */
    public static function setActor(?int $userId, ?string $email, ?string $roleCode): void
    {
        self::$userId = $userId;
        self::$userEmail = $email;
        self::$roleCode = $roleCode;
    }

    /**
     * Grava uma linha de auditoria. Retorna o id. Nunca lança para o chamador quebrar a operação de
     * negócio por causa do log? Ao contrário: auditoria que falha DEVE abortar a operação (fail-closed),
     * por isso a exceção é propagada — chame dentro da mesma transação da alteração.
     *
     * @param array<string,mixed>|null $diff  ['campo' => ['de' => x, 'para' => y], ...] — mascarado aqui
     */
    public static function log(string $action, ?string $entity = null, ?int $entityId = null, string $summary = '', ?array $diff = null): int
    {
        if (!in_array($action, self::ACTIONS, true)) {
            throw new \InvalidArgumentException("Ação de auditoria desconhecida: {$action}");
        }
        $diffJson = $diff === null ? null : self::canonicalJson(Masker::scrubArray($diff));
        $summary = mb_substr(Masker::scrubText($summary), 0, 300);

        $data = [
            'occurred_at'  => null, // trigger preenche UTC_TIMESTAMP(6)
            'user_id'      => self::$userId,
            'user_email'   => self::$userEmail,
            'role_code'    => self::$roleCode,
            'action'       => $action,
            'entity'       => $entity,
            'entity_id'    => $entityId,
            'summary'      => $summary,
            'diff_json'    => $diffJson,
            'ip'           => RequestContext::ip(),
            'user_agent'   => RequestContext::userAgent(),
            'request_id'   => RequestContext::requestId(),
            'session_hash' => PHP_SAPI === 'cli' ? null : SecureSession::hash(),
            'origin'       => Database::origin(),
        ];

        // Serializa a cadeia: dois INSERTs simultâneos não podem ler o mesmo prev_hash.
        if (!Database::lock('audit', 5)) {
            Logger::critical('Não foi possível obter o lock da auditoria');
            throw new \RuntimeException('Auditoria indisponível no momento. A operação foi cancelada.');
        }
        try {
            $id = Database::insert('audit_log', $data);
        } finally {
            Database::unlock('audit');
        }

        $tab = self::SHEET_TAB[$action] ?? 'AUDITORIA';
        self::enqueueSheetRow($id, $tab);
        return $id;
    }

    /** Linha para a planilha de logs: nunca CPF, RG, endereço, telefone ou saúde — só o que está em audit_log (já mascarado). */
    private static function enqueueSheetRow(int $auditId, string $tab): void
    {
        $row = Database::row('SELECT occurred_at, user_email, role_code, action, entity, entity_id, summary, ip, origin, hash FROM audit_log WHERE id = :id', ['id' => $auditId]);
        if ($row === null) {
            return;
        }
        $values = [
            (string) $row['occurred_at'] . ' UTC',
            (string) ($row['user_email'] ?? ''),
            (string) ($row['role_code'] ?? ''),
            (string) $row['action'],
            (string) ($row['entity'] ?? ''),
            $row['entity_id'] === null ? '' : (string) $row['entity_id'],
            (string) ($row['summary'] ?? ''),
            (string) ($row['ip'] ?? ''),
            (string) $row['origin'],
            (string) $row['hash'],
        ];
        $json = json_encode($values, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        Database::insert('sheet_log_outbox', [
            'tab_name'        => $tab,
            'audit_log_id'    => $auditId,
            'row_values_json' => $json,
            'row_hash'        => hash('sha256', $json),
            'status'          => 'PENDING',
            'next_attempt_at' => date('Y-m-d H:i:s'),
        ]);
    }

    /** JSON com chaves ordenadas recursivamente: o texto gravado é reproduzível pelo verificador. */
    public static function canonicalJson(array $data): string
    {
        self::ksortRecursive($data);
        return json_encode($data, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
    }

    private static function ksortRecursive(array &$a): void
    {
        foreach ($a as &$v) {
            if (is_array($v)) {
                self::ksortRecursive($v);
            }
        }
        unset($v);
        if (array_keys($a) !== range(0, count($a) - 1)) {
            ksort($a, SORT_STRING);
        }
    }

    // ---- verificação da cadeia ----------------------------------------------------------------------------

    /** Mesma fórmula do trigger trg_audit_log_bi. @param array<string,mixed> $r */
    public static function computeHash(array $r): string
    {
        $canon = implode('|', [
            (string) $r['prev_hash'], (string) $r['occurred_at'],
            (string) ($r['user_id'] ?? ''), (string) ($r['user_email'] ?? ''), (string) ($r['role_code'] ?? ''),
            (string) $r['action'], (string) ($r['entity'] ?? ''), (string) ($r['entity_id'] ?? ''),
            (string) ($r['summary'] ?? ''), (string) ($r['diff_json'] ?? ''), (string) ($r['ip'] ?? ''),
            (string) ($r['request_id'] ?? ''), (string) $r['origin'],
        ]);
        return hash('sha256', $canon);
    }

    /**
     * Verifica a cadeia entre dois ids (inclusive), em lotes.
     * @return array{ok:bool,checked:int,first_broken_id:?int,last_hash:?string,detail:?string}
     */
    public static function verifyChain(int $fromId = 1, ?int $toId = null, int $batch = 2000): array
    {
        $toId ??= (int) (Database::value('SELECT MAX(id) FROM audit_log') ?? 0);
        $prevRow = $fromId > 1
            ? Database::row('SELECT hash FROM audit_log WHERE id < :id ORDER BY id DESC LIMIT 1', ['id' => $fromId])
            : null;
        $prev = $prevRow === null ? self::GENESIS : (string) $prevRow['hash'];
        $checked = 0;
        $lastHash = null;
        $cursor = $fromId - 1;

        while ($cursor < $toId) {
            $rows = Database::rows(
                "SELECT id, DATE_FORMAT(occurred_at, '%Y-%m-%d %H:%i:%s.%f') AS occurred_at, user_id, user_email, role_code, action, entity,
                        entity_id, summary, diff_json, ip, request_id, origin, prev_hash, hash
                 FROM audit_log WHERE id > :c AND id <= :t ORDER BY id LIMIT " . (int) $batch,
                ['c' => $cursor, 't' => $toId]
            );
            if ($rows === []) {
                break;
            }
            foreach ($rows as $r) {
                if ($r['prev_hash'] !== $prev) {
                    return ['ok' => false, 'checked' => $checked, 'first_broken_id' => (int) $r['id'], 'last_hash' => $lastHash,
                            'detail' => "prev_hash da linha {$r['id']} não corresponde ao hash da linha anterior (linha removida ou inserida fora de ordem)."];
                }
                if (!hash_equals(self::computeHash($r), (string) $r['hash'])) {
                    return ['ok' => false, 'checked' => $checked, 'first_broken_id' => (int) $r['id'], 'last_hash' => $lastHash,
                            'detail' => "hash da linha {$r['id']} não confere com o conteúdo (linha alterada)."];
                }
                $prev = (string) $r['hash'];
                $lastHash = $prev;
                $checked++;
                $cursor = (int) $r['id'];
            }
        }
        return ['ok' => true, 'checked' => $checked, 'first_broken_id' => null, 'last_hash' => $lastHash, 'detail' => null];
    }

    /**
     * Confere se os triggers de proteção continuam ativos.
     * O usuário da app não enxerga information_schema.triggers (exige privilégio TRIGGER), então a verificação
     * é FUNCIONAL: tenta as operações que os triggers devem bloquear/alterar, dentro de uma transação que é
     * sempre desfeita. @return list<string> proteções ausentes (vazio = tudo ok)
     */
    public static function missingTriggers(): array
    {
        $missing = [];
        $pdo = Database::get();

        // 1) trg_audit_log_bu: UPDATE em audit_log tem que falhar com SQLSTATE 45000
        $pdo->beginTransaction();
        try {
            Database::run('UPDATE audit_log SET summary = summary WHERE id = (SELECT MIN(id) FROM (SELECT id FROM audit_log) t)');
            $missing[] = 'audit_log: UPDATE não bloqueado (trg_audit_log_bu)';
        } catch (\PDOException $e) {
            if ($e->getCode() !== '45000') {
                $missing[] = 'audit_log: erro inesperado ao testar UPDATE (' . $e->getCode() . ')';
            }
        } finally {
            $pdo->rollBack();
        }

        // 2) trg_audit_log_bi: INSERT deve receber hash encadeado
        $pdo->beginTransaction();
        try {
            $last = (string) (Database::value('SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1') ?? self::GENESIS);
            $id = Database::insert('audit_log', ['action' => 'SEGURANCA', 'summary' => 'sonda de verificação (desfeita)', 'origin' => Database::origin()]);
            $row = Database::row('SELECT prev_hash, hash FROM audit_log WHERE id = :id', ['id' => $id]);
            if ($row === null || strlen((string) $row['hash']) !== 64 || $row['prev_hash'] !== $last) {
                $missing[] = 'audit_log: hash não calculado no INSERT (trg_audit_log_bi)';
            }
        } catch (\Throwable $e) {
            $missing[] = 'audit_log: falha na sonda de INSERT (' . $e->getMessage() . ')';
        } finally {
            $pdo->rollBack();
        }

        // 3) versionamento: UPDATE neutro deve incrementar version e gerar linha em *_history
        foreach (['users', 'students', 'classes', 'enrollments'] as $table) {
            $row = Database::row("SELECT id, version FROM `{$table}` ORDER BY id LIMIT 1");
            if ($row === null) {
                continue; // sem dados ainda: nada a sondar
            }
            $pdo->beginTransaction();
            try {
                $col = $table === 'users' ? 'full_name' : ($table === 'classes' ? 'letter' : ($table === 'students' ? 'full_name' : 'status'));
                Database::run("UPDATE `{$table}` SET `{$col}` = `{$col}` WHERE id = :id", ['id' => (int) $row['id']]);
                $after = (int) Database::value("SELECT version FROM `{$table}` WHERE id = :id", ['id' => (int) $row['id']]);
                $hist = (int) Database::value("SELECT COUNT(*) FROM `{$table}_history` WHERE id = :id AND version = :v", ['id' => (int) $row['id'], 'v' => (int) $row['version']]);
                if ($after !== (int) $row['version'] + 1 || $hist < 1) {
                    $missing[] = "{$table}: versionamento/histórico não executado (trg_{$table}_bu)";
                }
            } catch (\Throwable $e) {
                $missing[] = "{$table}: falha na sonda de UPDATE (" . $e->getMessage() . ')';
            } finally {
                $pdo->rollBack();
            }
        }
        return $missing;
    }

    /**
     * Âncora diária: hash da última linha do dia (São Paulo) anterior, se ainda não existir.
     * @return array{created:bool,anchor_date:string,last_hash:?string,row_count:int}|null
     */
    public static function anchorYesterday(): ?array
    {
        $date = (new \DateTimeImmutable('yesterday'))->format('Y-m-d');
        if (Database::row('SELECT id FROM audit_anchor WHERE anchor_date = :d', ['d' => $date]) !== null) {
            return ['created' => false, 'anchor_date' => $date, 'last_hash' => null, 'row_count' => 0];
        }
        // fim do dia em São Paulo convertido para UTC
        $tz = new \DateTimeZone(date_default_timezone_get());
        $endLocal = new \DateTimeImmutable($date . ' 23:59:59.999999', $tz);
        $endUtc = $endLocal->setTimezone(new \DateTimeZone('UTC'))->format('Y-m-d H:i:s.u');
        $last = Database::row('SELECT id, hash FROM audit_log WHERE occurred_at <= :e ORDER BY id DESC LIMIT 1', ['e' => $endUtc]);
        if ($last === null) {
            return null;
        }
        $count = (int) Database::value('SELECT COUNT(*) FROM audit_log WHERE id <= :id', ['id' => (int) $last['id']]);
        Database::insert('audit_anchor', [
            'anchor_date' => $date, 'last_audit_id' => (int) $last['id'], 'last_hash' => (string) $last['hash'], 'row_count' => $count,
        ]);
        $auditId = self::log('ANCORA', 'audit_anchor', (int) $last['id'], "Âncora diária {$date}: {$count} linhas, hash " . substr((string) $last['hash'], 0, 16) . '…');
        return ['created' => true, 'anchor_date' => $date, 'last_hash' => (string) $last['hash'], 'row_count' => $count, 'audit_id' => $auditId];
    }
}
