<?php
// app/Google/SheetLogger.php — planilha de logs e segurança: cria as abas, envia a fila sheet_log_outbox, confere planilha × banco
declare(strict_types=1);

namespace App\Google;

use App\Database;
use App\Security\Logger;
use App\Security\RateLimiter;
use App\Security\SecurityEvents;
use App\Settings;

final class SheetLogger
{
    public const TABS = ['AUDITORIA', 'ACESSOS', 'SEGURANCA', 'ADMIN', 'SINCRONIZACAO', 'EXPORTACOES', 'ANCORAS'];
    public const HEADER = ['Data/hora (UTC)', 'Usuário', 'Perfil', 'Ação', 'Entidade', 'ID', 'Resumo', 'IP', 'Origem', 'Hash'];
    private const PROTECTION = 'Sistema CELEF: somente a conta técnica escreve';
    private const BATCH = 300;

    /** Planilha de logs configurada (linha de connected_sheets) ou null. @return array<string,mixed>|null */
    public static function sheet(): ?array
    {
        return Database::row("SELECT * FROM connected_sheets WHERE sheet_role = 'LOGS' AND deleted_at IS NULL AND sync_enabled = 1 ORDER BY id DESC LIMIT 1");
    }

    /**
     * Garante as 7 abas com cabeçalho congelado, em negrito, e a aba inteira protegida (só a conta técnica edita).
     * Idempotente. @return array{criadas:list<string>,protegidas:list<string>}
     */
    public static function ensureTabs(string $spreadsheetId, ?int $deadline = null): array
    {
        $meta = SheetsClient::metadata($spreadsheetId, $deadline);
        $existing = array_column($meta['tabs'], null, 'title');
        $missing = array_values(array_diff(self::TABS, array_keys($existing)));
        if ($missing !== []) {
            SheetsClient::batchUpdate($spreadsheetId, array_map(static fn(string $t) => SheetsClient::reqAddSheet($t, 1, count(self::HEADER)), $missing), $deadline);
            $meta = SheetsClient::metadata($spreadsheetId, $deadline);
            $existing = array_column($meta['tabs'], null, 'title');
        }
        // cabeçalho (só onde a linha 1 não for o cabeçalho esperado)
        $ranges = array_map(static fn(string $t) => SheetsClient::range($t, '1:1'), self::TABS);
        $current = SheetsClient::batchGet($spreadsheetId, $ranges, $deadline);
        $writes = [];
        foreach (self::TABS as $i => $t) {
            if (($current[$ranges[$i]][0] ?? []) !== self::HEADER) {
                $writes[] = ['range' => SheetsClient::range($t, 'A1'), 'values' => [self::HEADER]];
            }
        }
        SheetsClient::batchUpdateValues($spreadsheetId, $writes, $deadline);
        // congelar, estilizar e proteger
        $editor = GoogleOAuthToken::accountEmail();
        $requests = [];
        $protected = [];
        foreach (self::TABS as $t) {
            $tab = $existing[$t];
            if ($tab['frozen'] < 1) {
                $requests[] = SheetsClient::reqFreeze($tab['gid'], 1);
            }
            if (in_array($t, $missing, true) || $writes !== []) {
                $requests[] = SheetsClient::reqHeaderStyle($tab['gid'], count(self::HEADER));
            }
            if (!in_array(self::PROTECTION, array_column($tab['protected'], 'description'), true) && $editor !== null) {
                $requests[] = SheetsClient::reqProtect($tab['gid'], self::PROTECTION, [$editor]);
                $protected[] = $t;
            }
        }
        SheetsClient::batchUpdate($spreadsheetId, $requests, $deadline);
        return ['criadas' => $missing, 'protegidas' => $protected];
    }

    /**
     * Envia a fila para a planilha, em lotes por aba. Nada se perde: o banco é a fonte primária.
     * @return array{enviadas:int,falhas:int,pendentes:int,mensagem:string}
     */
    public static function flush(?int $deadline = null): array
    {
        $pending = (int) Database::value("SELECT COUNT(*) FROM sheet_log_outbox WHERE status IN ('PENDING','FAILED','SENDING')");
        $sheet = self::sheet();
        if ($sheet === null) {
            return ['enviadas' => 0, 'falhas' => 0, 'pendentes' => $pending, 'mensagem' => 'Nenhuma planilha de logs configurada: registros só no banco.'];
        }
        if (!GoogleOAuthToken::isConnected()) {
            self::alertIfStalled();
            return ['enviadas' => 0, 'falhas' => 0, 'pendentes' => $pending, 'mensagem' => 'Conta técnica não conectada: a fila aguarda.'];
        }
        if (!Database::lock('sheet_log_flush', 0)) {
            return ['enviadas' => 0, 'falhas' => 0, 'pendentes' => $pending, 'mensagem' => 'Envio já em andamento.'];
        }
        $sent = 0;
        $failed = 0;
        try {
            $spreadsheetId = (string) $sheet['spreadsheet_id'];
            // linhas presas em SENDING há mais de 10 min (execução interrompida) voltam para a fila
            Database::run("UPDATE sheet_log_outbox SET status = 'PENDING' WHERE status = 'SENDING' AND (next_attempt_at IS NULL OR next_attempt_at < NOW() - INTERVAL 10 MINUTE)");
            $tabsReady = false;
            foreach (self::TABS as $tab) {
                while ($deadline === null || time() < $deadline - 5) {
                    $rows = Database::rows("SELECT id, row_values_json FROM sheet_log_outbox WHERE tab_name = :t AND status IN ('PENDING','FAILED')
                                            AND (next_attempt_at IS NULL OR next_attempt_at <= NOW(3)) ORDER BY id LIMIT " . self::BATCH, ['t' => $tab]);
                    if ($rows === []) {
                        break;
                    }
                    $ids = array_map(static fn($r) => (int) $r['id'], $rows);
                    $in = implode(',', $ids);
                    Database::run("UPDATE sheet_log_outbox SET status = 'SENDING', next_attempt_at = NOW(3) WHERE id IN ({$in})");
                    try {
                        if (!$tabsReady) {
                            self::ensureTabs($spreadsheetId, $deadline);
                            $tabsReady = true;
                        }
                        $values = array_map(static fn($r) => (array) json_decode((string) $r['row_values_json'], true), $rows);
                        $first = SheetsClient::append($spreadsheetId, $tab, $values, $deadline);
                        foreach ($ids as $i => $id) {
                            Database::run("UPDATE sheet_log_outbox SET status = 'DONE', sent_at = NOW(3), last_error = NULL, sheet_row_number = :n WHERE id = :id",
                                ['n' => $first === null ? null : $first + $i, 'id' => $id]);
                        }
                        $sent += count($ids);
                    } catch (GoogleApiException $e) {
                        // espera crescente: 1, 2, 4… min (máx. 60); a linha continua na fila
                        Database::run("UPDATE sheet_log_outbox SET status = 'FAILED', attempts = LEAST(attempts + 1, 250), last_error = :e,
                                       next_attempt_at = NOW(3) + INTERVAL LEAST(POW(2, LEAST(attempts, 6)), 60) MINUTE WHERE id IN ({$in})", ['e' => mb_substr($e->reason . ': ' . $e->getMessage(), 0, 500)]);
                        $failed += count($ids);
                        Logger::error('Falha ao enviar lote para a planilha de logs', ['aba' => $tab, 'linhas' => count($ids), 'motivo' => $e->reason]);
                        if ($e->isAuth() || $e->isPermission()) {
                            break 2; // sem acesso: não adianta insistir nas outras abas agora
                        }
                        break;
                    }
                }
            }
            if ($sent > 0) {
                // no máximo 1 gravação por hora (tabela versionada); o detalhe de cada envio fica em sheet_log_outbox e cron_runs
                Database::run('UPDATE connected_sheets SET last_synced_at = NOW(3) WHERE id = :id AND (last_synced_at IS NULL OR last_synced_at < NOW() - INTERVAL 1 HOUR)', ['id' => (int) $sheet['id']]);
            }
        } finally {
            Database::unlock('sheet_log_flush');
        }
        self::alertIfStalled();
        $left = (int) Database::value("SELECT COUNT(*) FROM sheet_log_outbox WHERE status IN ('PENDING','FAILED','SENDING')");
        return ['enviadas' => $sent, 'falhas' => $failed, 'pendentes' => $left, 'mensagem' => "{$sent} linha(s) enviada(s), {$failed} com falha, {$left} na fila."];
    }

    /** Alerta (no máximo 1 a cada 6 h) quando há linha parada na fila há mais de alerts.sync_failure_minutes. */
    private static function alertIfStalled(): void
    {
        $minutes = Settings::int('alerts.sync_failure_minutes', 30);
        $oldest = Database::value("SELECT MIN(created_at) FROM sheet_log_outbox WHERE status IN ('PENDING','FAILED','SENDING')");
        if ($oldest === null || strtotime((string) $oldest) > time() - $minutes * 60) {
            return;
        }
        if (!RateLimiter::hit('alerta:falha_log_planilha', 1, 6 * 3600)['allowed']) {
            return;
        }
        $n = (int) Database::value("SELECT COUNT(*) FROM sheet_log_outbox WHERE status IN ('PENDING','FAILED','SENDING')");
        $err = (string) (Database::value("SELECT last_error FROM sheet_log_outbox WHERE last_error IS NOT NULL ORDER BY id DESC LIMIT 1") ?? 'sem detalhe');
        SecurityEvents::record('FALHA_LOG_PLANILHA', SecurityEvents::AVISO,
            "A planilha de logs não recebe registros há mais de {$minutes} min ({$n} linha(s) na fila desde {$oldest}). Os registros continuam íntegros no banco.",
            ['fila' => $n, 'desde' => (string) $oldest, 'ultimo_erro' => $err], 'sheet_log_outbox');
    }

    /** @return array{pendentes:int,falhas:int,enviadas:int,mais_antiga:?string,ultimo_erro:?string,ultimo_envio:?string} */
    public static function queueStats(): array
    {
        $r = Database::row("SELECT SUM(status IN ('PENDING','SENDING')) AS p, SUM(status = 'FAILED') AS f, SUM(status = 'DONE') AS d,
                                   MIN(CASE WHEN status <> 'DONE' THEN created_at END) AS oldest, MAX(sent_at) AS last_sent FROM sheet_log_outbox") ?? [];
        return [
            'pendentes' => (int) ($r['p'] ?? 0), 'falhas' => (int) ($r['f'] ?? 0), 'enviadas' => (int) ($r['d'] ?? 0),
            'mais_antiga' => $r['oldest'] ?? null, 'ultimo_envio' => $r['last_sent'] ?? null,
            'ultimo_erro' => Database::value("SELECT last_error FROM sheet_log_outbox WHERE status = 'FAILED' AND last_error IS NOT NULL ORDER BY id DESC LIMIT 1"),
        ];
    }

    /**
     * Confere planilha × banco: aponta linhas apagadas, alteradas ou estranhas na planilha de logs.
     * A chave é o hash (última coluna), que é o mesmo hash da linha em audit_log.
     * @return array{ok:bool,conferidas:int,apagadas:list<array<string,mixed>>,alteradas:list<array<string,mixed>>,estranhas:list<array<string,mixed>>}
     */
    public static function compare(string $spreadsheetId, ?int $deadline = null): array
    {
        $ranges = array_map(static fn(string $t) => SheetsClient::range($t, 'A2:J'), self::TABS);
        $data = SheetsClient::batchGet($spreadsheetId, $ranges, $deadline);
        $missing = [];
        $altered = [];
        $strange = [];
        $checked = 0;
        foreach (self::TABS as $i => $tab) {
            $sheetRows = [];
            foreach ($data[$ranges[$i]] as $n => $row) {
                $row = array_pad($row, count(self::HEADER), '');
                $hash = (string) $row[9];
                if (implode('', $row) === '') {
                    continue;
                }
                $sheetRows[$hash][] = ['linha' => $n + 2, 'valores' => $row];
            }
            $lastId = 0;
            do {
                $dbRows = Database::rows("SELECT id, audit_log_id, row_values_json, sheet_row_number FROM sheet_log_outbox WHERE tab_name = :t AND status = 'DONE' AND id > :last ORDER BY id LIMIT 2000", ['t' => $tab, 'last' => $lastId]);
                foreach ($dbRows as $r) {
                    $lastId = (int) $r['id'];
                    $checked++;
                    $expected = array_map('strval', SheetsClient::sanitizeRows([(array) json_decode((string) $r['row_values_json'], true)])[0]);
                    $hash = (string) ($expected[9] ?? '');
                    if (!isset($sheetRows[$hash]) || $sheetRows[$hash] === []) {
                        // o hash sumiu: ou a linha foi apagada, ou alguém alterou justamente a coluna do hash
                        $missing[] = ['aba' => $tab, 'audit_log_id' => $r['audit_log_id'], 'linha_original' => $r['sheet_row_number'], 'resumo' => $expected[6] ?? ''];
                        continue;
                    }
                    $found = array_shift($sheetRows[$hash]);
                    if ($found['valores'] !== array_pad($expected, count(self::HEADER), '')) {
                        $diff = [];
                        foreach (self::HEADER as $c => $name) {
                            if (($found['valores'][$c] ?? '') !== ($expected[$c] ?? '')) {
                                $diff[$name] = ['banco' => $expected[$c] ?? '', 'planilha' => $found['valores'][$c] ?? ''];
                            }
                        }
                        $altered[] = ['aba' => $tab, 'linha' => $found['linha'], 'audit_log_id' => $r['audit_log_id'], 'diferencas' => $diff];
                    }
                }
            } while (count($dbRows) === 2000 && ($deadline === null || time() < $deadline));
            foreach ($sheetRows as $hash => $left) {
                foreach ($left as $row) {
                    $strange[] = ['aba' => $tab, 'linha' => $row['linha'], 'resumo' => $row['valores'][6] ?? '', 'hash' => mb_substr((string) $hash, 0, 16)];
                }
            }
        }
        return ['ok' => $missing === [] && $altered === [] && $strange === [], 'conferidas' => $checked, 'apagadas' => $missing, 'alteradas' => $altered, 'estranhas' => $strange];
    }
}
