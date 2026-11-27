<?php
// app/Google/SheetsClient.php — Google Sheets API v4 via REST (sem bibliotecas)
declare(strict_types=1);

namespace App\Google;

final class SheetsClient
{
    /** Extrai o ID de um link do Google Planilhas, ou valida um ID puro. */
    public static function parseId(string $input): ?string
    {
        $input = trim($input);
        if (preg_match('~/spreadsheets/d/([A-Za-z0-9_-]{20,100})~', $input, $m)) {
            return $m[1];
        }
        return preg_match('/^[A-Za-z0-9_-]{20,100}$/', $input) ? $input : null;
    }

    /**
     * Proteção contra injeção de fórmula: valor que começa com = + - @ (ou TAB/CR) recebe apóstrofo.
     * Somado a valueInputOption=RAW, nada escrito pelo sistema é interpretado como fórmula — nem se a célula for
     * depois exportada para Excel/CSV. Números e booleanos passam inalterados.
     */
    public static function sanitizeCell(mixed $value): string|int|float|bool
    {
        if (is_int($value) || is_float($value) || is_bool($value)) {
            return $value;
        }
        $s = (string) ($value ?? '');
        if ($s !== '' && in_array($s[0], ['=', '+', '-', '@', "\t", "\r"], true)) {
            return "'" . $s;
        }
        return $s;
    }

    /** @param list<list<mixed>> $rows @return list<list<string|int|float|bool>> */
    public static function sanitizeRows(array $rows): array
    {
        return array_map(static fn(array $r): array => array_map([self::class, 'sanitizeCell'], array_values($r)), array_values($rows));
    }

    /** 'Nome da aba'!A1:Z — aspas simples duplicadas conforme a notação A1. */
    public static function range(string $tab, string $cells = ''): string
    {
        $q = "'" . str_replace("'", "''", $tab) . "'";
        return $cells === '' ? $q : $q . '!' . $cells;
    }

    /** Índice de coluna (1 = A) → letras. */
    public static function colLetter(int $index): string
    {
        $s = '';
        while ($index > 0) {
            $index--;
            $s = chr(65 + $index % 26) . $s;
            $index = intdiv($index, 26);
        }
        return $s;
    }

    private static function url(string $spreadsheetId, string $suffix = ''): string
    {
        return GoogleHttp::sheetsBase() . '/v4/spreadsheets/' . rawurlencode($spreadsheetId) . $suffix;
    }

    // ---- leitura -----------------------------------------------------------------------------------------

    /**
     * Metadados: título e abas (id, título, linhas/colunas, linhas congeladas, intervalos protegidos).
     * @return array{title:string,tabs:list<array{gid:int,title:string,rows:int,cols:int,frozen:int,protected:list<array{id:int,description:string}>}>}
     */
    public static function metadata(string $spreadsheetId, ?int $deadline = null): array
    {
        $d = GoogleHttp::json('GET', self::url($spreadsheetId), null,
            ['fields' => 'properties.title,sheets(properties(sheetId,title,gridProperties(rowCount,columnCount,frozenRowCount)),protectedRanges(protectedRangeId,description))'], $deadline);
        $tabs = [];
        foreach ($d['sheets'] ?? [] as $s) {
            $p = $s['properties'] ?? [];
            $tabs[] = [
                'gid' => (int) ($p['sheetId'] ?? 0), 'title' => (string) ($p['title'] ?? ''),
                'rows' => (int) ($p['gridProperties']['rowCount'] ?? 0), 'cols' => (int) ($p['gridProperties']['columnCount'] ?? 0),
                'frozen' => (int) ($p['gridProperties']['frozenRowCount'] ?? 0),
                'protected' => array_map(static fn($r) => ['id' => (int) ($r['protectedRangeId'] ?? 0), 'description' => (string) ($r['description'] ?? '')], $s['protectedRanges'] ?? []),
            ];
        }
        return ['title' => (string) ($d['properties']['title'] ?? ''), 'tabs' => $tabs];
    }

    /** @return list<list<string>> valores formatados como texto (linhas vazias no fim são omitidas pelo Google) */
    public static function get(string $spreadsheetId, string $range, ?int $deadline = null): array
    {
        $d = GoogleHttp::json('GET', self::url($spreadsheetId, '/values/' . rawurlencode($range)), null,
            ['majorDimension' => 'ROWS', 'valueRenderOption' => 'FORMATTED_VALUE'], $deadline);
        return self::stringRows($d['values'] ?? []);
    }

    /** @param list<string> $ranges @return array<string,list<list<string>>> na mesma ordem dos ranges pedidos */
    public static function batchGet(string $spreadsheetId, array $ranges, ?int $deadline = null): array
    {
        if ($ranges === []) {
            return [];
        }
        $d = GoogleHttp::json('GET', self::url($spreadsheetId, '/values:batchGet'), null,
            ['ranges' => array_values($ranges), 'majorDimension' => 'ROWS', 'valueRenderOption' => 'FORMATTED_VALUE'], $deadline);
        $out = [];
        foreach (array_values($ranges) as $i => $r) {
            $out[$r] = self::stringRows($d['valueRanges'][$i]['values'] ?? []);
        }
        return $out;
    }

    // ---- escrita (sempre RAW e sanitizada) ---------------------------------------------------------------

    /**
     * Acrescenta linhas ao fim da aba. Retorna o número da primeira linha gravada (ou null).
     * @param list<list<mixed>> $rows
     */
    public static function append(string $spreadsheetId, string $tab, array $rows, ?int $deadline = null): ?int
    {
        $d = GoogleHttp::json('POST', self::url($spreadsheetId, '/values/' . rawurlencode(self::range($tab, 'A1')) . ':append'),
            ['majorDimension' => 'ROWS', 'values' => self::sanitizeRows($rows)],
            ['valueInputOption' => 'RAW', 'insertDataOption' => 'INSERT_ROWS', 'includeValuesInResponse' => false], $deadline);
        $updated = (string) ($d['updates']['updatedRange'] ?? '');
        return preg_match('/![A-Z]+(\d+)/', $updated, $m) ? (int) $m[1] : null;
    }

    /**
     * Atualiza vários intervalos de uma vez.
     * @param list<array{range:string,values:list<list<mixed>>}> $data  @return int células atualizadas
     */
    public static function batchUpdateValues(string $spreadsheetId, array $data, ?int $deadline = null): int
    {
        if ($data === []) {
            return 0;
        }
        $payload = array_map(static fn(array $d): array => ['range' => $d['range'], 'majorDimension' => 'ROWS', 'values' => self::sanitizeRows($d['values'])], $data);
        $d = GoogleHttp::json('POST', self::url($spreadsheetId, '/values:batchUpdate'), ['valueInputOption' => 'RAW', 'data' => $payload], [], $deadline);
        return (int) ($d['totalUpdatedCells'] ?? 0);
    }

    /** Requisições estruturais (addSheet, updateSheetProperties, addProtectedRange…). @param list<array<string,mixed>> $requests @return list<array<string,mixed>> replies */
    public static function batchUpdate(string $spreadsheetId, array $requests, ?int $deadline = null): array
    {
        if ($requests === []) {
            return [];
        }
        $d = GoogleHttp::json('POST', self::url($spreadsheetId, ':batchUpdate'), ['requests' => array_values($requests)], [], $deadline);
        return $d['replies'] ?? [];
    }

    /** Requisição addSheet com a primeira linha congelada. @return array<string,mixed> */
    public static function reqAddSheet(string $title, int $frozenRows = 1, int $cols = 26): array
    {
        return ['addSheet' => ['properties' => ['title' => $title, 'gridProperties' => ['rowCount' => 1000, 'columnCount' => $cols, 'frozenRowCount' => $frozenRows]]]];
    }

    /** Requisição que congela linhas de uma aba existente. @return array<string,mixed> */
    public static function reqFreeze(int $gid, int $rows = 1): array
    {
        return ['updateSheetProperties' => ['properties' => ['sheetId' => $gid, 'gridProperties' => ['frozenRowCount' => $rows]], 'fields' => 'gridProperties.frozenRowCount']];
    }

    /**
     * Requisição addProtectedRange: só os e-mails informados editam. $rowRange = [inicio, fim) em índices 0-based; null = aba inteira.
     * @param list<string> $editors  @param array{0:int,1:int}|null $rowRange  @return array<string,mixed>
     */
    public static function reqProtect(int $gid, string $description, array $editors, ?array $rowRange = null): array
    {
        $range = ['sheetId' => $gid];
        if ($rowRange !== null) {
            $range['startRowIndex'] = $rowRange[0];
            $range['endRowIndex'] = $rowRange[1];
        }
        return ['addProtectedRange' => ['protectedRange' => [
            'range' => $range, 'description' => $description, 'warningOnly' => false,
            'editors' => ['users' => array_values($editors), 'domainUsersCanEdit' => false],
        ]]];
    }

    /** Cabeçalho em negrito com fundo cinza. @return array<string,mixed> */
    public static function reqHeaderStyle(int $gid, int $cols): array
    {
        return ['repeatCell' => [
            'range' => ['sheetId' => $gid, 'startRowIndex' => 0, 'endRowIndex' => 1, 'startColumnIndex' => 0, 'endColumnIndex' => $cols],
            'cell' => ['userEnteredFormat' => ['textFormat' => ['bold' => true], 'backgroundColor' => ['red' => 0.9, 'green' => 0.92, 'blue' => 0.95]]],
            'fields' => 'userEnteredFormat(textFormat.bold,backgroundColor)',
        ]];
    }

    /** @param mixed $rows @return list<list<string>> */
    private static function stringRows(mixed $rows): array
    {
        $out = [];
        foreach (is_array($rows) ? $rows : [] as $r) {
            $out[] = array_map(static fn($c): string => is_scalar($c) ? (string) $c : '', is_array($r) ? array_values($r) : []);
        }
        return $out;
    }
}
