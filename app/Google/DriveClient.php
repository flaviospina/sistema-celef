<?php
// app/Google/DriveClient.php — Google Drive API v3 (só metadados): dono, último editor e revisões de uma planilha
declare(strict_types=1);

namespace App\Google;

final class DriveClient
{
    /**
     * @return array{id:string,name:string,owner:?string,modified_at:?string,last_user_email:?string,last_user_name:?string,can_edit:bool,link:?string,head_revision:?string}
     */
    public static function file(string $fileId, ?int $deadline = null): array
    {
        $d = GoogleHttp::json('GET', GoogleHttp::driveBase() . '/drive/v3/files/' . rawurlencode($fileId), null, [
            'fields' => 'id,name,owners(emailAddress),modifiedTime,lastModifyingUser(emailAddress,displayName),capabilities(canEdit),webViewLink,headRevisionId,version',
            'supportsAllDrives' => true,
        ], $deadline);
        return [
            'id' => (string) ($d['id'] ?? $fileId), 'name' => (string) ($d['name'] ?? ''),
            'owner' => isset($d['owners'][0]['emailAddress']) ? mb_strtolower((string) $d['owners'][0]['emailAddress']) : null,
            'modified_at' => self::localTime($d['modifiedTime'] ?? null),
            'last_user_email' => isset($d['lastModifyingUser']['emailAddress']) ? mb_strtolower((string) $d['lastModifyingUser']['emailAddress']) : null,
            'last_user_name' => $d['lastModifyingUser']['displayName'] ?? null,
            'can_edit' => (bool) ($d['capabilities']['canEdit'] ?? false),
            'link' => $d['webViewLink'] ?? null,
            'head_revision' => isset($d['version']) ? (string) $d['version'] : ($d['headRevisionId'] ?? null),
        ];
    }

    /**
     * Revisões (quem e quando), da mais antiga para a mais nova; pagina até $max.
     * @return list<array{id:string,modified_at:?string,user_email:?string,user_name:?string}>
     */
    public static function revisions(string $fileId, int $max = 200, ?int $deadline = null): array
    {
        $out = [];
        $pageToken = null;
        do {
            $q = ['fields' => 'nextPageToken,revisions(id,modifiedTime,lastModifyingUser(emailAddress,displayName))', 'pageSize' => 200];
            if ($pageToken !== null) {
                $q['pageToken'] = $pageToken;
            }
            $d = GoogleHttp::json('GET', GoogleHttp::driveBase() . '/drive/v3/files/' . rawurlencode($fileId) . '/revisions', null, $q, $deadline);
            foreach ($d['revisions'] ?? [] as $r) {
                $out[] = [
                    'id' => (string) ($r['id'] ?? ''), 'modified_at' => self::localTime($r['modifiedTime'] ?? null),
                    'user_email' => isset($r['lastModifyingUser']['emailAddress']) ? mb_strtolower((string) $r['lastModifyingUser']['emailAddress']) : null,
                    'user_name' => $r['lastModifyingUser']['displayName'] ?? null,
                ];
            }
            $pageToken = $d['nextPageToken'] ?? null;
        } while ($pageToken !== null && count($out) < $max);
        return array_slice($out, -$max);
    }

    /** RFC 3339 (UTC) → 'Y-m-d H:i:s.v' no fuso da aplicação. */
    private static function localTime(mixed $rfc3339): ?string
    {
        if (!is_string($rfc3339) || $rfc3339 === '') {
            return null;
        }
        try {
            return (new \DateTimeImmutable($rfc3339))->setTimezone(new \DateTimeZone(date_default_timezone_get()))->format('Y-m-d H:i:s.v');
        } catch (\Throwable) {
            return null;
        }
    }
}
