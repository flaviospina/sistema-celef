<?php
// app/Security/Masker.php — mascaramento de dados pessoais para tela, auditoria, logs e planilha de logs
declare(strict_types=1);

namespace App\Security;

final class Masker
{
    /** Chaves (ou sufixos) consideradas sensíveis em arrays de diff/log. */
    private const SENSITIVE_KEYS = [
        'cpf', 'rg', 'ra', 'birth_date', 'mother_name', 'guardian_email', 'guardian_phone', 'address',
        'social_media', 'health_notes', 'physical_education', 'dentistry', 'details', 'registration', 'phone',
        'secret', 'token', 'password', 'senha', 'refresh_token', 'access_token', 'code_verifier', 'key',
    ];

    public static function cpf(?string $cpf): string
    {
        $d = preg_replace('/\D/', '', (string) $cpf) ?? '';
        return strlen($d) === 11 ? '***.***.' . substr($d, 6, 3) . '-**' : '***';
    }

    public static function rg(?string $rg): string
    {
        $d = preg_replace('/[^0-9A-Za-z]/', '', (string) $rg) ?? '';
        return strlen($d) >= 4 ? str_repeat('*', strlen($d) - 3) . substr($d, -3) : '***';
    }

    public static function ra(?string $ra): string
    {
        $d = preg_replace('/\D/', '', (string) $ra) ?? '';
        return strlen($d) >= 4 ? str_repeat('*', max(0, strlen($d) - 4)) . substr($d, -4) : '***';
    }

    public static function email(?string $email): string
    {
        $email = (string) $email;
        if (!str_contains($email, '@')) {
            return '***';
        }
        [$user, $domain] = explode('@', $email, 2);
        return mb_substr($user, 0, 1) . '***@' . $domain;
    }

    public static function phone(?string $phone): string
    {
        $d = preg_replace('/\D/', '', (string) $phone) ?? '';
        return strlen($d) >= 4 ? '(**) *****-' . substr($d, -4) : '***';
    }

    public static function name(?string $name): string
    {
        $parts = preg_split('/\s+/', trim((string) $name)) ?: [];
        if ($parts === [] || $parts[0] === '') {
            return '***';
        }
        return $parts[0] . (count($parts) > 1 ? ' ' . mb_substr(end($parts), 0, 1) . '.' : '');
    }

    public static function date(?string $isoDate): string
    {
        return preg_match('/^(\d{4})/', (string) $isoDate, $m) ? '**/**/' . $m[1] : '***';
    }

    public static function generic(?string $value): string
    {
        $value = (string) $value;
        if ($value === '') {
            return '';
        }
        $len = mb_strlen($value);
        return $len <= 3 ? '***' : mb_substr($value, 0, 1) . str_repeat('*', min($len - 2, 8)) . mb_substr($value, -1);
    }

    /** Escolhe a máscara pelo nome do campo (ex.: 'cpf', 'students.guardian_email'). */
    public static function byField(string $field, mixed $value): mixed
    {
        if ($value === null || $value === '' || is_bool($value) || is_array($value)) {
            return is_array($value) ? self::scrubArray($value) : $value;
        }
        $v = (string) $value;
        $f = strtolower(substr($field, (int) strrpos('.' . $field, '.')));
        $f = preg_replace('/_(enc|bidx)$/', '', $f) ?? $f;
        return match (true) {
            str_contains($f, 'cpf')                                  => self::cpf($v),
            $f === 'rg'                                              => self::rg($v),
            $f === 'ra'                                              => self::ra($v),
            str_contains($f, 'email')                                => self::email($v),
            str_contains($f, 'phone')                                => self::phone($v),
            str_contains($f, 'mother_name')                          => self::name($v),
            str_contains($f, 'birth_date')                           => self::date($v),
            self::isSensitiveKey($f)                                 => '***',
            default                                                  => $value,
        };
    }

    public static function isSensitiveKey(string $key): bool
    {
        $k = strtolower($key);
        $k = preg_replace('/_(enc|bidx)$/', '', $k) ?? $k;
        foreach (self::SENSITIVE_KEYS as $s) {
            if ($k === $s || str_ends_with($k, '_' . $s) || str_starts_with($k, $s . '_')) {
                return true;
            }
        }
        return false;
    }

    /** Mascara recursivamente um array pelo nome das chaves (usado em diff_json e logs). */
    public static function scrubArray(array $data): array
    {
        $out = [];
        foreach ($data as $key => $value) {
            $k = (string) $key;
            if (is_array($value)) {
                $out[$k] = self::isSensitiveKey($k) && !self::isDiffPair($value)
                    ? '***'
                    : (self::isDiffPair($value)
                        ? ['de' => self::byField($k, $value['de']), 'para' => self::byField($k, $value['para'])]
                        : self::scrubArray($value));
            } elseif (is_string($value)) {
                $out[$k] = self::isSensitiveKey($k) ? self::byField($k, $value) : self::scrubText($value);
            } else {
                $out[$k] = self::isSensitiveKey($k) ? '***' : $value;
            }
        }
        return $out;
    }

    /** Rede de segurança: oculta CPFs e e-mails que apareçam em texto livre. */
    public static function scrubText(string $text): string
    {
        $text = preg_replace_callback('/\b\d{3}\.?\d{3}\.?\d{3}-?\d{2}\b/', static fn($m) => self::cpf($m[0]), $text) ?? $text;
        $text = preg_replace_callback('/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}/', static fn($m) => self::email($m[0]), $text) ?? $text;
        return $text;
    }

    private static function isDiffPair(array $value): bool
    {
        return array_key_exists('de', $value) && array_key_exists('para', $value) && count($value) === 2;
    }
}
