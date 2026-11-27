<?php
// app/Security/Validator.php — validação server-side com mensagens em pt-BR
declare(strict_types=1);

namespace App\Security;

final class Validator
{
    /** @var array<string,string> campo => mensagem */
    private array $errors = [];
    /** @var array<string,mixed> */
    private array $data;

    /** @param array<string,mixed> $data */
    public function __construct(array $data)
    {
        $this->data = $data;
    }

    public function fails(): bool { return $this->errors !== []; }
    /** @return array<string,string> */
    public function errors(): array { return $this->errors; }
    public function value(string $field): mixed { return $this->data[$field] ?? null; }

    private function str(string $field): string
    {
        $v = $this->data[$field] ?? '';
        return is_scalar($v) ? trim((string) $v) : '';
    }

    private function fail(string $field, string $message): self
    {
        $this->errors[$field] ??= $message;
        return $this;
    }

    public function required(string $field, string $label): self
    {
        return $this->str($field) === '' ? $this->fail($field, "$label é obrigatório.") : $this;
    }

    public function length(string $field, string $label, int $min, int $max): self
    {
        $len = mb_strlen($this->str($field));
        if ($len === 0) {
            return $this;
        }
        return ($len < $min || $len > $max) ? $this->fail($field, "$label deve ter entre $min e $max caracteres.") : $this;
    }

    public function in(string $field, string $label, array $allowed): self
    {
        $v = $this->str($field);
        return ($v !== '' && !in_array($v, $allowed, true)) ? $this->fail($field, "$label tem um valor não permitido.") : $this;
    }

    public function integer(string $field, string $label, ?int $min = null, ?int $max = null): self
    {
        $v = $this->str($field);
        if ($v === '') {
            return $this;
        }
        if (!preg_match('/^-?\d+$/', $v)) {
            return $this->fail($field, "$label deve ser um número inteiro.");
        }
        $n = (int) $v;
        if (($min !== null && $n < $min) || ($max !== null && $n > $max)) {
            return $this->fail($field, "$label deve estar entre " . ($min ?? '-∞') . " e " . ($max ?? '∞') . '.');
        }
        return $this;
    }

    public function email(string $field, string $label): self
    {
        $v = $this->str($field);
        return ($v !== '' && !self::isEmail($v)) ? $this->fail($field, "$label não é um e-mail válido.") : $this;
    }

    public function scsEducaEmail(string $field, string $label, string $domain = 'scseduca.com.br'): self
    {
        $v = mb_strtolower($this->str($field));
        if ($v === '') {
            return $this;
        }
        if (!self::isEmail($v) || !str_ends_with($v, '@' . $domain)) {
            return $this->fail($field, "$label deve ser uma conta @$domain.");
        }
        return $this;
    }

    public function cpf(string $field, string $label = 'CPF'): self
    {
        $v = $this->str($field);
        return ($v !== '' && !self::isCpf($v)) ? $this->fail($field, "$label inválido (dígitos verificadores não conferem).") : $this;
    }

    public function dateBr(string $field, string $label): self
    {
        $v = $this->str($field);
        return ($v !== '' && self::parseDateBr($v) === null) ? $this->fail($field, "$label deve estar no formato dd/mm/aaaa.") : $this;
    }

    public function dateIso(string $field, string $label): self
    {
        $v = $this->str($field);
        if ($v === '') {
            return $this;
        }
        $d = \DateTimeImmutable::createFromFormat('!Y-m-d', $v);
        return ($d === false || $d->format('Y-m-d') !== $v) ? $this->fail($field, "$label deve ser uma data válida (aaaa-mm-dd).") : $this;
    }

    public function phoneBr(string $field, string $label): self
    {
        $d = preg_replace('/\D/', '', $this->str($field)) ?? '';
        return ($d !== '' && (strlen($d) < 10 || strlen($d) > 11)) ? $this->fail($field, "$label deve ter DDD + número (10 ou 11 dígitos).") : $this;
    }

    public function minReason(string $field, string $label = 'Motivo', int $min = 10): self
    {
        $v = $this->str($field);
        return mb_strlen($v) < $min ? $this->fail($field, "$label deve ter no mínimo $min caracteres.") : $this;
    }

    // ---- funções estáticas reutilizáveis ----------------------------------------------------------------

    public static function isEmail(string $email): bool
    {
        return filter_var($email, FILTER_VALIDATE_EMAIL) !== false && !preg_match('/[\x00-\x1F\s]/', $email);
    }

    /** CPF com dígitos verificadores (rejeita sequências repetidas). */
    public static function isCpf(string $cpf): bool
    {
        $d = preg_replace('/\D/', '', $cpf) ?? '';
        if (strlen($d) !== 11 || preg_match('/^(\d)\1{10}$/', $d)) {
            return false;
        }
        for ($t = 9; $t < 11; $t++) {
            $sum = 0;
            for ($i = 0; $i < $t; $i++) {
                $sum += (int) $d[$i] * (($t + 1) - $i);
            }
            $digit = ((10 * $sum) % 11) % 10;
            if ((int) $d[$t] !== $digit) {
                return false;
            }
        }
        return true;
    }

    /** dd/mm/aaaa → aaaa-mm-dd (ou null se inválida). */
    public static function parseDateBr(string $value): ?string
    {
        $value = trim($value);
        if (!preg_match('~^(\d{1,2})/(\d{1,2})/(\d{4})$~', $value, $m)) {
            return null;
        }
        $iso = sprintf('%04d-%02d-%02d', (int) $m[3], (int) $m[2], (int) $m[1]);
        $d = \DateTimeImmutable::createFromFormat('!Y-m-d', $iso);
        return ($d !== false && $d->format('Y-m-d') === $iso) ? $iso : null;
    }

    /** Remove acentos, caixa alta, espaços simples (para students.full_name_norm). */
    public static function normalizeName(string $name): string
    {
        $s = trim(preg_replace('/\s+/u', ' ', $name) ?? $name);
        $ascii = @iconv('UTF-8', 'ASCII//TRANSLIT//IGNORE', $s);
        if ($ascii === false || $ascii === '') {
            $ascii = $s;
        }
        $ascii = preg_replace("/['`^~\"]/", '', $ascii) ?? $ascii;
        return mb_strtoupper($ascii);
    }
}
