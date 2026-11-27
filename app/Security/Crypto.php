<?php
// app/Security/Crypto.php — criptografia de campo (XChaCha20-Poly1305), blind index (HMAC) e arquivos (secretstream)
declare(strict_types=1);

namespace App\Security;

use App\Config;

final class Crypto
{
    /** Formato do blob: 1 byte de versão da chave + 24 bytes de nonce + ciphertext (com tag de 16 bytes). */
    private const NONCE_LEN = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES; // 24
    private const FILE_CHUNK = 65536;

    /** @var array<int,string> */
    private static array $keys = [];
    private static ?string $blindKey = null;

    // ---- chaves ------------------------------------------------------------------------------------------

    public static function currentVersion(): int
    {
        return max(1, Config::int('APP_KEY_VERSION', 1));
    }

    private static function key(int $version): string
    {
        if (!isset(self::$keys[$version])) {
            $raw = Config::get('APP_KEY_V' . $version);
            if ($raw === null) {
                throw new \RuntimeException("Chave de criptografia APP_KEY_V{$version} não configurada no .env.");
            }
            $key = base64_decode($raw, true);
            if ($key === false || strlen($key) !== SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES) {
                throw new \RuntimeException("APP_KEY_V{$version} inválida: esperado base64 de 32 bytes.");
            }
            self::$keys[$version] = $key;
        }
        return self::$keys[$version];
    }

    private static function blindKey(): string
    {
        if (self::$blindKey === null) {
            $raw = Config::get('BLIND_INDEX_KEY');
            $key = $raw === null ? false : base64_decode($raw, true);
            if ($key === false || strlen($key) < 32) {
                throw new \RuntimeException('BLIND_INDEX_KEY não configurada ou inválida (base64 de 32 bytes).');
            }
            self::$blindKey = $key;
        }
        return self::$blindKey;
    }

    /** Gera um par de chaves novo (usado uma vez pela página /instalacao). @return array{app_key:string,blind_key:string} */
    public static function generateKeys(): array
    {
        return [
            'app_key'   => base64_encode(random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_KEYBYTES)),
            'blind_key' => base64_encode(random_bytes(32)),
        ];
    }

    // ---- campos ------------------------------------------------------------------------------------------

    /**
     * Cifra um valor. $context (ex.: 'students.cpf') entra como dado adicional autenticado:
     * um ciphertext copiado para outra coluna/tabela não decifra.
     */
    public static function encrypt(?string $plain, string $context = ''): ?string
    {
        if ($plain === null || $plain === '') {
            return null;
        }
        $version = self::currentVersion();
        $nonce = random_bytes(self::NONCE_LEN);
        $cipher = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt($plain, $context, $nonce, self::key($version));
        return chr($version) . $nonce . $cipher;
    }

    public static function decrypt(?string $blob, string $context = ''): ?string
    {
        if ($blob === null || $blob === '') {
            return null;
        }
        if (strlen($blob) < 1 + self::NONCE_LEN + SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_ABYTES) {
            throw new \RuntimeException('Dado cifrado corrompido (tamanho).');
        }
        $version = ord($blob[0]);
        $nonce = substr($blob, 1, self::NONCE_LEN);
        $cipher = substr($blob, 1 + self::NONCE_LEN);
        $plain = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt($cipher, $context, $nonce, self::key($version));
        if ($plain === false) {
            Logger::critical('Falha de autenticação ao decifrar campo', ['contexto' => $context, 'versao' => $version]);
            throw new \RuntimeException('Não foi possível decifrar o dado (chave ou contexto incorretos).');
        }
        return $plain;
    }

    /** Versão da chave usada em um blob (para a rotação em lotes). */
    public static function blobVersion(string $blob): int
    {
        return ord($blob[0] ?? "\0");
    }

    /** Recifra com a chave atual quando o blob estiver em versão antiga. */
    public static function rotate(string $blob, string $context = ''): string
    {
        if (self::blobVersion($blob) === self::currentVersion()) {
            return $blob;
        }
        $plain = self::decrypt($blob, $context);
        try {
            return (string) self::encrypt($plain, $context);
        } finally {
            if ($plain !== null) {
                sodium_memzero($plain);
            }
        }
    }

    // ---- blind index -------------------------------------------------------------------------------------

    /** HMAC-SHA256 (32 bytes binários) do valor já normalizado. Igualdade exata, sem busca parcial. */
    public static function blindIndex(?string $normalized): ?string
    {
        if ($normalized === null || $normalized === '') {
            return null;
        }
        return hash_hmac('sha256', $normalized, self::blindKey(), true);
    }

    public static function normalizeDigits(?string $value): ?string
    {
        $d = preg_replace('/\D/', '', (string) $value) ?? '';
        return $d === '' ? null : $d;
    }

    public static function normalizeEmail(?string $value): ?string
    {
        $e = mb_strtolower(trim((string) $value));
        return $e === '' ? null : $e;
    }

    // ---- arquivos (uploads) -----------------------------------------------------------------------------

    /** Cifra um arquivo inteiro para storage/ (formato: 1 byte versão + header secretstream + blocos). */
    public static function encryptFile(string $sourcePath, string $destPath): void
    {
        $version = self::currentVersion();
        $in = fopen($sourcePath, 'rb');
        $out = fopen($destPath, 'wb');
        if ($in === false || $out === false) {
            throw new \RuntimeException('Não foi possível abrir o arquivo para cifrar.');
        }
        try {
            [$state, $header] = sodium_crypto_secretstream_xchacha20poly1305_init_push(self::key($version));
            fwrite($out, chr($version) . $header);
            while (!feof($in)) {
                $chunk = fread($in, self::FILE_CHUNK);
                if ($chunk === false) {
                    throw new \RuntimeException('Erro de leitura ao cifrar arquivo.');
                }
                $tag = feof($in) ? SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL : SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_MESSAGE;
                fwrite($out, sodium_crypto_secretstream_xchacha20poly1305_push($state, $chunk, '', $tag));
            }
        } finally {
            fclose($in);
            fclose($out);
        }
        @chmod($destPath, 0600);
    }

    /** Decifra um arquivo cifrado escrevendo no stream de saída (ex.: php://output). */
    public static function decryptFileToStream(string $sourcePath, $outStream): void
    {
        $in = fopen($sourcePath, 'rb');
        if ($in === false) {
            throw new \RuntimeException('Arquivo cifrado não encontrado.');
        }
        try {
            $version = ord((string) fread($in, 1));
            $header = fread($in, SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES);
            if ($header === false || strlen($header) !== SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_HEADERBYTES) {
                throw new \RuntimeException('Cabeçalho do arquivo cifrado inválido.');
            }
            $state = sodium_crypto_secretstream_xchacha20poly1305_init_pull($header, self::key($version));
            $blockLen = self::FILE_CHUNK + SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_ABYTES;
            while (!feof($in)) {
                $block = fread($in, $blockLen);
                if ($block === false || $block === '') {
                    break;
                }
                $res = sodium_crypto_secretstream_xchacha20poly1305_pull($state, $block);
                if ($res === false) {
                    throw new \RuntimeException('Arquivo cifrado adulterado ou chave incorreta.');
                }
                [$plain, $tag] = $res;
                fwrite($outStream, $plain);
                if ($tag === SODIUM_CRYPTO_SECRETSTREAM_XCHACHA20POLY1305_TAG_FINAL) {
                    break;
                }
            }
        } finally {
            fclose($in);
        }
    }

    // ---- utilidades -------------------------------------------------------------------------------------

    public static function randomToken(int $bytes = 32): string
    {
        return rtrim(strtr(base64_encode(random_bytes($bytes)), '+/', '-_'), '=');
    }

    public static function sha256(string $data): string
    {
        return hash('sha256', $data);
    }
}
