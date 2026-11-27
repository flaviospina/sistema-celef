<?php
// app/Google/TechAccount.php — conexão da conta técnica (celef@) por OAuth: autorização única pelo Super Administrador
declare(strict_types=1);

namespace App\Google;

use App\Auth\GoogleOidc;
use App\Database;
use App\Security\AuditLog;
use App\Security\SecurityEvents;
use App\Settings;

final class TechAccount
{
    /** Escopos pedidos na autorização: identificação da conta + planilhas + metadados do Drive. */
    public const AUTH_SCOPES = 'openid email ' . GoogleOAuthToken::SCOPES;

    public static function expectedEmail(): string
    {
        return mb_strtolower((string) Settings::get('sheets.technical_account_email', 'celef@scseduca.com.br'));
    }

    /** Parâmetros extras do pedido de autorização (usados por Auth::beginGoogleFlow). @return array<string,mixed> */
    public static function authParams(): array
    {
        return [
            'client_id'   => GoogleOidc::techClientId(),
            'scope'       => self::AUTH_SCOPES,
            'access_type' => 'offline',                    // devolve refresh token
            'prompt'      => 'consent select_account',     // força a tela de consentimento (garante o refresh token)
            'login_hint'  => self::expectedEmail(),
        ];
    }

    /**
     * Conclui a conexão. Retorna null em caso de sucesso ou a mensagem de erro para o admin.
     * @param array<string,mixed> $claims  ID Token já verificado  @param array<string,mixed> $tokens resposta do token endpoint
     */
    public static function completeConnect(array $claims, array $tokens, array $actor): ?string
    {
        $email = mb_strtolower(trim((string) ($claims['email'] ?? '')));
        $expected = self::expectedEmail();
        if ($email !== $expected) {
            AuditLog::log('ADMIN', 'google_credentials', null, "Tentativa de conectar a conta técnica com a conta errada ({$email})");
            return "Você autorizou com a conta {$email}. A conta técnica configurada é {$expected}: repita e escolha essa conta na tela do Google.";
        }
        if (empty($tokens['refresh_token']) || !is_string($tokens['refresh_token'])) {
            return 'O Google não devolveu o token de renovação. Em myaccount.google.com → Segurança → Apps de terceiros, remova o acesso do "Sistema CELEF" para a conta técnica e conecte de novo.';
        }
        $granted = (string) ($tokens['scope'] ?? '');
        foreach (explode(' ', GoogleOAuthToken::SCOPES) as $needed) {
            if (!str_contains($granted, $needed)) {
                return 'A autorização não incluiu todas as permissões (planilhas e metadados do Drive). Repita e marque todas as caixas na tela do Google.';
            }
        }
        $id = GoogleOAuthToken::store('OAUTH_USER_ACCOUNT', $email, $tokens['refresh_token'], $granted, (int) $actor['id']);
        AuditLog::log('ADMIN', 'google_credentials', $id, "Conectou a conta técnica Google {$email}");
        SecurityEvents::record('ACAO_ADMIN', SecurityEvents::INFO, "{$actor['email']} conectou a conta técnica Google {$email} em " . date('d/m/Y H:i'),
            ['conta' => $email], 'google_credentials', $id, true, [(string) $actor['email']]);
        return null;
    }

    /**
     * Teste rápido: renova o token e lê os metadados de uma planilha (se informada) ou só valida o token.
     * @return array{ok:bool,mensagem:string}
     */
    public static function test(?string $spreadsheetId = null): array
    {
        try {
            GoogleOAuthToken::accessToken(true);
            if ($spreadsheetId !== null) {
                $meta = SheetsClient::metadata($spreadsheetId);
                $msg = "Token válido. Planilha \"{$meta['title']}\" acessível, " . count($meta['tabs']) . ' aba(s).';
            } else {
                $msg = 'Token renovado com sucesso: a conta técnica está autorizada.';
            }
            $cred = GoogleOAuthToken::activeCredential();
            Database::run('UPDATE google_credentials SET last_test_at = NOW(3), last_error = NULL WHERE id = :id', ['id' => (int) $cred['id']]);
            return ['ok' => true, 'mensagem' => $msg];
        } catch (GoogleApiException $e) {
            return ['ok' => false, 'mensagem' => $e->friendly(self::expectedEmail())];
        }
    }
}
