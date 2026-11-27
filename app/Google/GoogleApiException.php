<?php
// app/Google/GoogleApiException.php — erro de chamada às APIs do Google, com status HTTP e motivo
declare(strict_types=1);

namespace App\Google;

final class GoogleApiException extends \RuntimeException
{
    public function __construct(string $message, public readonly int $status = 0, public readonly string $reason = '', public readonly bool $retryable = false)
    {
        parent::__construct($message, $status);
    }

    public function isPermission(): bool { return in_array($this->status, [403, 404], true); }
    public function isAuth(): bool { return $this->status === 401 || $this->reason === 'invalid_grant'; }
    public function isQuota(): bool { return $this->status === 429 || in_array($this->reason, ['RESOURCE_EXHAUSTED', 'rateLimitExceeded', 'userRateLimitExceeded'], true); }

    /** Mensagem amigável em pt-BR para a tela do admin. */
    public function friendly(string $techEmail = 'a conta técnica'): string
    {
        return match (true) {
            $this->status === 404 => "Planilha não encontrada ou não compartilhada. Confira o ID e compartilhe a planilha com {$techEmail}.",
            $this->status === 403 => "Sem permissão. Compartilhe esta planilha com {$techEmail} (Leitor para a fonte da Secretaria; Editor para as planilhas da escola e de logs) e confira se as APIs Google Sheets e Google Drive estão ativadas no projeto do Google Cloud.",
            $this->isAuth()       => 'A autorização da conta técnica não é mais válida (senha trocada ou acesso revogado). Reconecte em Admin → Conta técnica Google.',
            $this->isQuota()      => 'Limite de uso da API do Google atingido. O sistema tentará de novo automaticamente em instantes.',
            $this->status >= 500  => 'O Google respondeu com erro temporário. Tente novamente em instantes.',
            default               => 'Falha ao falar com o Google: ' . $this->getMessage(),
        };
    }
}
