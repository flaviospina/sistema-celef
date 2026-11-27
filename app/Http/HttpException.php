<?php
// app/Http/HttpException.php — erro HTTP com título amigável (lançado pelos controllers)
declare(strict_types=1);

namespace App\Http;

final class HttpException extends \RuntimeException
{
    public function __construct(public readonly int $status, public readonly string $title, string $message)
    {
        parent::__construct($message, $status);
    }

    public static function notFound(string $message = 'O registro solicitado não existe ou foi removido.'): self
    {
        return new self(404, 'Não encontrado', $message);
    }

    public static function forbidden(string $message = 'Você não tem permissão para esta ação.'): self
    {
        return new self(403, 'Acesso negado', $message);
    }

    public static function unauthorized(string $message = 'Faça login para continuar.'): self
    {
        return new self(401, 'Login necessário', $message);
    }
}
