<?php
// app/Http/AuthenticatedController.php — base das telas que exigem login (e ciência do aviso de privacidade)
declare(strict_types=1);

namespace App\Http;

use App\Auth\Auth;
use App\Auth\Rbac;
use App\Security\SecureSession;
use App\Settings;

abstract class AuthenticatedController extends Controller
{
    /** @var array<string,mixed> */
    protected array $user;

    public function __construct(Request $request)
    {
        parent::__construct($request);
        $this->user = Auth::requireLogin($request->path);
        // primeiro acesso: registrar ciência do aviso de privacidade antes de qualquer tela
        $version = (string) Settings::get('privacy.notice_version', '1.0');
        if (($this->user['privacy_version'] ?? null) !== $version && !in_array($request->path, ['/privacidade/aceite', '/logout'], true)) {
            SecureSession::set('intended', Auth::safePath($request->path));
            Response::redirect('/privacidade/aceite');
        }
    }

    /** @param array<string,mixed> $data */
    protected function render(string $view, array $data = [], ?string $layout = 'layout/base', int $status = 200): never
    {
        $data += [
            'usuario' => $this->user,
            'can'     => static fn(string $code): bool => Rbac::can($code),
            'isAdmin' => Auth::isAdmin(),
        ];
        parent::render($view, $data, $layout, $status);
    }

    protected function can(string $code): bool
    {
        return Rbac::can($code, $this->user);
    }
}
