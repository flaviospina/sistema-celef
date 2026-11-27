<?php
// app/controllers/AuthController.php — login/logout com Google, reautenticação, aviso de privacidade, minhas sessões
declare(strict_types=1);

namespace App\controllers;

use App\Auth\Auth;
use App\Auth\GoogleOidc;
use App\Database;
use App\Http\Controller;
use App\Http\HttpException;
use App\Security\AuditLog;
use App\Security\RateLimiter;
use App\Security\RequestContext;
use App\Security\SecureSession;
use App\Settings;

final class AuthController extends Controller
{
    /** GET /login */
    public function login(): never
    {
        if (Auth::check()) {
            $this->redirect('/');
        }
        $this->render('auth/login', [
            'titulo' => 'Entrar', 'dominio' => GoogleOidc::hostedDomain(), 'configurado' => GoogleOidc::isConfigured(),
            'motivoSaida' => self::expiredReasonLabel(SecureSession::get('_expired_reason')),
        ], 'layout/login');
    }

    private static function expiredReasonLabel(mixed $reason): ?string
    {
        SecureSession::forget('_expired_reason');
        return match ($reason) {
            'REVOGADA'  => 'sessão encerrada por você em outro navegador ou por um administrador',
            'ABSOLUTA'  => 'tempo máximo de sessão atingido',
            'INATIVO'   => 'sua conta foi desativada',
            'TROCA_UA'  => 'navegador diferente do usado no login',
            'TROCA_IP'  => 'endereço de rede diferente do usado no login',
            'INATIVIDADE' => 'inatividade',
            null, ''    => null,
            default     => is_string($reason) ? strtolower($reason) : null,
        };
    }

    /** POST /login/google → redireciona para o Google */
    public function startGoogle(): never
    {
        if (Auth::check()) {
            $this->redirect('/');
        }
        if (!GoogleOidc::isConfigured()) {
            throw new HttpException(503, 'Login indisponível', 'O login com Google ainda não foi configurado (GOOGLE_CLIENT_ID/SECRET no .env).');
        }
        if (!RateLimiter::hit('ip:' . RequestContext::ip() . ':login', 15, 300, 600)['allowed']) {
            throw new HttpException(429, 'Muitas tentativas', 'Aguarde 10 minutos antes de tentar entrar novamente.');
        }
        $intended = SecureSession::get('intended');
        header('Location: ' . Auth::beginGoogleFlow('LOGIN', is_string($intended) ? $intended : null), true, 303);
        exit;
    }

    /** GET /auth/google/callback */
    public function callback(): never
    {
        if (!RateLimiter::hit('ip:' . RequestContext::ip() . ':callback', 30, 300)['allowed']) {
            throw new HttpException(429, 'Muitas tentativas', 'Aguarde alguns minutos.');
        }
        $to = Auth::completeGoogleFlow($this->request->query('code'), $this->request->query('state'), $this->request->query('error'));
        $this->redirect($to);
    }

    /** POST /logout */
    public function logout(): never
    {
        Auth::logout('LOGOUT');
        SecureSession::flash('success', 'Você saiu do sistema.');
        $this->redirect('/login');
    }

    /** GET /reauth → página explicativa; POST /reauth → vai ao Google com prompt=login */
    public function reauthPage(): never
    {
        Auth::requireLogin('/');
        $this->render('auth/reauth', ['titulo' => 'Confirmar identidade', 'retorno' => SecureSession::get('reauth_return', '/')], 'layout/login');
    }

    public function reauthStart(): never
    {
        Auth::requireLogin('/');
        header('Location: ' . Auth::beginGoogleFlow('REAUTH'), true, 303);
        exit;
    }

    /** GET /privacidade/aceite e POST /privacidade/aceite */
    public function privacyPage(): never
    {
        $u = Auth::requireLogin('/');
        $this->render('auth/privacidade-aceite', [
            'titulo' => 'Aviso de privacidade', 'usuario' => $u,
            'texto' => (string) Settings::get('privacy.notice_text', ''), 'versao' => (string) Settings::get('privacy.notice_version', '1.0'),
        ], 'layout/login');
    }

    public function privacyAccept(): never
    {
        $u = Auth::requireLogin('/');
        if ($this->request->input('ciente') !== '1') {
            SecureSession::flash('warning', 'É necessário marcar a caixa de ciência para continuar.');
            $this->redirect('/privacidade/aceite');
        }
        $version = (string) Settings::get('privacy.notice_version', '1.0');
        Database::insert('privacy_acknowledgements', ['user_id' => (int) $u['id'], 'version' => $version, 'ip' => RequestContext::ip(), 'user_agent' => RequestContext::userAgent()]);
        Database::run('UPDATE users SET privacy_accepted_at = NOW(3), privacy_version = :v, updated_by = :id WHERE id = :id2', ['v' => $version, 'id' => (int) $u['id'], 'id2' => (int) $u['id']]);
        AuditLog::log('ADMIN', 'users', (int) $u['id'], "Registrou ciência do aviso de privacidade v{$version}");
        $to = SecureSession::get('intended', '/');
        SecureSession::forget('intended');
        $this->redirect(is_string($to) ? $to : '/');
    }

    /** GET /minhas-sessoes */
    public function sessions(): never
    {
        $u = Auth::requireLogin('/minhas-sessoes');
        $rows = Database::rows('SELECT id, created_at, last_seen_at, ip, user_agent, revoked_at, revoke_reason FROM user_sessions WHERE user_id = :u ORDER BY created_at DESC LIMIT 30', ['u' => (int) $u['id']]);
        $this->render('auth/sessoes', ['titulo' => 'Minhas sessões', 'sessoes' => $rows, 'atual' => $u['session_hash'], 'usuario' => $u, 'can' => static fn(string $c) => \App\Auth\Rbac::can($c), 'isAdmin' => Auth::isAdmin()]);
    }

    /** POST /minhas-sessoes/encerrar-outras */
    public function revokeOthers(): never
    {
        Auth::requireLogin('/minhas-sessoes');
        $n = Auth::revokeOthers();
        SecureSession::flash('success', $n === 0 ? 'Não havia outras sessões ativas.' : "{$n} sessão(ões) encerrada(s).");
        $this->redirect('/minhas-sessoes');
    }
}
