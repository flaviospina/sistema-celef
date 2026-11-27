<?php
// app/controllers/Admin/TechAccountController.php — Admin → Conta técnica Google (conectar, testar, revogar, Service Account)
declare(strict_types=1);

namespace App\controllers\Admin;

use App\Auth\Auth;
use App\Auth\GoogleOidc;
use App\Auth\Rbac;
use App\Database;
use App\Google\GoogleJwt;
use App\Google\GoogleOAuthToken;
use App\Google\TechAccount;
use App\Http\HttpException;
use App\Http\Request;
use App\Security\RateLimiter;
use App\Security\SecureSession;
use App\Security\Validator;

final class TechAccountController extends AdminController
{
    public function __construct(Request $request)
    {
        parent::__construct($request);
        Rbac::require('admin.conta_tecnica');
        $this->requireSuperAdmin();
    }

    public function index(): never
    {
        $cred = GoogleOAuthToken::activeCredential();
        $history = Database::rows('SELECT c.id, c.kind, c.account_email, c.status, c.is_active, c.connected_at, c.revoked_at, c.last_refresh_at, c.last_test_at, c.last_error, u.email AS connected_by_email
                                   FROM google_credentials c LEFT JOIN users u ON u.id = c.connected_by ORDER BY c.id DESC LIMIT 10');
        $this->render('admin/conta-tecnica', [
            'titulo' => 'Conta técnica Google', 'secaoAdmin' => 'conta_tecnica', 'credencial' => $cred, 'historico' => $history,
            'emailEsperado' => TechAccount::expectedEmail(), 'loginConfigurado' => GoogleOidc::isConfigured(),
            'redirectUri' => GoogleOidc::redirectUri(), 'escopos' => explode(' ', GoogleOAuthToken::SCOPES),
        ]);
    }

    /** POST /admin/conta-tecnica/conectar → Google (consentimento da conta celef@) */
    public function connect(): never
    {
        if (!GoogleOidc::isConfigured()) {
            throw new HttpException(503, 'Indisponível', 'Configure GOOGLE_CLIENT_ID e GOOGLE_CLIENT_SECRET no .env.');
        }
        if (!RateLimiter::hit('user:' . $this->user['id'] . ':conta_tecnica', 10, 600)['allowed']) {
            throw new HttpException(429, 'Muitas tentativas', 'Aguarde alguns minutos.');
        }
        \App\Security\AuditLog::log('ADMIN', 'google_credentials', null, 'Iniciou a conexão da conta técnica Google');
        header('Location: ' . Auth::beginGoogleFlow('TECH_ACCOUNT', '/admin/conta-tecnica'), true, 303);
        exit;
    }

    /** POST /admin/conta-tecnica/testar */
    public function test(): never
    {
        $r = TechAccount::test();
        \App\Security\AuditLog::log('ADMIN', 'google_credentials', null, 'Testou a conta técnica: ' . ($r['ok'] ? 'ok' : 'falhou'));
        SecureSession::flash($r['ok'] ? 'success' : 'danger', $r['mensagem']);
        $this->redirect('/admin/conta-tecnica');
    }

    /** POST /admin/conta-tecnica/revogar */
    public function revoke(): never
    {
        $v = new Validator($this->request->all());
        $v->minReason('motivo');
        if ($v->fails()) {
            SecureSession::flash('danger', $v->errors()['motivo']);
            $this->redirect('/admin/conta-tecnica');
        }
        $cred = GoogleOAuthToken::activeCredential();
        if ($cred !== null) {
            GoogleOAuthToken::revoke((int) $this->user['id']);
            $reason = trim((string) $this->request->input('motivo'));
            $this->adminAction("revogou a conta técnica Google {$cred['account_email']} (motivo: {$reason})", 'google_credentials', (int) $cred['id']);
        }
        SecureSession::flash('success', 'Conta técnica revogada. Sincronização e planilha de logs ficam em espera até uma nova conexão.');
        $this->redirect('/admin/conta-tecnica');
    }

    /**
     * POST /admin/conta-tecnica/service-account — alternativa à conta celef@.
     * O navegador lê o arquivo JSON e envia só client_email e a chave privada em base64 (o JSON original contém URLs,
     * que o firewall da hospedagem bloquearia).
     */
    public function storeServiceAccount(): never
    {
        $email = mb_strtolower(trim((string) $this->request->input('sa_email')));
        $key = base64_decode((string) $this->request->input('sa_key_b64'), true);
        $error = $key === false ? 'Arquivo da Service Account ilegível.' : GoogleJwt::validate($email, $key);
        if ($error !== null) {
            SecureSession::flash('danger', $error);
            $this->redirect('/admin/conta-tecnica');
        }
        $json = json_encode(['client_email' => $email, 'private_key' => $key], JSON_THROW_ON_ERROR);
        $id = GoogleOAuthToken::store('SERVICE_ACCOUNT', $email, $json, GoogleOAuthToken::SCOPES, (int) $this->user['id']);
        sodium_memzero($json);
        $this->adminAction("configurou a Service Account {$email} como conta técnica", 'google_credentials', $id);
        $r = TechAccount::test();
        SecureSession::flash($r['ok'] ? 'success' : 'warning', 'Service Account gravada (chave cifrada). ' . $r['mensagem']);
        $this->redirect('/admin/conta-tecnica');
    }
}
