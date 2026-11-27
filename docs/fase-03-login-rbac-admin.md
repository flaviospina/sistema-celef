# Fase 3 — Login Google, RBAC e área administrativa

Entregue em 27/11/2026. Testada ponta a ponta com um emulador local do OpenID Connect do Google
(`tools/mock_google.php`: discovery, autorização, token com PKCE e JWKS com chave RSA real) e o roteiro
`tools/test_phase3.php` (55 verificações), sempre com o usuário MySQL restrito.

## Fluxo de login

1. `GET /login` → formulário com CSRF → `POST /login/google`.
2. `Auth::beginGoogleFlow`: `state`, `nonce`, `code_verifier` gerados; `oauth_states` recebe os hashes e o verifier cifrado;
   o hash do `state` também vai para a sessão PHP (o navegador que começou é o único que conclui).
3. Google → `GET /auth/google/callback?code&state`: state conferido com a sessão e com o banco (uso único, 10 min),
   troca do código com `code_verifier`, ID Token verificado (assinatura RS256 via JWKS, `iss`, `aud`, `azp`, `exp`, `iat`, `nonce`).
4. Regras do Workspace: `hd == scseduca.com.br`, `email_verified`, e-mail do domínio. Depois: padrões bloqueados,
   allowlist (`users`), ativo, `google_sub` igual ao registrado.
5. Sessão regenerada, `user_sessions` criada (IP, hash do navegador, expiração absoluta, `auth_time`), auditoria `LOGIN`.

## Verificações aprovadas

| Área | Verificado |
|---|---|
| OIDC | pedido com PKCE S256, `hd`, `nonce`, `state`; callback com state desconhecido → 403; token com assinatura adulterada → 403; e-mail não verificado → 403; conta Gmail e `hd` forjado → 403; mesmo e-mail com outro `sub` → 403 + evento crítico |
| Allowlist | não cadastrado, conta genérica (`celef@`), desativado → 403, `login_attempts` e `LOGIN_NEGADO` |
| Primeiro acesso | aceite do aviso de privacidade obrigatório, gravado em `privacy_acknowledgements` |
| Admin | cadastro (e-mail normalizado), validações 422, conta genérica recusada, autoedição de perfil ignorada, exclusão lógica com motivo, restauração, promoção a ADMIN, bloqueio do último Super Admin, matriz de permissões, configurações (faixa validada), padrões bloqueados, busca na auditoria, verificação manual da cadeia, painel de segurança |
| Sessões | duas sessões do mesmo usuário; "encerrar as outras" derruba a primeira; mudança de navegador derruba a sessão e gera evento |
| RBAC | professor não vê Admin, 403 em `/admin` e `/admin/auditoria`; escopo de turmas vazio → `1 = 0`; super admin sem restrição |
| Reautenticação | admin com login antigo vai a `/reauth`, Google chamado com `prompt=login` e `max_age=0`, retorno ao destino, auditoria `REAUTH`; logout revoga a sessão |

## Decisões

- **Validação do ID Token no servidor, sem biblioteca.** JWK → PEM montado em DER à mão; `openssl_verify` com SHA-256.
  JWKS em cache 6 h com nova busca automática quando o `kid` não é encontrado (rotação de chaves do Google).
- **Sessão no banco é a fonte da verdade.** A cada requisição a sessão PHP é confrontada com `user_sessions`:
  revogada, expirada, usuário inativo, navegador ou IP diferente → encerra, com motivo mostrado na tela de login.
- **Escopo no SQL.** `Rbac::classScopeSql('e.class_id')` devolve o fragmento `AND ... IN (...)` (ou `AND 1 = 0`)
  para as consultas das fases 6 a 8; nunca filtrar só na tela.
- **Nomes de campo com ponto** (`diary.edit_days`) chegam ao PHP com sublinhado; o controller de configurações
  faz a conversão.
