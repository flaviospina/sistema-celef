# Sistema de Gestão Escolar CELEF — LEIA-ME

Sistema web do **CELEF – Centro de Estudos de Línguas do Ensino Fundamental** (SME São Caetano do Sul): única
porta de entrada para alunos, turmas, diários, remanejamentos e desistências, com login individual Google
(@scseduca.com.br), auditoria imutável e sincronização com as planilhas Google da escola.

> Este LEIA-ME cresce a cada fase. **Fase 1 (banco de dados)** está descrita abaixo. As seções de código PHP,
> login Google, conta técnica, planilhas e cron serão acrescentadas nas fases seguintes.

---

## 1. Requisitos (HostGator plano Turbo)

| Item | Valor |
|---|---|
| PHP | 8.2 (cPanel → MultiPHP Manager), extensões `pdo_mysql`, `openssl`, `curl`, `sodium`, `mbstring`, `fileinfo`, `gd` |
| Banco | MySQL 8.0.16+ **ou** MariaDB 10.6+ (o padrão da HostGator atende; verificar em phpMyAdmin → "Servidor de banco de dados") |
| SSL | AutoSSL ativo no domínio do CELEF |
| Domínio | domínio próprio do CELEF (addon domain), **não** `public_html` |

---

## 2. Fase 1 — Banco de dados

### 2.1 Arquivos

| Arquivo | Para quê | Como usar |
|---|---|---|
| `sql/schema.sql` | 49 tabelas + 23 tabelas `*_history` | importar no phpMyAdmin (1º) |
| `sql/triggers.sql` | 150 triggers: cadeia de hash, imutabilidade, versionamento, validação de exclusão lógica | importar no phpMyAdmin (2º) |
| `sql/seed.sql` | perfis, permissões, configurações, padrões bloqueados, anos letivos, modelos, Super Admin | importar no phpMyAdmin (3º) |
| `sql/grants.sql` | **não importar**: roteiro dos usuários MySQL no cPanel + consultas de conferência | ler e seguir |

Os três arquivos importáveis são **idempotentes**: importar de novo não duplica nem apaga nada.

### 2.2 Passo a passo no cPanel

1. **MySQL® Databases → Criar novo banco:** `celef` (vira `<prefixo>_celef`).
2. **Adicionar novo usuário** duas vezes, com senhas geradas pelo botão do cPanel:
   - `celef_app` → senha vai para o `.env` (Fase 2).
   - `celef_inst` → senha fica só com você (gerenciador de senhas).
3. **Adicionar usuário ao banco:**
   - `celef_app` → marcar **somente** `SELECT`, `INSERT`, `UPDATE`, `EXECUTE`.
   - `celef_inst` → **Todos os privilégios**.
4. **Remote MySQL®:** não liberar nenhum host.
5. **phpMyAdmin → banco `<prefixo>_celef` → Importar**, nesta ordem: `schema.sql`, `triggers.sql`, `seed.sql`.
   Ao final do `seed.sql` aparece uma linha de conferência (6 perfis, 55 permissões, 1 usuário, hash de gênese).
6. **Conferir** com as consultas da seção C de `sql/grants.sql`. A consulta C6 **deve falhar** com a
   mensagem do trigger: é a prova de que a auditoria está protegida.

### 2.3 O que o banco já garante sozinho (antes de existir código PHP)

- **Nada é apagado:** `DELETE` falha em toda tabela de negócio e de histórico, para qualquer usuário.
- **Exclusão lógica exige motivo** (≥ 10 caracteres) e responsável.
- **Cada alteração gera uma versão anterior** em `*_history`, com quem, quando e origem.
- **Alteração fora da aplicação** (ex.: phpMyAdmin sem o contexto `@app_origin`) é aceita, mas marcada
  `FORA_DA_APLICACAO` e registrada em `security_events` para alerta.
- **Auditoria encadeada por hash** calculado pelo próprio banco; `UPDATE`/`DELETE` em `audit_log` falham.
- **Um aluno ativo por ano letivo**, **nº único por turma**, **uma conta técnica ativa**, **último Super Admin
  não pode ser removido**, **e-mail só @scseduca.com.br** — tudo por índice, `CHECK` ou trigger.

### 2.4 Versão do banco na HostGator

Em phpMyAdmin, no painel direito, veja "Versão do servidor". Aceitos: MySQL ≥ 8.0.16 ou MariaDB ≥ 10.6.
Se for MySQL 5.7 ou MariaDB < 10.2, as cláusulas `CHECK` são ignoradas silenciosamente (a app valida de
qualquer forma), mas peça à HostGator a migração do banco para a versão atual antes de ir para produção.

---

## 3. Fase 2 — Núcleo de segurança (código PHP)

### 3.1 O que foi entregue

| Pasta/arquivo | Conteúdo |
|---|---|
| `public/index.php`, `public/.htaccess` | front controller (constante `APP_ROOT`), HTTPS forçado, cabeçalhos, bloqueio de arquivos sensíveis |
| `public/assets/` | Bootstrap 5.3.3 local (`vendor/`), `css/app.css` (paleta provisória em variáveis CSS), `js/app.js`, pasta `img/marca/` com os nomes esperados |
| `app/config.php` | leitura do `.env` sem biblioteca (`App\Config`) |
| `app/bootstrap.php` | autoload, fuso, tratamento de erros, verificação de extensões |
| `app/Database.php` | PDO (prepared statements nativos, uma instrução por execução), **`@app_user_id`/`@app_origin` em toda conexão**, `updateVersioned` (lock otimista), `GET_LOCK` |
| `app/Settings.php` | leitura/gravação da tabela `settings` |
| `app/Security/Crypto.php` | XChaCha20-Poly1305 por campo com versão de chave e contexto autenticado; blind index HMAC; cifragem de arquivos em blocos |
| `app/Security/AuditLog.php` | gravação encadeada (`GET_LOCK('celef_audit')`), diff mascarado em JSON canônico, fila para a planilha de logs, `verifyChain`, sonda dos triggers, âncora diária |
| `app/Security/SecurityEvents.php` | eventos de segurança + fila `alert_outbox` com destinatários (admins ativos + `SUPER_ADMIN_EMAILS`) |
| `app/Security/Csrf.php`, `Headers.php`, `RateLimiter.php`, `SecureSession.php`, `Validator.php`, `Masker.php`, `Logger.php`, `RequestContext.php` | CSRF + verificação de Origin; CSP com nonce e demais cabeçalhos; limite por chave na tabela `rate_limits`; sessão `__Host-` Strict com expirações; validação (CPF etc.); mascaramento; log JSON diário; IP/UA/request_id |
| `app/Http/*` | Request, Response (`{ok,data,mensagem}`), Router, Kernel, View (escape + nonce), Controller base |
| `app/controllers/SystemController.php` | `/` (página provisória), `/status`, `/instalacao`, `/privacidade` |
| `cron/_bootstrap.php`, `cron/verify_audit.php`, `app/Cron/JobRunner.php` | scripts de cron (recusam web), lock anti-sobreposição, registro em `cron_runs` |
| `.env.example` | todas as variáveis, comentadas |

### 3.2 Publicar no HostGator (passo a passo)

1. **Document root do domínio.** cPanel → Domínios → (domínio do CELEF) → *Document Root* =
   `/home/<usuario>/<dominio-do-celef>/public`. Se o cPanel não permitir alterar, use o **plano B**: deixe o document
   root na pasta do domínio, coloque nela só o conteúdo de `public/`, mova `app/ sql/ cron/ storage/ .env` para
   `/home/<usuario>/<dominio-do-celef>_privado/` e, em `index.php`, troque a linha
   `define('APP_ROOT', dirname(__DIR__));` por `define('APP_ROOT', '/home/<usuario>/<dominio-do-celef>_privado');`.
2. **Upload.** Gerenciador de Arquivos → enviar o `.zip` do projeto para `/home/<usuario>/<dominio-do-celef>/` → Extrair.
   Conferir que existem `public/`, `app/`, `sql/`, `cron/`, `storage/`, `.env.example`.
3. **Permissões.** `storage/` e subpastas (`logs`, `uploads`, `sessions`, `cache`, `tmp`): 750. Depois de criar o
   `.env`: 600 (botão direito → Alterar permissões).
4. **MultiPHP Manager:** PHP 8.2 para o domínio. **MultiPHP INI Editor** (modo editor, para o domínio):
   `display_errors=Off`, `expose_php=Off`, `session.cookie_secure=1`, `session.use_strict_mode=1`,
   `allow_url_include=Off`, `allow_url_fopen=Off`, `memory_limit=256M`, `upload_max_filesize=10M`, `post_max_size=12M`.
5. **`.env`.** Copiar `.env.example` → `.env` (mesma pasta) e preencher `BASE_URL`, `DB_*` (usuário **celef_app**),
   `SUPER_ADMIN_EMAILS`. Deixe `APP_KEY_V1` e `BLIND_INDEX_KEY` vazios por enquanto.
6. **Chaves.** Abrir `https://<dominio>/instalacao`: a página gera `APP_KEY_V1`, `BLIND_INDEX_KEY` e `STATUS_TOKEN`.
   Copiar as linhas para o `.env`, salvar, **guardar uma cópia das chaves fora do servidor** (sem elas os dados cifrados
   e os backups são irrecuperáveis). Recarregar `/instalacao`: deve responder "Não encontrado".
7. **Conferir.** `https://<dominio>/status?token=<STATUS_TOKEN>` deve mostrar tudo **OK**, inclusive
   "Triggers de proteção (sonda funcional)" e "Privilégios do usuário da app: mínimos". Sem o token, `/status`
   responde só OK/erro.
8. **Cron.** cPanel → Cron Jobs → uma vez por dia (ex.: `20 0 * * *`):
   ```
   /usr/local/bin/php /home/<usuario>/<dominio-do-celef>/cron/verify_audit.php >> /home/<usuario>/<dominio-do-celef>/storage/logs/cron.log 2>&1
   ```
   Confirme o caminho do PHP 8.2 em cPanel → MultiPHP Manager (geralmente `/usr/local/bin/php` ou `/opt/cpanel/ea-php82/root/usr/bin/php`).
   Os demais crons (sincronização, planilha de logs, alertas, backup) entram nas fases 4, 5 e 10.

### 3.3 Decisões que valem registro

- **Fail-closed:** sem banco ou sem auditoria, a requisição falha (500/erro genérico) em vez de seguir sem registro.
  POST sem token CSRF → 419. Token válido mas `Origin`/`Referer` de outro site → negado.
- **Sonda funcional dos triggers.** O usuário da app não enxerga `information_schema.triggers` (exige privilégio
  TRIGGER). Por isso `/status` e o cron testam o comportamento: tentam um UPDATE em `audit_log` (deve falhar com
  45000), um INSERT (deve sair com hash encadeado) e um UPDATE neutro em `users`/`students` (deve versionar), tudo
  dentro de uma transação desfeita em seguida.
- **Sessões em `storage/sessions`**, não no `/tmp` compartilhado da hospedagem.
- **IP = `REMOTE_ADDR`** apenas: na HostGator não há proxy confiável; `X-Forwarded-For` é forjável.
- **Contexto autenticado na cifra:** o campo é cifrado com o nome `tabela.coluna` como dado adicional. Um blob
  copiado de `students.cpf` para `students.rg` não decifra.
- **E-mails de alerta** são enfileirados em `alert_outbox` desde já; o envio (SMTP da conta do domínio) chega na Fase 10.

---

## 4. Próximas fases

Fase 3 (login Google + admin), 4 (cliente Google), 5 (sincronização), 6–10 (módulos),
11 (testes de segurança). Cada fase acrescenta aqui a sua seção "Como publicar".
