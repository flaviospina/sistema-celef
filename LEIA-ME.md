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

## 3. Próximas fases

Fase 2 (núcleo de segurança), 3 (login Google + admin), 4 (cliente Google), 5 (sincronização), 6–10 (módulos),
11 (testes de segurança). Cada fase acrescenta aqui a sua seção "Como publicar".
