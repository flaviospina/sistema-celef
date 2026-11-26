-- =====================================================================================================
-- sql/schema.sql
-- Sistema de Gestão Escolar CELEF — esquema do banco de dados (Fase 1)
--
-- Compatível com MySQL 8.0.16+ e MariaDB 10.6+.
-- Idempotente: pode ser importado mais de uma vez (CREATE TABLE IF NOT EXISTS).
-- Importar no phpMyAdmin com o usuário de INSTALAÇÃO (privilégios completos), nunca com o usuário da app.
--
-- Convenções (ver docs/fase-01-modelagem.md §2):
--   * utf8mb4 / utf8mb4_unicode_ci / InnoDB em todas as tabelas.
--   * `version`      incrementada pelo trigger BEFORE UPDATE (lock otimista e casamento com a planilha).
--   * `origin`       APP | CRON | SEED | PLANILHA:<nome> | CARGA_INICIAL_PLANILHA | FORA_DA_APLICACAO.
--   * Exclusão lógica: `deleted_at`, `deleted_by`, `delete_reason` (mínimo 10 caracteres, validado por trigger).
--   * Campos cifrados: `<campo>_enc` (XChaCha20-Poly1305, nonce de 24 bytes prefixado) + `key_version`.
--     Busca exata por blind index `<campo>_bidx` = HMAC-SHA256(chave separada, valor normalizado).
--   * Datas de negócio em horário de São Paulo; `audit_log.occurred_at` em UTC com microssegundos.
--   * Marcadores lidos pelo gerador de triggers (não remover):
--       -- @history      → a tabela ganha uma `<tabela>_history` e triggers de versionamento
--       -- @append-only  → triggers bloqueiam UPDATE e DELETE (SIGNAL 45000)
--       -- @no-delete    → trigger bloqueia DELETE (SIGNAL 45000)
--   * Colunas `*_by` referenciam `users.id`; só as relações principais têm FOREIGN KEY declarada,
--     para não multiplicar índices em tabelas grandes (usuários nunca são apagados fisicamente).
-- =====================================================================================================

SET NAMES utf8mb4;
SET time_zone = '-03:00';
SET FOREIGN_KEY_CHECKS = 0;

-- =====================================================================================================
-- 1. IDENTIDADE, ACESSO E SESSÃO
-- =====================================================================================================

-- @history
CREATE TABLE IF NOT EXISTS `roles` (
  `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `code`          VARCHAR(30) NOT NULL COMMENT 'SUPER_ADMIN | ADMIN | SECRETARIA | COORDENACAO | PROFESSOR | AUDITOR',
  `name`          VARCHAR(80) NOT NULL,
  `description`   VARCHAR(300) NULL,
  `is_system`     TINYINT(1) NOT NULL DEFAULT 1 COMMENT '1 = perfil fixo do sistema (não pode ser removido)',
  `version`       INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`        VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`    BIGINT UNSIGNED NULL,
  `updated_at`    DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`    BIGINT UNSIGNED NULL,
  `deleted_at`    DATETIME(3) NULL,
  `deleted_by`    BIGINT UNSIGNED NULL,
  `delete_reason` VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_roles_code` (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Perfis de acesso (RBAC)';

-- @no-delete
CREATE TABLE IF NOT EXISTS `permissions` (
  `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `code`          VARCHAR(60) NOT NULL COMMENT 'ex.: aluno.ver, aluno.editar, exportar',
  `module`        VARCHAR(40) NOT NULL COMMENT 'módulo funcional: aluno, turma, diario, admin...',
  `description`   VARCHAR(300) NOT NULL,
  `is_sensitive`  TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = exige reautenticação Google e motivo',
  `created_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_permissions_code` (`code`),
  KEY `ix_permissions_module` (`module`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Permissões granulares por ação';

-- @no-delete
CREATE TABLE IF NOT EXISTS `role_permissions` (
  `role_id`       INT UNSIGNED NOT NULL,
  `permission_id` INT UNSIGNED NOT NULL,
  `is_granted`    TINYINT(1) NOT NULL DEFAULT 1 COMMENT '0 = revogada (mantém histórico em vez de apagar a linha)',
  `created_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`    BIGINT UNSIGNED NULL,
  `updated_at`    DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`    BIGINT UNSIGNED NULL,
  PRIMARY KEY (`role_id`, `permission_id`),
  CONSTRAINT `fk_rp_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`),
  CONSTRAINT `fk_rp_permission` FOREIGN KEY (`permission_id`) REFERENCES `permissions` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Permissões concedidas a cada perfil';

-- @history
CREATE TABLE IF NOT EXISTS `users` (
  `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `email`               VARCHAR(190) NOT NULL COMMENT 'minúsculo; obrigatoriamente @scseduca.com.br (validado na app)',
  `google_sub`          VARCHAR(64) NULL COMMENT 'claim sub do ID Token; preenchido no primeiro login',
  `full_name`           VARCHAR(160) NOT NULL,
  `picture_url`         VARCHAR(500) NULL,
  `role_id`             INT UNSIGNED NOT NULL,
  `is_active`           TINYINT(1) NOT NULL DEFAULT 1,
  `privacy_accepted_at` DATETIME(3) NULL COMMENT 'ciência do aviso de privacidade (versão em privacy_version)',
  `privacy_version`     VARCHAR(20) NULL,
  `last_login_at`       DATETIME(3) NULL,
  `last_login_ip`       VARCHAR(45) NULL,
  `amr_last`            VARCHAR(120) NULL COMMENT 'claim amr do último login (ex.: pwd,mfa) quando disponível',
  `notes`               VARCHAR(500) NULL,
  `version`             INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`              VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`          BIGINT UNSIGNED NULL,
  `updated_at`          DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`          BIGINT UNSIGNED NULL,
  `deleted_at`          DATETIME(3) NULL,
  `deleted_by`          BIGINT UNSIGNED NULL,
  `delete_reason`       VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_users_email` (`email`),
  UNIQUE KEY `uk_users_google_sub` (`google_sub`),
  KEY `ix_users_role` (`role_id`),
  KEY `ix_users_active` (`is_active`, `deleted_at`),
  CONSTRAINT `fk_users_role` FOREIGN KEY (`role_id`) REFERENCES `roles` (`id`),
  CONSTRAINT `chk_users_email_domain` CHECK (`email` LIKE '%@scseduca.com.br')
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Pessoas físicas autorizadas a entrar (allowlist)';

-- @history
CREATE TABLE IF NOT EXISTS `user_class_assignments` (
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`         BIGINT UNSIGNED NOT NULL,
  `class_id`        BIGINT UNSIGNED NOT NULL,
  `assignment_type` VARCHAR(20) NOT NULL COMMENT 'PROFESSOR | COORDENACAO',
  `school_year`     SMALLINT UNSIGNED NOT NULL,
  `started_on`      DATE NULL,
  `ended_on`        DATE NULL COMMENT 'preenchido quando o vínculo termina (nunca se apaga a linha)',
  `version`         INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`          VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`      BIGINT UNSIGNED NULL,
  `updated_at`      DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`      BIGINT UNSIGNED NULL,
  `deleted_at`      DATETIME(3) NULL,
  `deleted_by`      BIGINT UNSIGNED NULL,
  `delete_reason`   VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_uca_user_class_type` (`user_id`, `class_id`, `assignment_type`),
  KEY `ix_uca_class` (`class_id`),
  CONSTRAINT `fk_uca_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`),
  CONSTRAINT `fk_uca_class` FOREIGN KEY (`class_id`) REFERENCES `classes` (`id`),
  CONSTRAINT `chk_uca_type` CHECK (`assignment_type` IN ('PROFESSOR', 'COORDENACAO'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Escopo de turmas por usuário (professor/coordenação)';

-- @no-delete
CREATE TABLE IF NOT EXISTS `user_sessions` (
  `id`                  CHAR(64) NOT NULL COMMENT 'SHA-256 do id de sessão PHP (o id real nunca é gravado)',
  `user_id`             BIGINT UNSIGNED NOT NULL,
  `created_at`          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `last_seen_at`        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `absolute_expires_at` DATETIME(3) NOT NULL COMMENT 'expiração absoluta (padrão 8 h)',
  `google_auth_time`    DATETIME NULL COMMENT 'claim auth_time do ID Token; base da reautenticação (max_age)',
  `last_reauth_at`      DATETIME(3) NULL,
  `ip`                  VARCHAR(45) NOT NULL,
  `user_agent_hash`     CHAR(64) NOT NULL,
  `user_agent`          VARCHAR(300) NULL,
  `revoked_at`          DATETIME(3) NULL,
  `revoked_by`          BIGINT UNSIGNED NULL,
  `revoke_reason`       VARCHAR(30) NULL COMMENT 'LOGOUT | INATIVIDADE | ABSOLUTA | ADMIN | TROCA_UA_IP | OUTRAS_SESSOES',
  PRIMARY KEY (`id`),
  KEY `ix_sessions_user` (`user_id`, `revoked_at`),
  KEY `ix_sessions_expires` (`absolute_expires_at`),
  CONSTRAINT `fk_sessions_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Sessões no servidor (encerramento remoto, expiração)';

CREATE TABLE IF NOT EXISTS `oauth_states` (
  `state_hash`        CHAR(64) NOT NULL COMMENT 'SHA-256 do parâmetro state',
  `nonce_hash`        CHAR(64) NOT NULL,
  `code_verifier_enc` VARBINARY(255) NOT NULL COMMENT 'PKCE code_verifier cifrado',
  `purpose`           VARCHAR(20) NOT NULL COMMENT 'LOGIN | REAUTH | TECH_ACCOUNT',
  `redirect_to`       VARCHAR(500) NULL COMMENT 'rota interna de retorno (validada contra lista)',
  `user_id`           BIGINT UNSIGNED NULL COMMENT 'preenchido em REAUTH / TECH_ACCOUNT',
  `ip`                VARCHAR(45) NOT NULL,
  `created_at`        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `expires_at`        DATETIME(3) NOT NULL,
  `used_at`           DATETIME(3) NULL,
  PRIMARY KEY (`state_hash`),
  KEY `ix_oauth_states_expires` (`expires_at`),
  CONSTRAINT `chk_oauth_purpose` CHECK (`purpose` IN ('LOGIN', 'REAUTH', 'TECH_ACCOUNT'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Estados OAuth (PKCE) de vida curta; limpos pelo cron (única tabela com limpeza física, sem dado pessoal)';

-- @append-only
CREATE TABLE IF NOT EXISTS `login_attempts` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `occurred_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `email`       VARCHAR(190) NULL,
  `google_sub`  VARCHAR(64) NULL,
  `ip`          VARCHAR(45) NOT NULL,
  `user_agent`  VARCHAR(300) NULL,
  `outcome`     VARCHAR(30) NOT NULL COMMENT 'OK | DOMINIO_INVALIDO | NAO_CADASTRADO | INATIVO | CONTA_GENERICA | TOKEN_INVALIDO | BLOQUEADO_RATE',
  `detail`      VARCHAR(300) NULL,
  PRIMARY KEY (`id`),
  KEY `ix_login_attempts_email` (`email`, `occurred_at`),
  KEY `ix_login_attempts_ip` (`ip`, `occurred_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Tentativas de login (rate limit e alertas)';

-- @history
CREATE TABLE IF NOT EXISTS `blocked_email_patterns` (
  `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `pattern`       VARCHAR(190) NOT NULL COMMENT 'padrão LIKE, ex.: celef@%  celef%2026@%',
  `description`   VARCHAR(300) NULL,
  `is_active`     TINYINT(1) NOT NULL DEFAULT 1,
  `version`       INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`        VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`    BIGINT UNSIGNED NULL,
  `updated_at`    DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`    BIGINT UNSIGNED NULL,
  `deleted_at`    DATETIME(3) NULL,
  `deleted_by`    BIGINT UNSIGNED NULL,
  `delete_reason` VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_bep_pattern` (`pattern`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Contas genéricas/compartilhadas proibidas de entrar';

-- @no-delete
CREATE TABLE IF NOT EXISTS `rate_limits` (
  `bucket_key`    VARCHAR(190) NOT NULL COMMENT 'ex.: login:ip:1.2.3.4 | user:15:ver_sensivel',
  `window_start`  DATETIME NOT NULL,
  `hit_count`     INT UNSIGNED NOT NULL DEFAULT 0,
  `blocked_until` DATETIME NULL,
  `updated_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) ON UPDATE CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`bucket_key`),
  KEY `ix_rate_limits_window` (`window_start`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Contadores de rate limit por janela';

-- @history
CREATE TABLE IF NOT EXISTS `settings` (
  `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `setting_key`   VARCHAR(100) NOT NULL,
  `value_json`    JSON NOT NULL COMMENT 'valor serializado em JSON (string, número, booleano, lista)',
  `value_type`    VARCHAR(10) NOT NULL DEFAULT 'string' COMMENT 'string | int | bool | list | json',
  `group_name`    VARCHAR(40) NOT NULL COMMENT 'sessao | sync | alertas | lgpd | diario | seguranca | privacidade | marca',
  `description`   VARCHAR(300) NULL,
  `is_sensitive`  TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = alteração exige reautenticação',
  `version`       INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`        VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`    BIGINT UNSIGNED NULL,
  `updated_at`    DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`    BIGINT UNSIGNED NULL,
  `deleted_at`    DATETIME(3) NULL,
  `deleted_by`    BIGINT UNSIGNED NULL,
  `delete_reason` VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_settings_key` (`setting_key`),
  KEY `ix_settings_group` (`group_name`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Configurações editáveis no admin';

-- @append-only
CREATE TABLE IF NOT EXISTS `privacy_acknowledgements` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`     BIGINT UNSIGNED NOT NULL,
  `version`     VARCHAR(20) NOT NULL COMMENT 'versão do aviso de privacidade aceito',
  `accepted_at` DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `ip`          VARCHAR(45) NOT NULL,
  `user_agent`  VARCHAR(300) NULL,
  PRIMARY KEY (`id`),
  KEY `ix_privacy_user` (`user_id`, `accepted_at`),
  CONSTRAINT `fk_privacy_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Registro de ciência do aviso de privacidade (LGPD)';

-- =====================================================================================================
-- 2. AUDITORIA E SEGURANÇA
-- =====================================================================================================

-- @append-only
CREATE TABLE IF NOT EXISTS `audit_log` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `occurred_at`   DATETIME(6) NOT NULL COMMENT 'UTC, microssegundos. Se vier NULL o trigger preenche com UTC_TIMESTAMP(6)',
  `user_id`       BIGINT UNSIGNED NULL COMMENT 'NULL = cron, sincronização ou origem externa',
  `user_email`    VARCHAR(190) NULL,
  `role_code`     VARCHAR(30) NULL,
  `action`        VARCHAR(40) NOT NULL COMMENT 'LOGIN, LOGIN_NEGADO, LOGOUT, REAUTH, VER, VER_SENSIVEL, CRIAR, EDITAR, EXCLUIR, RESTAURAR, EXPORTAR, IMPRIMIR, PERMISSAO, ADMIN, SYNC_IN, SYNC_OUT, SYNC_CONFLITO, ALTERACAO_EXTERNA_PLANILHA, SEGURANCA, INSTALACAO',
  `entity`        VARCHAR(60) NULL COMMENT 'tabela/entidade afetada (students, classes, settings...)',
  `entity_id`     BIGINT UNSIGNED NULL,
  `summary`       VARCHAR(300) NULL COMMENT 'resumo legível, sem dado sensível',
  `diff_json`     LONGTEXT NULL COMMENT 'JSON canônico (chaves ordenadas) com campos sensíveis mascarados. LONGTEXT e não JSON para o hash ser reproduzível',
  `ip`            VARCHAR(45) NULL,
  `user_agent`    VARCHAR(300) NULL,
  `request_id`    CHAR(32) NULL,
  `session_hash`  CHAR(64) NULL,
  `origin`        VARCHAR(60) NULL COMMENT 'preenchido pelo trigger a partir de @app_origin; NULL na sessão = FORA_DA_APLICACAO',
  `prev_hash`     CHAR(64) NOT NULL DEFAULT '' COMMENT 'hash da linha anterior; calculado pelo trigger',
  `hash`          CHAR(64) NOT NULL DEFAULT '' COMMENT 'SHA-256(prev_hash | conteúdo canônico); calculado pelo trigger',
  PRIMARY KEY (`id`),
  KEY `ix_audit_occurred` (`occurred_at`),
  KEY `ix_audit_user` (`user_id`, `occurred_at`),
  KEY `ix_audit_entity` (`entity`, `entity_id`),
  KEY `ix_audit_action` (`action`, `occurred_at`),
  KEY `ix_audit_request` (`request_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Trilha de auditoria imutável com cadeia de hash';

-- @append-only
CREATE TABLE IF NOT EXISTS `audit_anchor` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `anchor_date`   DATE NOT NULL COMMENT 'dia (São Paulo) a que a âncora se refere',
  `last_audit_id` BIGINT UNSIGNED NOT NULL,
  `last_hash`     CHAR(64) NOT NULL,
  `row_count`     BIGINT UNSIGNED NOT NULL COMMENT 'total de linhas de audit_log até last_audit_id',
  `created_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_anchor_date` (`anchor_date`),
  CONSTRAINT `fk_anchor_audit` FOREIGN KEY (`last_audit_id`) REFERENCES `audit_log` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Âncora diária da cadeia de hash (enviada por e-mail e para a planilha de logs)';

-- @append-only allow: finished_at, rows_checked, result, first_broken_id, triggers_ok, detail
CREATE TABLE IF NOT EXISTS `audit_verification_runs` (
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `started_at`      DATETIME(3) NOT NULL,
  `finished_at`     DATETIME(3) NULL,
  `from_id`         BIGINT UNSIGNED NOT NULL,
  `to_id`           BIGINT UNSIGNED NOT NULL,
  `rows_checked`    BIGINT UNSIGNED NOT NULL DEFAULT 0,
  `result`          VARCHAR(10) NOT NULL COMMENT 'OK | QUEBRA | ERRO',
  `first_broken_id` BIGINT UNSIGNED NULL,
  `triggers_ok`     TINYINT(1) NOT NULL DEFAULT 1 COMMENT '0 = algum trigger de proteção não existe mais',
  `detail`          VARCHAR(1000) NULL,
  PRIMARY KEY (`id`),
  KEY `ix_avr_started` (`started_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Resultados do cron/verify_audit.php';

-- @no-delete
CREATE TABLE IF NOT EXISTS `security_events` (
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `occurred_at`     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `severity`        VARCHAR(10) NOT NULL DEFAULT 'AVISO' COMMENT 'INFO | AVISO | CRITICO',
  `kind`            VARCHAR(40) NOT NULL COMMENT 'LOGIN_NEGADO_REPETIDO, LEITURA_MASSIVA, ALTERACAO_EXTERNA_PLANILHA, FORA_DA_APLICACAO, QUEBRA_HASH, FALHA_SYNC, FALHA_LOG_PLANILHA, TOKEN_GOOGLE_INVALIDO, EXPORTACAO, ACAO_ADMIN, EXCLUSAO, DESISTENCIA, REMANEJAMENTO, TRIGGER_AUSENTE',
  `user_id`         BIGINT UNSIGNED NULL,
  `entity`          VARCHAR(60) NULL,
  `entity_id`       BIGINT UNSIGNED NULL,
  `detail_json`     JSON NULL,
  `audit_log_id`    BIGINT UNSIGNED NULL,
  `alert_sent_at`   DATETIME(3) NULL,
  `acknowledged_at` DATETIME(3) NULL,
  `acknowledged_by` BIGINT UNSIGNED NULL,
  PRIMARY KEY (`id`),
  KEY `ix_secev_occurred` (`occurred_at`),
  KEY `ix_secev_kind` (`kind`, `occurred_at`),
  KEY `ix_secev_pending_alert` (`alert_sent_at`, `severity`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Eventos de segurança (também alimentada por triggers)';

-- @no-delete
CREATE TABLE IF NOT EXISTS `alert_outbox` (
  `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `kind`              VARCHAR(40) NOT NULL,
  `recipients_json`   JSON NOT NULL COMMENT 'lista de e-mails @scseduca.com.br',
  `subject`           VARCHAR(200) NOT NULL,
  `body_text`         TEXT NOT NULL,
  `body_html`         MEDIUMTEXT NULL,
  `security_event_id` BIGINT UNSIGNED NULL,
  `status`            VARCHAR(10) NOT NULL DEFAULT 'PENDING' COMMENT 'PENDING | SENT | FAILED',
  `attempts`          TINYINT UNSIGNED NOT NULL DEFAULT 0,
  `next_attempt_at`   DATETIME(3) NULL,
  `last_error`        VARCHAR(500) NULL,
  `created_at`        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `sent_at`           DATETIME(3) NULL,
  PRIMARY KEY (`id`),
  KEY `ix_alert_outbox_status` (`status`, `next_attempt_at`),
  CONSTRAINT `chk_alert_status` CHECK (`status` IN ('PENDING', 'SENT', 'FAILED'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Fila de e-mails de alerta aos administradores';

-- @append-only allow: approved_by, approved_at, file_sha256, audit_log_id
CREATE TABLE IF NOT EXISTS `exports` (
  `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`           BIGINT UNSIGNED NOT NULL,
  `kind`              VARCHAR(10) NOT NULL COMMENT 'CSV | PDF | XLSX',
  `entity`            VARCHAR(60) NOT NULL,
  `filters_json`      JSON NULL,
  `record_count`      INT UNSIGNED NOT NULL,
  `reason`            VARCHAR(500) NOT NULL,
  `watermark_id`      CHAR(16) NOT NULL COMMENT 'identificador impresso na marca d água',
  `file_sha256`       CHAR(64) NULL,
  `requires_approval` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '1 = exportação em massa',
  `approved_by`       BIGINT UNSIGNED NULL,
  `approved_at`       DATETIME(3) NULL,
  `audit_log_id`      BIGINT UNSIGNED NULL,
  `created_at`        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_exports_watermark` (`watermark_id`),
  KEY `ix_exports_user` (`user_id`, `created_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Registro de exportações';

-- @no-delete
CREATE TABLE IF NOT EXISTS `cron_runs` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `job_name`    VARCHAR(40) NOT NULL COMMENT 'sync_sheets | flush_sheet_log | verify_audit | backup | send_alerts',
  `started_at`  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `finished_at` DATETIME(3) NULL,
  `status`      VARCHAR(10) NOT NULL DEFAULT 'RUNNING' COMMENT 'RUNNING | OK | ERROR | SKIPPED',
  `summary`     VARCHAR(500) NULL,
  `error`       VARCHAR(1000) NULL,
  PRIMARY KEY (`id`),
  KEY `ix_cron_runs_job` (`job_name`, `started_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Execuções dos jobs (detecta job parado há mais de 30 min)';

-- @no-delete
CREATE TABLE IF NOT EXISTS `backups` (
  `id`                 BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `kind`               VARCHAR(10) NOT NULL COMMENT 'DIARIO | MANUAL',
  `started_at`         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `finished_at`        DATETIME(3) NULL,
  `file_name`          VARCHAR(200) NULL,
  `size_bytes`         BIGINT UNSIGNED NULL,
  `sha256`             CHAR(64) NULL,
  `drive_file_id`      VARCHAR(100) NULL COMMENT 'cópia enviada ao Google Drive da conta técnica',
  `status`             VARCHAR(10) NOT NULL DEFAULT 'RUNNING' COMMENT 'RUNNING | OK | ERROR',
  `error`              VARCHAR(1000) NULL,
  `restore_tested_at`  DATETIME(3) NULL,
  `restore_tested_by`  BIGINT UNSIGNED NULL,
  `restore_result`     VARCHAR(500) NULL,
  `created_by`         BIGINT UNSIGNED NULL,
  PRIMARY KEY (`id`),
  KEY `ix_backups_started` (`started_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Backups cifrados e testes de restauração';

-- =====================================================================================================
-- 3. INTEGRAÇÃO GOOGLE (CONTA TÉCNICA, PLANILHAS, SINCRONIZAÇÃO, FILAS)
-- =====================================================================================================

-- @history
CREATE TABLE IF NOT EXISTS `google_credentials` (
  `id`              INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `kind`            VARCHAR(20) NOT NULL COMMENT 'OAUTH_USER_ACCOUNT (celef@) | SERVICE_ACCOUNT',
  `account_email`   VARCHAR(190) NOT NULL,
  `secret_enc`      BLOB NULL COMMENT 'refresh token OU JSON da Service Account, cifrados',
  `key_version`     TINYINT UNSIGNED NOT NULL DEFAULT 1,
  `scopes`          VARCHAR(500) NOT NULL,
  `status`          VARCHAR(10) NOT NULL DEFAULT 'CONNECTED' COMMENT 'CONNECTED | REVOKED | ERROR',
  `is_active`       TINYINT(1) NOT NULL DEFAULT 1,
  `active_key`      TINYINT GENERATED ALWAYS AS (IF(`is_active` = 1, 1, NULL)) STORED,
  `connected_at`    DATETIME(3) NULL,
  `connected_by`    BIGINT UNSIGNED NULL,
  `last_refresh_at` DATETIME(3) NULL,
  `last_test_at`    DATETIME(3) NULL,
  `last_error`      VARCHAR(500) NULL,
  `revoked_at`      DATETIME(3) NULL,
  `revoked_by`      BIGINT UNSIGNED NULL,
  `version`         INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`          VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`      BIGINT UNSIGNED NULL,
  `updated_at`      DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`      BIGINT UNSIGNED NULL,
  `deleted_at`      DATETIME(3) NULL,
  `deleted_by`      BIGINT UNSIGNED NULL,
  `delete_reason`   VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_gcred_single_active` (`active_key`),
  CONSTRAINT `chk_gcred_kind` CHECK (`kind` IN ('OAUTH_USER_ACCOUNT', 'SERVICE_ACCOUNT'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Credencial da conta técnica (só uma ativa por vez)';

-- @history
CREATE TABLE IF NOT EXISTS `connected_sheets` (
  `id`                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `name`                    VARCHAR(120) NOT NULL COMMENT 'nome amigável, ex.: CELEF • ALUNOS 2026',
  `spreadsheet_id`          VARCHAR(100) NOT NULL,
  `sheet_role`              VARCHAR(20) NOT NULL COMMENT 'FONTE_SECRETARIA | ESPELHO_ESCOLA | LOGS',
  `direction`               VARCHAR(12) NOT NULL COMMENT 'IN | OUT | BOTH | APPEND_ONLY',
  `school_year`             SMALLINT UNSIGNED NULL,
  `write_enabled`           TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'FONTE_SECRETARIA nasce 0; só Super Admin altera',
  `sync_enabled`            TINYINT(1) NOT NULL DEFAULT 1,
  `owner_email`             VARCHAR(190) NULL,
  `last_test_at`            DATETIME(3) NULL,
  `last_test_result`        VARCHAR(500) NULL,
  `last_drive_revision_id`  VARCHAR(64) NULL,
  `last_drive_modified_at`  DATETIME(3) NULL,
  `last_synced_at`          DATETIME(3) NULL,
  `version`                 INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`                  VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`              DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`              BIGINT UNSIGNED NULL,
  `updated_at`              DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`              BIGINT UNSIGNED NULL,
  `deleted_at`              DATETIME(3) NULL,
  `deleted_by`              BIGINT UNSIGNED NULL,
  `delete_reason`           VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_csheets_spreadsheet` (`spreadsheet_id`),
  CONSTRAINT `chk_csheets_role` CHECK (`sheet_role` IN ('FONTE_SECRETARIA', 'ESPELHO_ESCOLA', 'LOGS')),
  CONSTRAINT `chk_csheets_direction` CHECK (`direction` IN ('IN', 'OUT', 'BOTH', 'APPEND_ONLY'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Planilhas Google cadastradas no admin';

-- @history
CREATE TABLE IF NOT EXISTS `connected_sheet_tabs` (
  `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `connected_sheet_id`  BIGINT UNSIGNED NOT NULL,
  `tab_title`           VARCHAR(100) NOT NULL,
  `sheet_gid`           BIGINT UNSIGNED NOT NULL COMMENT 'sheetId numérico da aba (estável mesmo se renomeada)',
  `tab_kind`            VARCHAR(20) NOT NULL COMMENT 'TURMA | ALUNOS | REMANEJAMENTOS | DESISTENTES | TOTAIS | EXCLUIDOS | LOG',
  `class_id`            BIGINT UNSIGNED NULL COMMENT 'aba 1A…9I ↔ turma',
  `header_row`          SMALLINT UNSIGNED NOT NULL DEFAULT 1,
  `first_data_row`      SMALLINT UNSIGNED NOT NULL DEFAULT 2,
  `key_field`           VARCHAR(20) NOT NULL DEFAULT 'ra' COMMENT 'ra | school_email',
  `control_cols_start`  SMALLINT UNSIGNED NULL COMMENT 'índice (1 = A) da primeira coluna de controle oculta',
  `protected_range_id`  BIGINT UNSIGNED NULL,
  `is_active`           TINYINT(1) NOT NULL DEFAULT 1,
  `version`             INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`              VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`          BIGINT UNSIGNED NULL,
  `updated_at`          DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`          BIGINT UNSIGNED NULL,
  `deleted_at`          DATETIME(3) NULL,
  `deleted_by`          BIGINT UNSIGNED NULL,
  `delete_reason`       VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_tabs_sheet_gid` (`connected_sheet_id`, `sheet_gid`),
  KEY `ix_tabs_class` (`class_id`),
  CONSTRAINT `fk_tabs_sheet` FOREIGN KEY (`connected_sheet_id`) REFERENCES `connected_sheets` (`id`),
  CONSTRAINT `fk_tabs_class` FOREIGN KEY (`class_id`) REFERENCES `classes` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Abas de cada planilha e seu papel';

-- @history
CREATE TABLE IF NOT EXISTS `sheet_column_map` (
  `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `connected_sheet_id`  BIGINT UNSIGNED NOT NULL,
  `tab_id`              BIGINT UNSIGNED NULL COMMENT 'NULL = vale para todas as abas do mesmo tab_kind',
  `tab_kind`            VARCHAR(20) NOT NULL,
  `column_header`       VARCHAR(100) NOT NULL COMMENT 'texto do cabeçalho na planilha',
  `column_index`        SMALLINT UNSIGNED NOT NULL COMMENT '1 = A',
  `field_name`          VARCHAR(60) NOT NULL COMMENT 'campo do sistema, ex.: students.mother_name',
  `transform`           VARCHAR(20) NULL COMMENT 'DATE_BR | SIM_NAO | UPPER | DIGITS | TRIM | EMAIL',
  `is_key`              TINYINT(1) NOT NULL DEFAULT 0,
  `direction`           VARCHAR(5) NOT NULL DEFAULT 'BOTH' COMMENT 'IN | OUT | BOTH',
  `write_allowed`       TINYINT(1) NOT NULL DEFAULT 1 COMMENT 'LGPD: 0 = nunca escrever este campo na planilha',
  `is_control`          TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'coluna de controle (ÚLTIMA ALTERAÇÃO, ALTERADO POR, ID SISTEMA)',
  `version`             INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`              VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`          BIGINT UNSIGNED NULL,
  `updated_at`          DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`          BIGINT UNSIGNED NULL,
  `deleted_at`          DATETIME(3) NULL,
  `deleted_by`          BIGINT UNSIGNED NULL,
  `delete_reason`       VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  KEY `ix_colmap_sheet_kind` (`connected_sheet_id`, `tab_kind`, `tab_id`),
  CONSTRAINT `fk_colmap_sheet` FOREIGN KEY (`connected_sheet_id`) REFERENCES `connected_sheets` (`id`),
  CONSTRAINT `fk_colmap_tab` FOREIGN KEY (`tab_id`) REFERENCES `connected_sheet_tabs` (`id`),
  CONSTRAINT `chk_colmap_direction` CHECK (`direction` IN ('IN', 'OUT', 'BOTH'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Mapeamento cabeçalho da planilha ↔ campo do sistema';

CREATE TABLE IF NOT EXISTS `sheet_sync_state` (
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `tab_id`          BIGINT UNSIGNED NOT NULL,
  `row_number`      INT UNSIGNED NOT NULL,
  `row_key`         VARCHAR(190) NOT NULL COMMENT 'R.A. normalizado ou e-mail @scseduca',
  `entity`          VARCHAR(60) NULL,
  `entity_id`       BIGINT UNSIGNED NULL,
  `row_hash`        CHAR(64) NOT NULL COMMENT 'SHA-256 dos valores mapeados da linha na última leitura',
  `system_version`  INT UNSIGNED NULL COMMENT 'students.version / enrollments.version na última sync',
  `status`          VARCHAR(25) NOT NULL DEFAULT 'OK' COMMENT 'OK | MISSING | CONFLICT | PENDING_CONFIRMATION | EXCLUDED',
  `first_seen_at`   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `last_seen_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `missing_since`   DATETIME(3) NULL,
  `last_synced_at`  DATETIME(3) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_sync_state_tab_key` (`tab_id`, `row_key`),
  KEY `ix_sync_state_entity` (`entity`, `entity_id`),
  KEY `ix_sync_state_status` (`status`),
  CONSTRAINT `fk_sync_state_tab` FOREIGN KEY (`tab_id`) REFERENCES `connected_sheet_tabs` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Último estado conhecido de cada linha da planilha';

-- @no-delete
CREATE TABLE IF NOT EXISTS `sync_runs` (
  `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `trigger_type`        VARCHAR(12) NOT NULL COMMENT 'CRON | MANUAL | OPORTUNISTA',
  `triggered_by`        BIGINT UNSIGNED NULL,
  `connected_sheet_id`  BIGINT UNSIGNED NULL COMMENT 'NULL = todas as planilhas',
  `mode`                VARCHAR(8) NOT NULL DEFAULT 'WRITE' COMMENT 'DRY_RUN | WRITE',
  `direction`           VARCHAR(5) NOT NULL COMMENT 'IN | OUT | BOTH',
  `started_at`          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `finished_at`         DATETIME(3) NULL,
  `status`              VARCHAR(10) NOT NULL DEFAULT 'RUNNING' COMMENT 'RUNNING | OK | PARTIAL | ERROR',
  `rows_read`           INT UNSIGNED NOT NULL DEFAULT 0,
  `rows_created`        INT UNSIGNED NOT NULL DEFAULT 0,
  `rows_updated`        INT UNSIGNED NOT NULL DEFAULT 0,
  `rows_written`        INT UNSIGNED NOT NULL DEFAULT 0,
  `conflicts`           INT UNSIGNED NOT NULL DEFAULT 0,
  `external_changes`    INT UNSIGNED NOT NULL DEFAULT 0,
  `errors`              INT UNSIGNED NOT NULL DEFAULT 0,
  `cursor_json`         JSON NULL COMMENT 'ponto de retomada (aba, linha) para a próxima execução',
  `log_excerpt`         TEXT NULL,
  PRIMARY KEY (`id`),
  KEY `ix_sync_runs_started` (`started_at`),
  KEY `ix_sync_runs_sheet` (`connected_sheet_id`, `started_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Execuções da sincronização';

-- @no-delete
CREATE TABLE IF NOT EXISTS `sync_findings` (
  `id`          BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `sync_run_id` BIGINT UNSIGNED NOT NULL,
  `tab_id`      BIGINT UNSIGNED NULL,
  `row_number`  INT UNSIGNED NULL,
  `row_key`     VARCHAR(190) NULL,
  `severity`    VARCHAR(10) NOT NULL COMMENT 'INFO | AVISO | ERRO',
  `code`        VARCHAR(30) NOT NULL COMMENT 'CPF_INVALIDO, DUPLICADO_CPF, DUPLICADO_RA, ALUNO_EM_DUAS_TURMAS, TURMA_INEXISTENTE, SEM_CHAVE, LINHA_VAZIA, DATA_INVALIDA, EMAIL_INVALIDO, CABECALHO_DIVERGENTE',
  `message`     VARCHAR(500) NOT NULL,
  `detail_json` JSON NULL COMMENT 'dados mascarados',
  `created_at`  DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `resolved_at` DATETIME(3) NULL,
  `resolved_by` BIGINT UNSIGNED NULL,
  PRIMARY KEY (`id`),
  KEY `ix_findings_run` (`sync_run_id`, `severity`),
  KEY `ix_findings_open` (`resolved_at`, `code`),
  CONSTRAINT `fk_findings_run` FOREIGN KEY (`sync_run_id`) REFERENCES `sync_runs` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Inconsistências encontradas no dry-run e na carga';

-- @no-delete
CREATE TABLE IF NOT EXISTS `sync_conflicts` (
  `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `sync_run_id`         BIGINT UNSIGNED NOT NULL,
  `connected_sheet_id`  BIGINT UNSIGNED NOT NULL,
  `tab_id`              BIGINT UNSIGNED NOT NULL,
  `row_number`          INT UNSIGNED NOT NULL,
  `row_key`             VARCHAR(190) NOT NULL,
  `entity`              VARCHAR(60) NOT NULL,
  `entity_id`           BIGINT UNSIGNED NOT NULL,
  `field_name`          VARCHAR(60) NOT NULL,
  `base_value_enc`      BLOB NULL COMMENT 'valor na última sincronização (cifrado)',
  `system_value_enc`    BLOB NULL,
  `sheet_value_enc`     BLOB NULL,
  `key_version`         TINYINT UNSIGNED NOT NULL DEFAULT 1,
  `detected_at`         DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `status`              VARCHAR(12) NOT NULL DEFAULT 'PENDING' COMMENT 'PENDING | KEEP_SYSTEM | KEEP_SHEET | MANUAL | IGNORED',
  `resolved_at`         DATETIME(3) NULL,
  `resolved_by`         BIGINT UNSIGNED NULL,
  `resolution_note`     VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  KEY `ix_conflicts_status` (`status`, `detected_at`),
  KEY `ix_conflicts_entity` (`entity`, `entity_id`),
  CONSTRAINT `fk_conflicts_run` FOREIGN KEY (`sync_run_id`) REFERENCES `sync_runs` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Mesmo campo alterado na planilha e no sistema';

-- @append-only
CREATE TABLE IF NOT EXISTS `external_sheet_changes` (
  `id`                    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `sync_run_id`           BIGINT UNSIGNED NOT NULL,
  `connected_sheet_id`    BIGINT UNSIGNED NOT NULL,
  `tab_id`                BIGINT UNSIGNED NOT NULL,
  `row_number`            INT UNSIGNED NOT NULL,
  `column_header`         VARCHAR(100) NULL,
  `row_key`               VARCHAR(190) NULL,
  `old_value_masked`      VARCHAR(300) NULL,
  `new_value_masked`      VARCHAR(300) NULL,
  `drive_revision_id`     VARCHAR(64) NULL,
  `drive_modified_at`     DATETIME(3) NULL,
  `drive_user_email`      VARCHAR(190) NULL,
  `authorship_identified` TINYINT(1) NOT NULL DEFAULT 0 COMMENT '0 = autor é a própria conta celef@ (não identificável)',
  `detected_at`           DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `security_event_id`     BIGINT UNSIGNED NULL,
  `audit_log_id`          BIGINT UNSIGNED NULL,
  PRIMARY KEY (`id`),
  KEY `ix_extchg_detected` (`detected_at`),
  KEY `ix_extchg_sheet` (`connected_sheet_id`, `detected_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Edições feitas diretamente na planilha, fora do sistema';

-- @append-only
CREATE TABLE IF NOT EXISTS `drive_revisions` (
  `id`                    BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `connected_sheet_id`    BIGINT UNSIGNED NOT NULL,
  `revision_id`           VARCHAR(64) NOT NULL,
  `modified_at`           DATETIME(3) NOT NULL,
  `modifying_user_email`  VARCHAR(190) NULL,
  `modifying_user_name`   VARCHAR(160) NULL,
  `fetched_at`            DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_drive_rev` (`connected_sheet_id`, `revision_id`),
  CONSTRAINT `fk_drive_rev_sheet` FOREIGN KEY (`connected_sheet_id`) REFERENCES `connected_sheets` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Revisões lidas via Drive API (revisions.list)';

-- @no-delete
CREATE TABLE IF NOT EXISTS `sheet_outbox` (
  `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `connected_sheet_id`  BIGINT UNSIGNED NOT NULL,
  `tab_id`              BIGINT UNSIGNED NULL COMMENT 'NULL quando a aba ainda será resolvida (ex.: aba da turma nova)',
  `entity`              VARCHAR(60) NOT NULL,
  `entity_id`           BIGINT UNSIGNED NOT NULL,
  `operation`           VARCHAR(25) NOT NULL COMMENT 'UPDATE_ROW | APPEND_ROW | MARK_EXCLUDED | APPEND_REMANEJAMENTO | APPEND_DESISTENTE | UPDATE_TOTALS',
  `row_key`             VARCHAR(190) NULL,
  `row_number`          INT UNSIGNED NULL,
  `payload_json`        JSON NOT NULL COMMENT 'valores por coluna, já protegidos contra injeção de fórmula',
  `payload_hash`        CHAR(64) NOT NULL COMMENT 'permite reconhecer a própria escrita na leitura seguinte',
  `expected_row_hash`   CHAR(64) NULL COMMENT 'estado que a linha deve ter antes da escrita; diferente → conflito',
  `status`              VARCHAR(10) NOT NULL DEFAULT 'PENDING' COMMENT 'PENDING | SENDING | DONE | FAILED | CONFLICT | CANCELLED',
  `attempts`            TINYINT UNSIGNED NOT NULL DEFAULT 0,
  `next_attempt_at`     DATETIME(3) NULL,
  `last_error`          VARCHAR(500) NULL,
  `created_at`          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`          BIGINT UNSIGNED NULL COMMENT 'autor humano da alteração (NULL = cron/sync)',
  `audit_log_id`        BIGINT UNSIGNED NULL,
  `sent_at`             DATETIME(3) NULL,
  PRIMARY KEY (`id`),
  KEY `ix_outbox_status` (`status`, `next_attempt_at`),
  KEY `ix_outbox_entity` (`entity`, `entity_id`),
  KEY `ix_outbox_payload_hash` (`payload_hash`),
  CONSTRAINT `fk_outbox_sheet` FOREIGN KEY (`connected_sheet_id`) REFERENCES `connected_sheets` (`id`),
  CONSTRAINT `chk_outbox_status` CHECK (`status` IN ('PENDING', 'SENDING', 'DONE', 'FAILED', 'CONFLICT', 'CANCELLED'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Fila Sistema → Planilha espelho';

-- @no-delete
CREATE TABLE IF NOT EXISTS `sheet_log_outbox` (
  `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `tab_name`          VARCHAR(20) NOT NULL COMMENT 'AUDITORIA | ACESSOS | SEGURANCA | ADMIN | SINCRONIZACAO | EXPORTACOES | ANCORAS',
  `audit_log_id`      BIGINT UNSIGNED NULL,
  `row_values_json`   JSON NOT NULL COMMENT 'valores da linha; nunca CPF, RG, endereço, telefone ou saúde',
  `row_hash`          CHAR(64) NOT NULL,
  `status`            VARCHAR(10) NOT NULL DEFAULT 'PENDING' COMMENT 'PENDING | SENDING | DONE | FAILED',
  `attempts`          TINYINT UNSIGNED NOT NULL DEFAULT 0,
  `next_attempt_at`   DATETIME(3) NULL,
  `last_error`        VARCHAR(500) NULL,
  `created_at`        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `sent_at`           DATETIME(3) NULL,
  `sheet_row_number`  INT UNSIGNED NULL,
  PRIMARY KEY (`id`),
  KEY `ix_log_outbox_status` (`status`, `next_attempt_at`),
  KEY `ix_log_outbox_audit` (`audit_log_id`),
  CONSTRAINT `chk_log_outbox_status` CHECK (`status` IN ('PENDING', 'SENDING', 'DONE', 'FAILED'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Fila Banco → Planilha de logs e segurança';

-- =====================================================================================================
-- 4. NEGÓCIO (ESCOLA)
-- =====================================================================================================

-- @history
CREATE TABLE IF NOT EXISTS `school_years` (
  `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `school_year`   SMALLINT UNSIGNED NOT NULL COMMENT 'ex.: 2026',
  `label`         VARCHAR(40) NOT NULL,
  `is_current`    TINYINT(1) NOT NULL DEFAULT 0,
  `starts_on`     DATE NULL,
  `ends_on`       DATE NULL,
  `version`       INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`        VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`    BIGINT UNSIGNED NULL,
  `updated_at`    DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`    BIGINT UNSIGNED NULL,
  `deleted_at`    DATETIME(3) NULL,
  `deleted_by`    BIGINT UNSIGNED NULL,
  `delete_reason` VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_school_years_year` (`school_year`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Anos letivos';

-- @history
CREATE TABLE IF NOT EXISTS `classes` (
  `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `school_year`       SMALLINT UNSIGNED NOT NULL,
  `grade`             TINYINT UNSIGNED NOT NULL COMMENT '1 a 9 (ano do Ensino Fundamental)',
  `letter`            CHAR(1) NOT NULL COMMENT 'A a M',
  `code`              VARCHAR(12) NOT NULL DEFAULT '' COMMENT 'ex.: 6A/2026 — montado pelo trigger a partir de grade, letter e school_year',
  `weekday`           TINYINT UNSIGNED NULL COMMENT '1 = segunda … 7 = domingo',
  `starts_at`         TIME NULL,
  `ends_at`           TIME NULL,
  `teacher_user_id`   BIGINT UNSIGNED NULL,
  `classroom_email`   VARCHAR(190) NULL COMMENT 'e-mail da turma no Google Classroom',
  `classroom_id`      VARCHAR(60) NULL,
  `room`              VARCHAR(40) NULL,
  `capacity`          SMALLINT UNSIGNED NULL,
  `status`            VARCHAR(10) NOT NULL DEFAULT 'ATIVA' COMMENT 'ATIVA | ENCERRADA',
  `version`           INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`            VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`        BIGINT UNSIGNED NULL,
  `updated_at`        DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`        BIGINT UNSIGNED NULL,
  `deleted_at`        DATETIME(3) NULL,
  `deleted_by`        BIGINT UNSIGNED NULL,
  `delete_reason`     VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_classes_code` (`code`),
  UNIQUE KEY `uk_classes_year_grade_letter` (`school_year`, `grade`, `letter`),
  KEY `ix_classes_teacher` (`teacher_user_id`),
  CONSTRAINT `fk_classes_year` FOREIGN KEY (`school_year`) REFERENCES `school_years` (`school_year`),
  CONSTRAINT `fk_classes_teacher` FOREIGN KEY (`teacher_user_id`) REFERENCES `users` (`id`),
  CONSTRAINT `chk_classes_grade` CHECK (`grade` BETWEEN 1 AND 9),
  CONSTRAINT `chk_classes_letter` CHECK (`letter` BETWEEN 'A' AND 'Z'),
  CONSTRAINT `chk_classes_status` CHECK (`status` IN ('ATIVA', 'ENCERRADA'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Turmas (ano + letra + ano letivo)';

-- @history
CREATE TABLE IF NOT EXISTS `students` (
  `id`                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `full_name`               VARCHAR(160) NOT NULL,
  `full_name_norm`          VARCHAR(160) NOT NULL COMMENT 'sem acentos, maiúsculo, espaços simples — para busca',
  `school_email`            VARCHAR(190) NULL COMMENT 'e-mail do aluno @scseduca.com.br (chave alternativa)',
  `ra_enc`                  VARBINARY(120) NULL COMMENT 'R.A. cifrado',
  `ra_bidx`                 BINARY(32) NULL COMMENT 'blind index do R.A. (só dígitos)',
  `cpf_enc`                 VARBINARY(120) NULL,
  `cpf_bidx`                BINARY(32) NULL,
  `rg_enc`                  VARBINARY(120) NULL,
  `birth_date_enc`          VARBINARY(80) NULL,
  `birth_year`              SMALLINT UNSIGNED NULL COMMENT 'em claro, só para indicadores por faixa etária',
  `mother_name_enc`         VARBINARY(300) NULL,
  `guardian_email_enc`      VARBINARY(300) NULL,
  `guardian_email_bidx`     BINARY(32) NULL,
  `guardian_phone_enc`      VARBINARY(120) NULL,
  `address_enc`             VARBINARY(600) NULL,
  `image_consent`           TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'denormalizado do último registro em image_consents',
  `social_media_enc`        VARBINARY(600) NULL COMMENT 'campo REDES SOCIAIS — a revisar com a direção (LGPD art. 14)',
  `health_notes_enc`        BLOB NULL COMMENT 'observações gerais de saúde',
  `physical_education_enc`  BLOB NULL COMMENT 'coluna EDUCAÇÃO FÍSICA',
  `dentistry_enc`           BLOB NULL COMMENT 'coluna ODONTOLOGIA',
  `origin_school`           VARCHAR(160) NULL COMMENT 'coluna ESCOLA (escola de origem do aluno)',
  `group_name`              VARCHAR(40) NULL COMMENT 'coluna GRUPO',
  `status`                  VARCHAR(12) NOT NULL DEFAULT 'ATIVO' COMMENT 'ATIVO | REMANEJADO | DESISTENTE | TRANSFERIDO',
  `photo_attachment_id`     BIGINT UNSIGNED NULL,
  `source_row_key`          VARCHAR(190) NULL COMMENT 'chave da linha na planilha de origem (carga inicial)',
  `key_version`             TINYINT UNSIGNED NOT NULL DEFAULT 1,
  `version`                 INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`                  VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`              DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`              BIGINT UNSIGNED NULL,
  `updated_at`              DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`              BIGINT UNSIGNED NULL,
  `deleted_at`              DATETIME(3) NULL,
  `deleted_by`              BIGINT UNSIGNED NULL,
  `delete_reason`           VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_students_school_email` (`school_email`),
  UNIQUE KEY `uk_students_ra_bidx` (`ra_bidx`),
  UNIQUE KEY `uk_students_cpf_bidx` (`cpf_bidx`),
  KEY `ix_students_name` (`full_name_norm`),
  KEY `ix_students_status` (`status`, `deleted_at`),
  KEY `ix_students_guardian_email` (`guardian_email_bidx`),
  CONSTRAINT `chk_students_status` CHECK (`status` IN ('ATIVO', 'REMANEJADO', 'DESISTENTE', 'TRANSFERIDO'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Ficha do aluno (uma linha por pessoa); dados sensíveis cifrados';

-- @append-only
CREATE TABLE IF NOT EXISTS `image_consents` (
  `id`            BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `student_id`    BIGINT UNSIGNED NOT NULL,
  `consented`     TINYINT(1) NOT NULL,
  `term_version`  VARCHAR(20) NOT NULL,
  `recorded_at`   DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `recorded_by`   BIGINT UNSIGNED NULL,
  `source`        VARCHAR(60) NOT NULL DEFAULT 'APP' COMMENT 'APP | PLANILHA:<nome> | CARGA_INICIAL_PLANILHA',
  `notes`         VARCHAR(300) NULL,
  PRIMARY KEY (`id`),
  KEY `ix_image_consents_student` (`student_id`, `recorded_at`),
  CONSTRAINT `fk_image_consents_student` FOREIGN KEY (`student_id`) REFERENCES `students` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Histórico de autorização de uso de imagem';

-- @history
CREATE TABLE IF NOT EXISTS `enrollments` (
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `student_id`      BIGINT UNSIGNED NOT NULL,
  `class_id`        BIGINT UNSIGNED NOT NULL,
  `school_year`     SMALLINT UNSIGNED NOT NULL,
  `roll_number`     SMALLINT UNSIGNED NULL COMMENT 'coluna Nº da lista da turma',
  `status`          VARCHAR(12) NOT NULL DEFAULT 'ATIVA' COMMENT 'ATIVA | REMANEJADA | DESISTENTE | TRANSFERIDA',
  `started_on`      DATE NULL COMMENT 'coluna ENTRADA',
  `ended_on`        DATE NULL COMMENT 'coluna SAÍDA (data)',
  `exit_authorized` TINYINT(1) NOT NULL DEFAULT 0 COMMENT 'coluna Saída (sim/não): autorizado a sair sozinho — premissa a confirmar',
  `notes`           VARCHAR(1000) NULL COMMENT 'coluna Observações (pedagógicas; saúde vai cifrada em students/student_documents)',
  `active_key`      BIGINT UNSIGNED GENERATED ALWAYS AS (IF(`status` = 'ATIVA' AND `deleted_at` IS NULL, `student_id`, NULL)) STORED,
  `roll_key`        BIGINT UNSIGNED GENERATED ALWAYS AS (IF(`status` = 'ATIVA' AND `deleted_at` IS NULL, `class_id`, NULL)) STORED,
  `version`         INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`          VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`      BIGINT UNSIGNED NULL,
  `updated_at`      DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`      BIGINT UNSIGNED NULL,
  `deleted_at`      DATETIME(3) NULL,
  `deleted_by`      BIGINT UNSIGNED NULL,
  `delete_reason`   VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_enroll_one_active_per_year` (`active_key`, `school_year`),
  UNIQUE KEY `uk_enroll_roll_number` (`roll_key`, `roll_number`),
  KEY `ix_enroll_student` (`student_id`, `school_year`),
  KEY `ix_enroll_class` (`class_id`, `status`),
  CONSTRAINT `fk_enroll_student` FOREIGN KEY (`student_id`) REFERENCES `students` (`id`),
  CONSTRAINT `fk_enroll_class` FOREIGN KEY (`class_id`) REFERENCES `classes` (`id`),
  CONSTRAINT `fk_enroll_year` FOREIGN KEY (`school_year`) REFERENCES `school_years` (`school_year`),
  CONSTRAINT `chk_enroll_status` CHECK (`status` IN ('ATIVA', 'REMANEJADA', 'DESISTENTE', 'TRANSFERIDA'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Matrícula do aluno em uma turma, por ano letivo. Índice único impede aluno ativo em duas turmas';

-- @history
CREATE TABLE IF NOT EXISTS `class_transfers` (
  `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `student_id`          BIGINT UNSIGNED NOT NULL,
  `from_enrollment_id`  BIGINT UNSIGNED NOT NULL,
  `to_enrollment_id`    BIGINT UNSIGNED NOT NULL,
  `from_class_id`       BIGINT UNSIGNED NOT NULL,
  `to_class_id`         BIGINT UNSIGNED NOT NULL,
  `school_year`         SMALLINT UNSIGNED NOT NULL,
  `transferred_at`      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3) COMMENT 'relógio do servidor; nunca digitado',
  `transferred_by`      BIGINT UNSIGNED NULL COMMENT 'usuário logado; nunca digitado',
  `record_moved_at`     DATETIME(3) NULL COMMENT 'troca do prontuário',
  `record_moved_by`     BIGINT UNSIGNED NULL,
  `reason`              VARCHAR(500) NULL,
  `sheet_outbox_id`     BIGINT UNSIGNED NULL,
  `version`             INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`              VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`          BIGINT UNSIGNED NULL,
  `updated_at`          DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`          BIGINT UNSIGNED NULL,
  `deleted_at`          DATETIME(3) NULL,
  `deleted_by`          BIGINT UNSIGNED NULL,
  `delete_reason`       VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  KEY `ix_ctransfers_student` (`student_id`, `transferred_at`),
  KEY `ix_ctransfers_year` (`school_year`, `transferred_at`),
  CONSTRAINT `fk_ctransfers_student` FOREIGN KEY (`student_id`) REFERENCES `students` (`id`),
  CONSTRAINT `fk_ctransfers_from_enroll` FOREIGN KEY (`from_enrollment_id`) REFERENCES `enrollments` (`id`),
  CONSTRAINT `fk_ctransfers_to_enroll` FOREIGN KEY (`to_enrollment_id`) REFERENCES `enrollments` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Remanejamentos entre turmas (aba REMANEJAMENTOS)';

-- @history
CREATE TABLE IF NOT EXISTS `withdrawals` (
  `id`                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `student_id`              BIGINT UNSIGNED NOT NULL,
  `enrollment_id`           BIGINT UNSIGNED NOT NULL,
  `class_id`                BIGINT UNSIGNED NOT NULL,
  `school_year`             SMALLINT UNSIGNED NOT NULL,
  `withdrawn_at`            DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `withdrawn_by`            BIGINT UNSIGNED NULL,
  `reason_code`             VARCHAR(12) NOT NULL DEFAULT 'OUTRO' COMMENT 'MUDANCA | HORARIO | SAUDE | FAMILIA | OUTRO',
  `reason`                  VARCHAR(500) NULL,
  `documents_returned_at`   DATETIME(3) NULL COMMENT 'retirada dos documentos',
  `documents_returned_by`   BIGINT UNSIGNED NULL,
  `sheet_outbox_id`         BIGINT UNSIGNED NULL,
  `version`                 INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`                  VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`              DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`              BIGINT UNSIGNED NULL,
  `updated_at`              DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`              BIGINT UNSIGNED NULL,
  `deleted_at`              DATETIME(3) NULL,
  `deleted_by`              BIGINT UNSIGNED NULL,
  `delete_reason`           VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  KEY `ix_withdrawals_student` (`student_id`, `withdrawn_at`),
  KEY `ix_withdrawals_year` (`school_year`, `withdrawn_at`),
  CONSTRAINT `fk_withdrawals_student` FOREIGN KEY (`student_id`) REFERENCES `students` (`id`),
  CONSTRAINT `fk_withdrawals_enroll` FOREIGN KEY (`enrollment_id`) REFERENCES `enrollments` (`id`),
  CONSTRAINT `chk_withdrawals_reason` CHECK (`reason_code` IN ('MUDANCA', 'HORARIO', 'SAUDE', 'FAMILIA', 'OUTRO'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Desistências (aba DESISTENTES)';

-- @history
CREATE TABLE IF NOT EXISTS `school_transfers` (
  `id`                  BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `student_id`          BIGINT UNSIGNED NOT NULL,
  `enrollment_id`       BIGINT UNSIGNED NOT NULL,
  `school_year`         SMALLINT UNSIGNED NOT NULL,
  `transferred_at`      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `transferred_by`      BIGINT UNSIGNED NULL,
  `destination_school`  VARCHAR(160) NULL,
  `declaration_id`      BIGINT UNSIGNED NULL,
  `notes`               VARCHAR(500) NULL,
  `version`             INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`              VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`          DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`          BIGINT UNSIGNED NULL,
  `updated_at`          DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`          BIGINT UNSIGNED NULL,
  `deleted_at`          DATETIME(3) NULL,
  `deleted_by`          BIGINT UNSIGNED NULL,
  `delete_reason`       VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  KEY `ix_stransfers_student` (`student_id`, `transferred_at`),
  CONSTRAINT `fk_stransfers_student` FOREIGN KEY (`student_id`) REFERENCES `students` (`id`),
  CONSTRAINT `fk_stransfers_enroll` FOREIGN KEY (`enrollment_id`) REFERENCES `enrollments` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Transferências para outra escola';

-- @history
CREATE TABLE IF NOT EXISTS `diary_lessons` (
  `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `class_id`          BIGINT UNSIGNED NOT NULL,
  `lesson_date`       DATE NOT NULL,
  `lesson_number`     TINYINT UNSIGNED NOT NULL DEFAULT 1 COMMENT 'ordem da aula no dia',
  `content`           TEXT NULL COMMENT 'conteúdo trabalhado',
  `homework`          VARCHAR(1000) NULL,
  `locked_at`         DATETIME(3) NULL COMMENT 'após diario.edit_days só edita com aprovação',
  `unlock_request_id` BIGINT UNSIGNED NULL,
  `version`           INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`            VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`        BIGINT UNSIGNED NULL,
  `updated_at`        DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`        BIGINT UNSIGNED NULL,
  `deleted_at`        DATETIME(3) NULL,
  `deleted_by`        BIGINT UNSIGNED NULL,
  `delete_reason`     VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_lessons_class_date_num` (`class_id`, `lesson_date`, `lesson_number`),
  CONSTRAINT `fk_lessons_class` FOREIGN KEY (`class_id`) REFERENCES `classes` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Diário do professor: aulas';

-- @history
CREATE TABLE IF NOT EXISTS `diary_attendance` (
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `lesson_id`       BIGINT UNSIGNED NOT NULL,
  `enrollment_id`   BIGINT UNSIGNED NOT NULL,
  `status`          CHAR(2) NOT NULL COMMENT 'P = presente | F = falta | FJ = falta justificada',
  `note`            VARCHAR(300) NULL,
  `version`         INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`          VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`      BIGINT UNSIGNED NULL,
  `updated_at`      DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`      BIGINT UNSIGNED NULL,
  `deleted_at`      DATETIME(3) NULL,
  `deleted_by`      BIGINT UNSIGNED NULL,
  `delete_reason`   VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_attendance_lesson_enroll` (`lesson_id`, `enrollment_id`),
  KEY `ix_attendance_enroll` (`enrollment_id`, `status`),
  CONSTRAINT `fk_attendance_lesson` FOREIGN KEY (`lesson_id`) REFERENCES `diary_lessons` (`id`),
  CONSTRAINT `fk_attendance_enroll` FOREIGN KEY (`enrollment_id`) REFERENCES `enrollments` (`id`),
  CONSTRAINT `chk_attendance_status` CHECK (`status` IN ('P', 'F', 'FJ'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Diário do professor: frequência por aluno e aula';

-- @no-delete
CREATE TABLE IF NOT EXISTS `diary_change_requests` (
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `lesson_id`       BIGINT UNSIGNED NOT NULL,
  `requested_by`    BIGINT UNSIGNED NOT NULL,
  `justification`   VARCHAR(1000) NOT NULL,
  `status`          VARCHAR(10) NOT NULL DEFAULT 'PENDING' COMMENT 'PENDING | APPROVED | REJECTED',
  `decided_by`      BIGINT UNSIGNED NULL,
  `decided_at`      DATETIME(3) NULL,
  `decision_note`   VARCHAR(500) NULL,
  `created_at`      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  PRIMARY KEY (`id`),
  KEY `ix_dcr_lesson` (`lesson_id`, `status`),
  CONSTRAINT `fk_dcr_lesson` FOREIGN KEY (`lesson_id`) REFERENCES `diary_lessons` (`id`),
  CONSTRAINT `chk_dcr_status` CHECK (`status` IN ('PENDING', 'APPROVED', 'REJECTED'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Pedidos de edição do diário fora do prazo';

-- @history
CREATE TABLE IF NOT EXISTS `attachments` (
  `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `owner_entity`      VARCHAR(60) NOT NULL COMMENT 'students | student_documents | branding_assets | staff',
  `owner_id`          BIGINT UNSIGNED NULL,
  `kind`              VARCHAR(20) NOT NULL COMMENT 'FOTO | ATESTADO | LAUDO | JUSTIFICATIVA | MARCA | OUTRO',
  `original_name_enc` VARBINARY(600) NULL COMMENT 'nome original cifrado (pode conter nome do aluno)',
  `stored_name`       CHAR(64) NOT NULL COMMENT 'nome aleatório em storage/uploads/',
  `mime_type`         VARCHAR(100) NOT NULL COMMENT 'detectado pelo conteúdo (finfo), não pela extensão',
  `size_bytes`        INT UNSIGNED NOT NULL,
  `sha256`            CHAR(64) NOT NULL COMMENT 'hash do conteúdo em claro',
  `key_version`       TINYINT UNSIGNED NOT NULL DEFAULT 1,
  `uploaded_by`       BIGINT UNSIGNED NULL,
  `version`           INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`            VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`        BIGINT UNSIGNED NULL,
  `updated_at`        DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`        BIGINT UNSIGNED NULL,
  `deleted_at`        DATETIME(3) NULL,
  `deleted_by`        BIGINT UNSIGNED NULL,
  `delete_reason`     VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_attachments_stored_name` (`stored_name`),
  KEY `ix_attachments_owner` (`owner_entity`, `owner_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Arquivos enviados, gravados cifrados fora da raiz pública';

-- @history
CREATE TABLE IF NOT EXISTS `student_documents` (
  `id`              BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `student_id`      BIGINT UNSIGNED NOT NULL,
  `enrollment_id`   BIGINT UNSIGNED NULL,
  `kind`            VARCHAR(15) NOT NULL COMMENT 'ATESTADO | LAUDO | JUSTIFICATIVA | OUTRO',
  `from_date`       DATE NULL,
  `to_date`         DATE NULL,
  `days`            SMALLINT UNSIGNED NULL,
  `details_enc`     BLOB NULL COMMENT 'descrição/CID/observações cifradas',
  `key_version`     TINYINT UNSIGNED NOT NULL DEFAULT 1,
  `attachment_id`   BIGINT UNSIGNED NULL,
  `access_level`    VARCHAR(12) NOT NULL DEFAULT 'RESTRITO' COMMENT 'RESTRITO (secretaria/direção) | COORDENACAO | TURMA (professor da turma)',
  `recorded_by`     BIGINT UNSIGNED NULL,
  `version`         INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`          VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`      DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`      BIGINT UNSIGNED NULL,
  `updated_at`      DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`      BIGINT UNSIGNED NULL,
  `deleted_at`      DATETIME(3) NULL,
  `deleted_by`      BIGINT UNSIGNED NULL,
  `delete_reason`   VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  KEY `ix_sdocs_student` (`student_id`, `kind`, `from_date`),
  CONSTRAINT `fk_sdocs_student` FOREIGN KEY (`student_id`) REFERENCES `students` (`id`),
  CONSTRAINT `fk_sdocs_attachment` FOREIGN KEY (`attachment_id`) REFERENCES `attachments` (`id`),
  CONSTRAINT `chk_sdocs_kind` CHECK (`kind` IN ('ATESTADO', 'LAUDO', 'JUSTIFICATIVA', 'OUTRO')),
  CONSTRAINT `chk_sdocs_access` CHECK (`access_level` IN ('RESTRITO', 'COORDENACAO', 'TURMA'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Atestados, laudos e justificativas de falta (nunca vão para planilha)';

-- @history
CREATE TABLE IF NOT EXISTS `staff` (
  `id`                BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `user_id`           BIGINT UNSIGNED NULL COMMENT 'vínculo com a conta de acesso, quando houver',
  `full_name`         VARCHAR(160) NOT NULL,
  `job_title`         VARCHAR(80) NULL,
  `registration_enc`  VARBINARY(120) NULL COMMENT 'matrícula funcional cifrada',
  `phone_enc`         VARBINARY(120) NULL,
  `work_email`        VARCHAR(190) NULL,
  `status`            VARCHAR(10) NOT NULL DEFAULT 'ATIVO' COMMENT 'ATIVO | INATIVO',
  `started_on`        DATE NULL,
  `ended_on`          DATE NULL,
  `key_version`       TINYINT UNSIGNED NOT NULL DEFAULT 1,
  `version`           INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`            VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`        DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`        BIGINT UNSIGNED NULL,
  `updated_at`        DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`        BIGINT UNSIGNED NULL,
  `deleted_at`        DATETIME(3) NULL,
  `deleted_by`        BIGINT UNSIGNED NULL,
  `delete_reason`     VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_staff_user` (`user_id`),
  KEY `ix_staff_name` (`full_name`),
  CONSTRAINT `fk_staff_user` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Funcionários / servidores';

-- @history
CREATE TABLE IF NOT EXISTS `declaration_templates` (
  `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `code`          VARCHAR(40) NOT NULL COMMENT 'ex.: MATRICULA, FREQUENCIA, TRANSFERENCIA',
  `name`          VARCHAR(120) NOT NULL,
  `body_html`     MEDIUMTEXT NOT NULL COMMENT 'modelo com marcadores {{aluno.nome}} etc.',
  `template_version` INT UNSIGNED NOT NULL DEFAULT 1,
  `is_active`     TINYINT(1) NOT NULL DEFAULT 1,
  `version`       INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`        VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`    BIGINT UNSIGNED NULL,
  `updated_at`    DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`    BIGINT UNSIGNED NULL,
  `deleted_at`    DATETIME(3) NULL,
  `deleted_by`    BIGINT UNSIGNED NULL,
  `delete_reason` VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_decl_templates_code` (`code`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Modelos de declaração';

-- @append-only allow: revoked_at, revoked_by, revoke_reason, pdf_sha256
CREATE TABLE IF NOT EXISTS `declarations` (
  `id`                      BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  `student_id`              BIGINT UNSIGNED NOT NULL,
  `template_id`             INT UNSIGNED NOT NULL,
  `template_version`        INT UNSIGNED NOT NULL,
  `control_number`          VARCHAR(20) NOT NULL COMMENT 'ex.: 2026-000123',
  `verification_token_hash` CHAR(64) NOT NULL COMMENT 'SHA-256 do token do QR Code (token real só no PDF)',
  `payload_json`            JSON NOT NULL COMMENT 'snapshot dos dados impressos (sem CPF/RG completos)',
  `pdf_sha256`              CHAR(64) NULL,
  `issued_at`               DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `issued_by`               BIGINT UNSIGNED NOT NULL,
  `revoked_at`              DATETIME(3) NULL,
  `revoked_by`              BIGINT UNSIGNED NULL,
  `revoke_reason`           VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  UNIQUE KEY `uk_declarations_control` (`control_number`),
  UNIQUE KEY `uk_declarations_token` (`verification_token_hash`),
  KEY `ix_declarations_student` (`student_id`, `issued_at`),
  CONSTRAINT `fk_declarations_student` FOREIGN KEY (`student_id`) REFERENCES `students` (`id`),
  CONSTRAINT `fk_declarations_template` FOREIGN KEY (`template_id`) REFERENCES `declaration_templates` (`id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Declarações emitidas (revogação permitida só nos campos revoked_*)';

-- @history
CREATE TABLE IF NOT EXISTS `branding_assets` (
  `id`            INT UNSIGNED NOT NULL AUTO_INCREMENT,
  `kind`          VARCHAR(15) NOT NULL COMMENT 'LOGO | LOGO_BRANCO | FACHADA | FAVICON',
  `attachment_id` BIGINT UNSIGNED NOT NULL,
  `is_active`     TINYINT(1) NOT NULL DEFAULT 1,
  `palette_json`  JSON NULL COMMENT 'paleta extraída do logo (variáveis CSS)',
  `version`       INT UNSIGNED NOT NULL DEFAULT 1,
  `origin`        VARCHAR(60) NOT NULL DEFAULT 'APP',
  `created_at`    DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),
  `created_by`    BIGINT UNSIGNED NULL,
  `updated_at`    DATETIME(3) NULL DEFAULT NULL ON UPDATE CURRENT_TIMESTAMP(3),
  `updated_by`    BIGINT UNSIGNED NULL,
  `deleted_at`    DATETIME(3) NULL,
  `deleted_by`    BIGINT UNSIGNED NULL,
  `delete_reason` VARCHAR(500) NULL,
  PRIMARY KEY (`id`),
  KEY `ix_branding_kind` (`kind`, `is_active`),
  CONSTRAINT `fk_branding_attachment` FOREIGN KEY (`attachment_id`) REFERENCES `attachments` (`id`),
  CONSTRAINT `chk_branding_kind` CHECK (`kind` IN ('LOGO', 'LOGO_BRANCO', 'FACHADA', 'FAVICON'))
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Identidade visual trocável pelo admin';

-- @@HISTORY_TABLES@@
