-- =====================================================================================================
-- sql/triggers.sql
-- Sistema de Gestão Escolar CELEF — triggers de integridade, versionamento e imutabilidade (Fase 1)
--
-- Gerado por tools/gen_sql.py a partir dos marcadores de sql/schema.sql. Importar DEPOIS de schema.sql,
-- no phpMyAdmin, com o usuário de INSTALAÇÃO. Idempotente (DROP TRIGGER IF EXISTS antes de cada CREATE).
-- Sem cláusula DEFINER (evita erro de privilégio SUPER em hospedagem compartilhada).
--
-- Variáveis de sessão que a aplicação define em TODA conexão (app/Database.php, Fase 2):
--     SET @app_user_id = <id do usuário logado ou NULL>, @app_origin = 'APP' | 'CRON' | 'PLANILHA:<nome>' | ...
-- Conexão sem @app_origin (phpMyAdmin, script avulso) = FORA_DA_APLICACAO: a alteração é aceita, mas
-- registrada em security_events e a app dispara alerta por e-mail.
--
-- Cadeia de hash da auditoria (trg_audit_log_bi):
--     hash = SHA2(CONCAT_WS('|', prev_hash, DATE_FORMAT(occurred_at,'%Y-%m-%d %H:%i:%s.%f'),
--                 COALESCE(user_id,''), COALESCE(user_email,''), COALESCE(role_code,''), action,
--                 COALESCE(entity,''), COALESCE(entity_id,''), COALESCE(summary,''), COALESCE(diff_json,''),
--                 COALESCE(ip,''), COALESCE(request_id,''), origin), 256)
--     prev_hash da primeira linha = 64 zeros. cron/verify_audit.php recalcula em PHP com a mesma fórmula.
--     A aplicação envolve cada INSERT em GET_LOCK('celef_audit', 5) para impedir bifurcação da cadeia.
-- =====================================================================================================

SET NAMES utf8mb4;

DELIMITER $$

-- -----------------------------------------------------------------------------------------------------
-- audit_log: cadeia de hash + origem + imutabilidade
-- -----------------------------------------------------------------------------------------------------
DROP TRIGGER IF EXISTS `trg_audit_log_bi`$$
CREATE TRIGGER `trg_audit_log_bi` BEFORE INSERT ON `audit_log` FOR EACH ROW
BEGIN
  DECLARE v_prev CHAR(64);
  IF NEW.occurred_at IS NULL THEN
    SET NEW.occurred_at = UTC_TIMESTAMP(6);
  END IF;
  IF NEW.origin IS NULL OR NEW.origin = '' THEN
    SET NEW.origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  END IF;
  IF @app_origin IS NULL THEN
    SET NEW.origin = 'FORA_DA_APLICACAO';
  END IF;
  IF NEW.user_id IS NULL AND @app_user_id IS NOT NULL THEN
    SET NEW.user_id = @app_user_id;
  END IF;
  SET v_prev = (SELECT h.`hash` FROM `audit_log` h ORDER BY h.`id` DESC LIMIT 1);
  SET NEW.prev_hash = COALESCE(v_prev, REPEAT('0', 64));
  SET NEW.hash = SHA2(CONCAT_WS('|',
      NEW.prev_hash,
      DATE_FORMAT(NEW.occurred_at, '%Y-%m-%d %H:%i:%s.%f'),
      COALESCE(NEW.user_id, ''),
      COALESCE(NEW.user_email, ''),
      COALESCE(NEW.role_code, ''),
      NEW.action,
      COALESCE(NEW.entity, ''),
      COALESCE(NEW.entity_id, ''),
      COALESCE(NEW.summary, ''),
      COALESCE(NEW.diff_json, ''),
      COALESCE(NEW.ip, ''),
      COALESCE(NEW.request_id, ''),
      NEW.origin
  ), 256);
END$$

DROP TRIGGER IF EXISTS `trg_audit_log_bu`$$
CREATE TRIGGER `trg_audit_log_bu` BEFORE UPDATE ON `audit_log` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela audit_log e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_audit_log_bd`$$
CREATE TRIGGER `trg_audit_log_bd` BEFORE DELETE ON `audit_log` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em audit_log. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

-- -----------------------------------------------------------------------------------------------------
-- Tabelas somente-inclusão (append-only) e tabelas sem DELETE
-- -----------------------------------------------------------------------------------------------------
DROP TRIGGER IF EXISTS `trg_permissions_bd`$$
CREATE TRIGGER `trg_permissions_bd` BEFORE DELETE ON `permissions` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em permissions. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_role_permissions_bd`$$
CREATE TRIGGER `trg_role_permissions_bd` BEFORE DELETE ON `role_permissions` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em role_permissions. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_user_sessions_bd`$$
CREATE TRIGGER `trg_user_sessions_bd` BEFORE DELETE ON `user_sessions` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em user_sessions. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_login_attempts_bu`$$
CREATE TRIGGER `trg_login_attempts_bu` BEFORE UPDATE ON `login_attempts` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela login_attempts e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_login_attempts_bd`$$
CREATE TRIGGER `trg_login_attempts_bd` BEFORE DELETE ON `login_attempts` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em login_attempts. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_rate_limits_bd`$$
CREATE TRIGGER `trg_rate_limits_bd` BEFORE DELETE ON `rate_limits` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em rate_limits. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_privacy_acknowledgements_bu`$$
CREATE TRIGGER `trg_privacy_acknowledgements_bu` BEFORE UPDATE ON `privacy_acknowledgements` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela privacy_acknowledgements e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_privacy_acknowledgements_bd`$$
CREATE TRIGGER `trg_privacy_acknowledgements_bd` BEFORE DELETE ON `privacy_acknowledgements` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em privacy_acknowledgements. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_audit_anchor_bu`$$
CREATE TRIGGER `trg_audit_anchor_bu` BEFORE UPDATE ON `audit_anchor` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela audit_anchor e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_audit_anchor_bd`$$
CREATE TRIGGER `trg_audit_anchor_bd` BEFORE DELETE ON `audit_anchor` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em audit_anchor. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_audit_verification_runs_bu`$$
CREATE TRIGGER `trg_audit_verification_runs_bu` BEFORE UPDATE ON `audit_verification_runs` FOR EACH ROW
BEGIN
  -- somente as colunas [finished_at, rows_checked, result, first_broken_id, triggers_ok, detail] podem mudar
  IF NOT (OLD.`id` <=> NEW.`id`)
      OR NOT (OLD.`started_at` <=> NEW.`started_at`)
      OR NOT (OLD.`from_id` <=> NEW.`from_id`)
      OR NOT (OLD.`to_id` <=> NEW.`to_id`) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela audit_verification_runs: somente as colunas finished_at, rows_checked, result, first_broken_id, triggers_ok, detail podem ser alteradas.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_audit_verification_runs_bd`$$
CREATE TRIGGER `trg_audit_verification_runs_bd` BEFORE DELETE ON `audit_verification_runs` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em audit_verification_runs. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_security_events_bd`$$
CREATE TRIGGER `trg_security_events_bd` BEFORE DELETE ON `security_events` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em security_events. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_alert_outbox_bd`$$
CREATE TRIGGER `trg_alert_outbox_bd` BEFORE DELETE ON `alert_outbox` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em alert_outbox. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_exports_bu`$$
CREATE TRIGGER `trg_exports_bu` BEFORE UPDATE ON `exports` FOR EACH ROW
BEGIN
  -- somente as colunas [approved_by, approved_at, file_sha256, audit_log_id] podem mudar
  IF NOT (OLD.`id` <=> NEW.`id`)
      OR NOT (OLD.`user_id` <=> NEW.`user_id`)
      OR NOT (OLD.`kind` <=> NEW.`kind`)
      OR NOT (OLD.`entity` <=> NEW.`entity`)
      OR NOT (OLD.`filters_json` <=> NEW.`filters_json`)
      OR NOT (OLD.`record_count` <=> NEW.`record_count`)
      OR NOT (OLD.`reason` <=> NEW.`reason`)
      OR NOT (OLD.`watermark_id` <=> NEW.`watermark_id`)
      OR NOT (OLD.`requires_approval` <=> NEW.`requires_approval`)
      OR NOT (OLD.`created_at` <=> NEW.`created_at`) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela exports: somente as colunas approved_by, approved_at, file_sha256, audit_log_id podem ser alteradas.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_exports_bd`$$
CREATE TRIGGER `trg_exports_bd` BEFORE DELETE ON `exports` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em exports. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_cron_runs_bd`$$
CREATE TRIGGER `trg_cron_runs_bd` BEFORE DELETE ON `cron_runs` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em cron_runs. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_backups_bd`$$
CREATE TRIGGER `trg_backups_bd` BEFORE DELETE ON `backups` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em backups. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_sync_runs_bd`$$
CREATE TRIGGER `trg_sync_runs_bd` BEFORE DELETE ON `sync_runs` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em sync_runs. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_sync_findings_bd`$$
CREATE TRIGGER `trg_sync_findings_bd` BEFORE DELETE ON `sync_findings` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em sync_findings. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_sync_conflicts_bd`$$
CREATE TRIGGER `trg_sync_conflicts_bd` BEFORE DELETE ON `sync_conflicts` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em sync_conflicts. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_external_sheet_changes_bu`$$
CREATE TRIGGER `trg_external_sheet_changes_bu` BEFORE UPDATE ON `external_sheet_changes` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela external_sheet_changes e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_external_sheet_changes_bd`$$
CREATE TRIGGER `trg_external_sheet_changes_bd` BEFORE DELETE ON `external_sheet_changes` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em external_sheet_changes. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_drive_revisions_bu`$$
CREATE TRIGGER `trg_drive_revisions_bu` BEFORE UPDATE ON `drive_revisions` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela drive_revisions e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_drive_revisions_bd`$$
CREATE TRIGGER `trg_drive_revisions_bd` BEFORE DELETE ON `drive_revisions` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em drive_revisions. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_sheet_outbox_bd`$$
CREATE TRIGGER `trg_sheet_outbox_bd` BEFORE DELETE ON `sheet_outbox` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em sheet_outbox. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_sheet_log_outbox_bd`$$
CREATE TRIGGER `trg_sheet_log_outbox_bd` BEFORE DELETE ON `sheet_log_outbox` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em sheet_log_outbox. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_image_consents_bu`$$
CREATE TRIGGER `trg_image_consents_bu` BEFORE UPDATE ON `image_consents` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela image_consents e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_image_consents_bd`$$
CREATE TRIGGER `trg_image_consents_bd` BEFORE DELETE ON `image_consents` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em image_consents. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_diary_change_requests_bd`$$
CREATE TRIGGER `trg_diary_change_requests_bd` BEFORE DELETE ON `diary_change_requests` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em diary_change_requests. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_declarations_bu`$$
CREATE TRIGGER `trg_declarations_bu` BEFORE UPDATE ON `declarations` FOR EACH ROW
BEGIN
  -- somente as colunas [revoked_at, revoked_by, revoke_reason, pdf_sha256] podem mudar
  IF NOT (OLD.`id` <=> NEW.`id`)
      OR NOT (OLD.`student_id` <=> NEW.`student_id`)
      OR NOT (OLD.`template_id` <=> NEW.`template_id`)
      OR NOT (OLD.`template_version` <=> NEW.`template_version`)
      OR NOT (OLD.`control_number` <=> NEW.`control_number`)
      OR NOT (OLD.`verification_token_hash` <=> NEW.`verification_token_hash`)
      OR NOT (OLD.`payload_json` <=> NEW.`payload_json`)
      OR NOT (OLD.`issued_at` <=> NEW.`issued_at`)
      OR NOT (OLD.`issued_by` <=> NEW.`issued_by`) THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela declarations: somente as colunas revoked_at, revoked_by, revoke_reason, pdf_sha256 podem ser alteradas.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_declarations_bd`$$
CREATE TRIGGER `trg_declarations_bd` BEFORE DELETE ON `declarations` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em declarations. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

-- -----------------------------------------------------------------------------------------------------
-- Versionamento (BEFORE UPDATE → *_history), exclusão lógica validada, origem e detecção FORA_DA_APLICACAO
-- -----------------------------------------------------------------------------------------------------
DROP TRIGGER IF EXISTS `trg_roles_bi`$$
CREATE TRIGGER `trg_roles_bi` BEFORE INSERT ON `roles` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'roles', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_roles_bu`$$
CREATE TRIGGER `trg_roles_bu` BEFORE UPDATE ON `roles` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `roles_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `code`, `name`, `description`, `is_system`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`code`, OLD.`name`, OLD.`description`, OLD.`is_system`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'roles', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_roles_bd`$$
CREATE TRIGGER `trg_roles_bd` BEFORE DELETE ON `roles` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em roles. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_roles_history_bu`$$
CREATE TRIGGER `trg_roles_history_bu` BEFORE UPDATE ON `roles_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela roles_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_roles_history_bd`$$
CREATE TRIGGER `trg_roles_history_bd` BEFORE DELETE ON `roles_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em roles_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_users_bi`$$
CREATE TRIGGER `trg_users_bi` BEFORE INSERT ON `users` FOR EACH ROW
BEGIN
  SET NEW.`email` = LOWER(TRIM(NEW.`email`));
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'users', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_users_bu`$$
CREATE TRIGGER `trg_users_bu` BEFORE UPDATE ON `users` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  DECLARE v_other_super INT;
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  SET NEW.`email` = LOWER(TRIM(NEW.`email`));
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  -- protecao: nunca deixar o sistema sem Super Administrador ativo
  IF (SELECT r.`code` FROM `roles` r WHERE r.`id` = OLD.`role_id`) = 'SUPER_ADMIN'
     AND OLD.`is_active` = 1 AND OLD.`deleted_at` IS NULL
     AND (NEW.`is_active` = 0 OR NEW.`deleted_at` IS NOT NULL OR NEW.`role_id` <> OLD.`role_id`) THEN
    SET v_other_super = (SELECT COUNT(*) FROM `users` u JOIN `roles` r ON r.`id` = u.`role_id`
                         WHERE r.`code` = 'SUPER_ADMIN' AND u.`is_active` = 1 AND u.`deleted_at` IS NULL AND u.`id` <> OLD.`id`);
    IF v_other_super = 0 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e possivel remover, rebaixar ou desativar o ultimo Super Administrador ativo.';
    END IF;
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `users_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `email`, `google_sub`, `full_name`, `picture_url`, `role_id`, `is_active`, `privacy_accepted_at`, `privacy_version`, `last_login_at`, `last_login_ip`, `amr_last`, `notes`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`email`, OLD.`google_sub`, OLD.`full_name`, OLD.`picture_url`, OLD.`role_id`, OLD.`is_active`, OLD.`privacy_accepted_at`, OLD.`privacy_version`, OLD.`last_login_at`, OLD.`last_login_ip`, OLD.`amr_last`, OLD.`notes`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'users', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_users_bd`$$
CREATE TRIGGER `trg_users_bd` BEFORE DELETE ON `users` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em users. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_users_history_bu`$$
CREATE TRIGGER `trg_users_history_bu` BEFORE UPDATE ON `users_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela users_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_users_history_bd`$$
CREATE TRIGGER `trg_users_history_bd` BEFORE DELETE ON `users_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em users_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_user_class_assignments_bi`$$
CREATE TRIGGER `trg_user_class_assignments_bi` BEFORE INSERT ON `user_class_assignments` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'user_class_assignments', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_user_class_assignments_bu`$$
CREATE TRIGGER `trg_user_class_assignments_bu` BEFORE UPDATE ON `user_class_assignments` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `user_class_assignments_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `user_id`, `class_id`, `assignment_type`, `school_year`, `started_on`, `ended_on`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`user_id`, OLD.`class_id`, OLD.`assignment_type`, OLD.`school_year`, OLD.`started_on`, OLD.`ended_on`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'user_class_assignments', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_user_class_assignments_bd`$$
CREATE TRIGGER `trg_user_class_assignments_bd` BEFORE DELETE ON `user_class_assignments` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em user_class_assignments. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_user_class_assignments_history_bu`$$
CREATE TRIGGER `trg_user_class_assignments_history_bu` BEFORE UPDATE ON `user_class_assignments_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela user_class_assignments_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_user_class_assignments_history_bd`$$
CREATE TRIGGER `trg_user_class_assignments_history_bd` BEFORE DELETE ON `user_class_assignments_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em user_class_assignments_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_blocked_email_patterns_bi`$$
CREATE TRIGGER `trg_blocked_email_patterns_bi` BEFORE INSERT ON `blocked_email_patterns` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'blocked_email_patterns', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_blocked_email_patterns_bu`$$
CREATE TRIGGER `trg_blocked_email_patterns_bu` BEFORE UPDATE ON `blocked_email_patterns` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `blocked_email_patterns_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `pattern`, `description`, `is_active`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`pattern`, OLD.`description`, OLD.`is_active`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'blocked_email_patterns', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_blocked_email_patterns_bd`$$
CREATE TRIGGER `trg_blocked_email_patterns_bd` BEFORE DELETE ON `blocked_email_patterns` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em blocked_email_patterns. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_blocked_email_patterns_history_bu`$$
CREATE TRIGGER `trg_blocked_email_patterns_history_bu` BEFORE UPDATE ON `blocked_email_patterns_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela blocked_email_patterns_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_blocked_email_patterns_history_bd`$$
CREATE TRIGGER `trg_blocked_email_patterns_history_bd` BEFORE DELETE ON `blocked_email_patterns_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em blocked_email_patterns_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_settings_bi`$$
CREATE TRIGGER `trg_settings_bi` BEFORE INSERT ON `settings` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'settings', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_settings_bu`$$
CREATE TRIGGER `trg_settings_bu` BEFORE UPDATE ON `settings` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `settings_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `setting_key`, `value_json`, `value_type`, `group_name`, `description`, `is_sensitive`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`setting_key`, OLD.`value_json`, OLD.`value_type`, OLD.`group_name`, OLD.`description`, OLD.`is_sensitive`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'settings', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_settings_bd`$$
CREATE TRIGGER `trg_settings_bd` BEFORE DELETE ON `settings` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em settings. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_settings_history_bu`$$
CREATE TRIGGER `trg_settings_history_bu` BEFORE UPDATE ON `settings_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela settings_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_settings_history_bd`$$
CREATE TRIGGER `trg_settings_history_bd` BEFORE DELETE ON `settings_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em settings_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_google_credentials_bi`$$
CREATE TRIGGER `trg_google_credentials_bi` BEFORE INSERT ON `google_credentials` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'google_credentials', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_google_credentials_bu`$$
CREATE TRIGGER `trg_google_credentials_bu` BEFORE UPDATE ON `google_credentials` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `google_credentials_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `kind`, `account_email`, `secret_enc`, `key_version`, `scopes`, `status`, `is_active`, `connected_at`, `connected_by`, `last_refresh_at`, `last_test_at`, `last_error`, `revoked_at`, `revoked_by`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`kind`, OLD.`account_email`, OLD.`secret_enc`, OLD.`key_version`, OLD.`scopes`, OLD.`status`, OLD.`is_active`, OLD.`connected_at`, OLD.`connected_by`, OLD.`last_refresh_at`, OLD.`last_test_at`, OLD.`last_error`, OLD.`revoked_at`, OLD.`revoked_by`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'google_credentials', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_google_credentials_bd`$$
CREATE TRIGGER `trg_google_credentials_bd` BEFORE DELETE ON `google_credentials` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em google_credentials. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_google_credentials_history_bu`$$
CREATE TRIGGER `trg_google_credentials_history_bu` BEFORE UPDATE ON `google_credentials_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela google_credentials_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_google_credentials_history_bd`$$
CREATE TRIGGER `trg_google_credentials_history_bd` BEFORE DELETE ON `google_credentials_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em google_credentials_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_connected_sheets_bi`$$
CREATE TRIGGER `trg_connected_sheets_bi` BEFORE INSERT ON `connected_sheets` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'connected_sheets', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_connected_sheets_bu`$$
CREATE TRIGGER `trg_connected_sheets_bu` BEFORE UPDATE ON `connected_sheets` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `connected_sheets_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `name`, `spreadsheet_id`, `sheet_role`, `direction`, `school_year`, `write_enabled`, `sync_enabled`, `owner_email`, `last_test_at`, `last_test_result`, `last_drive_revision_id`, `last_drive_modified_at`, `last_synced_at`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`name`, OLD.`spreadsheet_id`, OLD.`sheet_role`, OLD.`direction`, OLD.`school_year`, OLD.`write_enabled`, OLD.`sync_enabled`, OLD.`owner_email`, OLD.`last_test_at`, OLD.`last_test_result`, OLD.`last_drive_revision_id`, OLD.`last_drive_modified_at`, OLD.`last_synced_at`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'connected_sheets', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_connected_sheets_bd`$$
CREATE TRIGGER `trg_connected_sheets_bd` BEFORE DELETE ON `connected_sheets` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em connected_sheets. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_connected_sheets_history_bu`$$
CREATE TRIGGER `trg_connected_sheets_history_bu` BEFORE UPDATE ON `connected_sheets_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela connected_sheets_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_connected_sheets_history_bd`$$
CREATE TRIGGER `trg_connected_sheets_history_bd` BEFORE DELETE ON `connected_sheets_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em connected_sheets_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_connected_sheet_tabs_bi`$$
CREATE TRIGGER `trg_connected_sheet_tabs_bi` BEFORE INSERT ON `connected_sheet_tabs` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'connected_sheet_tabs', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_connected_sheet_tabs_bu`$$
CREATE TRIGGER `trg_connected_sheet_tabs_bu` BEFORE UPDATE ON `connected_sheet_tabs` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `connected_sheet_tabs_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `connected_sheet_id`, `tab_title`, `sheet_gid`, `tab_kind`, `class_id`, `header_row`, `first_data_row`, `key_field`, `control_cols_start`, `protected_range_id`, `is_active`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`connected_sheet_id`, OLD.`tab_title`, OLD.`sheet_gid`, OLD.`tab_kind`, OLD.`class_id`, OLD.`header_row`, OLD.`first_data_row`, OLD.`key_field`, OLD.`control_cols_start`, OLD.`protected_range_id`, OLD.`is_active`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'connected_sheet_tabs', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_connected_sheet_tabs_bd`$$
CREATE TRIGGER `trg_connected_sheet_tabs_bd` BEFORE DELETE ON `connected_sheet_tabs` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em connected_sheet_tabs. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_connected_sheet_tabs_history_bu`$$
CREATE TRIGGER `trg_connected_sheet_tabs_history_bu` BEFORE UPDATE ON `connected_sheet_tabs_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela connected_sheet_tabs_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_connected_sheet_tabs_history_bd`$$
CREATE TRIGGER `trg_connected_sheet_tabs_history_bd` BEFORE DELETE ON `connected_sheet_tabs_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em connected_sheet_tabs_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_sheet_column_map_bi`$$
CREATE TRIGGER `trg_sheet_column_map_bi` BEFORE INSERT ON `sheet_column_map` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'sheet_column_map', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_sheet_column_map_bu`$$
CREATE TRIGGER `trg_sheet_column_map_bu` BEFORE UPDATE ON `sheet_column_map` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `sheet_column_map_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `connected_sheet_id`, `tab_id`, `tab_kind`, `column_header`, `column_index`, `field_name`, `transform`, `is_key`, `direction`, `write_allowed`, `is_control`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`connected_sheet_id`, OLD.`tab_id`, OLD.`tab_kind`, OLD.`column_header`, OLD.`column_index`, OLD.`field_name`, OLD.`transform`, OLD.`is_key`, OLD.`direction`, OLD.`write_allowed`, OLD.`is_control`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'sheet_column_map', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_sheet_column_map_bd`$$
CREATE TRIGGER `trg_sheet_column_map_bd` BEFORE DELETE ON `sheet_column_map` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em sheet_column_map. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_sheet_column_map_history_bu`$$
CREATE TRIGGER `trg_sheet_column_map_history_bu` BEFORE UPDATE ON `sheet_column_map_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela sheet_column_map_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_sheet_column_map_history_bd`$$
CREATE TRIGGER `trg_sheet_column_map_history_bd` BEFORE DELETE ON `sheet_column_map_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em sheet_column_map_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_school_years_bi`$$
CREATE TRIGGER `trg_school_years_bi` BEFORE INSERT ON `school_years` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'school_years', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_school_years_bu`$$
CREATE TRIGGER `trg_school_years_bu` BEFORE UPDATE ON `school_years` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `school_years_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `school_year`, `label`, `is_current`, `starts_on`, `ends_on`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`school_year`, OLD.`label`, OLD.`is_current`, OLD.`starts_on`, OLD.`ends_on`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'school_years', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_school_years_bd`$$
CREATE TRIGGER `trg_school_years_bd` BEFORE DELETE ON `school_years` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em school_years. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_school_years_history_bu`$$
CREATE TRIGGER `trg_school_years_history_bu` BEFORE UPDATE ON `school_years_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela school_years_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_school_years_history_bd`$$
CREATE TRIGGER `trg_school_years_history_bd` BEFORE DELETE ON `school_years_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em school_years_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_classes_bi`$$
CREATE TRIGGER `trg_classes_bi` BEFORE INSERT ON `classes` FOR EACH ROW
BEGIN
  SET NEW.`letter` = UPPER(NEW.`letter`);
  SET NEW.`code` = CONCAT(NEW.`grade`, NEW.`letter`, '/', NEW.`school_year`);
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'classes', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_classes_bu`$$
CREATE TRIGGER `trg_classes_bu` BEFORE UPDATE ON `classes` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  SET NEW.`letter` = UPPER(NEW.`letter`);
  SET NEW.`code` = CONCAT(NEW.`grade`, NEW.`letter`, '/', NEW.`school_year`);
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `classes_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `school_year`, `grade`, `letter`, `code`, `weekday`, `starts_at`, `ends_at`, `teacher_user_id`, `classroom_email`, `classroom_id`, `room`, `capacity`, `status`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`school_year`, OLD.`grade`, OLD.`letter`, OLD.`code`, OLD.`weekday`, OLD.`starts_at`, OLD.`ends_at`, OLD.`teacher_user_id`, OLD.`classroom_email`, OLD.`classroom_id`, OLD.`room`, OLD.`capacity`, OLD.`status`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'classes', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_classes_bd`$$
CREATE TRIGGER `trg_classes_bd` BEFORE DELETE ON `classes` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em classes. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_classes_history_bu`$$
CREATE TRIGGER `trg_classes_history_bu` BEFORE UPDATE ON `classes_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela classes_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_classes_history_bd`$$
CREATE TRIGGER `trg_classes_history_bd` BEFORE DELETE ON `classes_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em classes_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_students_bi`$$
CREATE TRIGGER `trg_students_bi` BEFORE INSERT ON `students` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'students', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_students_bu`$$
CREATE TRIGGER `trg_students_bu` BEFORE UPDATE ON `students` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `students_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `full_name`, `full_name_norm`, `school_email`, `ra_enc`, `ra_bidx`, `cpf_enc`, `cpf_bidx`, `rg_enc`, `birth_date_enc`, `birth_year`, `mother_name_enc`, `guardian_email_enc`, `guardian_email_bidx`, `guardian_phone_enc`, `address_enc`, `image_consent`, `social_media_enc`, `health_notes_enc`, `physical_education_enc`, `dentistry_enc`, `origin_school`, `group_name`, `status`, `photo_attachment_id`, `source_row_key`, `key_version`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`full_name`, OLD.`full_name_norm`, OLD.`school_email`, OLD.`ra_enc`, OLD.`ra_bidx`, OLD.`cpf_enc`, OLD.`cpf_bidx`, OLD.`rg_enc`, OLD.`birth_date_enc`, OLD.`birth_year`, OLD.`mother_name_enc`, OLD.`guardian_email_enc`, OLD.`guardian_email_bidx`, OLD.`guardian_phone_enc`, OLD.`address_enc`, OLD.`image_consent`, OLD.`social_media_enc`, OLD.`health_notes_enc`, OLD.`physical_education_enc`, OLD.`dentistry_enc`, OLD.`origin_school`, OLD.`group_name`, OLD.`status`, OLD.`photo_attachment_id`, OLD.`source_row_key`, OLD.`key_version`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'students', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_students_bd`$$
CREATE TRIGGER `trg_students_bd` BEFORE DELETE ON `students` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em students. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_students_history_bu`$$
CREATE TRIGGER `trg_students_history_bu` BEFORE UPDATE ON `students_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela students_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_students_history_bd`$$
CREATE TRIGGER `trg_students_history_bd` BEFORE DELETE ON `students_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em students_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_enrollments_bi`$$
CREATE TRIGGER `trg_enrollments_bi` BEFORE INSERT ON `enrollments` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'enrollments', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_enrollments_bu`$$
CREATE TRIGGER `trg_enrollments_bu` BEFORE UPDATE ON `enrollments` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `enrollments_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `student_id`, `class_id`, `school_year`, `roll_number`, `status`, `started_on`, `ended_on`, `exit_authorized`, `notes`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`student_id`, OLD.`class_id`, OLD.`school_year`, OLD.`roll_number`, OLD.`status`, OLD.`started_on`, OLD.`ended_on`, OLD.`exit_authorized`, OLD.`notes`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'enrollments', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_enrollments_bd`$$
CREATE TRIGGER `trg_enrollments_bd` BEFORE DELETE ON `enrollments` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em enrollments. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_enrollments_history_bu`$$
CREATE TRIGGER `trg_enrollments_history_bu` BEFORE UPDATE ON `enrollments_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela enrollments_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_enrollments_history_bd`$$
CREATE TRIGGER `trg_enrollments_history_bd` BEFORE DELETE ON `enrollments_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em enrollments_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_class_transfers_bi`$$
CREATE TRIGGER `trg_class_transfers_bi` BEFORE INSERT ON `class_transfers` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'class_transfers', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_class_transfers_bu`$$
CREATE TRIGGER `trg_class_transfers_bu` BEFORE UPDATE ON `class_transfers` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `class_transfers_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `student_id`, `from_enrollment_id`, `to_enrollment_id`, `from_class_id`, `to_class_id`, `school_year`, `transferred_at`, `transferred_by`, `record_moved_at`, `record_moved_by`, `reason`, `sheet_outbox_id`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`student_id`, OLD.`from_enrollment_id`, OLD.`to_enrollment_id`, OLD.`from_class_id`, OLD.`to_class_id`, OLD.`school_year`, OLD.`transferred_at`, OLD.`transferred_by`, OLD.`record_moved_at`, OLD.`record_moved_by`, OLD.`reason`, OLD.`sheet_outbox_id`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'class_transfers', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_class_transfers_bd`$$
CREATE TRIGGER `trg_class_transfers_bd` BEFORE DELETE ON `class_transfers` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em class_transfers. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_class_transfers_history_bu`$$
CREATE TRIGGER `trg_class_transfers_history_bu` BEFORE UPDATE ON `class_transfers_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela class_transfers_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_class_transfers_history_bd`$$
CREATE TRIGGER `trg_class_transfers_history_bd` BEFORE DELETE ON `class_transfers_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em class_transfers_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_withdrawals_bi`$$
CREATE TRIGGER `trg_withdrawals_bi` BEFORE INSERT ON `withdrawals` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'withdrawals', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_withdrawals_bu`$$
CREATE TRIGGER `trg_withdrawals_bu` BEFORE UPDATE ON `withdrawals` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `withdrawals_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `student_id`, `enrollment_id`, `class_id`, `school_year`, `withdrawn_at`, `withdrawn_by`, `reason_code`, `reason`, `documents_returned_at`, `documents_returned_by`, `sheet_outbox_id`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`student_id`, OLD.`enrollment_id`, OLD.`class_id`, OLD.`school_year`, OLD.`withdrawn_at`, OLD.`withdrawn_by`, OLD.`reason_code`, OLD.`reason`, OLD.`documents_returned_at`, OLD.`documents_returned_by`, OLD.`sheet_outbox_id`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'withdrawals', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_withdrawals_bd`$$
CREATE TRIGGER `trg_withdrawals_bd` BEFORE DELETE ON `withdrawals` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em withdrawals. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_withdrawals_history_bu`$$
CREATE TRIGGER `trg_withdrawals_history_bu` BEFORE UPDATE ON `withdrawals_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela withdrawals_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_withdrawals_history_bd`$$
CREATE TRIGGER `trg_withdrawals_history_bd` BEFORE DELETE ON `withdrawals_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em withdrawals_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_school_transfers_bi`$$
CREATE TRIGGER `trg_school_transfers_bi` BEFORE INSERT ON `school_transfers` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'school_transfers', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_school_transfers_bu`$$
CREATE TRIGGER `trg_school_transfers_bu` BEFORE UPDATE ON `school_transfers` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `school_transfers_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `student_id`, `enrollment_id`, `school_year`, `transferred_at`, `transferred_by`, `destination_school`, `declaration_id`, `notes`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`student_id`, OLD.`enrollment_id`, OLD.`school_year`, OLD.`transferred_at`, OLD.`transferred_by`, OLD.`destination_school`, OLD.`declaration_id`, OLD.`notes`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'school_transfers', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_school_transfers_bd`$$
CREATE TRIGGER `trg_school_transfers_bd` BEFORE DELETE ON `school_transfers` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em school_transfers. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_school_transfers_history_bu`$$
CREATE TRIGGER `trg_school_transfers_history_bu` BEFORE UPDATE ON `school_transfers_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela school_transfers_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_school_transfers_history_bd`$$
CREATE TRIGGER `trg_school_transfers_history_bd` BEFORE DELETE ON `school_transfers_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em school_transfers_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_diary_lessons_bi`$$
CREATE TRIGGER `trg_diary_lessons_bi` BEFORE INSERT ON `diary_lessons` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'diary_lessons', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_diary_lessons_bu`$$
CREATE TRIGGER `trg_diary_lessons_bu` BEFORE UPDATE ON `diary_lessons` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `diary_lessons_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `class_id`, `lesson_date`, `lesson_number`, `content`, `homework`, `locked_at`, `unlock_request_id`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`class_id`, OLD.`lesson_date`, OLD.`lesson_number`, OLD.`content`, OLD.`homework`, OLD.`locked_at`, OLD.`unlock_request_id`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'diary_lessons', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_diary_lessons_bd`$$
CREATE TRIGGER `trg_diary_lessons_bd` BEFORE DELETE ON `diary_lessons` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em diary_lessons. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_diary_lessons_history_bu`$$
CREATE TRIGGER `trg_diary_lessons_history_bu` BEFORE UPDATE ON `diary_lessons_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela diary_lessons_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_diary_lessons_history_bd`$$
CREATE TRIGGER `trg_diary_lessons_history_bd` BEFORE DELETE ON `diary_lessons_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em diary_lessons_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_diary_attendance_bi`$$
CREATE TRIGGER `trg_diary_attendance_bi` BEFORE INSERT ON `diary_attendance` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'diary_attendance', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_diary_attendance_bu`$$
CREATE TRIGGER `trg_diary_attendance_bu` BEFORE UPDATE ON `diary_attendance` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `diary_attendance_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `lesson_id`, `enrollment_id`, `status`, `note`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`lesson_id`, OLD.`enrollment_id`, OLD.`status`, OLD.`note`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'diary_attendance', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_diary_attendance_bd`$$
CREATE TRIGGER `trg_diary_attendance_bd` BEFORE DELETE ON `diary_attendance` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em diary_attendance. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_diary_attendance_history_bu`$$
CREATE TRIGGER `trg_diary_attendance_history_bu` BEFORE UPDATE ON `diary_attendance_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela diary_attendance_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_diary_attendance_history_bd`$$
CREATE TRIGGER `trg_diary_attendance_history_bd` BEFORE DELETE ON `diary_attendance_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em diary_attendance_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_attachments_bi`$$
CREATE TRIGGER `trg_attachments_bi` BEFORE INSERT ON `attachments` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'attachments', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_attachments_bu`$$
CREATE TRIGGER `trg_attachments_bu` BEFORE UPDATE ON `attachments` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `attachments_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `owner_entity`, `owner_id`, `kind`, `original_name_enc`, `stored_name`, `mime_type`, `size_bytes`, `sha256`, `key_version`, `uploaded_by`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`owner_entity`, OLD.`owner_id`, OLD.`kind`, OLD.`original_name_enc`, OLD.`stored_name`, OLD.`mime_type`, OLD.`size_bytes`, OLD.`sha256`, OLD.`key_version`, OLD.`uploaded_by`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'attachments', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_attachments_bd`$$
CREATE TRIGGER `trg_attachments_bd` BEFORE DELETE ON `attachments` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em attachments. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_attachments_history_bu`$$
CREATE TRIGGER `trg_attachments_history_bu` BEFORE UPDATE ON `attachments_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela attachments_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_attachments_history_bd`$$
CREATE TRIGGER `trg_attachments_history_bd` BEFORE DELETE ON `attachments_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em attachments_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_student_documents_bi`$$
CREATE TRIGGER `trg_student_documents_bi` BEFORE INSERT ON `student_documents` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'student_documents', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_student_documents_bu`$$
CREATE TRIGGER `trg_student_documents_bu` BEFORE UPDATE ON `student_documents` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `student_documents_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `student_id`, `enrollment_id`, `kind`, `from_date`, `to_date`, `days`, `details_enc`, `key_version`, `attachment_id`, `access_level`, `recorded_by`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`student_id`, OLD.`enrollment_id`, OLD.`kind`, OLD.`from_date`, OLD.`to_date`, OLD.`days`, OLD.`details_enc`, OLD.`key_version`, OLD.`attachment_id`, OLD.`access_level`, OLD.`recorded_by`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'student_documents', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_student_documents_bd`$$
CREATE TRIGGER `trg_student_documents_bd` BEFORE DELETE ON `student_documents` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em student_documents. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_student_documents_history_bu`$$
CREATE TRIGGER `trg_student_documents_history_bu` BEFORE UPDATE ON `student_documents_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela student_documents_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_student_documents_history_bd`$$
CREATE TRIGGER `trg_student_documents_history_bd` BEFORE DELETE ON `student_documents_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em student_documents_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_staff_bi`$$
CREATE TRIGGER `trg_staff_bi` BEFORE INSERT ON `staff` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'staff', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_staff_bu`$$
CREATE TRIGGER `trg_staff_bu` BEFORE UPDATE ON `staff` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `staff_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `user_id`, `full_name`, `job_title`, `registration_enc`, `phone_enc`, `work_email`, `status`, `started_on`, `ended_on`, `key_version`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`user_id`, OLD.`full_name`, OLD.`job_title`, OLD.`registration_enc`, OLD.`phone_enc`, OLD.`work_email`, OLD.`status`, OLD.`started_on`, OLD.`ended_on`, OLD.`key_version`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'staff', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_staff_bd`$$
CREATE TRIGGER `trg_staff_bd` BEFORE DELETE ON `staff` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em staff. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_staff_history_bu`$$
CREATE TRIGGER `trg_staff_history_bu` BEFORE UPDATE ON `staff_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela staff_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_staff_history_bd`$$
CREATE TRIGGER `trg_staff_history_bd` BEFORE DELETE ON `staff_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em staff_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_declaration_templates_bi`$$
CREATE TRIGGER `trg_declaration_templates_bi` BEFORE INSERT ON `declaration_templates` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'declaration_templates', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_declaration_templates_bu`$$
CREATE TRIGGER `trg_declaration_templates_bu` BEFORE UPDATE ON `declaration_templates` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `declaration_templates_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `code`, `name`, `body_html`, `template_version`, `is_active`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`code`, OLD.`name`, OLD.`body_html`, OLD.`template_version`, OLD.`is_active`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'declaration_templates', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_declaration_templates_bd`$$
CREATE TRIGGER `trg_declaration_templates_bd` BEFORE DELETE ON `declaration_templates` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em declaration_templates. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_declaration_templates_history_bu`$$
CREATE TRIGGER `trg_declaration_templates_history_bu` BEFORE UPDATE ON `declaration_templates_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela declaration_templates_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_declaration_templates_history_bd`$$
CREATE TRIGGER `trg_declaration_templates_history_bd` BEFORE DELETE ON `declaration_templates_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em declaration_templates_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_branding_assets_bi`$$
CREATE TRIGGER `trg_branding_assets_bi` BEFORE INSERT ON `branding_assets` FOR EACH ROW
BEGIN
  IF @app_origin IS NULL THEN
    SET NEW.`origin` = 'FORA_DA_APLICACAO';
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'branding_assets', NULL,
              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN
    SET NEW.`origin` = @app_origin;
  END IF;
  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;
  SET NEW.`version` = 1;
  IF NEW.`deleted_at` IS NOT NULL THEN
    SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Nao e permitido inserir um registro ja excluido.';
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_branding_assets_bu`$$
CREATE TRIGGER `trg_branding_assets_bu` BEFORE UPDATE ON `branding_assets` FOR EACH ROW
BEGIN
  DECLARE v_origin VARCHAR(60);
  DECLARE v_op VARCHAR(12);
  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');
  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN
    SET v_op = 'SOFT_DELETE';
    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).';
    END IF;
    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;
    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN ('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA') THEN
      SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Exclusao logica exige o usuario responsavel (deleted_by).';
    END IF;
  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN
    SET v_op = 'RESTORE';
    SET NEW.`deleted_by` = NULL;
    SET NEW.`delete_reason` = NULL;
  ELSE
    SET v_op = 'UPDATE';
  END IF;
  SET NEW.`version` = OLD.`version` + 1;
  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;
  SET NEW.`origin` = v_origin;
  INSERT INTO `branding_assets_history` (`history_op`, `history_at`, `history_by`, `history_origin`, `id`, `kind`, `attachment_id`, `is_active`, `palette_json`, `version`, `origin`, `created_at`, `created_by`, `updated_at`, `updated_by`, `deleted_at`, `deleted_by`, `delete_reason`)
    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, OLD.`id`, OLD.`kind`, OLD.`attachment_id`, OLD.`is_active`, OLD.`palette_json`, OLD.`version`, OLD.`origin`, OLD.`created_at`, OLD.`created_by`, OLD.`updated_at`, OLD.`updated_by`, OLD.`deleted_at`, OLD.`deleted_by`, OLD.`delete_reason`);
  IF @app_origin IS NULL THEN
    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)
      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, 'branding_assets', OLD.`id`,
              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));
  END IF;
END$$

DROP TRIGGER IF EXISTS `trg_branding_assets_bd`$$
CREATE TRIGGER `trg_branding_assets_bd` BEFORE DELETE ON `branding_assets` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em branding_assets. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DROP TRIGGER IF EXISTS `trg_branding_assets_history_bu`$$
CREATE TRIGGER `trg_branding_assets_history_bu` BEFORE UPDATE ON `branding_assets_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'Tabela branding_assets_history e somente para inclusao: UPDATE nao permitido.';
END$$

DROP TRIGGER IF EXISTS `trg_branding_assets_history_bd`$$
CREATE TRIGGER `trg_branding_assets_history_bd` BEFORE DELETE ON `branding_assets_history` FOR EACH ROW
BEGIN
  SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = 'DELETE fisico nao permitido em branding_assets_history. Use a exclusao logica (deleted_at) pela aplicacao.';
END$$

DELIMITER ;
