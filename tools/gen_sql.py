#!/usr/bin/env python3
"""
tools/gen_sql.py — gerador das tabelas *_history e do arquivo sql/triggers.sql

Lê sql/schema.sql, interpreta os marcadores:
    -- @history                       → cria <tabela>_history + triggers de versionamento/soft delete
    -- @append-only [allow: c1, c2]   → bloqueia DELETE; bloqueia UPDATE (exceto nas colunas listadas)
    -- @no-delete                     → bloqueia DELETE
e escreve:
    sql/schema.sql   (substitui o marcador -- @@HISTORY_TABLES@@ pelas tabelas de histórico)
    sql/triggers.sql

Ferramenta de desenvolvimento: o Flávio não precisa executá-la. Os arquivos gerados já vão prontos no repositório.
Uso:  python3 tools/gen_sql.py
"""
import re, sys, pathlib

ROOT = pathlib.Path(__file__).resolve().parent.parent
SCHEMA = ROOT / 'sql' / 'schema.sql'
TRIGGERS = ROOT / 'sql' / 'triggers.sql'
TEMPLATE_BACKUP = ROOT / 'tools' / 'schema.template.sql'

SYSTEM_ORIGINS_SQL = "('CRON', 'SEED', 'CARGA_INICIAL_PLANILHA')"  # além de PLANILHA:%

# regras específicas por tabela, inseridas no início dos triggers BEFORE INSERT / BEFORE UPDATE
HOOKS = {
    'classes': {
        'bi': ["  SET NEW.`letter` = UPPER(NEW.`letter`);",
               "  SET NEW.`code` = CONCAT(NEW.`grade`, NEW.`letter`, '/', NEW.`school_year`);"],
        'bu': ["  SET NEW.`letter` = UPPER(NEW.`letter`);",
               "  SET NEW.`code` = CONCAT(NEW.`grade`, NEW.`letter`, '/', NEW.`school_year`);"],
    },
    'users': {
        'bi': ["  SET NEW.`email` = LOWER(TRIM(NEW.`email`));"],
        'bu': ["  SET NEW.`email` = LOWER(TRIM(NEW.`email`));"],
    },
}

src = SCHEMA.read_text(encoding='utf-8')
if '-- @@HISTORY_TABLES@@' in src:
    TEMPLATE_BACKUP.write_text(src, encoding='utf-8')   # guarda o template para regenerações futuras
else:
    src = TEMPLATE_BACKUP.read_text(encoding='utf-8')

# ---------------------------------------------------------------- parsing
tables = {}   # name -> dict(marker, allow, cols=[(name,type,generated)], has_soft_delete)
order = []
pat = re.compile(r"--\s*@(history|append-only|no-delete)([^\n]*)\nCREATE TABLE IF NOT EXISTS `(\w+)` \((.*?)\n\) ENGINE", re.S)
for m in pat.finditer(src):
    marker, extra, name, body = m.group(1), m.group(2), m.group(3), m.group(4)
    allow = []
    am = re.search(r'allow:\s*([\w,\s]+)', extra)
    if am:
        allow = [c.strip() for c in am.group(1).split(',') if c.strip()]
    cols = []
    for line in body.split('\n'):
        cm = re.match(r"\s+`(\w+)`\s+(.*?),?\s*$", line)
        if not cm:
            continue
        cname, rest = cm.group(1), cm.group(2)
        tm = re.match(r"((?:\w+)(?:\([^)]*\))?(?:\s+UNSIGNED)?)", rest)
        ctype = tm.group(1)
        cols.append((cname, ctype, 'GENERATED ALWAYS' in rest))
    names = [c[0] for c in cols]
    tables[name] = dict(marker=marker, allow=allow, cols=cols,
                        soft=('deleted_at' in names and 'delete_reason' in names),
                        has_origin='origin' in names, has_version='version' in names,
                        has_created_by='created_by' in names, has_updated_by='updated_by' in names)
    order.append(name)

# ---------------------------------------------------------------- history tables
hist_sql = ["-- =====================================================================================================",
            "-- 5. TABELAS DE HISTÓRICO (geradas por tools/gen_sql.py — preenchidas somente por trigger)",
            "--    Mesmas colunas da tabela-mãe (todas opcionais) + history_*. Colunas geradas não são copiadas.",
            "-- ====================================================================================================="]
for name in order:
    t = tables[name]
    if t['marker'] != 'history':
        continue
    lines = [f"CREATE TABLE IF NOT EXISTS `{name}_history` (",
             "  `history_id`     BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,",
             "  `history_op`     VARCHAR(12) NOT NULL COMMENT 'UPDATE | SOFT_DELETE | RESTORE',",
             "  `history_at`     DATETIME(3) NOT NULL DEFAULT CURRENT_TIMESTAMP(3),",
             "  `history_by`     BIGINT UNSIGNED NULL COMMENT '@app_user_id no momento da alteração',",
             "  `history_origin` VARCHAR(60) NOT NULL COMMENT 'APP | CRON | PLANILHA:<nome> | FORA_DA_APLICACAO ...',"]
    for cname, ctype, gen in t['cols']:
        if gen:
            continue
        lines.append(f"  `{cname}` {ctype} NULL,")
    lines.append("  PRIMARY KEY (`history_id`),")
    lines.append(f"  KEY `ix_{name}_hist_row` (`id`, `history_at`)")
    lines.append(f") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci COMMENT='Versões anteriores de {name}';")
    hist_sql.append('\n'.join(lines))
    hist_sql.append('')

final_schema = src.replace('-- @@HISTORY_TABLES@@', '\n'.join(hist_sql) + "\nSET FOREIGN_KEY_CHECKS = 1;\n")
SCHEMA.write_text(final_schema, encoding='utf-8')

# ---------------------------------------------------------------- triggers
out = []
w = out.append
w("""-- =====================================================================================================
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
""")

def sig(msg):
    return f"SIGNAL SQLSTATE '45000' SET MESSAGE_TEXT = '{msg}';"

# ---- audit_log (escrito à mão)
w("-- -----------------------------------------------------------------------------------------------------")
w("-- audit_log: cadeia de hash + origem + imutabilidade")
w("-- -----------------------------------------------------------------------------------------------------")
w("DROP TRIGGER IF EXISTS `trg_audit_log_bi`$$")
w("""CREATE TRIGGER `trg_audit_log_bi` BEFORE INSERT ON `audit_log` FOR EACH ROW
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
""")

def guard_update(name, allow):
    """Trigger BEFORE UPDATE para tabelas append-only (opcionalmente permitindo algumas colunas)."""
    w(f"DROP TRIGGER IF EXISTS `trg_{name}_bu`$$")
    if not allow:
        w(f"""CREATE TRIGGER `trg_{name}_bu` BEFORE UPDATE ON `{name}` FOR EACH ROW
BEGIN
  {sig(f'Tabela {name} e somente para inclusao: UPDATE nao permitido.')}
END$$
""")
        return
    conds = []
    for cname, ctype, gen in tables[name]['cols']:
        if gen or cname in allow:
            continue
        conds.append(f"NOT (OLD.`{cname}` <=> NEW.`{cname}`)")
    cond = "\n      OR ".join(conds)
    allowed = ', '.join(allow)
    w(f"""CREATE TRIGGER `trg_{name}_bu` BEFORE UPDATE ON `{name}` FOR EACH ROW
BEGIN
  -- somente as colunas [{allowed}] podem mudar
  IF {cond} THEN
    {sig(f'Tabela {name}: somente as colunas {allowed} podem ser alteradas.')}
  END IF;
END$$
""")

def guard_delete(name):
    w(f"DROP TRIGGER IF EXISTS `trg_{name}_bd`$$")
    w(f"""CREATE TRIGGER `trg_{name}_bd` BEFORE DELETE ON `{name}` FOR EACH ROW
BEGIN
  {sig(f'DELETE fisico nao permitido em {name}. Use a exclusao logica (deleted_at) pela aplicacao.')}
END$$
""")

# audit_log guards
guard_update('audit_log', [])
guard_delete('audit_log')

# ---- demais append-only / no-delete
w("-- -----------------------------------------------------------------------------------------------------")
w("-- Tabelas somente-inclusão (append-only) e tabelas sem DELETE")
w("-- -----------------------------------------------------------------------------------------------------")
for name in order:
    t = tables[name]
    if name == 'audit_log':
        continue
    if t['marker'] == 'append-only':
        guard_update(name, t['allow'])
        guard_delete(name)
    elif t['marker'] == 'no-delete':
        guard_delete(name)

# ---- history / versionamento
w("-- -----------------------------------------------------------------------------------------------------")
w("-- Versionamento (BEFORE UPDATE → *_history), exclusão lógica validada, origem e detecção FORA_DA_APLICACAO")
w("-- -----------------------------------------------------------------------------------------------------")
for name in order:
    t = tables[name]
    if t['marker'] != 'history':
        continue
    plain_cols = [c for c in t['cols'] if not c[2]]
    col_list = ', '.join(f"`{c[0]}`" for c in plain_cols)
    old_list = ', '.join(f"OLD.`{c[0]}`" for c in plain_cols)

    # BEFORE INSERT
    w(f"DROP TRIGGER IF EXISTS `trg_{name}_bi`$$")
    body = list(HOOKS.get(name, {}).get('bi', []))
    body.append("  IF @app_origin IS NULL THEN")
    if t['has_origin']:
        body.append("    SET NEW.`origin` = 'FORA_DA_APLICACAO';")
    body.append(f"    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)")
    body.append(f"      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, '{name}', NULL,")
    body.append(f"              JSON_OBJECT('operacao', 'INSERT', 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));")
    if t['has_origin']:
        body.append("  ELSEIF NEW.`origin` IS NULL OR NEW.`origin` = '' OR NEW.`origin` = 'APP' THEN")
        body.append("    SET NEW.`origin` = @app_origin;")
    body.append("  END IF;")
    if t['has_created_by']:
        body.append("  IF NEW.`created_by` IS NULL THEN SET NEW.`created_by` = @app_user_id; END IF;")
    if t['has_version']:
        body.append("  SET NEW.`version` = 1;")
    if t['soft']:
        body.append("  IF NEW.`deleted_at` IS NOT NULL THEN")
        body.append(f"    {sig('Nao e permitido inserir um registro ja excluido.')}")
        body.append("  END IF;")
    w(f"CREATE TRIGGER `trg_{name}_bi` BEFORE INSERT ON `{name}` FOR EACH ROW\nBEGIN\n" + '\n'.join(body) + "\nEND$$\n")

    # BEFORE UPDATE
    w(f"DROP TRIGGER IF EXISTS `trg_{name}_bu`$$")
    body = []
    body.append("  DECLARE v_origin VARCHAR(60);")
    body.append("  DECLARE v_op VARCHAR(12);")
    if name == 'users':
        body.append("  DECLARE v_other_super INT;")
    body.append("  SET v_origin = COALESCE(@app_origin, 'FORA_DA_APLICACAO');")
    body.extend(HOOKS.get(name, {}).get('bu', []))
    if t['soft']:
        body.append("  IF OLD.`deleted_at` IS NULL AND NEW.`deleted_at` IS NOT NULL THEN")
        body.append("    SET v_op = 'SOFT_DELETE';")
        body.append("    IF NEW.`delete_reason` IS NULL OR CHAR_LENGTH(TRIM(NEW.`delete_reason`)) < 10 THEN")
        body.append(f"      {sig('Exclusao logica exige motivo com no minimo 10 caracteres (delete_reason).')}")
        body.append("    END IF;")
        body.append("    IF NEW.`deleted_by` IS NULL THEN SET NEW.`deleted_by` = @app_user_id; END IF;")
        body.append(f"    IF NEW.`deleted_by` IS NULL AND v_origin NOT LIKE 'PLANILHA:%' AND v_origin NOT IN {SYSTEM_ORIGINS_SQL} THEN")
        body.append(f"      {sig('Exclusao logica exige o usuario responsavel (deleted_by).')}")
        body.append("    END IF;")
        body.append("  ELSEIF OLD.`deleted_at` IS NOT NULL AND NEW.`deleted_at` IS NULL THEN")
        body.append("    SET v_op = 'RESTORE';")
        body.append("    SET NEW.`deleted_by` = NULL;")
        body.append("    SET NEW.`delete_reason` = NULL;")
        body.append("  ELSE")
        body.append("    SET v_op = 'UPDATE';")
        body.append("  END IF;")
    else:
        body.append("  SET v_op = 'UPDATE';")
    if name == 'users':
        body.append("  -- protecao: nunca deixar o sistema sem Super Administrador ativo")
        body.append("  IF (SELECT r.`code` FROM `roles` r WHERE r.`id` = OLD.`role_id`) = 'SUPER_ADMIN'")
        body.append("     AND OLD.`is_active` = 1 AND OLD.`deleted_at` IS NULL")
        body.append("     AND (NEW.`is_active` = 0 OR NEW.`deleted_at` IS NOT NULL OR NEW.`role_id` <> OLD.`role_id`) THEN")
        body.append("    SET v_other_super = (SELECT COUNT(*) FROM `users` u JOIN `roles` r ON r.`id` = u.`role_id`")
        body.append("                         WHERE r.`code` = 'SUPER_ADMIN' AND u.`is_active` = 1 AND u.`deleted_at` IS NULL AND u.`id` <> OLD.`id`);")
        body.append("    IF v_other_super = 0 THEN")
        body.append(f"      {sig('Nao e possivel remover, rebaixar ou desativar o ultimo Super Administrador ativo.')}")
        body.append("    END IF;")
        body.append("  END IF;")
    if t['has_version']:
        body.append("  SET NEW.`version` = OLD.`version` + 1;")
    if t['has_updated_by']:
        body.append("  IF NEW.`updated_by` IS NULL OR NEW.`updated_by` <=> OLD.`updated_by` THEN SET NEW.`updated_by` = @app_user_id; END IF;")
    if t['has_origin']:
        body.append("  SET NEW.`origin` = v_origin;")
    body.append(f"  INSERT INTO `{name}_history` (`history_op`, `history_at`, `history_by`, `history_origin`, {col_list})")
    body.append(f"    VALUES (v_op, CURRENT_TIMESTAMP(3), @app_user_id, v_origin, {old_list});")
    body.append("  IF @app_origin IS NULL THEN")
    body.append(f"    INSERT INTO `security_events` (`severity`, `kind`, `user_id`, `entity`, `entity_id`, `detail_json`)")
    body.append(f"      VALUES ('CRITICO', 'FORA_DA_APLICACAO', NULL, '{name}', OLD.`id`,")
    body.append(f"              JSON_OBJECT('operacao', v_op, 'usuario_mysql', CURRENT_USER(), 'conexao', CONNECTION_ID()));")
    body.append("  END IF;")
    w(f"CREATE TRIGGER `trg_{name}_bu` BEFORE UPDATE ON `{name}` FOR EACH ROW\nBEGIN\n" + '\n'.join(body) + "\nEND$$\n")

    # BEFORE DELETE
    guard_delete(name)

    # a tabela de histórico também é somente-inclusão
    guard_update(f"{name}_history", [])
    guard_delete(f"{name}_history")
w("DELIMITER ;\n")

txt = '\n'.join(out)
TRIGGERS.write_text(txt, encoding='utf-8')
print(f"tabelas lidas: {len(tables)} | history: {sum(1 for t in tables.values() if t['marker']=='history')} | append-only: {sum(1 for t in tables.values() if t['marker']=='append-only')} | no-delete: {sum(1 for t in tables.values() if t['marker']=='no-delete')}")
