-- =====================================================================================================
-- sql/seed.sql
-- Sistema de Gestão Escolar CELEF — dados iniciais (Fase 1)
--
-- Importar DEPOIS de schema.sql e triggers.sql, no phpMyAdmin, com o usuário de INSTALAÇÃO.
-- Idempotente: usa INSERT IGNORE (nunca sobrescreve ajustes feitos depois pelo admin).
--
-- Cria: perfis, permissões, permissões por perfil, configurações, padrões de e-mail bloqueados,
--       anos letivos, modelos de declaração, o Super Administrador inicial e a primeira linha da auditoria.
-- =====================================================================================================

SET NAMES utf8mb4;
SET time_zone = '-03:00';

-- Contexto para os triggers: origem SEED (não dispara alerta FORA_DA_APLICACAO), sem usuário.
SET @app_origin  = 'SEED';
SET @app_user_id = NULL;

-- -----------------------------------------------------------------------------------------------------
-- 1. Perfis
-- -----------------------------------------------------------------------------------------------------
INSERT IGNORE INTO `roles` (`code`, `name`, `description`, `is_system`, `origin`) VALUES
  ('SUPER_ADMIN', 'Super Administrador', 'Acesso total, inclusive gerenciar administradores, conta técnica e planilhas conectadas.', 1, 'SEED'),
  ('ADMIN',       'Administrador',       'Acesso total, exceto gerenciar Super Administradores, conta técnica e planilhas conectadas.', 1, 'SEED'),
  ('SECRETARIA',  'Secretaria',          'Matrícula, remanejamento, desistência, transferência, declarações.', 1, 'SEED'),
  ('COORDENACAO', 'Coordenação',         'Vê tudo; edita diários e observações pedagógicas.', 1, 'SEED'),
  ('PROFESSOR',   'Professor(a)',        'Somente as próprias turmas: lista, frequência, diário, observações.', 1, 'SEED'),
  ('AUDITOR',     'Auditor (leitura)',   'Somente leitura e trilha de auditoria; não vê dados sensíveis completos.', 1, 'SEED');

-- -----------------------------------------------------------------------------------------------------
-- 2. Permissões (is_sensitive = 1 → exige reautenticação Google + motivo)
-- -----------------------------------------------------------------------------------------------------
INSERT IGNORE INTO `permissions` (`code`, `module`, `description`, `is_sensitive`) VALUES
  ('aluno.ver',                 'aluno',         'Ver ficha do aluno com dados sensíveis mascarados', 0),
  ('aluno.criar',               'aluno',         'Cadastrar aluno', 0),
  ('aluno.editar',              'aluno',         'Editar ficha do aluno', 0),
  ('aluno.excluir',             'aluno',         'Excluir aluno (exclusão lógica com motivo)', 1),
  ('aluno.restaurar',           'aluno',         'Restaurar aluno da lixeira', 1),
  ('aluno.ver_sensivel',        'aluno',         'Ver CPF, RG, R.A., endereço, telefone e e-mail do responsável sem máscara', 1),
  ('aluno.ver_documentos',      'aluno',         'Ver atestados, laudos e anexos do aluno', 1),
  ('aluno.historico',           'aluno',         'Ver linha do tempo de alterações do aluno', 0),
  ('turma.ver',                 'turma',         'Ver turmas e listas', 0),
  ('turma.criar',               'turma',         'Criar turma', 0),
  ('turma.editar',              'turma',         'Editar turma', 0),
  ('turma.excluir',             'turma',         'Excluir turma (exclusão lógica)', 1),
  ('matricula.ver',             'matricula',     'Ver matrículas', 0),
  ('matricula.criar',           'matricula',     'Matricular aluno em turma', 0),
  ('matricula.editar',          'matricula',     'Editar matrícula (nº, datas, saída)', 0),
  ('matricula.editar_observacoes', 'matricula',  'Editar observações pedagógicas da lista', 0),
  ('remanejamento.ver',         'remanejamento', 'Ver remanejamentos', 0),
  ('remanejamento.registrar',   'remanejamento', 'Registrar remanejamento entre turmas', 0),
  ('desistencia.ver',           'desistencia',   'Ver desistências', 0),
  ('desistencia.registrar',     'desistencia',   'Registrar desistência', 0),
  ('transferencia.ver',         'transferencia', 'Ver transferências', 0),
  ('transferencia.registrar',   'transferencia', 'Registrar transferência para outra escola', 0),
  ('diario.ver',                'diario',        'Ver diário e frequência', 0),
  ('diario.editar',             'diario',        'Lançar aulas e frequência dentro do prazo', 0),
  ('diario.editar_fora_prazo',  'diario',        'Editar diário fora do prazo (com justificativa)', 0),
  ('diario.aprovar_edicao',     'diario',        'Aprovar pedidos de edição fora do prazo', 0),
  ('documento.ver',             'documento',     'Ver atestados e justificativas (conforme nível de acesso)', 0),
  ('documento.criar',           'documento',     'Registrar atestado, laudo ou justificativa', 0),
  ('documento.editar',          'documento',     'Editar documentos do aluno', 0),
  ('documento.ver_laudo',       'documento',     'Ver laudos (acesso restrito)', 1),
  ('carometro.ver',             'carometro',     'Ver carômetro (só alunos com autorização de imagem)', 0),
  ('carometro.cracha',          'carometro',     'Gerar crachás em PDF', 0),
  ('declaracao.emitir',         'declaracao',    'Emitir declarações em PDF', 0),
  ('declaracao.revogar',        'declaracao',    'Revogar declaração emitida', 1),
  ('funcionario.ver',           'funcionario',   'Ver cadastro de funcionários', 0),
  ('funcionario.editar',        'funcionario',   'Editar cadastro de funcionários', 0),
  ('indicadores.ver',           'indicadores',   'Ver painel de indicadores', 0),
  ('exportar',                  'exportar',      'Exportar dados (com motivo e marca d água)', 1),
  ('exportar.aprovar_massa',    'exportar',      'Aprovar exportação em massa', 1),
  ('auditoria.ver',             'auditoria',     'Consultar trilha de auditoria', 0),
  ('auditoria.verificar',       'auditoria',     'Verificar a cadeia de hash', 0),
  ('auditoria.conferir_planilha', 'auditoria',   'Conferir planilha de logs × banco', 0),
  ('lgpd.relatorio_acessos',    'lgpd',          'Relatório "quem acessou os dados deste aluno"', 0),
  ('admin.usuarios',            'admin',         'Cadastrar, editar, ativar/desativar usuários', 1),
  ('admin.administradores',     'admin',         'Criar, promover e rebaixar administradores', 1),
  ('admin.perfis',              'admin',         'Ajustar permissões por perfil', 1),
  ('admin.conta_tecnica',       'admin',         'Conectar/reconectar/revogar a conta técnica Google', 1),
  ('admin.planilhas',           'admin',         'Cadastrar e mapear planilhas conectadas', 1),
  ('admin.planilha_logs',       'admin',         'Configurar a planilha de logs e segurança', 1),
  ('admin.sincronizacao',       'admin',         'Ver status, sincronizar agora, resolver conflitos', 1),
  ('admin.seguranca',           'admin',         'Painel de segurança, sessões ativas, alertas', 1),
  ('admin.configuracoes',       'admin',         'Configurações gerais', 1),
  ('admin.lixeira',             'admin',         'Ver e restaurar registros excluídos', 1),
  ('admin.identidade_visual',   'admin',         'Trocar logo, fachada e favicon', 0),
  ('admin.backups',             'admin',         'Ver backups e registrar teste de restauração', 1);

-- -----------------------------------------------------------------------------------------------------
-- 3. Permissões por perfil (ajustáveis em Admin → Perfis e permissões)
-- -----------------------------------------------------------------------------------------------------
-- SUPER_ADMIN: tudo
INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`)
  SELECT r.`id`, p.`id` FROM `roles` r JOIN `permissions` p WHERE r.`code` = 'SUPER_ADMIN';

-- ADMIN: tudo, exceto administradores, conta técnica e planilhas (exclusivos do Super Admin)
INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`)
  SELECT r.`id`, p.`id` FROM `roles` r JOIN `permissions` p
  WHERE r.`code` = 'ADMIN'
    AND p.`code` NOT IN ('admin.administradores', 'admin.conta_tecnica', 'admin.planilhas', 'admin.planilha_logs');

-- SECRETARIA
INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`)
  SELECT r.`id`, p.`id` FROM `roles` r JOIN `permissions` p
  WHERE r.`code` = 'SECRETARIA' AND p.`code` IN (
    'aluno.ver', 'aluno.criar', 'aluno.editar', 'aluno.excluir', 'aluno.ver_sensivel', 'aluno.ver_documentos', 'aluno.historico',
    'turma.ver', 'turma.criar', 'turma.editar',
    'matricula.ver', 'matricula.criar', 'matricula.editar', 'matricula.editar_observacoes',
    'remanejamento.ver', 'remanejamento.registrar', 'desistencia.ver', 'desistencia.registrar',
    'transferencia.ver', 'transferencia.registrar',
    'documento.ver', 'documento.criar', 'documento.editar',
    'carometro.ver', 'carometro.cracha', 'declaracao.emitir',
    'funcionario.ver', 'indicadores.ver', 'exportar', 'lgpd.relatorio_acessos');

-- COORDENACAO
INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`)
  SELECT r.`id`, p.`id` FROM `roles` r JOIN `permissions` p
  WHERE r.`code` = 'COORDENACAO' AND p.`code` IN (
    'aluno.ver', 'aluno.ver_sensivel', 'aluno.ver_documentos', 'aluno.historico',
    'turma.ver', 'matricula.ver', 'matricula.editar_observacoes',
    'remanejamento.ver', 'desistencia.ver', 'transferencia.ver',
    'diario.ver', 'diario.editar', 'diario.editar_fora_prazo', 'diario.aprovar_edicao',
    'documento.ver', 'documento.criar', 'documento.editar', 'documento.ver_laudo',
    'carometro.ver', 'indicadores.ver');

-- PROFESSOR (escopo restrito às próprias turmas, aplicado no SQL pela app)
INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`)
  SELECT r.`id`, p.`id` FROM `roles` r JOIN `permissions` p
  WHERE r.`code` = 'PROFESSOR' AND p.`code` IN (
    'aluno.ver', 'turma.ver', 'matricula.ver', 'diario.ver', 'diario.editar',
    'documento.ver', 'documento.criar', 'carometro.ver');

-- AUDITOR (somente leitura; dados sensíveis sempre mascarados)
INSERT IGNORE INTO `role_permissions` (`role_id`, `permission_id`)
  SELECT r.`id`, p.`id` FROM `roles` r JOIN `permissions` p
  WHERE r.`code` = 'AUDITOR' AND p.`code` IN (
    'aluno.ver', 'aluno.historico', 'turma.ver', 'matricula.ver',
    'remanejamento.ver', 'desistencia.ver', 'transferencia.ver', 'diario.ver', 'indicadores.ver',
    'auditoria.ver', 'auditoria.verificar', 'auditoria.conferir_planilha', 'lgpd.relatorio_acessos');

-- -----------------------------------------------------------------------------------------------------
-- 4. Configurações iniciais
-- -----------------------------------------------------------------------------------------------------
INSERT IGNORE INTO `settings` (`setting_key`, `value_json`, `value_type`, `group_name`, `description`, `is_sensitive`, `origin`) VALUES
  ('session.idle_minutes',            '15',     'int',    'sessao',      'Expiração por inatividade (minutos)', 1, 'SEED'),
  ('session.absolute_hours',          '8',      'int',    'sessao',      'Expiração absoluta da sessão (horas)', 1, 'SEED'),
  ('session.admin_reauth_minutes',    '10',     'int',    'sessao',      'Área admin exige reautenticação se o login tiver mais que N minutos', 1, 'SEED'),
  ('session.bind_user_agent',         'true',   'bool',   'sessao',      'Mudança de navegador/rede força novo login', 1, 'SEED'),
  ('sync.batch_rows',                 '500',    'int',    'sync',        'Linhas por lote de sincronização', 0, 'SEED'),
  ('sync.max_seconds',                '60',     'int',    'sync',        'Tempo máximo por execução do cron (segundos)', 0, 'SEED'),
  ('sync.cron_minutes',               '5',      'int',    'sync',        'Intervalo configurado no cron do cPanel (informativo)', 0, 'SEED'),
  ('sync.opportunistic',              'true',   'bool',   'sync',        'Disparar sincronização quando um admin acessa o painel', 0, 'SEED'),
  ('sync.log_flush_minutes',          '2',      'int',    'sync',        'Intervalo de envio da fila para a planilha de logs', 0, 'SEED'),
  ('sync.missing_row_policy',         '"CONFIRMAR"', 'string', 'sync',   'Aluno que sumiu da planilha: CONFIRMAR (fila) — nunca excluir automaticamente', 1, 'SEED'),
  ('sheets.technical_account_email',  '"celef@scseduca.com.br"', 'string', 'sync', 'Conta técnica padrão que lê e grava nas planilhas', 1, 'SEED'),
  ('alerts.emails',                   '[]',     'list',   'alertas',     'E-mails que recebem alertas (vazio = todos os administradores ativos)', 1, 'SEED'),
  ('alerts.from_email',               '""',     'string', 'alertas',     'Remetente dos e-mails (conta do domínio do CELEF)', 1, 'SEED'),
  ('alerts.sync_failure_minutes',     '30',     'int',    'alertas',     'Alertar se sincronização ou planilha de logs falhar por mais de N minutos', 0, 'SEED'),
  ('security.sensitive_hourly_limit', '50',     'int',    'seguranca',   'Leituras de dados sensíveis por usuário/hora antes de alertar', 1, 'SEED'),
  ('security.login_fail_limit',       '10',     'int',    'seguranca',   'Logins negados por IP em 15 min antes de bloquear', 1, 'SEED'),
  ('security.export_max_rows',        '500',    'int',    'seguranca',   'Limite de registros por exportação', 1, 'SEED'),
  ('security.mass_export_threshold',  '200',    'int',    'seguranca',   'A partir de N registros a exportação exige aprovação de administrador', 1, 'SEED'),
  ('diary.edit_days',                 '7',      'int',    'diario',      'Dias em que o professor edita o diário sem aprovação', 0, 'SEED'),
  ('lgpd.retention_years',            '5',      'int',    'lgpd',        'Anos de retenção após a saída do aluno antes de anonimizar', 1, 'SEED'),
  ('lgpd.collect_social_media',       'false',  'bool',   'lgpd',        'Coletar o campo REDES SOCIAIS (revisar com a direção)', 1, 'SEED'),
  ('lgpd.image_term_version',         '"1.0"',  'string', 'lgpd',        'Versão vigente do termo de autorização de imagem', 0, 'SEED'),
  ('privacy.notice_version',          '"1.0"',  'string', 'privacidade', 'Versão vigente do aviso de privacidade', 0, 'SEED'),
  ('privacy.notice_text',             '"Este sistema trata dados pessoais de crianças e adolescentes (LGPD, art. 14) exclusivamente para a gestão escolar do CELEF. Todo acesso é registrado de forma permanente e vinculado à sua conta @scseduca.com.br."', 'string', 'privacidade', 'Texto exibido no primeiro acesso', 0, 'SEED'),
  ('branding.school_name',            '"CELEF – Centro de Estudos de Línguas do Ensino Fundamental"', 'string', 'marca', 'Nome da instituição', 0, 'SEED'),
  ('branding.org_name',               '"Secretaria Municipal de Educação de São Caetano do Sul"', 'string', 'marca', 'Órgão', 0, 'SEED'),
  ('backup.retention_days',           '90',     'int',    'seguranca',   'Dias de retenção dos backups cifrados', 1, 'SEED');

-- -----------------------------------------------------------------------------------------------------
-- 5. Contas genéricas/compartilhadas bloqueadas no login (padrões LIKE; só pessoas físicas entram)
-- -----------------------------------------------------------------------------------------------------
INSERT IGNORE INTO `blocked_email_patterns` (`pattern`, `description`, `origin`) VALUES
  ('celef@%',        'Conta compartilhada da escola (conta técnica; nunca faz login no sistema)', 'SEED'),
  ('celef%2026@%',   'Contas de turma/ano 2026 (ex.: celef6a2026@)', 'SEED'),
  ('celef%2027@%',   'Contas de turma/ano 2027', 'SEED'),
  ('celef%2028@%',   'Contas de turma/ano 2028', 'SEED'),
  ('turma%@%',       'Contas de turma', 'SEED'),
  ('aluno%@%',       'Contas de alunos', 'SEED'),
  ('secretaria%@%',  'Conta genérica de setor', 'SEED'),
  ('direcao%@%',     'Conta genérica de setor', 'SEED'),
  ('coordenacao%@%', 'Conta genérica de setor', 'SEED');

-- -----------------------------------------------------------------------------------------------------
-- 6. Anos letivos
-- -----------------------------------------------------------------------------------------------------
INSERT IGNORE INTO `school_years` (`school_year`, `label`, `is_current`, `starts_on`, `ends_on`, `origin`) VALUES
  (2026, 'Ano letivo 2026', 1, '2026-02-02', '2026-12-18', 'SEED'),
  (2027, 'Ano letivo 2027', 0, '2027-02-01', '2027-12-17', 'SEED');

-- -----------------------------------------------------------------------------------------------------
-- 7. Modelos de declaração (texto base; edição em Admin na Fase 9)
-- -----------------------------------------------------------------------------------------------------
INSERT IGNORE INTO `declaration_templates` (`code`, `name`, `body_html`, `template_version`, `origin`) VALUES
  ('MATRICULA', 'Declaração de matrícula',
   '<p>Declaramos, para os devidos fins, que <strong>{{aluno.nome}}</strong>, R.A. {{aluno.ra_mascarado}}, está regularmente matriculado(a) no {{turma.ano}}º ano, turma {{turma.letra}}, do CELEF – Centro de Estudos de Línguas do Ensino Fundamental, no ano letivo de {{turma.ano_letivo}}.</p><p>{{cidade}}, {{data_longa}}.</p><p>Nº de controle: {{controle}}</p>', 1, 'SEED'),
  ('FREQUENCIA', 'Declaração de frequência',
   '<p>Declaramos que <strong>{{aluno.nome}}</strong>, R.A. {{aluno.ra_mascarado}}, matriculado(a) no {{turma.ano}}º ano, turma {{turma.letra}}, frequenta regularmente as aulas do CELEF no ano letivo de {{turma.ano_letivo}}, com {{frequencia.percentual}}% de presença no período de {{periodo.inicio}} a {{periodo.fim}}.</p><p>{{cidade}}, {{data_longa}}.</p><p>Nº de controle: {{controle}}</p>', 1, 'SEED'),
  ('TRANSFERENCIA', 'Declaração de transferência',
   '<p>Declaramos que <strong>{{aluno.nome}}</strong>, R.A. {{aluno.ra_mascarado}}, esteve matriculado(a) no CELEF – Centro de Estudos de Línguas do Ensino Fundamental, {{turma.ano}}º ano, turma {{turma.letra}}, no ano letivo de {{turma.ano_letivo}}, até {{transferencia.data}}, quando foi transferido(a) a pedido do responsável.</p><p>{{cidade}}, {{data_longa}}.</p><p>Nº de controle: {{controle}}</p>', 1, 'SEED');

-- -----------------------------------------------------------------------------------------------------
-- 8. Super Administrador inicial (também listado em SUPER_ADMIN_EMAILS no .env; a app impede rebaixamento)
-- -----------------------------------------------------------------------------------------------------
INSERT IGNORE INTO `users` (`email`, `full_name`, `role_id`, `is_active`, `notes`, `origin`)
  SELECT 'flaviospina@scseduca.com.br', 'Flávio Spina', r.`id`, 1, 'Super Administrador inicial (seed.sql)', 'SEED'
  FROM `roles` r WHERE r.`code` = 'SUPER_ADMIN';

-- -----------------------------------------------------------------------------------------------------
-- 9. Primeira linha da trilha de auditoria (gênese da cadeia de hash)
-- -----------------------------------------------------------------------------------------------------
INSERT INTO `audit_log` (`occurred_at`, `user_id`, `user_email`, `role_code`, `action`, `entity`, `entity_id`, `summary`, `diff_json`, `ip`, `request_id`, `origin`)
  SELECT UTC_TIMESTAMP(6), NULL, NULL, NULL, 'INSTALACAO', 'sistema', NULL,
         'Instalação inicial do banco de dados (schema, triggers e seed)', NULL, NULL, NULL, 'SEED'
  FROM DUAL
  WHERE NOT EXISTS (SELECT 1 FROM `audit_log` WHERE `action` = 'INSTALACAO');

-- Conferência rápida (aparece no resultado do phpMyAdmin)
SELECT
  (SELECT COUNT(*) FROM `roles`)            AS perfis,
  (SELECT COUNT(*) FROM `permissions`)      AS permissoes,
  (SELECT COUNT(*) FROM `role_permissions`) AS permissoes_por_perfil,
  (SELECT COUNT(*) FROM `settings`)         AS configuracoes,
  (SELECT COUNT(*) FROM `users`)            AS usuarios,
  (SELECT `hash` FROM `audit_log` ORDER BY `id` DESC LIMIT 1) AS hash_genese;
