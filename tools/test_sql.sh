#!/usr/bin/env bash
# tools/test_sql.sh — testes de comportamento do esquema/triggers num MariaDB/MySQL local.
# Uso: SOCK=/dev/shm/celef.sock DB=celef_test bash tools/test_sql.sh
set -u
SOCK="${SOCK:-/dev/shm/celef.sock}"; DB="${DB:-celef_test}"; USER="${USER_DB:-root}"
M() { mariadb --socket="$SOCK" -u"$USER" -N "$DB" -e "$1" 2>&1; }
PASS=0; FAIL=0
ok()   { out=$(M "$1"); if [ $? -eq 0 ]; then PASS=$((PASS+1)); echo "  ✔ $2"; else FAIL=$((FAIL+1)); echo "  ✘ $2"; echo "      $out"; fi; }
fail() { out=$(M "$1"); if [ $? -ne 0 ]; then PASS=$((PASS+1)); echo "  ✔ $2  [$(echo "$out" | grep -o "ERROR [0-9]*[^:]*:.*" | head -1 | cut -c1-110)]"; else FAIL=$((FAIL+1)); echo "  ✘ $2 (deveria falhar)"; fi; }
eq()   { out=$(M "$1" | tr -d '\r'); if [ "$out" == "$2" ]; then PASS=$((PASS+1)); echo "  ✔ $3"; else FAIL=$((FAIL+1)); echo "  ✘ $3 → esperado [$2], obtido [$out]"; fi; }
CTX="SET @app_origin='APP', @app_user_id=1;"

echo "== 1. Auditoria imutável e cadeia de hash"
fail "$CTX UPDATE audit_log SET summary='x' WHERE id=1;" "UPDATE em audit_log é bloqueado"
fail "$CTX DELETE FROM audit_log WHERE id=1;" "DELETE em audit_log é bloqueado"
ok "$CTX INSERT INTO audit_log (occurred_at,user_id,user_email,role_code,action,entity,entity_id,summary,diff_json,ip,request_id) VALUES (UTC_TIMESTAMP(6),1,'flaviospina@scseduca.com.br','SUPER_ADMIN','LOGIN',NULL,NULL,'Login com Google',NULL,'10.0.0.1',REPLACE(UUID(),'-',''));
INSERT INTO audit_log (occurred_at,user_id,user_email,role_code,action,entity,entity_id,summary,diff_json,ip,request_id) VALUES (UTC_TIMESTAMP(6),1,'flaviospina@scseduca.com.br','SUPER_ADMIN','EDITAR','students',7,'Editou aluno','{\"full_name\":{\"de\":\"A\",\"para\":\"B\"},\"cpf\":\"***\"}','10.0.0.1',REPLACE(UUID(),'-',''));" "insere 2 linhas de auditoria com contexto"
ok "INSERT INTO audit_log (action,summary) VALUES ('ADMIN','inserção sem contexto (phpMyAdmin)');" "insere linha sem contexto"
eq "SELECT origin FROM audit_log ORDER BY id DESC LIMIT 1;" "FORA_DA_APLICACAO" "linha sem @app_origin recebe FORA_DA_APLICACAO"
eq "SELECT COUNT(*) FROM audit_log a LEFT JOIN audit_log p ON p.id = (SELECT MAX(id) FROM audit_log WHERE id < a.id) WHERE a.prev_hash <> COALESCE(p.hash, REPEAT('0',64));" "0" "prev_hash de cada linha = hash da anterior"
eq "SELECT COUNT(*) FROM audit_log WHERE hash <> SHA2(CONCAT_WS('|',prev_hash,DATE_FORMAT(occurred_at,'%Y-%m-%d %H:%i:%s.%f'),COALESCE(user_id,''),COALESCE(user_email,''),COALESCE(role_code,''),action,COALESCE(entity,''),COALESCE(entity_id,''),COALESCE(summary,''),COALESCE(diff_json,''),COALESCE(ip,''),COALESCE(request_id,''),origin),256);" "0" "hash recalculado a partir das colunas gravadas confere"

echo "== 2. Turmas (code montado por trigger, FORA_DA_APLICACAO)"
ok "$CTX INSERT INTO classes (school_year,grade,letter,weekday,starts_at,ends_at) VALUES (2026,6,'a',2,'14:00','15:30');" "insere turma 6A/2026"
eq "SELECT code, origin, created_by FROM classes WHERE id=1;" "6A/2026	APP	1" "code = 6A/2026, origin APP, created_by do contexto"
fail "$CTX INSERT INTO classes (school_year,grade,letter) VALUES (2026,6,'A');" "turma duplicada (ano+série+letra) é rejeitada"
fail "$CTX INSERT INTO classes (school_year,grade,letter) VALUES (2026,10,'A');" "CHECK grade 1..9"
ok "INSERT INTO classes (school_year,grade,letter) VALUES (2026,7,'B');" "insere turma sem contexto"
eq "SELECT origin FROM classes WHERE code='7B/2026';" "FORA_DA_APLICACAO" "origin FORA_DA_APLICACAO"
eq "SELECT kind, entity, severity FROM security_events ORDER BY id DESC LIMIT 1;" "FORA_DA_APLICACAO	classes	CRITICO" "security_events registra o INSERT externo"

echo "== 3. Alunos: versionamento, histórico, exclusão lógica"
ok "$CTX INSERT INTO students (full_name,full_name_norm,school_email,birth_year,status) VALUES ('Ana Souza','ANA SOUZA','ana.souza@scseduca.com.br',2015,'ATIVO');" "insere aluno"
ok "SET @app_origin='APP', @app_user_id=1; UPDATE students SET full_name='Ana de Souza', full_name_norm='ANA DE SOUZA' WHERE id=1 AND version=1;" "edita aluno com lock otimista"
eq "SELECT version, updated_by, origin FROM students WHERE id=1;" "2	1	APP" "version 2, updated_by 1"
eq "SELECT history_op, history_by, history_origin, full_name, version FROM students_history WHERE id=1;" "UPDATE	1	APP	Ana Souza	1" "histórico guarda o estado anterior"
eq "SET @app_origin='PLANILHA:ALUNOS 2026'; UPDATE students SET group_name='G1' WHERE id=1; SELECT origin, version, updated_by IS NULL FROM students WHERE id=1;" "PLANILHA:ALUNOS 2026	3	1" "alteração vinda da planilha grava origin PLANILHA:..."
fail "$CTX UPDATE students SET deleted_at=NOW(3) WHERE id=1;" "exclusão lógica sem motivo é rejeitada"
fail "$CTX UPDATE students SET deleted_at=NOW(3), delete_reason='curto' WHERE id=1;" "motivo com menos de 10 caracteres é rejeitado"
ok "$CTX UPDATE students SET deleted_at=NOW(3), delete_reason='Duplicidade de cadastro confirmada pela secretaria' WHERE id=1;" "exclusão lógica com motivo"
eq "SELECT deleted_by, version FROM students WHERE id=1;" "1	4" "deleted_by preenchido pelo contexto"
eq "SELECT history_op FROM students_history WHERE id=1 ORDER BY history_id DESC LIMIT 1;" "SOFT_DELETE" "histórico registra SOFT_DELETE"
ok "$CTX UPDATE students SET deleted_at=NULL WHERE id=1;" "restauração"
eq "SELECT deleted_by IS NULL, delete_reason IS NULL, (SELECT history_op FROM students_history WHERE id=1 ORDER BY history_id DESC LIMIT 1) FROM students WHERE id=1;" "1	1	RESTORE" "restauração limpa deleted_by/motivo e registra RESTORE"
fail "$CTX DELETE FROM students WHERE id=1;" "DELETE físico em students é bloqueado"
fail "$CTX UPDATE students_history SET full_name='x' WHERE history_id=1;" "UPDATE em students_history é bloqueado"
fail "$CTX DELETE FROM students_history WHERE history_id=1;" "DELETE em students_history é bloqueado"
ok "UPDATE students SET group_name='G2' WHERE id=1;" "update sem contexto é aceito..."
eq "SELECT origin, (SELECT COUNT(*) FROM security_events WHERE entity='students' AND kind='FORA_DA_APLICACAO') FROM students WHERE id=1;" "FORA_DA_APLICACAO	1" "...mas marca FORA_DA_APLICACAO e gera evento de segurança"

echo "== 4. Matrículas: um aluno ativo por ano, nº único por turma"
ok "$CTX INSERT INTO enrollments (student_id,class_id,school_year,roll_number,status) VALUES (1,1,2026,1,'ATIVA');" "matrícula na 6A"
fail "$CTX INSERT INTO enrollments (student_id,class_id,school_year,roll_number,status) VALUES (1,(SELECT id FROM classes WHERE code='7B/2026'),2026,1,'ATIVA');" "segunda matrícula ATIVA no mesmo ano é rejeitada"
ok "$CTX UPDATE enrollments SET status='REMANEJADA', ended_on=CURDATE() WHERE id=1;" "encerra a primeira (REMANEJADA)"
ok "$CTX INSERT INTO enrollments (student_id,class_id,school_year,roll_number,status) VALUES (1,(SELECT id FROM classes WHERE code='7B/2026'),2026,1,'ATIVA');" "nova matrícula ATIVA na 7B"
ok "$CTX INSERT INTO students (full_name,full_name_norm) VALUES ('Bruno Lima','BRUNO LIMA');" "insere 2º aluno"
fail "$CTX INSERT INTO enrollments (student_id,class_id,school_year,roll_number,status) VALUES ((SELECT id FROM students WHERE full_name_norm='BRUNO LIMA'),(SELECT id FROM classes WHERE code='7B/2026'),2026,1,'ATIVA');" "nº 1 repetido na mesma turma é rejeitado"
ok "$CTX INSERT INTO enrollments (student_id,class_id,school_year,roll_number,status) VALUES ((SELECT id FROM students WHERE full_name_norm='BRUNO LIMA'),(SELECT id FROM classes WHERE code='7B/2026'),2026,2,'ATIVA');" "nº 2 na mesma turma"

echo "== 5. Usuários"
fail "$CTX INSERT INTO users (email,full_name,role_id) VALUES ('fulano@gmail.com','Fulano',3);" "e-mail fora de @scseduca.com.br é rejeitado (CHECK)"
fail "$CTX UPDATE users SET is_active=0 WHERE id=1;" "desativar o único Super Admin é rejeitado"
fail "$CTX UPDATE users SET role_id=(SELECT id FROM roles WHERE code='ADMIN') WHERE id=1;" "rebaixar o único Super Admin é rejeitado"
ok "$CTX INSERT INTO users (email,full_name,role_id) VALUES ('  Maria.Silva@scseduca.com.br ','Maria Silva',(SELECT id FROM roles WHERE code='SUPER_ADMIN'));" "insere 2º Super Admin"
eq "SELECT email FROM users WHERE full_name='Maria Silva';" "maria.silva@scseduca.com.br" "e-mail normalizado (minúsculo, sem espaços)"
ok "$CTX UPDATE users SET is_active=0 WHERE id=1;" "com outro Super Admin ativo, desativar o primeiro é permitido"
ok "$CTX UPDATE users SET is_active=1 WHERE id=1;" "reativa"
fail "$CTX DELETE FROM users WHERE full_name='Maria Silva';" "DELETE em users é bloqueado"
fail "$CTX DELETE FROM roles WHERE id=6;" "DELETE em roles é bloqueado"
fail "$CTX DELETE FROM role_permissions WHERE role_id=6;" "DELETE em role_permissions é bloqueado"

echo "== 6. Conta técnica, declarações, exportações"
ok "$CTX INSERT INTO google_credentials (kind,account_email,scopes) VALUES ('OAUTH_USER_ACCOUNT','celef@scseduca.com.br','spreadsheets drive.metadata.readonly');" "credencial ativa"
fail "$CTX INSERT INTO google_credentials (kind,account_email,scopes) VALUES ('SERVICE_ACCOUNT','sa@proj.iam.gserviceaccount.com','spreadsheets');" "segunda credencial ativa é rejeitada"
ok "$CTX UPDATE google_credentials SET is_active=0, status='REVOKED' WHERE id=1; INSERT INTO google_credentials (kind,account_email,scopes) VALUES ('SERVICE_ACCOUNT','sa@proj.iam.gserviceaccount.com','spreadsheets');" "desativando a primeira, a segunda entra"
ok "$CTX INSERT INTO declarations (student_id,template_id,template_version,control_number,verification_token_hash,payload_json,issued_by) VALUES (1,1,1,'2026-000001',SHA2('tok',256),'{\"aluno\":\"Ana\"}',1);" "emite declaração"
fail "$CTX UPDATE declarations SET payload_json='{}' WHERE id=1;" "alterar conteúdo da declaração é bloqueado"
ok "$CTX UPDATE declarations SET revoked_at=NOW(3), revoked_by=1, revoke_reason='Emitida com turma errada' WHERE id=1;" "revogar (só campos revoked_*) é permitido"
fail "$CTX DELETE FROM declarations WHERE id=1;" "DELETE em declarations é bloqueado"
ok "$CTX INSERT INTO exports (user_id,kind,entity,record_count,reason,watermark_id,requires_approval) VALUES (1,'CSV','students',300,'Relatório para a Secretaria de Educação','ABCDEF0123456789',1);" "registra exportação em massa"
fail "$CTX UPDATE exports SET reason='outro' WHERE id=1;" "alterar motivo da exportação é bloqueado"
ok "$CTX UPDATE exports SET approved_by=2, approved_at=NOW(3) WHERE id=1;" "aprovar exportação é permitido"
fail "$CTX UPDATE login_attempts SET outcome='OK' WHERE id=0; INSERT INTO login_attempts (ip,outcome) VALUES ('1.1.1.1','NAO_CADASTRADO'); UPDATE login_attempts SET outcome='OK' WHERE ip='1.1.1.1';" "login_attempts é somente inclusão"
fail "$CTX INSERT INTO image_consents (student_id,consented,term_version) VALUES (1,1,'1.0'); UPDATE image_consents SET consented=0 WHERE student_id=1;" "image_consents é somente inclusão"

echo "== 7. Usuário MySQL da aplicação (SELECT, INSERT, UPDATE, EXECUTE)"
mariadb --socket="$SOCK" -uroot -e "CREATE USER IF NOT EXISTS 'celef_app'@'localhost' IDENTIFIED BY 'senha-teste'; REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'celef_app'@'localhost'; GRANT SELECT, INSERT, UPDATE, EXECUTE ON \`$DB\`.* TO 'celef_app'@'localhost'; FLUSH PRIVILEGES;" 2>&1
A() { mariadb --socket="$SOCK" -ucelef_app -psenha-teste -N "$DB" -e "$1" 2>&1; }
out=$(A "DELETE FROM oauth_states WHERE 1=1;"); [ $? -ne 0 ] && { PASS=$((PASS+1)); echo "  ✔ app não tem DELETE  [$(echo "$out" | cut -c1-90)]"; } || { FAIL=$((FAIL+1)); echo "  ✘ app conseguiu DELETE"; }
out=$(A "DROP TRIGGER trg_audit_log_bu;"); [ $? -ne 0 ] && { PASS=$((PASS+1)); echo "  ✔ app não remove triggers"; } || { FAIL=$((FAIL+1)); echo "  ✘ app removeu trigger"; }
out=$(A "ALTER TABLE students ADD COLUMN x INT;"); [ $? -ne 0 ] && { PASS=$((PASS+1)); echo "  ✔ app não tem ALTER"; } || { FAIL=$((FAIL+1)); echo "  ✘ app alterou tabela"; }
out=$(A "$CTX INSERT INTO audit_log (action,summary,ip) VALUES ('VER','teste app','1.2.3.4'); SELECT origin, LENGTH(hash) FROM audit_log ORDER BY id DESC LIMIT 1;"); [ "$out" == "APP	64" ] && { PASS=$((PASS+1)); echo "  ✔ app insere em audit_log e o trigger calcula o hash"; } || { FAIL=$((FAIL+1)); echo "  ✘ app em audit_log: [$out]"; }
out=$(A "$CTX UPDATE students SET group_name='G3' WHERE full_name_norm='BRUNO LIMA'; SELECT version FROM students WHERE full_name_norm='BRUNO LIMA';"); [ "$out" == "2" ] && { PASS=$((PASS+1)); echo "  ✔ app atualiza students e o trigger versiona"; } || { FAIL=$((FAIL+1)); echo "  ✘ app update students: [$out]"; }

echo; echo "RESULTADO: $PASS ok, $FAIL falhas"
[ $FAIL -eq 0 ]
