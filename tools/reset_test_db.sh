#!/usr/bin/env bash
# tools/reset_test_db.sh — recria o banco de teste local (schema + triggers + seed) e o usuário restrito
set -e
SOCK="${SOCK:-/dev/shm/celef.sock}"; DB="${DB:-celef_test}"
M="mariadb --socket=$SOCK -uroot"
$M -e "DROP DATABASE IF EXISTS \`$DB\`; CREATE DATABASE \`$DB\` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;"
$M "$DB" < sql/schema.sql
$M "$DB" < sql/triggers.sql
$M "$DB" < sql/seed.sql > /dev/null
$M -e "CREATE USER IF NOT EXISTS 'celef_app'@'127.0.0.1' IDENTIFIED BY 'senha-teste'; CREATE USER IF NOT EXISTS 'celef_app'@'localhost' IDENTIFIED BY 'senha-teste';
       GRANT SELECT, INSERT, UPDATE, EXECUTE ON \`$DB\`.* TO 'celef_app'@'127.0.0.1'; GRANT SELECT, INSERT, UPDATE, EXECUTE ON \`$DB\`.* TO 'celef_app'@'localhost'; FLUSH PRIVILEGES;"
echo "banco $DB recriado"
