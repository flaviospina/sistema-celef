# Fase 2 — Núcleo de segurança

Entregue em 27/11/2026. Testado localmente com PHP 8.3 + MariaDB 10.11 usando o usuário MySQL **restrito**
(`SELECT, INSERT, UPDATE, EXECUTE`): `tools/test_phase2.php` (40 verificações) e sondas HTTP com o servidor embutido.

## Resultados dos testes

| Área | Verificado |
|---|---|
| Crypto | cifra/decifra com contexto; contexto errado e blob adulterado falham; nonce aleatório; blind index determinístico; arquivo de 200 KB cifrado em blocos e restaurado |
| Validator | CPF com dígito verificador; datas dd/mm/aaaa; normalização de nome; mensagens pt-BR |
| Masker | CPF, e-mail, telefone; diff mascarado por nome de chave e por padrão em texto livre |
| CSRF | token + Origin correto aceito; Origin estranho, sem Origin/Referer, token errado ou ausente negados |
| Database | `@app_user_id`/`@app_origin` definidos; busca por blind index; lock otimista recusa versão antiga |
| AuditLog | autor/origem/hash; diff mascarado em JSON canônico; fila da planilha de logs sem dado sensível; ação desconhecida rejeitada; **30 inserções simultâneas em 2 processos sem bifurcar a cadeia** |
| SecurityEvents | evento + alerta enfileirado para os administradores, sem CPF no corpo |
| RateLimiter | bloqueio na 3ª ocorrência com `retry_after`; permanece bloqueado |
| HTTP | CSP com nonce, X-Frame-Options, Referrer-Policy, cookie HttpOnly/SameSite=Strict; 404/405/419/429 corretos; JSON `{ok,data,mensagem}`; `/instalacao` 404 com chaves configuradas; scripts de `cron/` respondem 403 via web |
| Cron | `verify_audit.php`: cadeia íntegra, sonda de triggers, âncora diária criada, alertas de eventos criados por trigger, rotação de logs |

## Formato dos dados cifrados

`1 byte versão da chave | 24 bytes nonce | ciphertext + tag (16 bytes)`. O contexto (`tabela.coluna`) é AAD.
Arquivos: `1 byte versão | header secretstream (24) | blocos de 64 KiB + 17 bytes`.

## Fórmula do hash (igual ao trigger)

`SHA-256(prev_hash | occurred_at(%Y-%m-%d %H:%i:%s.%f) | user_id | user_email | role_code | action | entity | entity_id | summary | diff_json | ip | request_id | origin)`, campos nulos como vazio, separador `|`. `AuditLog::computeHash()` e `cron/verify_audit.php` reproduzem em PHP.
