# Fase 4 — Cliente Google, conta técnica e planilha de logs

Entregue em 27/11/2026. Testada com o emulador local (`tools/mock_google.php`, agora com token de renovação,
Service Account, revogação e as APIs Sheets v4 e Drive v3) e com o usuário MySQL restrito.

## Verificações

| Roteiro | Resultado |
|---|---|
| `tools/test_phase4.php` | 56 verificações |
| `tools/test_phase4_browser.js` (Chromium real) | 9 verificações |
| Regressão `test_phase3.php` / `test_phase2.php` | 56 / 42 |

| Área | Verificado |
|---|---|
| Conta técnica | autorizar com a conta errada é recusado; pedido com `access_type=offline`, `prompt=consent`, `login_hint`; refresh token cifrado e nunca exibido; sessão do Super Admin preservada; cache do access token cifrado |
| Planilhas | cadastro por ID, duplicada e inválida recusadas; teste de conexão lista abas e cabeçalhos; tipo da aba sugerido; dono via Drive; planilha não compartilhada e acesso só de leitura com mensagens claras; fonte da Secretaria somente leitura e escrita só com confirmação; exclusão lógica |
| Planilha de logs | 7 abas, cabeçalho, linha congelada, proteção só para a conta técnica; fila esvaziada e idêntica ao banco; injeção de fórmula neutralizada; nenhum CPF; idempotência |
| Robustez | dois 503 seguidos resolvidos por retentativa; 401 no meio renova o token; `invalid_grant` marca ERROR, alerta e a fila aguarda; após reconectar a fila é enviada |
| Conferência | detecta linha apagada, alterada e inventada; evento crítico `PLANILHA_LOGS_ADULTERADA` |
| Navegador real | link colado vira ID no navegador e nenhuma URL vai no POST; link inválido não é enviado; JSON da Service Account lido no navegador (só e-mail e chave em base64 trafegam) |
| Servidor de produção (sondagem do firewall) | todos os formatos de formulário do admin passam; só o campo com URL é barrado (406), como previsto |

## Decisões

- **Mesmo cliente OAuth e mesmo retorno do login.** A conexão da conta técnica usa o propósito `TECH_ACCOUNT` em
  `oauth_states` e a página-ponte `retorno.css`. Quem está logado no sistema continua sendo o Super Admin; a conta
  Google autorizada é a `celef@`, conferida pelo ID Token.
- **Fila com espera crescente.** Falha de envio agenda nova tentativa em 2, 4, 8… minutos (máximo 60). Erro de
  autorização ou de permissão interrompe o lote para não martelar a API.
- **Conferência por hash.** A última coluna de cada linha é o hash da linha em `audit_log`. Hash ausente significa linha
  apagada (ou a própria coluna do hash foi alterada); hash presente com valores diferentes significa linha alterada;
  hash desconhecido significa linha inventada.
- **Tabelas versionadas não recebem carimbo a cada execução.** `last_refresh_at` é gravado no máximo uma vez por dia e
  `last_synced_at` uma vez por hora, para não inflar `*_history`. O detalhe fica em `sheet_log_outbox` e `cron_runs`.
