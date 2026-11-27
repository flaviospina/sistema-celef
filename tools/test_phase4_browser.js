// tools/test_phase4_browser.js — Fase 4 em navegador real (Chromium/Playwright): conexão da conta técnica (retorno entre sites)
// e cadastro de planilha colando o LINK (o navegador deve enviar só o ID; a URL nunca vai ao servidor).
// Uso: node tools/test_phase4_browser.js   (app em 127.0.0.1:8088, emulador em localhost:8090, banco recriado)
const { chromium } = require('playwright');
const fs = require('fs');
const BASE = 'http://127.0.0.1:8088/celef/public', MOCK = '/dev/shm/mock_google';
const user = (u) => fs.writeFileSync(`${MOCK}/user.json`, JSON.stringify(u));
const flavio = { email: 'flaviospina@scseduca.com.br', sub: 'sub-flavio', hd: 'scseduca.com.br', email_verified: true, name: 'Flávio Spina' };
const celef = { email: 'celef@scseduca.com.br', sub: 'sub-celef', hd: 'scseduca.com.br', email_verified: true, name: 'CELEF' };
let pass = 0, fail = 0;
const ok = (c, l) => { c ? pass++ : fail++; console.log(`  ${c ? '✔' : '✘'} ${l}`); };
(async () => {
  fs.mkdirSync(`${MOCK}/sheets`, { recursive: true });
  const ID = 'NAVEGADOR2026_abcdefghijklmnopqrstuvwxyz';
  fs.writeFileSync(`${MOCK}/sheets/${ID}.json`, JSON.stringify({ title: 'Planilha do navegador', shared: 'editor', owner: 'celef@scseduca.com.br', revisions: [],
    tabs: [{ gid: 1, title: '3B', frozen: 0, protected: [], values: [['Nº', 'NOME', 'R.A.']] }] }));
  const browser = await chromium.launch();
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const posts = [];
  page.on('request', r => { if (r.method() === 'POST' && r.url().startsWith(BASE)) posts.push({ url: r.url(), body: r.postData() || '' }); });
  const settle = async (pred) => { await page.waitForURL(pred, { timeout: 20000 }); await page.waitForLoadState('networkidle'); };

  user(flavio);
  await page.goto(`${BASE}/login`);
  await page.click('button:has-text("Entrar com Google")');
  await settle(u => !/login|callback|retorno\.css|8090/.test(u.href));
  if (page.url().includes('/privacidade/aceite')) { await page.check('#ciente'); await page.click('button:has-text("Continuar")'); await page.waitForLoadState('networkidle'); }

  console.log('== Conta técnica no navegador');
  await page.goto(`${BASE}/admin/conta-tecnica`);
  user(celef);
  await page.click('button:has-text("Conectar conta Google")');
  await settle(u => u.href.endsWith('/admin/conta-tecnica'));
  const txt = await page.textContent('body');
  ok(txt.includes('Conectada') && txt.includes('celef@scseduca.com.br'), 'conta técnica conectada pelo fluxo real (Google em outro site → retorno.css → callback)');
  ok(txt.includes('Flávio'), 'sessão do Super Admin preservada depois de autorizar como celef@');

  console.log('== Planilha: colar o link envia só o ID');
  await page.goto(`${BASE}/admin/planilhas`);
  await page.fill('[data-planilha-link]', `https://docs.google.com/spreadsheets/d/${ID}/edit#gid=0`);
  ok((await page.inputValue('[data-planilha-id]')) === ID, 'o script extraiu o ID do link colado');
  ok((await page.textContent('[data-planilha-status]')).includes('ID reconhecido'), 'a tela confirma o ID reconhecido');
  await page.fill('#name', 'Planilha do navegador');
  posts.length = 0;
  await Promise.all([page.waitForURL(/\/admin\/planilhas\/\d+$/), page.click('button:has-text("Cadastrar")')]);
  const sent = decodeURIComponent(posts.find(p => p.url.endsWith('/admin/planilhas'))?.body || '');
  ok(sent.includes(`spreadsheet_id=${ID}`) && !/https?:\/\//.test(sent) && !sent.includes('docs.google'), 'o POST contém só o ID: nenhuma URL foi enviada ao servidor');
  await page.click('button:has-text("Testar conexão")');
  await page.waitForLoadState('networkidle');
  const det = await page.textContent('body');
  ok(det.includes('acessível pela conta técnica') && det.includes('3B') && det.includes('TURMA'), 'teste de conexão pelo navegador lista a aba 3B como TURMA');

  console.log('== Link inválido não é enviado');
  await page.goto(`${BASE}/admin/planilhas`);
  await page.fill('[data-planilha-link]', 'https://exemplo.com/qualquer-coisa');
  await page.fill('#name', 'Inválida');
  posts.length = 0;
  await page.click('button:has-text("Cadastrar")');
  await page.waitForTimeout(800);
  ok(posts.length === 0 && (await page.textContent('[data-planilha-status]')).includes('Não reconheci'), 'link que não é de planilha: o envio é bloqueado no navegador');

  console.log('== Service Account: o arquivo JSON é lido no navegador');
  await page.goto(`${BASE}/admin/conta-tecnica`);
  await page.click('summary');
  const { generateKeyPairSync } = require('crypto');
  const { privateKey, publicKey } = generateKeyPairSync('rsa', { modulusLength: 2048, publicKeyEncoding: { type: 'spki', format: 'pem' }, privateKeyEncoding: { type: 'pkcs8', format: 'pem' } });
  fs.writeFileSync(`${MOCK}/sa_pub.pem`, publicKey);
  const saJson = { type: 'service_account', project_id: 'proj-celef', client_email: 'celef-sync@proj-celef.iam.gserviceaccount.com', private_key: privateKey,
    auth_uri: 'https://accounts.google.com/o/oauth2/auth', token_uri: 'https://oauth2.googleapis.com/token' };
  fs.writeFileSync('/dev/shm/sa-teste.json', JSON.stringify(saJson));
  await page.setInputFiles('#sa_arquivo', '/dev/shm/sa-teste.json');
  await page.waitForFunction(() => !document.getElementById('sa_enviar').disabled);
  posts.length = 0;
  page.once('dialog', d => d.accept());
  await Promise.all([page.waitForLoadState('networkidle'), page.click('#sa_enviar')]);
  await page.waitForTimeout(500);
  const saSent = decodeURIComponent(posts.find(p => p.url.endsWith('/service-account'))?.body || '');
  ok(saSent.includes('sa_email=celef-sync@proj-celef.iam.gserviceaccount.com') && !/https?:\/\//.test(saSent) && !saSent.includes('BEGIN PRIVATE KEY'), 'enviados só e-mail e chave em base64: sem URLs e sem PEM em claro');
  ok((await page.textContent('body')).includes('Service Account gravada'), 'Service Account gravada e testada');
  await browser.close();
  console.log(`\nRESULTADO: ${pass} ok, ${fail} falhas`);
  process.exit(fail === 0 ? 0 : 1);
})().catch(e => { console.error('ERRO', e.message); process.exit(1); });
