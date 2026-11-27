// tools/test_phase3_browser.js — fluxo de login em navegador real (Chromium/Playwright) contra o emulador do Google em outro site.
// Uso: node tools/test_phase3_browser.js  (app em 127.0.0.1:8088, emulador em localhost:8090; ver tools/test_phase3.php)
// Fluxo real de navegador (Chromium): login → Google emulado em OUTRO site (localhost:8090) → callback.html → callback PHP
const { chromium } = require('playwright');
(async () => {
  const browser = await chromium.launch();
  const ctx = await browser.newContext({ deviceScaleFactor: 1 });
  const page = await ctx.newPage();
  const nav = [];
  page.on('framenavigated', f => { if (f === page.mainFrame()) nav.push(f.url()); });
  page.on('response', r => { if (r.request().isNavigationRequest()) nav.push(`   [${r.status()}] ${r.url()}`); });

  await page.goto('http://127.0.0.1:8088/celef/public/login');
  await page.click('button:has-text("Entrar com Google")');
  await page.waitForURL(u => !u.href.includes('/login') && !u.href.includes('callback') && !u.href.includes('retorno.css') && !u.href.includes('8090'), { timeout: 20000 });
  await page.waitForLoadState('networkidle');
  // aceite do aviso de privacidade
  if (page.url().includes('/privacidade/aceite')) {
    await page.check('#ciente');
    await page.click('button:has-text("Continuar")');
    await page.waitForLoadState('networkidle');
  }
  const body = await page.textContent('body');
  console.log('navegações:'); nav.forEach(u => console.log('  ', u));
  console.log('URL final:', page.url());
  console.log('menu exibido:', body.includes('Olá, Flávio') ? 'SIM' : 'NÃO');
  const cookies = await ctx.cookies('http://127.0.0.1:8088');
  console.log('cookie sessão:', cookies.map(c => `${c.name} sameSite=${c.sameSite} httpOnly=${c.httpOnly}`).join(', '));
  // área admin e logout no mesmo navegador
  await page.goto('http://127.0.0.1:8088/celef/public/admin');
  console.log('admin abre:', (await page.textContent('body')).includes('Painel administrativo') ? 'SIM' : 'NÃO');
  await browser.close();
})().catch(e => { console.error('ERRO', e); process.exit(1); });
