<?php
// tools/lib_test.php — utilitários compartilhados pelos roteiros de teste (navegador simulado com cURL + contadores)
declare(strict_types=1);

$GLOBALS['pass'] = 0; $GLOBALS['fail'] = 0;
function ok(bool $c, string $l, string $x = ''): void { if ($c) { $GLOBALS['pass']++; echo "  ✔ $l\n"; } else { $GLOBALS['fail']++; echo "  ✘ $l $x\n"; } }
function finish(): never { echo "\nRESULTADO: {$GLOBALS['pass']} ok, {$GLOBALS['fail']} falhas\n"; exit($GLOBALS['fail'] === 0 ? 0 : 1); }

final class Browser
{
    public string $jar; public string $lastUrl = ''; public int $status = 0; public string $body = ''; public string $headers = '';
    public function __construct(public string $base, public string $mockDir, public string $ua = 'TesteCELEF/1.0') { $this->jar = (string) tempnam('/dev/shm', 'jar'); }

    public function req(string $method, string $url, array $post = [], bool $follow = true, array $hdr = []): string
    {
        $ch = curl_init($url);
        curl_setopt_array($ch, [CURLOPT_RETURNTRANSFER => true, CURLOPT_HEADER => true, CURLOPT_COOKIEJAR => $this->jar, CURLOPT_COOKIEFILE => $this->jar,
            CURLOPT_FOLLOWLOCATION => $follow, CURLOPT_MAXREDIRS => 10, CURLOPT_USERAGENT => $this->ua, CURLOPT_PROXY => '', CURLOPT_HTTPHEADER => $hdr, CURLOPT_TIMEOUT => 60]);
        if ($method === 'POST') { curl_setopt($ch, CURLOPT_POST, true); curl_setopt($ch, CURLOPT_POSTFIELDS, http_build_query($post)); }
        $r = (string) curl_exec($ch);
        $this->status = (int) curl_getinfo($ch, CURLINFO_RESPONSE_CODE); $this->lastUrl = (string) curl_getinfo($ch, CURLINFO_EFFECTIVE_URL);
        $hs = (int) curl_getinfo($ch, CURLINFO_HEADER_SIZE); $this->headers = substr($r, 0, $hs); $this->body = substr($r, $hs); curl_close($ch);
        return $this->body;
    }
    public function get(string $path): string { return $this->req('GET', $this->base . $path); }
    public function post(string $path, array $data = []): string { $data['_csrf'] = $this->csrf(); return $this->req('POST', $this->base . $path, $data, true, ['Origin: ' . preg_replace('~^(https?://[^/]+).*~', '$1', $this->base)]); }
    public function csrf(): string { return preg_match('/name="_csrf" value="([a-f0-9]{64})"/', $this->body, $m) ? $m[1] : ''; }
    public function has(string $needle): bool { return str_contains($this->body, $needle); }
    /** Texto dos alertas (mensagens flash) da página atual. */
    public function alerts(): string { preg_match_all('~<div class="alert[^"]*"[^>]*>(.*?)</div>~s', $this->body, $m); return html_entity_decode(trim(strip_tags(implode(' | ', $m[1])))); }

    /** Faz o que o JS da página-ponte (retorno.css) faria. */
    public function forwardCallback(): void
    {
        if (!preg_match_all('~^Location:\s*(\S*retorno\.css[#?]\S+)~mi', $this->headers, $m)) { return; }
        $loc = end($m[1]);
        parse_str(str_contains($loc, '#') ? substr($loc, strpos($loc, '#') + 1) : (string) parse_url($loc, PHP_URL_QUERY), $q);
        $this->req('GET', $this->base . '/auth/google/callback?' . http_build_query(array_intersect_key($q, array_flip(['code', 'state', 'error']))));
    }
    public function setGoogleUser(array $user): void { @mkdir($this->mockDir, 0700, true); file_put_contents($this->mockDir . '/user.json', json_encode($user)); }
    public function login(array $user): string
    {
        $this->setGoogleUser($user); $this->get('/login'); $this->post('/login/google'); $this->forwardCallback();
        if (str_contains($this->lastUrl, '/privacidade/aceite')) { $this->post('/privacidade/aceite', ['ciente' => '1']); }
        return $this->body;
    }
}
