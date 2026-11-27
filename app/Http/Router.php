<?php
// app/Http/Router.php — roteador simples: método + caminho (com {parametros}) → Controller@metodo
declare(strict_types=1);

namespace App\Http;

final class Router
{
    /** @var list<array{method:string,pattern:string,regex:string,handler:array{0:class-string,1:string},params:list<string>}> */
    private array $routes = [];

    /** @param array{0:class-string,1:string} $handler */
    public function add(string $method, string $pattern, array $handler): void
    {
        $params = [];
        $regex = preg_replace_callback('/\{(\w+)\}/', static function ($m) use (&$params) {
            $params[] = $m[1];
            return '([A-Za-z0-9_\-]{1,64})';
        }, $pattern);
        $this->routes[] = ['method' => strtoupper($method), 'pattern' => $pattern, 'regex' => '~^' . $regex . '$~', 'handler' => $handler, 'params' => $params];
    }

    /** @param array{0:class-string,1:string} $handler */
    public function get(string $pattern, array $handler): void { $this->add('GET', $pattern, $handler); }
    /** @param array{0:class-string,1:string} $handler */
    public function post(string $pattern, array $handler): void { $this->add('POST', $pattern, $handler); }

    /** @return array{handler:array{0:class-string,1:string},params:array<string,string>}|null  null = 404; 'METHOD' = 405 */
    public function match(string $method, string $path): array|string|null
    {
        $pathMatched = false;
        foreach ($this->routes as $r) {
            if (!preg_match($r['regex'], $path, $m)) {
                continue;
            }
            $pathMatched = true;
            if ($r['method'] !== $method && !($r['method'] === 'GET' && $method === 'HEAD')) {
                continue;
            }
            array_shift($m);
            return ['handler' => $r['handler'], 'params' => array_combine($r['params'], $m) ?: []];
        }
        return $pathMatched ? 'METHOD' : null;
    }
}
