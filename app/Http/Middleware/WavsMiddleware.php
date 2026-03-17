<?php
namespace App\Http\Middleware;
use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class WavsMiddleware
{
    const MAX = 500;
    const SKIP = ['wavs-track-poll', 'wavs-track-clear'];

    public function handle(Request $request, Closure $next): Response
    {
        $start = microtime(true);
        $response = $next($request);
        $path = ltrim($request->getPathInfo(), '/');
        foreach (self::SKIP as $s) {
            if (str_starts_with($path, $s))
                return $response;
        }
        $ms = round((microtime(true) - $start) * 1000, 2);
        $entry = [
            'ts' => now()->format('Y-m-d H:i:s'),
            'method' => $request->method(),
            'url' => $request->getPathInfo(),
            'query' => $request->getQueryString() ? '?' . $request->getQueryString() : '',
            'status' => $response->getStatusCode(),
            'ms' => $ms,
            'ip' => $request->ip(),
        ];
        $file = storage_path('app/wavs_log.json');
        $all = file_exists($file) ? (json_decode(file_get_contents($file), true) ?? []) : [];
        $all[] = $entry;
        if (count($all) > self::MAX)
            $all = array_slice($all, -self::MAX);
        file_put_contents($file . '.tmp', json_encode($all));
        rename($file . '.tmp', $file);
        return $response;
    }
}
