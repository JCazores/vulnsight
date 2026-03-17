<?php
namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class BlockSensitivePaths
{
    private array $blocked = [
        '/.env',
        '/.env.backup',
        '/.env.local',
        '/.env.example',
        '/.git',
        '/.git/HEAD',
        '/.git/config',
        '/backup.sql',
        '/dump.sql',
        '/database.sql',
        '/backup.zip',
        '/www.zip',
        '/phpinfo.php',
        '/info.php',
        '/config.php',
        '/composer.json',
        '/composer.lock',
        '/package.json',
        '/storage/logs/laravel.log',
    ];

    public function handle(Request $request, Closure $next)
    {
        $path = '/' . ltrim($request->path(), '/');

        foreach ($this->blocked as $blocked) {
            if (str_starts_with($path, $blocked)) {
                abort(404);
            }
        }

        return $next($request);
    }
}
