<?php

namespace App\Services\Scanner;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * ExposedPathScanner
 *
 * Makes real HTTP requests to common sensitive paths and reports
 * any that return 200 OK (or 403 for directories that shouldn't be accessible).
 *
 * This catches what ZAP often misses because ZAP crawls from links —
 * it won't discover /.env or /backup.sql unless they're linked somewhere.
 */
class ExposedPathScanner
{
    /**
     * Paths to probe, grouped by category.
     * Each entry: [path, description, severity, why_dangerous]
     */
    private array $paths = [

        // ── Laravel/PHP specific ─────────────────────────────────────────────
        [
            'path' => '/.env',
            'name' => 'Environment File Exposed: /.env',
            'severity' => 'critical',
            'description' => 'The .env file is publicly accessible. This file contains database '
                . 'credentials, app secrets, API keys, and other sensitive configuration.',
            'solution' => 'Block access to .env in your web server config. In nginx: '
                . 'location ~ /\.env { deny all; }',
            'steps' => [
                'Add "location ~ /\\.env { deny all; }" to your nginx config.',
                'For Apache: add "Require all denied" in a <Files ".env"> block in .htaccess',
                'Move .env outside the web root as a long-term fix.',
            ],
        ],
        [
            'path' => '/.env.backup',
            'name' => 'Environment Backup File Exposed: /.env.backup',
            'severity' => 'critical',
            'description' => 'A backup of the .env file is publicly accessible.',
            'solution' => 'Delete this file and block access to all dotfiles.',
            'steps' => ['Delete /.env.backup from your server immediately.'],
        ],
        [
            'path' => '/.env.example',
            'name' => 'Environment Example File Exposed: /.env.example',
            'severity' => 'medium',
            'description' => '.env.example reveals your app\'s configuration structure and may '
                . 'expose default values or commented-out secrets.',
            'solution' => 'Block public access to .env.example.',
            'steps' => ['Block access to .env.example in your web server config.'],
        ],
        [
            'path' => '/phpinfo.php',
            'name' => 'PHP Info Page Exposed: /phpinfo.php',
            'severity' => 'high',
            'description' => 'phpinfo() output is publicly accessible. This reveals PHP version, '
                . 'loaded extensions, config values, environment variables, and server paths — '
                . 'a goldmine for attackers.',
            'solution' => 'Delete phpinfo.php from your web root immediately.',
            'steps' => ['Delete phpinfo.php from public/'],
        ],
        [
            'path' => '/info.php',
            'name' => 'PHP Info Page Exposed: /info.php',
            'severity' => 'high',
            'description' => 'phpinfo() output is publicly accessible.',
            'solution' => 'Delete info.php from your web root.',
            'steps' => ['Delete info.php from public/'],
        ],
        [
            'path' => '/storage/logs/laravel.log',
            'name' => 'Laravel Log File Exposed',
            'severity' => 'high',
            'description' => 'The Laravel application log is publicly accessible. Log files '
                . 'contain stack traces with file paths, class names, database queries, '
                . 'and sometimes user data.',
            'solution' => 'Block access to /storage/logs/ in your web server config.',
            'steps' => [
                'In nginx: location /storage { deny all; }',
                'In Laravel, ensure storage/ is not inside public/',
            ],
        ],
        [
            'path' => '/.git/HEAD',
            'name' => 'Git Repository Exposed: /.git/',
            'severity' => 'critical',
            'description' => 'The .git directory is publicly accessible. An attacker can '
                . 'reconstruct your entire source code, including all commit history, '
                . 'hardcoded secrets, and removed credentials.',
            'solution' => 'Block access to .git in your web server. Never deploy with .git in the web root.',
            'steps' => [
                'nginx: location ~ /\\.git { deny all; }',
                'Remove .git from your deployment or use .gitignore rules.',
            ],
        ],
        [
            'path' => '/.git/config',
            'name' => 'Git Config Exposed: /.git/config',
            'severity' => 'high',
            'description' => '.git/config is accessible, revealing your remote repository URLs '
                . 'which may contain credentials or private repo locations.',
            'solution' => 'Block access to .git directory entirely.',
            'steps' => ['Block .git access in web server (see .git/HEAD finding).'],
        ],

        // ── Backup files ─────────────────────────────────────────────────────
        [
            'path' => '/backup.sql',
            'name' => 'Database Backup Exposed: /backup.sql',
            'severity' => 'critical',
            'description' => 'A SQL database dump is publicly accessible. This exposes all '
                . 'your database data including user passwords, emails, and application data.',
            'solution' => 'Never store database backups in the web root. Delete this file immediately.',
            'steps' => ['Delete backup.sql from public/', 'Store backups outside the web root.'],
        ],
        [
            'path' => '/dump.sql',
            'name' => 'Database Dump Exposed: /dump.sql',
            'severity' => 'critical',
            'description' => 'A SQL database dump is publicly accessible.',
            'solution' => 'Delete dump.sql from public/.',
            'steps' => ['Delete dump.sql from public/'],
        ],
        [
            'path' => '/database.sql',
            'name' => 'Database File Exposed: /database.sql',
            'severity' => 'critical',
            'description' => 'A SQL database file is publicly accessible.',
            'solution' => 'Delete and move out of web root.',
            'steps' => ['Delete database.sql from public/'],
        ],
        [
            'path' => '/backup.zip',
            'name' => 'Archive Backup Exposed: /backup.zip',
            'severity' => 'critical',
            'description' => 'A zip archive (possibly a site backup) is publicly accessible.',
            'solution' => 'Remove archive from web root and store backups securely.',
            'steps' => ['Delete backup.zip from public/'],
        ],
        [
            'path' => '/www.zip',
            'name' => 'Site Archive Exposed: /www.zip',
            'severity' => 'critical',
            'description' => 'A zip archive of the web root is publicly accessible.',
            'solution' => 'Delete immediately and store backups outside web root.',
            'steps' => ['Delete www.zip from public/'],
        ],

        // ── Config files ─────────────────────────────────────────────────────
        [
            'path' => '/config.php',
            'name' => 'Configuration File Exposed: /config.php',
            'severity' => 'critical',
            'description' => 'config.php is publicly accessible and likely contains database '
                . 'credentials and other secrets.',
            'solution' => 'Move config files outside the web root.',
            'steps' => ['Delete or move config.php outside of public/'],
        ],
        [
            'path' => '/wp-config.php',
            'name' => 'WordPress Config Exposed: /wp-config.php',
            'severity' => 'critical',
            'description' => 'WordPress configuration file is publicly accessible.',
            'solution' => 'Block access to wp-config.php in web server config.',
            'steps' => ['nginx: location ~* wp-config\\.php { deny all; }'],
        ],

        // ── Development artifacts ─────────────────────────────────────────────
        [
            'path' => '/composer.json',
            'name' => 'Composer Manifest Exposed: /composer.json',
            'severity' => 'low',
            'description' => 'composer.json reveals all your PHP dependencies and their versions. '
                . 'This helps attackers identify packages with known CVEs.',
            'solution' => 'Move composer.json above the web root or block access.',
            'steps' => [
                'nginx: location = /composer.json { deny all; }',
                'Or move composer.json to the project root above public/',
            ],
        ],
        [
            'path' => '/composer.lock',
            'name' => 'Composer Lock File Exposed: /composer.lock',
            'severity' => 'low',
            'description' => 'composer.lock reveals exact versions of all dependencies, making '
                . 'it trivial to look up known CVEs for your specific versions.',
            'solution' => 'Block access to composer.lock.',
            'steps' => ['nginx: location = /composer.lock { deny all; }'],
        ],
        [
            'path' => '/package.json',
            'name' => 'NPM Manifest Exposed: /package.json',
            'severity' => 'low',
            'description' => 'package.json reveals frontend dependencies and versions.',
            'solution' => 'Block access to package.json.',
            'steps' => ['nginx: location = /package.json { deny all; }'],
        ],
        [
            'path' => '/.htaccess',
            'name' => 'htaccess File Exposed: /.htaccess',
            'severity' => 'medium',
            'description' => '.htaccess reveals your web server rewrite rules, blocked paths, '
                . 'and may expose internal directory structure.',
            'solution' => 'Block access to .htaccess files.',
            'steps' => ['nginx: location ~ /\\.ht { deny all; }'],
        ],

        // ── Laravel test vulnerability routes (your own test-vulns) ──────────
        [
            'path' => '/test-vulns',
            'name' => 'Intentionally Vulnerable Test Routes Exposed: /test-vulns',
            'severity' => 'critical',
            'description' => 'Your application has intentionally vulnerable test routes accessible '
                . 'at /test-vulns. These routes contain SQL injection, XSS, and open redirect '
                . 'vulnerabilities that are publicly accessible.',
            'solution' => 'Remove or gate test-vulns routes behind auth middleware before going to production. '
                . 'These routes exist in web.php and should only be reachable in development.',
            'steps' => [
                'Wrap test-vulns routes in ->middleware(\'auth\') or delete them before production.',
                'Add WAVS_TESTING=false check: Route::get(\'/test-vulns\', ...)->middleware(\'auth\')',
            ],
        ],

        // ── Admin panels ─────────────────────────────────────────────────────
        [
            'path' => '/admin',
            'name' => 'Admin Panel Publicly Reachable: /admin',
            'severity' => 'medium',
            'description' => 'The /admin route is accessible. While your app has auth checks, '
                . 'the admin panel should ideally be IP-restricted or behind additional '
                . 'authentication.',
            'solution' => 'Consider restricting /admin to specific IP ranges in your web server config.',
            'steps' => [
                'nginx: location /admin { allow 192.168.1.0/24; deny all; }',
                'Or add IP middleware: if(!in_array($request->ip(), config(\'admin.allowed_ips\'))) abort(403)',
            ],
        ],
    ];

    /**
     * Scan $targetUrl by probing all sensitive paths.
     *
     * For local targets (localhost / private IP): uses filesystem checks — avoids
     * the self-request deadlock that occurs when the job tries to HTTP-request
     * the same server that's running it (especially with QUEUE_CONNECTION=sync).
     *
     * For remote targets: uses HTTP with a short 3s connect timeout.
     */
    public function scan(string $targetUrl): array
    {
        $findings = [];
        $base = rtrim($targetUrl, '/');

        if ($this->isLocalTarget($targetUrl)) {
            return $this->scanViaFilesystem($targetUrl);
        }

        foreach ($this->paths as $check) {
            $url = $base . $check['path'];

            try {
                $response = Http::timeout(3)          // 3s max — fail fast on remote
                    ->connectTimeout(2)
                    ->withHeaders(['User-Agent' => 'VulnSight-Scanner/1.0'])
                    ->withoutRedirecting()
                    ->get($url);

                if ($response->status() === 200) {
                    $body = substr($response->body(), 0, 500);
                    $evidence = "HTTP 200 response from {$url}. Preview: " . $this->sanitiseEvidence($body);

                    $findings[] = array_merge($check, [
                        'url' => $url,
                        'cve' => null,
                        'evidence' => $evidence,
                        'method' => 'GET',
                        'source' => 'path_scanner',
                    ]);

                    Log::info("ExposedPathScanner: found {$url} (200)");
                }
            } catch (\Throwable $e) {
                Log::debug("ExposedPathScanner: probe failed for {$url}: " . $e->getMessage());
            }
        }

        return $findings;
    }

    /**
     * For localhost targets: check the filesystem directly instead of making
     * HTTP requests to ourselves (which deadlocks under sync queue).
     *
     * Maps each sensitive path to its actual filesystem location relative to
     * the Laravel public/ directory or project root.
     */
    private function scanViaFilesystem(string $targetUrl): array
    {
        $findings = [];
        $publicPath = public_path();
        $basePath = base_path();

        // Map URL path → actual filesystem path to check
        $fsMap = [
            '/.env' => $basePath . '/.env',
            '/.env.backup' => $basePath . '/.env.backup',
            '/.env.example' => $basePath . '/.env.example',
            '/phpinfo.php' => $publicPath . '/phpinfo.php',
            '/info.php' => $publicPath . '/info.php',
            '/storage/logs/laravel.log' => $basePath . '/storage/logs/laravel.log',
            '/.git/HEAD' => $basePath . '/.git/HEAD',
            '/.git/config' => $basePath . '/.git/config',
            '/backup.sql' => $publicPath . '/backup.sql',
            '/dump.sql' => $publicPath . '/dump.sql',
            '/database.sql' => $publicPath . '/database.sql',
            '/backup.zip' => $publicPath . '/backup.zip',
            '/www.zip' => $publicPath . '/www.zip',
            '/config.php' => $publicPath . '/config.php',
            '/wp-config.php' => $publicPath . '/wp-config.php',
            '/composer.json' => $basePath . '/composer.json',
            '/composer.lock' => $basePath . '/composer.lock',
            '/package.json' => $basePath . '/package.json',
            '/.htaccess' => $publicPath . '/.htaccess',
            '/test-vulns' => null,  // checked via route existence below
        ];

        foreach ($this->paths as $check) {
            $urlPath = $check['path'];
            $fsPath = $fsMap[$urlPath] ?? null;

            // Special case: test-vulns — check if the route is registered
            if ($urlPath === '/test-vulns') {
                if (
                    \Illuminate\Support\Facades\Route::has('test-vulns')
                    || $this->routeExists('/test-vulns')
                ) {
                    $findings[] = array_merge($check, [
                        'url' => rtrim($targetUrl, '/') . '/test-vulns',
                        'cve' => null,
                        'evidence' => 'Route /test-vulns exists and is publicly reachable.',
                        'method' => 'GET',
                        'source' => 'path_scanner',
                    ]);
                }
                continue;
            }

            // /admin is always accessible in dev — skip for local
            if ($urlPath === '/admin') {
                continue;
            }

            if ($fsPath && file_exists($fsPath)) {
                // .env.example and composer files are expected to exist — only flag if
                // they would also be web-accessible (i.e. inside public/)
                $webAccessible = str_starts_with(realpath($fsPath) ?: $fsPath, realpath($publicPath) ?: $publicPath);

                // Files outside public/ are only flagged if explicitly dangerous
                $alwaysDangerous = in_array($urlPath, ['/.env', '/.env.backup', '/.git/HEAD', '/.git/config']);

                if ($webAccessible || $alwaysDangerous) {
                    // For dangerous files outside public/, verify they're actually
                    // HTTP-accessible before flagging — avoids false positives when
                    // Laravel/nginx correctly blocks them at the router level.
                    if ($alwaysDangerous && !$webAccessible) {
                        $testUrl = rtrim($targetUrl, '/') . $urlPath;
                        $verified = $this->verifyHttpAccessible($testUrl);
                        if (!$verified) {
                            continue; // File exists on disk but server blocks HTTP access — not a finding
                        }
                    }
                    $findings[] = array_merge($check, [
                        'url' => rtrim($targetUrl, '/') . $urlPath,
                        'cve' => null,
                        'evidence' => "File exists on filesystem: {$fsPath}",
                        'method' => 'GET',
                        'source' => 'path_scanner',
                    ]);
                    Log::info("ExposedPathScanner: found {$fsPath} (filesystem check)");
                }
            }
        }

        Log::info('ExposedPathScanner: filesystem scan complete — ' . count($findings) . ' findings');
        return $findings;
    }

    /**
     * Verify a URL actually returns sensitive file content over HTTP.
     * Returns true only if the response looks like a real file (not an HTML page).
     * Used to eliminate false positives from filesystem checks.
     */
    private function verifyHttpAccessible(string $url): bool
    {
        try {
            $kernel = app(\Illuminate\Contracts\Http\Kernel::class);
            $request = \Illuminate\Http\Request::create($url, 'GET');
            $response = $kernel->handle($request);
            $kernel->terminate($request, $response);

            $status = $response->getStatusCode();
            $contentType = $response->headers->get('Content-Type', '');
            $body = substr($response->getContent(), 0, 200);

            // If it returns HTML (our app's frontend), it's NOT accessible
            if (str_contains($body, '<!DOCTYPE') || str_contains($body, '<html')) {
                return false;
            }

            // 404/403/301 = blocked
            if (in_array($status, [403, 404, 301, 302])) {
                return false;
            }

            // 200 with non-HTML content = real file exposed
            return $status === 200 && !str_contains($contentType, 'text/html');

        } catch (\Throwable $e) {
            return false;
        }
    }

    private function isLocalTarget(string $url): bool
    {
        $host = strtolower(parse_url($url, PHP_URL_HOST) ?? '');
        return in_array($host, ['localhost', '127.0.0.1', '::1'], true)
            || str_starts_with($host, '192.168.')
            || str_starts_with($host, '10.')
            || preg_match('/^172\.(1[6-9]|2\d|3[01])\./', $host);
    }

    private function routeExists(string $path): bool
    {
        foreach (\Illuminate\Support\Facades\Route::getRoutes() as $route) {
            if ('/' . ltrim($route->uri(), '/') === $path) {
                return true;
            }
        }
        return false;
    }

    /**
     * Strip potentially dangerous content from evidence snippets.
     */
    private function sanitiseEvidence(string $body): string
    {
        // Remove anything that looks like a real password or secret
        $body = preg_replace('/(["\']?(?:password|secret|key|token|pass)["\']?\s*[=:]\s*)["\']?[^"\'\s,}]{4,}["\']?/i', '$1[REDACTED]', $body);
        return mb_substr(strip_tags($body), 0, 300);
    }
}
