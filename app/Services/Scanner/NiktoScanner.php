<?php

namespace App\Services\Scanner;

use Illuminate\Support\Facades\Log;

/**
 * NiktoScanner — Pure PHP replacement for Nikto v2.1.5 (broken JSON/txt output)
 *
 * Checks: sensitive file exposure, dangerous HTTP methods, security headers,
 * cookie flags, server version disclosure, directory listing.
 */
class NiktoScanner
{
    private int $timeout = 8;

    // bodyMatch: at least ONE string must appear in the response body.
    // Empty array = any 200 non-HTML response counts (e.g. binary files).
    // This prevents Laravel's SPA catch-all (which returns 200 HTML for every
    // unknown route) from being flagged as a real finding.
    private const SENSITIVE_PATHS = [
        '/.env' => ['severity' => 'critical', 'name' => 'Environment File Exposed', 'bodyMatch' => ['APP_KEY', 'APP_ENV', 'DB_PASSWORD', 'DB_HOST']],
        '/.env.backup' => ['severity' => 'critical', 'name' => 'Environment Backup File Exposed', 'bodyMatch' => ['APP_KEY', 'APP_ENV', 'DB_']],
        '/.env.local' => ['severity' => 'critical', 'name' => 'Environment File Exposed (.env.local)', 'bodyMatch' => ['APP_KEY', 'APP_ENV', 'DB_']],
        '/.git/config' => ['severity' => 'critical', 'name' => 'Git Repository Config Exposed', 'bodyMatch' => ['[core]', '[remote', 'repositoryformatversion']],
        '/.git/HEAD' => ['severity' => 'high', 'name' => 'Git Repository HEAD Exposed', 'bodyMatch' => ['ref: refs/', 'refs/heads/']],
        '/phpinfo.php' => ['severity' => 'high', 'name' => 'PHPInfo Page Exposed', 'bodyMatch' => ['PHP Version', 'phpinfo()', 'php.ini']],
        '/info.php' => ['severity' => 'high', 'name' => 'PHPInfo Page Exposed', 'bodyMatch' => ['PHP Version', 'phpinfo()', 'php.ini']],
        '/adminer.php' => ['severity' => 'critical', 'name' => 'Adminer Database Tool Exposed', 'bodyMatch' => ['adminer', 'Adminer', 'db=', 'username=']],
        '/phpmyadmin/' => ['severity' => 'critical', 'name' => 'phpMyAdmin Exposed', 'bodyMatch' => ['phpMyAdmin', 'phpmyadmin', 'pma_', 'PMA_']],
        '/phpmyadmin/index.php' => ['severity' => 'critical', 'name' => 'phpMyAdmin Exposed', 'bodyMatch' => ['phpMyAdmin', 'phpmyadmin', 'pma_', 'PMA_']],
        '/config.php' => ['severity' => 'critical', 'name' => 'Config File Exposed', 'bodyMatch' => ['<?php', 'password', 'database', 'DB_HOST']],
        '/backup.sql' => ['severity' => 'critical', 'name' => 'SQL Backup File Exposed', 'bodyMatch' => ['INSERT INTO', 'CREATE TABLE', '-- MySQL', 'DROP TABLE']],
        '/dump.sql' => ['severity' => 'critical', 'name' => 'SQL Dump File Exposed', 'bodyMatch' => ['INSERT INTO', 'CREATE TABLE', '-- MySQL', 'DROP TABLE']],
        '/backup.zip' => ['severity' => 'high', 'name' => 'Backup Archive Exposed', 'bodyMatch' => [], 'contentType' => ['application/zip', 'application/octet-stream']],
        '/.htaccess' => ['severity' => 'medium', 'name' => '.htaccess File Exposed', 'bodyMatch' => ['RewriteEngine', 'RewriteRule', 'Options', 'AllowOverride']],
        '/server-status' => ['severity' => 'medium', 'name' => 'Apache Server Status Exposed', 'bodyMatch' => ['Apache Server Status', 'Server Version', 'requests/sec']],
        '/telescope' => ['severity' => 'high', 'name' => 'Laravel Telescope Exposed', 'bodyMatch' => ['Telescope', 'telescope', 'laravel-telescope']],
        '/horizon' => ['severity' => 'high', 'name' => 'Laravel Horizon Exposed', 'bodyMatch' => ['Horizon', 'horizon', 'laravel-horizon']],
        '/storage/logs/laravel.log' => ['severity' => 'critical', 'name' => 'Laravel Log File Exposed', 'bodyMatch' => ['[20', 'local.ERROR', 'local.INFO', 'Stack trace', 'Laravel']],
        '/test.php' => ['severity' => 'medium', 'name' => 'Test PHP File Exposed', 'bodyMatch' => ['<?php', 'test', 'Test', 'phpinfo']],
        '/wp-login.php' => ['severity' => 'medium', 'name' => 'WordPress Login Exposed', 'bodyMatch' => ['wp-login', 'WordPress', 'wp_', 'user_login']],
    ];

    private const DANGEROUS_METHODS = ['PUT', 'DELETE', 'TRACE'];

    public function isAvailable(): bool
    {
        return true;
    }

    public function scan(string $targetUrl, int $maxTime = 90, ?\Closure $shouldAbort = null): array
    {
        $findings = [];
        $targetUrl = rtrim($targetUrl, '/');
        $abort = $shouldAbort ?? fn() => false;
        Log::info("NiktoScanner (PHP): scanning {$targetUrl}");

        try {
            if ($abort())
                return [];
            $findings = array_merge($findings, $this->checkHeaders($targetUrl));
            if ($abort())
                return $findings;
            $findings = array_merge($findings, $this->checkDangerousMethods($targetUrl));
            if ($abort())
                return $findings;
            $findings = array_merge($findings, $this->checkSensitivePaths($targetUrl, $abort));
            if ($abort())
                return $findings;
            $findings = array_merge($findings, $this->checkDirectoryListing($targetUrl, $abort));
        } catch (\Throwable $e) {
            Log::error("NiktoScanner exception: " . $e->getMessage());
        }

        Log::info("NiktoScanner (PHP): found " . count($findings) . " items");
        return $findings;
    }

    private function checkHeaders(string $targetUrl): array
    {
        $findings = [];
        $headers = $this->fetchHeaders($targetUrl);
        if (empty($headers))
            return [];

        $headerStr = strtolower(implode("\n", $headers));

        // Server version disclosure
        foreach ($headers as $h) {
            if (preg_match('/^server:\s*(.+)/i', $h, $m)) {
                $server = trim($m[1]);
                if (preg_match('/[\d.]+/', $server)) {
                    $findings[] = $this->finding(
                        'Server Version Disclosure',
                        $targetUrl,
                        'low',
                        "Server header reveals version: {$server}. Attackers can target known CVEs.",
                        'nginx: `server_tokens off;` | Apache: `ServerTokens Prod`',
                        "Server: {$server}"
                    );
                }
            }
        }

        // X-Powered-By
        foreach ($headers as $h) {
            if (preg_match('/^x-powered-by:\s*(.+)/i', $h, $m)) {
                $val = trim($m[1]);
                $findings[] = $this->finding(
                    'X-Powered-By Header Discloses Technology',
                    $targetUrl,
                    'low',
                    "X-Powered-By reveals: {$val}",
                    'PHP: set `expose_php = Off` in php.ini',
                    "X-Powered-By: {$val}"
                );
            }
        }

        // X-Frame-Options
        if (!str_contains($headerStr, 'x-frame-options') && !str_contains($headerStr, 'frame-ancestors')) {
            $findings[] = $this->finding(
                'Missing X-Frame-Options Header',
                $targetUrl,
                'medium',
                'Site can be embedded in iframes — clickjacking risk.',
                "Add: X-Frame-Options: DENY",
                'X-Frame-Options header absent'
            );
        }

        // X-Content-Type-Options
        if (!str_contains($headerStr, 'x-content-type-options')) {
            $findings[] = $this->finding(
                'Missing X-Content-Type-Options Header',
                $targetUrl,
                'low',
                'Browsers may MIME-sniff responses enabling content injection.',
                'Add: X-Content-Type-Options: nosniff',
                'X-Content-Type-Options header absent'
            );
        }

        // HSTS (HTTPS only)
        if (str_starts_with($targetUrl, 'https') && !str_contains($headerStr, 'strict-transport-security')) {
            $findings[] = $this->finding(
                'Missing HSTS Header',
                $targetUrl,
                'medium',
                'HSTS absent — users can be downgraded to HTTP via MITM.',
                'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains',
                'Strict-Transport-Security header absent on HTTPS'
            );
        }

        // CSP
        if (!str_contains($headerStr, 'content-security-policy')) {
            $findings[] = $this->finding(
                'Missing Content-Security-Policy Header',
                $targetUrl,
                'medium',
                'No CSP — XSS attacks have maximum impact without it.',
                "Add: Content-Security-Policy: default-src 'self'",
                'Content-Security-Policy header absent'
            );
        }

        // Insecure cookies
        foreach ($headers as $h) {
            if (preg_match('/^set-cookie:\s*(.+)/i', $h, $m)) {
                $cookie = $m[1];
                $cookieName = explode('=', $cookie)[0];
                if (!stripos($cookie, 'httponly')) {
                    $findings[] = $this->finding(
                        "Cookie Missing HttpOnly Flag: {$cookieName}",
                        $targetUrl,
                        'medium',
                        "Cookie '{$cookieName}' lacks HttpOnly — readable by JavaScript, enabling XSS session theft.",
                        'Laravel: set SESSION_COOKIE_HTTP_ONLY=true in .env',
                        "Set-Cookie: {$cookie}"
                    );
                }
                if (str_starts_with($targetUrl, 'https') && !stripos($cookie, 'secure')) {
                    $findings[] = $this->finding(
                        "Cookie Missing Secure Flag: {$cookieName}",
                        $targetUrl,
                        'medium',
                        "Cookie '{$cookieName}' lacks Secure flag — may be sent over HTTP.",
                        'Laravel: set SESSION_SECURE_COOKIE=true in .env',
                        "Set-Cookie: {$cookie}"
                    );
                }
            }
        }

        return $findings;
    }

    private function checkDangerousMethods(string $targetUrl): array
    {
        $findings = [];
        foreach (self::DANGEROUS_METHODS as $method) {
            try {
                $ctx = stream_context_create([
                    'http' => ['method' => $method, 'timeout' => $this->timeout, 'ignore_errors' => true, 'follow_location' => false],
                    'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
                ]);
                $hdrs = @get_headers($targetUrl, false, $ctx);
                if (!$hdrs)
                    continue;
                preg_match('/HTTP\/[\d.]+ (\d+)/', $hdrs[0] ?? '', $m);
                $code = (int) ($m[1] ?? 0);
                if (in_array($code, [200, 201, 204, 301, 302])) {
                    $findings[] = $this->finding(
                        "Dangerous HTTP Method Enabled: {$method}",
                        $targetUrl,
                        $method === 'TRACE' ? 'medium' : 'high',
                        "HTTP {$method} is accepted (HTTP {$code}). Attackers may modify/delete resources.",
                        "nginx: `limit_except GET POST { deny all; }`",
                        "{$method} {$targetUrl} → HTTP {$code}",
                        $method
                    );
                }
            } catch (\Throwable) {
            }
        }
        return $findings;
    }

    private function checkSensitivePaths(string $targetUrl, \Closure $abort = null): array
    {
        $abort = $abort ?? fn() => false;
        $findings = [];
        foreach (self::SENSITIVE_PATHS as $path => $meta) {
            if ($abort())
                break;
            $url = $targetUrl . $path;
            try {
                $ctx = stream_context_create([
                    'http' => [
                        'method' => 'GET',
                        'timeout' => $this->timeout,
                        'ignore_errors' => true,
                        'follow_location' => false,
                        'header' => 'User-Agent: Mozilla/5.0',
                    ],
                    'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
                ]);

                $body = @file_get_contents($url, false, $ctx);
                $hdrs = $http_response_header ?? [];
                if (!$hdrs)
                    continue;

                preg_match('/HTTP\/[\d.]+ (\d+)/', $hdrs[0] ?? '', $m);
                $status = (int) ($m[1] ?? 0);

                if ($status !== 200)
                    continue;

                // Get Content-Type from response headers
                $contentType = '';
                foreach ($hdrs as $h) {
                    if (stripos($h, 'content-type:') === 0) {
                        $contentType = strtolower(trim(substr($h, 13)));
                        break;
                    }
                }

                // Rule 1: reject HTML responses — these are the SPA catch-all
                if (str_contains($contentType, 'text/html')) {
                    Log::debug("NiktoScanner: {$path} returned HTML — SPA catch-all, skipping");
                    continue;
                }

                // Rule 2: reject if body looks like an HTML page
                $trimmed = ltrim((string) $body);
                if (
                    stripos($trimmed, '<!DOCTYPE') === 0 ||
                    stripos($trimmed, '<html') === 0 ||
                    str_contains((string) $body, '<title>') ||
                    str_contains((string) $body, '<meta ')
                ) {
                    Log::debug("NiktoScanner: {$path} body looks like HTML — skipping");
                    continue;
                }

                // Rule 3: content-type whitelist for binary files (zip etc.)
                $requiredContentTypes = $meta['contentType'] ?? [];
                if (!empty($requiredContentTypes)) {
                    $ctMatched = false;
                    foreach ($requiredContentTypes as $ct) {
                        if (str_contains($contentType, $ct)) {
                            $ctMatched = true;
                            break;
                        }
                    }
                    if (!$ctMatched)
                        continue;
                }

                // Rule 4: body must contain at least one expected string
                $bodyMatches = $meta['bodyMatch'] ?? [];
                if (!empty($bodyMatches)) {
                    $bodyMatched = false;
                    foreach ($bodyMatches as $needle) {
                        if (str_contains((string) $body, $needle)) {
                            $bodyMatched = true;
                            break;
                        }
                    }
                    if (!$bodyMatched) {
                        Log::debug("NiktoScanner: {$path} returned 200 non-HTML but body didn't match — false positive avoided");
                        continue;
                    }
                }

                // All checks passed — real finding
                $findings[] = $this->finding(
                    $meta['name'],
                    $url,
                    $meta['severity'],
                    "Path `{$path}` returned HTTP 200 with matching content — publicly accessible.",
                    "Block in nginx/Apache or delete from web root.",
                    "GET {$url} → HTTP 200 (body confirmed)"
                );

                Log::info("NiktoScanner: CONFIRMED {$url}");

            } catch (\Throwable) {
            }
        }
        return $findings;
    }

    private function checkDirectoryListing(string $targetUrl, \Closure $abort = null): array
    {
        $abort = $abort ?? fn() => false;
        $findings = [];
        foreach (['/images/', '/uploads/', '/files/', '/storage/', '/assets/'] as $path) {
            if ($abort())
                break;
            $url = $targetUrl . $path;
            try {
                $ctx = stream_context_create([
                    'http' => ['method' => 'GET', 'timeout' => $this->timeout, 'ignore_errors' => true],
                    'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
                ]);
                $body = @file_get_contents($url, false, $ctx);
                if (!$body)
                    continue;
                $hdrs = $http_response_header ?? [];
                preg_match('/HTTP\/[\d.]+ (\d+)/', $hdrs[0] ?? '', $m);
                if ((int) ($m[1] ?? 0) === 200 && preg_match('/<title>Index of/i', $body)) {
                    $findings[] = $this->finding(
                        'Directory Listing Enabled',
                        $url,
                        'medium',
                        "Directory listing enabled at `{$path}` — attackers can enumerate files.",
                        'nginx: `autoindex off;` | Apache: `Options -Indexes`',
                        "GET {$url} → HTTP 200 with directory index"
                    );
                }
            } catch (\Throwable) {
            }
        }
        return $findings;
    }

    private function fetchHeaders(string $url): array
    {
        try {
            $ctx = stream_context_create([
                'http' => ['method' => 'GET', 'timeout' => $this->timeout, 'ignore_errors' => true, 'follow_location' => false],
                'ssl' => ['verify_peer' => false, 'verify_peer_name' => false],
            ]);
            @file_get_contents($url, false, $ctx);
            return $http_response_header ?? [];
        } catch (\Throwable) {
            return [];
        }
    }

    private function finding(string $name, string $url, string $severity, string $desc, string $solution, string $evidence, string $method = 'GET'): array
    {
        return [
            'name' => $name,
            'url' => $url,
            'severity' => $severity,
            'description' => $desc,
            'solution' => $solution,
            'evidence' => $evidence,
            'method' => $method,
            'cve' => null,
            'source' => 'nikto-php',
            'confidence' => 3,
        ];
    }
}
