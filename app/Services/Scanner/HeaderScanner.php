<?php

namespace App\Services\Scanner;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

/**
 * HeaderScanner
 *
 * For LOCAL targets (localhost/private IP): dispatches a request through
 * Laravel's own HTTP kernel — no TCP connection needed, instant, no deadlock.
 *
 * For REMOTE targets: makes a real HTTP request with a short timeout.
 */
class HeaderScanner
{
    private array $required = [
        'Content-Security-Policy' => [
            'severity' => 'high',
            'description' => 'Content Security Policy (CSP) header is missing. Without CSP, the browser '
                . 'will execute any inline script or load resources from any origin, making the app '
                . 'vulnerable to Cross-Site Scripting (XSS) attacks.',
            'solution' => "Add a Content-Security-Policy header. Minimum: default-src 'self'",
            'steps' => [
                "Add Content-Security-Policy: default-src 'self' to your HTTP response headers.",
                'Use SecurityHeaders.php middleware to set this.',
                'Test your policy at https://csp-evaluator.withgoogle.com/',
            ],
            'cve' => null,
            'owasp' => 'https://owasp.org/www-project-secure-headers/#content-security-policy',
        ],
        'X-Frame-Options' => [
            'severity' => 'medium',
            'description' => 'X-Frame-Options header is missing. This allows your app to be embedded '
                . 'in an iframe, enabling clickjacking attacks.',
            'solution' => 'Add X-Frame-Options: DENY or SAMEORIGIN.',
            'steps' => ["Add X-Frame-Options: DENY to your SecurityHeaders middleware."],
            'cve' => null,
            'owasp' => 'https://owasp.org/www-community/attacks/Clickjacking',
        ],
        'X-Content-Type-Options' => [
            'severity' => 'medium',
            'description' => 'X-Content-Type-Options: nosniff is missing. Browsers may MIME-sniff '
                . 'responses and execute scripts disguised as other file types.',
            'solution' => 'Add X-Content-Type-Options: nosniff to all responses.',
            'steps' => ["Add X-Content-Type-Options: nosniff in SecurityHeaders middleware."],
            'cve' => null,
            'owasp' => 'https://owasp.org/www-project-secure-headers/#x-content-type-options',
        ],
        'Strict-Transport-Security' => [
            'severity' => 'medium',
            'description' => 'HSTS header is missing. Without HSTS, users can be downgraded to HTTP.',
            'solution' => 'Add Strict-Transport-Security: max-age=31536000; includeSubDomains',
            'steps' => ['Only set on HTTPS. On localhost HTTP this is not applicable.'],
            'cve' => null,
            'owasp' => 'https://owasp.org/www-community/controls/HTTP_Strict_Transport_Security_Cheat_Sheet',
        ],
        'Referrer-Policy' => [
            'severity' => 'low',
            'description' => 'Referrer-Policy header is missing. The browser sends full URLs in '
                . 'the Referer header to external sites, leaking sensitive parameters.',
            'solution' => 'Add Referrer-Policy: strict-origin-when-cross-origin',
            'steps' => ['Add Referrer-Policy: strict-origin-when-cross-origin to SecurityHeaders middleware.'],
            'cve' => null,
            'owasp' => 'https://owasp.org/www-project-secure-headers/#referrer-policy',
        ],
        'Permissions-Policy' => [
            'severity' => 'low',
            'description' => 'Permissions-Policy header is missing. Embedded content may access '
                . 'browser APIs like camera, microphone, geolocation.',
            'solution' => 'Add Permissions-Policy: camera=(), microphone=(), geolocation=()',
            'steps' => ['Add Permissions-Policy: camera=(), microphone=(), geolocation=() to SecurityHeaders middleware.'],
            'cve' => null,
            'owasp' => 'https://owasp.org/www-project-secure-headers/#permissions-policy',
        ],
    ];

    private array $dangerous = [
        'X-Powered-By' => [
            'severity' => 'low',
            'description' => 'X-Powered-By header reveals your server technology (e.g. PHP/8.2). '
                . 'Attackers use this to target version-specific vulnerabilities.',
            'solution' => 'Remove X-Powered-By header via SecurityHeaders middleware.',
            'steps' => [
                "Call header_remove('X-Powered-By') in SecurityHeaders::handle().",
                'Add expose_php = Off in php.ini.',
            ],
        ],
        'Server' => [
            'severity' => 'low',
            'description' => 'Server header reveals your web server software and version.',
            'solution' => 'Remove or obfuscate the Server header.',
            'steps' => [
                'Nginx: server_tokens off;',
                'Apache: ServerTokens Prod + ServerSignature Off',
            ],
        ],
    ];

    public function scan(string $targetUrl): array
    {
        if ($this->isLocalTarget($targetUrl)) {
            return $this->scanViaKernel($targetUrl);
        }

        return $this->scanViaHttp($targetUrl);
    }

    // ─────────────────────────────────────────────────────────────────────────
    // LOCAL: dispatch through Laravel kernel — zero TCP overhead, no deadlock
    // ─────────────────────────────────────────────────────────────────────────
    private function scanViaKernel(string $targetUrl): array
    {
        try {
            $request = \Illuminate\Http\Request::create($targetUrl, 'GET', [], [], [], [
                'HTTP_USER_AGENT' => 'VulnSight-HeaderScanner/1.0',
                'HTTP_HOST' => parse_url($targetUrl, PHP_URL_HOST) . ':' . (parse_url($targetUrl, PHP_URL_PORT) ?? 80),
            ]);

            /** @var \Illuminate\Contracts\Http\Kernel $kernel */
            $kernel = app(\Illuminate\Contracts\Http\Kernel::class);
            $response = $kernel->handle($request);
            $kernel->terminate($request, $response);

            $headers = [];
            foreach ($response->headers->all() as $name => $values) {
                $headers[strtolower($name)] = $values;
            }

            $cookies = $response->headers->getCookies();

            return $this->analyse($headers, $cookies, $targetUrl, isHttps: false);

        } catch (\Throwable $e) {
            Log::warning("HeaderScanner (kernel) failed for {$targetUrl}: " . $e->getMessage());
            return [];
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // REMOTE: real HTTP request with short timeout
    // ─────────────────────────────────────────────────────────────────────────
    private function scanViaHttp(string $targetUrl): array
    {
        try {
            $response = Http::timeout(5)
                ->connectTimeout(3)
                ->withHeaders(['User-Agent' => 'VulnSight-HeaderScanner/1.0'])
                ->get($targetUrl);

            $headers = [];
            foreach ($response->headers() as $name => $values) {
                $headers[strtolower($name)] = $values;
            }

            return $this->analyse(
                $headers,
                [],
                $targetUrl,
                isHttps: str_starts_with($targetUrl, 'https')
            );

        } catch (\Throwable $e) {
            Log::warning("HeaderScanner failed for {$targetUrl}: " . $e->getMessage());
            return [];
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Core analysis — same logic for both local and remote
    // ─────────────────────────────────────────────────────────────────────────
    private function analyse(array $headers, array $cookies, string $targetUrl, bool $isHttps): array
    {
        $findings = [];

        // Missing required headers
        foreach ($this->required as $header => $rule) {
            $key = strtolower($header);
            if (!isset($headers[$key]) || empty($headers[$key])) {
                if ($header === 'Strict-Transport-Security' && !$isHttps) {
                    continue; // HSTS not applicable on HTTP
                }
                $findings[] = $this->makeFinding(
                    name: "Missing Security Header: {$header}",
                    url: $targetUrl,
                    severity: $rule['severity'],
                    description: $rule['description'],
                    solution: $rule['solution'],
                    steps: $rule['steps'],
                    cve: $rule['cve'],
                    evidence: "Header '{$header}' was not present in the HTTP response.",
                    owasp: $rule['owasp'] ?? null,
                );
            }
        }

        // CSP quality audit
        if (isset($headers['content-security-policy'])) {
            $csp = is_array($headers['content-security-policy'])
                ? ($headers['content-security-policy'][0] ?? '')
                : $headers['content-security-policy'];
            $findings = array_merge($findings, $this->auditCsp($csp, $targetUrl));
        }

        // Dangerous headers that should be removed
        foreach ($this->dangerous as $header => $rule) {
            $key = strtolower($header);
            if (isset($headers[$key]) && !empty($headers[$key])) {
                $value = is_array($headers[$key]) ? implode(', ', $headers[$key]) : $headers[$key];
                $findings[] = $this->makeFinding(
                    name: "Information Disclosure via {$header} Header",
                    url: $targetUrl,
                    severity: $rule['severity'],
                    description: $rule['description'],
                    solution: $rule['solution'],
                    steps: $rule['steps'],
                    evidence: "{$header}: {$value}",
                );
            }
        }

        // Cookie security
        foreach ($cookies as $cookie) {
            $name = $cookie->getName();

            if (!$cookie->isHttpOnly()) {
                $findings[] = $this->makeFinding(
                    name: "Cookie Missing HttpOnly Flag: {$name}",
                    url: $targetUrl,
                    severity: 'medium',
                    description: "Cookie '{$name}' lacks HttpOnly — JavaScript can read it via XSS.",
                    solution: 'Set HttpOnly on all session/auth cookies.',
                    steps: ['Set SESSION_COOKIE_HTTPONLY=true in .env'],
                    evidence: "Cookie: {$name}",
                );
            }

            if ($isHttps && !$cookie->isSecure()) {
                $findings[] = $this->makeFinding(
                    name: "Cookie Missing Secure Flag: {$name}",
                    url: $targetUrl,
                    severity: 'medium',
                    description: "Cookie '{$name}' lacks Secure flag — may be sent over HTTP.",
                    solution: 'Set SESSION_SECURE_COOKIE=true in .env',
                    steps: ['Set SESSION_SECURE_COOKIE=true in .env'],
                    evidence: "Cookie: {$name}",
                );
            }
        }

        return $findings;
    }

    private function auditCsp(string $csp, string $url): array
    {
        $findings = [];

        // ── script-src checks ─────────────────────────────────────────────────
        // Extract only the script-src directive value (up to the next semicolon).
        // Prevents false positives when 'unsafe-inline' is in style-src or other
        // directives but NOT in script-src.
        preg_match("/script-src\s([^;]+)/i", $csp, $scriptSrcMatch);
        $scriptSrc = $scriptSrcMatch[1] ?? '';
        \Log::debug('HeaderScanner scriptSrc: ' . $scriptSrc); // ADD THIS
        \Log::debug('HeaderScanner full CSP: ' . $csp);        // ADD THIS TOO

        if (str_contains($scriptSrc, "'unsafe-inline'")) {
            // A nonce or hash causes modern browsers to ignore 'unsafe-inline' —
            // so this is only a real finding when neither is present.
            $hasNonce = (bool) preg_match("/'nonce-[^']+'/", $scriptSrc);
            $hasHash = (bool) preg_match("/'(sha256|sha384|sha512)-[^']+'/", $scriptSrc);

            if (!$hasNonce && !$hasHash) {
                $findings[] = $this->makeFinding(
                    name: "Weak CSP: unsafe-inline in script-src",
                    url: $url,
                    severity: 'medium',
                    description: "CSP allows 'unsafe-inline' in script-src with no nonce or hash, "
                    . "bypassing XSS protection entirely.",
                    solution: "Remove 'unsafe-inline' and use nonces or hashes instead.",
                    steps: ["Replace 'unsafe-inline' with a nonce: script-src 'nonce-{random}'"],
                    evidence: "script-src:{$scriptSrc}",
                );
            }
        }

        if (str_contains($scriptSrc, "'unsafe-eval'")) {
            $findings[] = $this->makeFinding(
                name: "Weak CSP: unsafe-eval present",
                url: $url,
                severity: 'medium',
                description: "CSP allows 'unsafe-eval', enabling dynamic code execution via eval().",
                solution: "Remove 'unsafe-eval' and refactor code that uses eval().",
                steps: ["Remove 'unsafe-eval' from CSP script-src."],
                evidence: "script-src:{$scriptSrc}",
            );
        }

        if (preg_match('/script-src[^;]*\*/', $csp)) {
            $findings[] = $this->makeFinding(
                name: "Weak CSP: wildcard in script-src",
                url: $url,
                severity: 'high',
                description: "script-src contains wildcard (*), allowing scripts from any origin.",
                solution: "Replace * with explicit allowed origins in script-src.",
                steps: ["List only specific domains in script-src."],
                evidence: "script-src:{$scriptSrc}",
            );
        }

        return $findings;
    }

    private function isLocalTarget(string $url): bool
    {
        $host = strtolower(parse_url($url, PHP_URL_HOST) ?? '');
        return in_array($host, ['localhost', '127.0.0.1', '::1'], true)
            || str_starts_with($host, '192.168.')
            || str_starts_with($host, '10.')
            || preg_match('/^172\.(1[6-9]|2\d|3[01])\./', $host);
    }

    private function makeFinding(
        string $name,
        string $url,
        string $severity,
        string $description,
        string $solution,
        array $steps = [],
        ?string $cve = null,
        ?string $evidence = null,
        ?string $owasp = null
    ): array {
        return [
            'name' => $name,
            'url' => $url,
            'severity' => $severity,
            'description' => $description,
            'solution' => $solution,
            'steps' => $steps,
            'cve' => $cve,
            'evidence' => $evidence,
            'owasp' => $owasp,
            'method' => 'GET',
            'source' => 'header_scanner',
        ];
    }
}
