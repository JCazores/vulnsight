<?php

namespace App\Services\Modules;

use App\Models\DiscoveredUrl;

class SecurityHeadersModule extends BaseModule
{
    public function name(): string
    {
        return 'headers';
    }

    // header name => [severity, description, recommendation, owasp]
    private array $requiredHeaders = [
        'strict-transport-security' => [
            'severity' => 'high',
            'name' => 'Missing HSTS Header',
            'description' => 'The Strict-Transport-Security header is absent. Without it, browsers may connect over unencrypted HTTP even when HTTPS is available, enabling downgrade attacks.',
            'recommendation' => 'Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload',
            'owasp' => 'https://owasp.org/www-project-secure-headers/#http-strict-transport-security',
            'cvss' => 60,
        ],
        'content-security-policy' => [
            'severity' => 'medium',
            'name' => 'Missing Content-Security-Policy Header',
            'description' => 'No Content-Security-Policy header is set. CSP is the primary browser-side defence against XSS attacks.',
            'recommendation' => "Add a CSP header. Start with: Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'",
            'owasp' => 'https://owasp.org/www-project-secure-headers/#content-security-policy',
            'cvss' => 50,
        ],
        'x-frame-options' => [
            'severity' => 'medium',
            'name' => 'Missing X-Frame-Options Header',
            'description' => 'The page can be loaded inside an iframe, making it vulnerable to clickjacking attacks.',
            'recommendation' => 'Add: X-Frame-Options: DENY (or SAMEORIGIN if you need iframes from your own domain). Prefer frame-ancestors in CSP.',
            'owasp' => 'https://owasp.org/www-project-secure-headers/#x-frame-options',
            'cvss' => 40,
        ],
        'x-content-type-options' => [
            'severity' => 'low',
            'name' => 'Missing X-Content-Type-Options Header',
            'description' => 'Without X-Content-Type-Options: nosniff, browsers may MIME-sniff responses and execute files as a different content type, enabling injection attacks.',
            'recommendation' => 'Add: X-Content-Type-Options: nosniff',
            'owasp' => 'https://owasp.org/www-project-secure-headers/#x-content-type-options',
            'cvss' => 30,
        ],
        'referrer-policy' => [
            'severity' => 'low',
            'name' => 'Missing Referrer-Policy Header',
            'description' => 'Without a Referrer-Policy header, the full URL (including query parameters that may contain sensitive data) can be leaked to third parties via the Referer header.',
            'recommendation' => 'Add: Referrer-Policy: no-referrer-when-downgrade (or stricter: strict-origin-when-cross-origin)',
            'owasp' => 'https://owasp.org/www-project-secure-headers/#referrer-policy',
            'cvss' => 20,
        ],
        'permissions-policy' => [
            'severity' => 'low',
            'name' => 'Missing Permissions-Policy Header',
            'description' => 'No Permissions-Policy is set. This header controls which browser features (camera, microphone, geolocation) are accessible to the page.',
            'recommendation' => 'Add: Permissions-Policy: geolocation=(), camera=(), microphone=()',
            'owasp' => 'https://owasp.org/www-project-secure-headers/#permissions-policy',
            'cvss' => 15,
        ],
    ];

    private array $dangerousHeaders = [
        'server' => 'Server header discloses web server software and version, aiding fingerprinting.',
        'x-powered-by' => 'X-Powered-By header discloses the application framework/version, aiding targeted attacks.',
        'x-aspnet-version' => 'X-AspNet-Version discloses the .NET version in use.',
        'x-aspnetmvc-version' => 'X-AspNetMvc-Version discloses the MVC framework version.',
    ];

    // Only run once per target root, not on every URL
    private array $checkedHosts = [];

    public function run(DiscoveredUrl $discoveredUrl): void
    {
        $host = parse_url($discoveredUrl->url, PHP_URL_HOST);
        if (isset($this->checkedHosts[$host]))
            return;
        $this->checkedHosts[$host] = true;

        $headers = $discoveredUrl->response_headers ?? [];
        if (empty($headers))
            return;

        $headerKeys = array_map('strtolower', array_keys($headers));

        // Check missing required headers
        foreach ($this->requiredHeaders as $headerName => $meta) {
            if (!in_array($headerName, $headerKeys)) {
                $this->report(
                    discoveredUrl: $discoveredUrl,
                    type: 'missing_header',
                    name: $meta['name'],
                    severity: $meta['severity'],
                    url: $discoveredUrl->url,
                    method: 'GET',
                    parameter: $headerName,
                    payload: '',
                    evidence: "Header '{$headerName}' was absent from the HTTP response.",
                    requestRaw: "GET / HTTP/1.1\r\nHost: {$host}",
                    responseRaw: implode("\r\n", array_map(fn($k, $v) => "$k: $v", array_keys($headers), $headers)),
                    description: $meta['description'],
                    recommendation: $meta['recommendation'],
                    owasp: $meta['owasp'],
                    cvss: $meta['cvss'],
                );
            }
        }

        // Check dangerous informational headers
        foreach ($this->dangerousHeaders as $headerName => $description) {
            if (in_array($headerName, $headerKeys)) {
                $value = $headers[$headerName] ?? '';
                $this->report(
                    discoveredUrl: $discoveredUrl,
                    type: 'info_disclosure_header',
                    name: 'Information Disclosure via HTTP Header',
                    severity: 'low',
                    url: $discoveredUrl->url,
                    method: 'GET',
                    parameter: $headerName,
                    payload: '',
                    evidence: "{$headerName}: {$value}",
                    requestRaw: "GET / HTTP/1.1\r\nHost: {$host}",
                    responseRaw: "{$headerName}: {$value}",
                    description: $description,
                    recommendation: "Remove the '{$headerName}' header from your web server / framework configuration.",
                    owasp: 'https://owasp.org/www-project-secure-headers/',
                    cvss: 10,
                );
            }
        }

        // Check for insecure cookies
        $this->checkCookies($discoveredUrl, $headers);
    }

    private function checkCookies(DiscoveredUrl $discoveredUrl, array $headers): void
    {
        $setCookie = $headers['set-cookie'] ?? null;
        if (!$setCookie)
            return;

        $cookies = is_array($setCookie) ? $setCookie : [$setCookie];

        foreach ($cookies as $cookie) {
            $cookieLower = strtolower($cookie);
            $cookieName = explode('=', $cookie)[0];

            // Session cookies should have HttpOnly
            if (
                !str_contains($cookieLower, 'httponly') &&
                preg_match('/session|sess|auth|token|jwt/i', $cookieName)
            ) {
                $this->report(
                    discoveredUrl: $discoveredUrl,
                    type: 'insecure_cookie',
                    name: 'Session Cookie Missing HttpOnly Flag',
                    severity: 'medium',
                    url: $discoveredUrl->url,
                    method: 'GET',
                    parameter: 'Set-Cookie',
                    payload: '',
                    evidence: "Set-Cookie: {$cookie}",
                    requestRaw: '',
                    responseRaw: "Set-Cookie: {$cookie}",
                    description: "The cookie '{$cookieName}' does not have the HttpOnly flag set. This allows JavaScript to read the cookie, which can lead to session hijacking via XSS.",
                    recommendation: 'Set the HttpOnly flag on all session cookies. In Laravel: SESSION_HTTP_ONLY=true in .env',
                    owasp: 'https://owasp.org/www-community/HttpOnly',
                    cvss: 50,
                );
            }

            // Cookies sent over HTTP should have Secure flag
            if (
                !str_contains($cookieLower, 'secure') &&
                str_starts_with($discoveredUrl->url, 'https')
            ) {
                $this->report(
                    discoveredUrl: $discoveredUrl,
                    type: 'insecure_cookie',
                    name: 'Cookie Missing Secure Flag',
                    severity: 'low',
                    url: $discoveredUrl->url,
                    method: 'GET',
                    parameter: 'Set-Cookie',
                    payload: '',
                    evidence: "Set-Cookie: {$cookie}",
                    requestRaw: '',
                    responseRaw: "Set-Cookie: {$cookie}",
                    description: "The cookie '{$cookieName}' is missing the Secure flag. It may be transmitted over unencrypted HTTP connections.",
                    recommendation: 'Set the Secure flag on all cookies. In Laravel: SESSION_SECURE_COOKIE=true in .env',
                    owasp: 'https://owasp.org/www-community/controls/SecureCookieAttribute',
                    cvss: 30,
                );
            }
        }
    }
}
