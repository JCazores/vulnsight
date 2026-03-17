<?php

namespace App\Services\Modules;

use App\Models\DiscoveredUrl;
use App\Models\Scan;
use App\Models\Vulnerability;
use App\Services\Scanner\HttpClient;

abstract class BaseModule
{
    protected HttpClient $http;
    protected Scan $scan;

    public function __construct(Scan $scan, HttpClient $http)
    {
        $this->scan = $scan;
        $this->http = $http;
    }

    abstract public function name(): string;
    abstract public function run(DiscoveredUrl $url): void;

    protected function report(
        DiscoveredUrl $discoveredUrl,
        string $type,
        string $name,
        string $severity,
        string $url,
        string $method,
        string $parameter,
        string $payload,
        string $evidence,
        string $requestRaw,
        string $responseRaw,
        string $description = '',
        string $recommendation = '',
        string $owasp = '',
        ?string $cve = null,
        ?int $cvss = null
    ): Vulnerability {
        return Vulnerability::create([
            'scan_id' => $this->scan->id,
            'discovered_url_id' => $discoveredUrl->id,
            'type' => $type,
            'name' => $name,
            'severity' => $severity,
            'cve' => $cve,
            'cvss_score' => $cvss,
            'url' => $url,
            'method' => $method,
            'parameter' => $parameter,
            'payload' => $payload,
            'evidence' => $evidence,
            'request_raw' => $requestRaw,
            'response_raw' => substr($responseRaw, 0, 5000),
            'description' => $description,
            'recommendation' => $recommendation,
            'owasp_ref' => $owasp,
            'status' => 'confirmed',
            'is_new' => true,
        ]);
    }

    /**
     * Build a raw HTTP request string for evidence.
     */
    protected function buildRequestRaw(string $method, string $url, array $params = [], array $extraHeaders = []): string
    {
        $parsed = parse_url($url);
        $path = ($parsed['path'] ?? '/') . (isset($parsed['query']) ? '?' . $parsed['query'] : '');
        $host = $parsed['host'] ?? '';
        $body = $method === 'POST' ? http_build_query($params) : '';
        $headers = array_merge(['Host' => $host, 'Content-Type' => 'application/x-www-form-urlencoded'], $extraHeaders);
        $headerStr = implode("\r\n", array_map(fn($k, $v) => "$k: $v", array_keys($headers), $headers));
        return "{$method} {$path} HTTP/1.1\r\n{$headerStr}\r\n\r\n{$body}";
    }

    /**
     * Inject a payload into every parameter of a URL and return the modified URL.
     */
    protected function injectIntoUrl(string $url, string $paramName, string $payload): string
    {
        $parsed = parse_url($url);
        parse_str($parsed['query'] ?? '', $params);
        $params[$paramName] = $payload;
        $base = ($parsed['scheme'] ?? 'http') . '://' . ($parsed['host'] ?? '');
        if (isset($parsed['port']))
            $base .= ':' . $parsed['port'];
        $base .= $parsed['path'] ?? '/';
        return $base . '?' . http_build_query($params);
    }

    protected function isRunning(): bool
    {
        return $this->scan->fresh()->status === 'running';
    }
}
