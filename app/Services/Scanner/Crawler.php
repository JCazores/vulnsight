<?php

namespace App\Services\Scanner;

use App\Models\Scan;
use App\Models\DiscoveredUrl;
use Illuminate\Support\Facades\Log;

class Crawler
{
    private HttpClient $http;
    private Scan $scan;
    private array $visited = [];
    private array $queue = [];
    private string $baseHost = '';
    private array $exclusions = [];

    public function __construct(Scan $scan, HttpClient $http)
    {
        $this->scan = $scan;
        $this->http = $http;
        $this->exclusions = $scan->exclusion_rules ?? [];
    }

    /**
     * Crawl all targets up to configured depth.
     * Returns array of DiscoveredUrl IDs to scan.
     */
    public function crawl(): array
    {
        $discoveredIds = [];

        foreach ($this->scan->targets as $target) {
            $this->scan->update(['current_phase' => 'Crawling: ' . $target->url]);

            $this->baseHost = parse_url($target->url, PHP_URL_HOST);
            $this->visited = [];
            $this->queue = [['url' => $target->url, 'depth' => 0]];

            while (!empty($this->queue) && $this->scan->fresh()->status === 'running') {
                $item = array_shift($this->queue);
                $url = $item['url'];
                $depth = $item['depth'];

                if (isset($this->visited[$url]))
                    continue;
                if ($depth > $this->scan->crawl_depth)
                    continue;
                if ($this->isExcluded($url))
                    continue;

                $this->visited[$url] = true;

                $result = $this->http->get($url, [], 'crawler');
                if (!$result)
                    continue;

                // Save to DB
                $discovered = DiscoveredUrl::create([
                    'scan_id' => $this->scan->id,
                    'url' => $url,
                    'method' => 'GET',
                    'status_code' => $result['status'],
                    'response_time_ms' => $result['ms'],
                    'response_body' => substr($result['body'], 0, 200_000), // cap at 200KB
                    'response_headers' => $result['headers'],
                    'parameters' => $this->extractQueryParams($url),
                    'forms' => $this->extractForms($result['body'], $url),
                    'depth' => $depth,
                    'scanned' => false,
                ]);

                $discoveredIds[] = $discovered->id;
                $this->scan->increment('urls_discovered');

                // Enqueue links found on this page
                if ($depth < $this->scan->crawl_depth) {
                    $links = $this->extractLinks($result['body'], $url);
                    foreach ($links as $link) {
                        if (!isset($this->visited[$link])) {
                            $this->queue[] = ['url' => $link, 'depth' => $depth + 1];
                        }
                    }
                }

                // Also discover API endpoints from JS files
                if (str_contains($result['headers']['content-type'] ?? '', 'javascript')) {
                    $this->extractJsEndpoints($result['body'], $url);
                }
            }
        }

        return $discoveredIds;
    }

    // ── Extraction helpers ────────────────────────────────────

    private function extractLinks(string $html, string $baseUrl): array
    {
        $links = [];

        // <a href>
        preg_match_all('/<a\s[^>]*href=["\']([^"\'#?][^"\']*)["\'][^>]*>/i', $html, $matches);
        foreach ($matches[1] as $href) {
            $absolute = $this->toAbsolute($href, $baseUrl);
            if ($absolute && $this->isSameHost($absolute)) {
                $links[] = $absolute;
            }
        }

        // <form action>
        preg_match_all('/<form\s[^>]*action=["\']([^"\']*)["\'][^>]*>/i', $html, $matches);
        foreach ($matches[1] as $action) {
            $absolute = $this->toAbsolute($action, $baseUrl);
            if ($absolute && $this->isSameHost($absolute)) {
                $links[] = $absolute;
            }
        }

        // <script src> — crawl JS files for endpoints
        preg_match_all('/<script\s[^>]*src=["\']([^"\']*)["\'][^>]*>/i', $html, $matches);
        foreach ($matches[1] as $src) {
            $absolute = $this->toAbsolute($src, $baseUrl);
            if ($absolute && $this->isSameHost($absolute)) {
                $links[] = $absolute;
            }
        }

        return array_unique($links);
    }

    private function extractForms(string $html, string $baseUrl): array
    {
        $forms = [];
        preg_match_all('/<form([^>]*)>(.*?)<\/form>/is', $html, $formMatches);

        foreach ($formMatches[0] as $i => $formHtml) {
            $attrs = $formMatches[1][$i];
            $body = $formMatches[2][$i];

            preg_match('/action=["\']([^"\']*)["\']/', $attrs, $actionMatch);
            preg_match('/method=["\']([^"\']*)["\']/', $attrs, $methodMatch);

            $action = isset($actionMatch[1])
                ? $this->toAbsolute($actionMatch[1], $baseUrl)
                : $baseUrl;

            $method = strtoupper($methodMatch[1] ?? 'GET');

            // Extract all input fields
            $fields = [];
            preg_match_all('/<input([^>]*)>/i', $body, $inputMatches);
            foreach ($inputMatches[1] as $inputAttrs) {
                preg_match('/name=["\']([^"\']*)["\']/', $inputAttrs, $nm);
                preg_match('/type=["\']([^"\']*)["\']/', $inputAttrs, $tp);
                preg_match('/value=["\']([^"\']*)["\']/', $inputAttrs, $vl);

                if (!empty($nm[1])) {
                    $fields[] = [
                        'name' => $nm[1],
                        'type' => $tp[1] ?? 'text',
                        'value' => $vl[1] ?? '',
                    ];
                }
            }

            // <textarea> and <select>
            preg_match_all('/<textarea[^>]*name=["\']([^"\']*)["\'][^>]*>/i', $body, $taMatches);
            foreach ($taMatches[1] as $name) {
                $fields[] = ['name' => $name, 'type' => 'textarea', 'value' => ''];
            }

            if ($action) {
                $forms[] = compact('action', 'method', 'fields');
            }
        }

        return $forms;
    }

    private function extractQueryParams(string $url): array
    {
        $query = parse_url($url, PHP_URL_QUERY);
        if (!$query)
            return [];
        parse_str($query, $params);
        return array_keys($params);
    }

    private function extractJsEndpoints(string $js, string $baseUrl): void
    {
        // Find strings that look like API paths: '/api/...', '/v1/...', etc.
        preg_match_all('/["\'](\/(api|v\d|graphql|rest|admin)[^\s"\'<>{}|\\\\^`\[\]]*)["\']/', $js, $matches);
        foreach ($matches[1] as $path) {
            $absolute = $this->toAbsolute($path, $baseUrl);
            if ($absolute && !isset($this->visited[$absolute])) {
                $this->queue[] = ['url' => $absolute, 'depth' => 1];
            }
        }
    }

    private function toAbsolute(string $href, string $baseUrl): ?string
    {
        $href = trim($href);
        if (empty($href) || str_starts_with($href, 'javascript:') || str_starts_with($href, 'mailto:')) {
            return null;
        }

        if (str_starts_with($href, 'http://') || str_starts_with($href, 'https://')) {
            return $this->normalizeUrl($href);
        }

        $base = parse_url($baseUrl);
        if (!$base)
            return null;

        $scheme = $base['scheme'] ?? 'http';
        $host = $base['host'] ?? '';
        $port = isset($base['port']) ? ':' . $base['port'] : '';

        if (str_starts_with($href, '//')) {
            return $this->normalizeUrl($scheme . ':' . $href);
        }

        if (str_starts_with($href, '/')) {
            return $this->normalizeUrl("{$scheme}://{$host}{$port}{$href}");
        }

        // Relative path
        $basePath = isset($base['path']) ? dirname($base['path']) : '/';
        return $this->normalizeUrl("{$scheme}://{$host}{$port}{$basePath}/{$href}");
    }

    private function normalizeUrl(string $url): string
    {
        // Remove fragments
        return preg_replace('/#.*$/', '', $url);
    }

    private function isSameHost(string $url): bool
    {
        $host = parse_url($url, PHP_URL_HOST);
        return $host === $this->baseHost;
    }

    private function isExcluded(string $url): bool
    {
        foreach ($this->exclusions as $rule) {
            if (str_contains($url, $rule))
                return true;
        }
        return false;
    }
}
