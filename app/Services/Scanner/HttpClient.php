<?php

namespace App\Services\Scanner;

use App\Models\Scan;
use App\Models\HttpRequest as HttpRequestLog;
use GuzzleHttp\Client;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\TransferStats;
use Illuminate\Support\Facades\Log;
use Psr\Http\Message\ResponseInterface;

class HttpClient
{
    private Client $client;
    private Scan $scan;
    private array $authHeaders = [];
    private float $lastRequestAt = 0;
    private float $minInterval = 0.05; // 20 rps default

    public function __construct(Scan $scan)
    {
        $this->scan = $scan;

        // Min interval between requests = 1 / max_rps
        $this->minInterval = 1.0 / max(1, $scan->max_rps);

        // Build auth headers from the first credential on this scan
        $credential = $scan->credentials()->first();
        if ($credential) {
            $this->authHeaders = $credential->toHeaders();
        }

        $this->client = new Client([
            'timeout' => $scan->request_timeout,
            'connect_timeout' => 10,
            'allow_redirects' => $scan->follow_redirects
                ? ['max' => 5, 'track_redirects' => true]
                : false,
            'verify' => false,   // accept self-signed certs on test targets
            'http_errors' => false,   // don't throw on 4xx/5xx — we want those responses
            'headers' => array_merge([
                'User-Agent' => 'VulnSight/1.0 (security scanner; contact your admin)',
                'Accept' => 'text/html,application/xhtml+xml,application/json,*/*',
                'Accept-Language' => 'en-US,en;q=0.9',
            ], $this->authHeaders),
        ]);
    }

    /**
     * Send a request and return a normalised result array.
     * Returns null if the request completely fails (network error).
     */
    public function send(
        string $method,
        string $url,
        array $options = [],
        string $module = 'crawler',
        string $payload = ''
    ): ?array {
        $this->rateLimit();

        $transferTime = 0;
        $options['on_stats'] = function (TransferStats $stats) use (&$transferTime) {
            $transferTime = $stats->getTransferTime();
        };

        try {
            $start = microtime(true);
            $response = $this->client->request($method, $url, $options);
            $ms = (int) round((microtime(true) - $start) * 1000);

            $statusCode = $response->getStatusCode();
            $body = (string) $response->getBody();
            $headers = $this->headersToFlat($response);

            // Log to DB
            $this->logRequest($method, $url, $statusCode, $ms, $module, $payload);

            // Increment scan counter
            $this->scan->increment('requests_sent');

            return [
                'status' => $statusCode,
                'body' => $body,
                'headers' => $headers,
                'ms' => $ms,
                'url' => $url,
                'method' => $method,
                'response' => $response,
            ];

        } catch (ConnectException $e) {
            $this->logRequest($method, $url, null, null, $module, $payload, true, 'Connection failed: ' . $e->getMessage());
            Log::warning("Scanner connect error: {$url} — " . $e->getMessage());
            return null;

        } catch (RequestException $e) {
            $status = $e->hasResponse() ? $e->getResponse()->getStatusCode() : null;
            $this->logRequest($method, $url, $status, null, $module, $payload, true, $e->getMessage());
            return null;

        } catch (\Throwable $e) {
            Log::error("Scanner unexpected error: {$url} — " . $e->getMessage());
            return null;
        }
    }

    public function get(string $url, array $options = [], string $module = 'crawler'): ?array
    {
        return $this->send('GET', $url, $options, $module);
    }

    public function post(string $url, array $data, string $module = 'probe', string $payload = ''): ?array
    {
        return $this->send('POST', $url, ['form_params' => $data], $module, $payload);
    }

    public function postJson(string $url, array $data, string $module = 'probe', string $payload = ''): ?array
    {
        return $this->send('POST', $url, ['json' => $data], $module, $payload);
    }

    // ── Helpers ────────────────────────────────────────────────

    private function rateLimit(): void
    {
        $now = microtime(true);
        $wait = $this->minInterval - ($now - $this->lastRequestAt);
        if ($wait > 0)
            usleep((int) ($wait * 1_000_000));
        $this->lastRequestAt = microtime(true);
    }

    private function headersToFlat(ResponseInterface $response): array
    {
        $flat = [];
        foreach ($response->getHeaders() as $name => $values) {
            $flat[strtolower($name)] = implode(', ', $values);
        }
        return $flat;
    }

    private function logRequest(
        string $method,
        string $url,
        ?int $status,
        ?int $ms,
        string $module,
        string $payload,
        bool $flagged = false,
        string $flagReason = ''
    ): void {
        try {
            HttpRequestLog::create([
                'scan_id' => $this->scan->id,
                'method' => $method,
                'url' => substr($url, 0, 2048),
                'status_code' => $status,
                'response_time_ms' => $ms,
                'module' => $module,
                'payload' => $payload ? substr($payload, 0, 500) : null,
                'flagged' => $flagged,
                'flag_reason' => $flagReason ?: null,
                'sent_at' => now(),
            ]);
        } catch (\Throwable $e) {
            // Never let logging break the scanner
        }
    }
}
