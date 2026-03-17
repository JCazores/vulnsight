<?php

namespace App\Services\Scanner;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class ProofVerifier
{
    private int $timeout = 10;

    private const DB_ERROR_STRINGS = [
        'SQLSTATE[',
        'You have an error in your SQL syntax',
        'Illuminate\Database\QueryException',
        'syntax error',
        'pg_query()',
        'Warning: mysqli',
        'ORA-0',
        'Unclosed quotation mark',
        'supplied argument is not a valid MySQL',
    ];

    private const PASSWD_STRINGS = [
        'root:x:0:0',
        'root:*:0:0',
        '/bin/bash',
        '/bin/sh',
        'nobody:x:',
    ];

    public function verifyAll(array $findings, string $targetUrl): array
    {
        $confirmed = [];

        foreach ($findings as $f) {
            try {
                $result = $this->verify($f, $targetUrl);
                if ($result !== null) {
                    $confirmed[] = $result;
                } else {
                    Log::info("ProofVerifier: DISCARDED (false positive) — " . ($f['name'] ?? '') . " at " . ($f['url'] ?? ''));
                }
            } catch (\Throwable $e) {
                Log::warning("ProofVerifier: exception verifying '" . ($f['name'] ?? '') . "': " . $e->getMessage());
                $f['verified'] = false;
                $f['proof']    = 'Verification failed: ' . $e->getMessage();
                $confirmed[]   = $f;
            }
        }

        return $confirmed;
    }

    public function verify(array $finding, string $targetUrl): ?array
    {
        if (in_array($finding['source'] ?? '', ['dependency_scanner', 'header_scanner'], true)) {
            return $finding;
        }

        $type = $this->classify($finding['name'] ?? '');

        return match ($type) {
            'sqli'          => $this->confirmSqli($finding, $targetUrl),
            'xss'           => $this->confirmXss($finding, $targetUrl),
            'open_redirect' => $this->confirmRedirect($finding, $targetUrl),
            'exposed_file'  => $finding,
            'path_traversal'=> $this->confirmTraversal($finding, $targetUrl),
            'csrf'          => $this->confirmCsrf($finding),
            'static_code'   => $finding,
            default         => $this->confirmZapGeneric($finding),
        };
    }

    private function confirmSqli(array $f, string $targetUrl): ?array
    {
        $url    = $f['url'] ?? $targetUrl;
        $param  = $f['parameter'] ?? $f['param'] ?? null;
        $method = strtoupper($f['method'] ?? 'GET');

        foreach (["'", "1'", "' OR ''='"] as $payload) {
            try {
                $response = $this->inject($url, $method, $param, $payload);
                $body     = $response->body();

                foreach (self::DB_ERROR_STRINGS as $signal) {
                    if (stripos($body, $signal) !== false) {
                        $f['verified'] = true;
                        $f['proof']    = "SQL injection confirmed: response contained DB error '{$signal}' when param '{$param}' = '{$payload}'.";
                        return $f;
                    }
                }

                $trueResp  = $this->inject($url, $method, $param, "1 OR 1=1");
                $falseResp = $this->inject($url, $method, $param, "1 AND 1=2");
                $diff      = abs(strlen($trueResp->body()) - strlen($falseResp->body()));

                if ($diff > 30) {
                    $f['verified'] = true;
                    $f['proof']    = "Boolean-based SQL injection confirmed: TRUE=" . strlen($trueResp->body()) . " bytes vs FALSE=" . strlen($falseResp->body()) . " bytes (diff={$diff}).";
                    return $f;
                }
            } catch (\Throwable $e) {
                Log::debug("SQLi confirm failed: " . $e->getMessage());
            }
        }

        return null;
    }

    private function confirmXss(array $f, string $targetUrl): ?array
    {
        $url    = $f['url'] ?? $targetUrl;
        $param  = $f['parameter'] ?? $f['param'] ?? null;
        $method = strtoupper($f['method'] ?? 'GET');
        $marker = 'WAVSPROBE' . substr(md5(uniqid()), 0, 8);
        $payload = "<script>{$marker}</script>";

        try {
            $response = $this->inject($url, $method, $param, $payload);
            $body     = $response->body();

            if (str_contains($body, $payload)) {
                $f['verified'] = true;
                $f['proof']    = "XSS confirmed: payload appeared verbatim unescaped in response for param '{$param}'.";
                return $f;
            }

            if (str_contains($body, htmlspecialchars($payload))) {
                return null;
            }
        } catch (\Throwable $e) {
            Log::debug("XSS confirm failed: " . $e->getMessage());
        }

        return null;
    }

    private function confirmRedirect(array $f, string $targetUrl): ?array
    {
        $url   = $f['url'] ?? $targetUrl;
        $param = $f['parameter'] ?? $f['param'] ?? null;
        $probe = 'https://proof.wavs-verify.invalid';

        try {
            $response = Http::timeout($this->timeout)
                ->withoutRedirecting()
                ->withHeaders(['User-Agent' => 'VulnSight-Verifier/1.0'])
                ->get($url, [$param => $probe]);

            $location = $response->header('Location') ?? '';
            $status   = $response->status();

            if (in_array($status, [301, 302, 303, 307, 308], true)
                && str_contains($location, 'proof.wavs-verify.invalid')) {
                $f['verified'] = true;
                $f['proof']    = "Open redirect confirmed: HTTP {$status} Location: {$location}";
                return $f;
            }
        } catch (\Throwable $e) {
            Log::debug("Redirect confirm failed: " . $e->getMessage());
        }

        return null;
    }

    private function confirmTraversal(array $f, string $targetUrl): ?array
    {
        $url    = $f['url'] ?? $targetUrl;
        $param  = $f['parameter'] ?? null;
        $method = strtoupper($f['method'] ?? 'GET');

        try {
            $response = $this->inject($url, $method, $param, '../../../etc/passwd');
            $body     = $response->body();

            foreach (self::PASSWD_STRINGS as $signal) {
                if (str_contains($body, $signal)) {
                    $f['verified'] = true;
                    $f['proof']    = "Path traversal confirmed: response contained '{$signal}'.";
                    return $f;
                }
            }
        } catch (\Throwable $e) {
            Log::debug("Traversal confirm failed: " . $e->getMessage());
        }

        return null;
    }

    private function confirmCsrf(array $f): ?array
    {
        $url = $f['url'] ?? '';
        if (!$url) return null;

        try {
            $response = Http::timeout($this->timeout)
                ->withHeaders([
                    'User-Agent'   => 'VulnSight-Verifier/1.0',
                    'Content-Type' => 'application/x-www-form-urlencoded',
                ])
                ->post($url, ['probe' => 'csrf_test']);

            $status = $response->status();

            if ($status === 419) return null;

            if ($status >= 200 && $status < 300) {
                $f['verified'] = true;
                $f['proof']    = "CSRF confirmed: POST without _token accepted with HTTP {$status}.";
                return $f;
            }
        } catch (\Throwable $e) {
            Log::debug("CSRF confirm failed: " . $e->getMessage());
        }

        return null;
    }

    private function confirmZapGeneric(array $f): ?array
    {
        $conf = is_int($f['confidence'] ?? null)
            ? $f['confidence']
            : $this->confStrToInt((string) ($f['confidence'] ?? 'low'));

        if ($conf >= 3) {
            $f['verified'] = true;
            $f['proof']    = 'ZAP reported High/Confirmed confidence.';
            return $f;
        }

        if ($conf === 2) {
            $f['verified'] = false;
            $f['proof']    = 'ZAP Medium confidence — manual verification recommended.';
            return $f;
        }

        return null;
    }

    private function classify(string $name): string
    {
        $n = strtolower($name);
        if (str_contains($n, 'sql') || str_contains($n, 'injection'))             return 'sqli';
        if (str_contains($n, 'xss') || str_contains($n, 'cross-site scripting'))  return 'xss';
        if (str_contains($n, 'redirect'))                                          return 'open_redirect';
        if (str_contains($n, 'exposed') || str_contains($n, '.env') || str_contains($n, 'backup') || str_contains($n, 'git') || str_contains($n, 'log file')) return 'exposed_file';
        if (str_contains($n, 'traversal'))                                         return 'path_traversal';
        if (str_contains($n, 'csrf') || str_contains($n, 'cross-site request'))   return 'csrf';
        if (str_contains($n, 'source://'))                                         return 'static_code';
        return 'generic';
    }

    private function inject(string $url, string $method, ?string $param, string $payload): \Illuminate\Http\Client\Response
    {
        $http = Http::timeout($this->timeout)
            ->withHeaders(['User-Agent' => 'VulnSight-Verifier/1.0'])
            ->withoutRedirecting();

        if (!$param) {
            return match ($method) {
                'POST'  => $http->post($url),
                default => $http->get($url),
            };
        }

        $parts = parse_url($url);
        parse_str($parts['query'] ?? '', $existing);
        $existing[$param] = $payload;

        $base = ($parts['scheme'] ?? 'http') . '://'
            . ($parts['host'] ?? 'localhost')
            . (isset($parts['port']) ? ':' . $parts['port'] : '')
            . ($parts['path'] ?? '/');

        return match ($method) {
            'POST'  => $http->post($base, $existing),
            'PUT'   => $http->put($base, $existing),
            default => $http->get($base, $existing),
        };
    }

    private function confStrToInt(string $c): int
    {
        return match (strtolower($c)) {
            'confirmed'      => 4,
            'high'           => 3,
            'medium'         => 2,
            'low'            => 1,
            'false positive' => 0,
            default          => 1,
        };
    }
}
