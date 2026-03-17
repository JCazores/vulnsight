<?php

namespace App\Services\Scanner;

use Illuminate\Support\Facades\Log;

/**
 * NucleiScanner
 *
 * Replaces ZAP. Uses Nuclei by ProjectDiscovery.
 *
 * Install:
 *   wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
 *   unzip nuclei_linux_amd64.zip
 *   sudo mv nuclei /usr/local/bin/
 *   nuclei -update-templates
 */
class NucleiScanner
{
    /**
     * Tags used when running against a remote/production target.
     * Against localhost we skip tags entirely so all templates can run.
     */
    private const TAGS = [
        'sqli',
        'xss',
        'lfi',
        'rce',
        'ssrf',
        'redirect',
        'exposure',
        'misconfig',
        'laravel',
        'php',
        'headers',
        'cve',
    ];

    // Severities to include (skip 'info' — too much noise)
    private const MIN_SEVERITY = ['low', 'medium', 'high', 'critical'];

    private function nucleiBin(): string
    {
        $envPath = env('NUCLEI_PATH', '');
        if ($envPath && file_exists($envPath)) {
            return $envPath;
        }

        foreach ([
            '/usr/local/bin/nuclei',
            '/usr/bin/nuclei',
            '/home/' . get_current_user() . '/go/bin/nuclei',
            '/root/go/bin/nuclei',
            '/snap/bin/nuclei',
        ] as $path) {
            if (file_exists($path)) {
                return $path;
            }
        }

        $found = trim(shell_exec('which nuclei 2>/dev/null') ?? '');
        return $found;
    }

    public function isAvailable(): bool
    {
        return !empty($this->nucleiBin());
    }

    /**
     * Detect whether a URL points to localhost / a private network.
     * Against these targets we relax tag filtering so templates actually run.
     */
    private function isLocalTarget(string $url): bool
    {
        $host = strtolower(parse_url($url, PHP_URL_HOST) ?? '');

        return in_array($host, ['localhost', '127.0.0.1', '::1'], true)
            || str_starts_with($host, '192.168.')
            || str_starts_with($host, '10.')
            || preg_match('/^172\.(1[6-9]|2\d|3[01])\./', $host);
    }

    /**
     * Detect the installed Nuclei version so we can use correct flags.
     * Returns a version string like "3.2.1" or null on failure.
     */
    private function nucleiVersion(): ?string
    {
        $bin = $this->nucleiBin();
        if (!$bin) {
            return null;
        }

        $raw = trim(shell_exec("{$bin} -version 2>&1") ?? '');
        if (preg_match('/(\d+\.\d+\.\d+)/', $raw, $m)) {
            return $m[1];
        }
        return null;
    }

    /**
     * Not used anymore — v3.7+ uses -jle / -jsonl-export for file output.
     * Kept for reference only.
     */
    private function resolveJsonFlag(string $bin): string
    {
        return '-jle'; // v3.7+: -jle <file> writes JSONL to file
    }

    /**
     * Run Nuclei against $targetUrl.
     * Returns normalised findings array — all real, template-verified.
     */
    public function scan(string $targetUrl, int $maxTime = 300, ?\Closure $shouldAbort = null): array
    {
        $bin = $this->nucleiBin();
        $abort = $shouldAbort ?? fn() => false;

        if (!$bin) {
            Log::info('NucleiScanner: nuclei not found — skipping. Install from github.com/projectdiscovery/nuclei/releases');
            return [];
        }

        if ($abort())
            return [];

        $outputFile = storage_path('app/nuclei_' . uniqid() . '.json');
        $findings = [];
        $isLocal = $this->isLocalTarget($targetUrl);

        try {
            $severity = implode(',', self::MIN_SEVERITY);
            $stderrFile = storage_path('app/nuclei_stderr_' . uniqid() . '.txt');

            $parts = [
                escapeshellarg($bin),
                '-u',
                escapeshellarg($targetUrl),
                '-severity',
                escapeshellarg($severity),
                '-jle',
                escapeshellarg($outputFile),
                '-nc',
                '-duc',
                '-timeout',
                '5',
                '-bulk-size',
                '5',
                '-rate-limit',
                '30',
                '-max-host-error',
                '3',
                '-no-interactsh',
            ];

            if (!$isLocal) {
                $parts[] = '-tags';
                $parts[] = escapeshellarg(implode(',', self::TAGS));
            } else {
                $parts[] = '-tags';
                $parts[] = escapeshellarg('headers,misconfig,exposure,laravel,php,debug,config');
                $parts[] = '-exclude-tags';
                $parts[] = escapeshellarg('oast,blind,dos,fuzzing,intrusive');
            }

            $cmd = implode(' ', $parts) . ' 2>' . escapeshellarg($stderrFile);

            Log::info("NucleiScanner: running against {$targetUrl}", [
                'local_target' => $isLocal,
                'cmd' => $cmd,
            ]);

            // Use proc_open instead of exec so we can kill the process on abort
            $descriptors = [1 => ['pipe', 'w']]; // stdout (we use -jle so stdout is minimal)
            $process = proc_open($cmd, $descriptors, $pipes);

            if (!is_resource($process)) {
                Log::error('NucleiScanner: proc_open failed');
                return [];
            }

            // Poll every second — read stdout (mostly empty) and check abort flag
            stream_set_blocking($pipes[1], false);
            $startTime = time();
            while (true) {
                // Hard timeout
                if ((time() - $startTime) >= $maxTime) {
                    Log::warning("NucleiScanner: hit {$maxTime}s timeout — killing process");
                    proc_terminate($process, 9);
                    break;
                }

                // Force-stop: kill the process immediately
                if ($abort()) {
                    Log::info("NucleiScanner: abort signal received — killing nuclei process");
                    proc_terminate($process, 9);
                    fclose($pipes[1]);
                    proc_close($process);
                    return []; // return nothing — scan was cancelled
                }

                $status = proc_get_status($process);
                if (!$status['running']) {
                    break; // process finished naturally
                }

                sleep(1);
            }

            fclose($pipes[1]);
            $exitCode = proc_close($process);

            $stderr = file_exists($stderrFile) ? trim(file_get_contents($stderrFile)) : '';
            if (file_exists($stderrFile))
                unlink($stderrFile);

            Log::info("NucleiScanner: finished (exit code {$exitCode})", [
                'stderr_snippet' => $stderr ? mb_substr($stderr, 0, 500) : null,
            ]);

            if ($exitCode === 2) {
                Log::warning("NucleiScanner: exit code 2 — no templates matched. Run `nuclei -update-templates`. stderr: " . mb_substr($stderr, 0, 300));
                return [];
            }

            if (!file_exists($outputFile) || filesize($outputFile) === 0) {
                Log::info('NucleiScanner: no output file — clean result (exit code ' . $exitCode . ')');
                return [];
            }

            $lines = file($outputFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            foreach ($lines as $line) {
                $data = json_decode(trim($line), true);
                if (json_last_error() !== JSON_ERROR_NONE || empty($data))
                    continue;
                $finding = $this->normalise($data, $targetUrl);
                if ($finding)
                    $findings[] = $finding;
            }

            Log::info("NucleiScanner: found " . count($findings) . " findings");

        } catch (\Throwable $e) {
            Log::error("NucleiScanner exception: " . $e->getMessage());
        } finally {
            if (file_exists($outputFile))
                unlink($outputFile);
        }

        return $findings;
    }

    // ─────────────────────────────────────────────────────────────

    private function normalise(array $data, string $targetUrl): ?array
    {
        $name = $data['info']['name'] ?? $data['template-id'] ?? 'Nuclei Finding';
        $severity = strtolower($data['info']['severity'] ?? 'low');
        $url = $data['matched-at'] ?? $data['host'] ?? $targetUrl;
        $desc = $data['info']['description'] ?? '';
        $reference = $data['info']['reference'] ?? [];
        $tags = $data['info']['tags'] ?? [];
        $matcher = $data['matcher-name'] ?? '';
        $extracted = $data['extracted-results'] ?? [];
        $curled = $data['curl-command'] ?? '';

        // FIX 6: Correctly extract HTTP method from request field (was always 'GET')
        $method = 'GET';
        if (!empty($data['request'])) {
            // Nuclei request field is a raw HTTP string; first word is the method
            if (preg_match('/^(GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)/i', $data['request'], $mMatch)) {
                $method = strtoupper($mMatch[1]);
            }
        }

        // Build evidence from what Nuclei actually matched
        $evidence = $matcher ? "Matcher: {$matcher}" : '';
        if (!empty($extracted)) {
            $evidence .= ($evidence ? ' | ' : '') . 'Extracted: ' . implode(', ', array_slice($extracted, 0, 3));
        }
        if (!$evidence) {
            $evidence = "Nuclei template '{$data['template-id']}' matched on {$url}";
        }

        // Extract CVE from template ID or tags
        $cve = null;
        if (preg_match('/CVE-\d{4}-\d+/i', $data['template-id'] ?? '', $m)) {
            $cve = strtoupper($m[0]);
        }
        if (!$cve) {
            foreach ((array) $tags as $tag) {
                if (preg_match('/CVE-\d{4}-\d+/i', $tag, $m)) {
                    $cve = strtoupper($m[0]);
                    break;
                }
            }
        }

        $refs = is_array($reference) ? $reference : [$reference];
        $solution = $this->solution($name, $severity, (array) $tags);
        $steps = $this->steps($name, (array) $tags, $refs);

        $severityMap = [
            'critical' => 'critical',
            'high' => 'high',
            'medium' => 'medium',
            'low' => 'low',
            'info' => 'low',
        ];

        return [
            'name' => $name . ($cve ? " ({$cve})" : ''),
            'url' => $url,
            'severity' => $severityMap[$severity] ?? 'low',
            'description' => $desc ?: "Nuclei detected: {$name}",
            'solution' => $solution,
            'steps' => $steps,
            'evidence' => $evidence,
            'cve' => $cve,
            'method' => $method,   // Fixed: was hardcoded GET
            'parameter' => null,
            'payload' => $curled ? mb_substr($curled, 0, 500) : null,
            'source' => 'nuclei',
            'confidence' => 3,       // Nuclei template match = high confidence
            'verified' => true,    // Templates verify their own findings
            'proof' => "Nuclei template '{$data['template-id']}' matched. Evidence: {$evidence}",
        ];
    }

    private function solution(string $name, string $severity, array $tags): string
    {
        $n = strtolower($name);
        $t = implode(' ', $tags);

        if (str_contains($n, 'sql') || str_contains($t, 'sqli')) {
            return 'Use parameterised queries. Never concatenate user input into SQL strings.';
        }
        if (str_contains($n, 'xss') || str_contains($t, 'xss')) {
            return 'Use {{ $var }} in Blade templates. Never use {!! $var !!} with user input.';
        }
        if (str_contains($n, 'redirect')) {
            return 'Validate redirect URLs against a whitelist of allowed domains.';
        }
        if (str_contains($n, 'exposure') || str_contains($n, 'disclosure')) {
            return 'Remove or restrict access to the exposed file/endpoint.';
        }
        if (str_contains($n, 'header')) {
            return 'Add the missing security header in your SecurityHeaders middleware.';
        }
        if (str_contains($n, 'laravel') || str_contains($n, 'debug')) {
            return 'Set APP_DEBUG=false and APP_ENV=production in .env for production.';
        }
        if ($severity === 'critical' || $severity === 'high') {
            return 'Patch immediately — review the referenced advisory for specific fix.';
        }
        return 'Review the finding and apply the recommended fix from the Nuclei template.';
    }

    private function steps(string $name, array $tags, array $refs): array
    {
        $n = strtolower($name);

        if (str_contains($n, 'sql')) {
            $steps = [
                'Replace raw DB::select() with parameterised queries: DB::select("SELECT * WHERE id = ?", [$id])',
                'Or use Eloquent: User::find($id)',
                'Run: php artisan make:model with proper relationships',
            ];
        } elseif (str_contains($n, 'xss')) {
            $steps = [
                'Replace {!! $var !!} with {{ $var }} in all Blade templates',
                'Audit all views: grep -r "{!!" resources/views/',
                'Add Content-Security-Policy header',
            ];
        } elseif (str_contains($n, 'debug') || str_contains($n, 'laravel')) {
            $steps = [
                'Set APP_DEBUG=false in .env',
                'Set APP_ENV=production in .env',
                'Run: php artisan config:cache',
            ];
        } elseif (str_contains($n, 'exposure') || str_contains($n, 'disclosure')) {
            $steps = [
                'Delete or restrict the exposed file',
                'Add nginx rule: location ~ /\\.sensitive { deny all; }',
            ];
        } else {
            $steps = ['Review the finding details and apply the recommended fix'];
        }

        if (!empty($refs)) {
            $steps[] = 'Full advisory: ' . $refs[0];
        }

        return $steps;
    }
}
