<?php

namespace App\Services;

use App\Models\Scan;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Str;

/**
 * NucleiService
 *
 * Orchestrates real vulnerability scanning using:
 *   1. Nuclei  — primary engine (CVEs, misconfigs, OWASP Top 10 templates)
 *   2. Nikto   — web server misconfiguration checks
 *   3. testssl — SSL/TLS flaw detection (https targets only)
 *
 * Each scan runs as background processes. Results are polled from a
 * temp JSONL output file that Nuclei writes to, enabling streaming updates.
 *
 * Environment variables (set in .env):
 *   NUCLEI_PATH   = /home/jeycee/go/bin/nuclei   (required)
 *   NIKTO_PATH    = /usr/bin/nikto                (optional, falls back to system PATH)
 *   TESTSSL_PATH  = /usr/local/bin/testssl.sh     (optional)
 */
class NucleiService
{
    private string $nucleiPath;
    private string $niktoPath;
    private string $testsslPath;
    private string $outputDir;

    // Nuclei template tags to test — covers OWASP Top 10
    private const NUCLEI_TAGS = [
        'cve',
        'sqli',
        'xss',
        'ssrf',
        'rce',
        'lfi',
        'open-redirect',
        'xxe',
        'idor',
        'misconfig',
        'exposure',
        'takeover',
        'unauth',
        'auth-bypass',
        'default-login',
        'token-spray',
        'jwt',
        'cors',
        'csrf',
        'broken-auth',
    ];

    public function __construct()
    {
        $this->nucleiPath = env('NUCLEI_PATH', 'nuclei');
        $this->niktoPath = env('NIKTO_PATH', 'nikto');
        $this->testsslPath = env('TESTSSL_PATH', 'testssl.sh');
        $this->outputDir = storage_path('app/scan-results');

        if (!is_dir($this->outputDir)) {
            mkdir($this->outputDir, 0755, true);
        }
    }

    // ── Start Scan ────────────────────────────────────────────────────────────
    /**
     * Launches Nuclei (+ Nikto, testssl) as background processes.
     * Returns a scan_id key used for polling.
     */
    public function startScan(Scan $scan, string $targetUrl): array
    {
        $scanKey = 'scan_' . $scan->id . '_' . Str::random(8);
        $outputFile = $this->outputDir . '/' . $scanKey . '.jsonl';
        $niktoFile = $this->outputDir . '/' . $scanKey . '_nikto.json';
        $testsslFile = $this->outputDir . '/' . $scanKey . '_testssl.json';
        $pidFile = $this->outputDir . '/' . $scanKey . '.pid';

        // Validate that Nuclei binary exists
        if (!$this->binaryExists($this->nucleiPath)) {
            throw new \RuntimeException(
                'Nuclei not found at: ' . $this->nucleiPath .
                '. Install with: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest'
            );
        }

        $tags = implode(',', self::NUCLEI_TAGS);

        // Build Nuclei command
        // -j = JSON output (one result per line = JSONL)
        // -silent = no banner noise
        // -rl = rate limit (requests per second, from config)
        // -timeout = per-request timeout
        // -fr = follow redirects
        $rateLimit = env('WAVS_MAX_REQUESTS_PER_SECOND', 50);
        $timeout = env('WAVS_CONNECT_TIMEOUT', 10);
        $verifySSL = env('WAVS_VERIFY_SSL', false) ? '' : '-disable-update-check';
        $userAgent = env('WAVS_USER_AGENT', 'VulnSight/1.0 (security scanner)');

        $nucleiCmd = implode(' ', array_filter([
            escapeshellarg($this->nucleiPath),
            '-u',
            escapeshellarg($targetUrl),
            '-tags',
            escapeshellarg($tags),
            '-j',
            '-o',
            escapeshellarg($outputFile),
            '-rl',
            (int) $rateLimit,
            '-timeout',
            (int) $timeout,
            '-fr',
            '-silent',
            '-no-color',
            '-header',
            escapeshellarg('User-Agent: ' . $userAgent),
            env('WAVS_VERIFY_SSL', false) ? '' : '-disable-update-check',
        ]));

        // Background launch: redirect stderr to log, capture PID
        $logFile = $this->outputDir . '/' . $scanKey . '_nuclei.log';
        $bgCmd = "({$nucleiCmd} > /dev/null 2>{$logFile}; echo DONE >> {$outputFile}) & echo \$! > {$pidFile}";

        exec($bgCmd);

        // Launch Nikto in background too (if available)
        if ($this->binaryExists($this->niktoPath)) {
            $niktoLog = $this->outputDir . '/' . $scanKey . '_nikto.log';
            $niktoCmd = escapeshellarg($this->niktoPath) .
                ' -h ' . escapeshellarg($targetUrl) .
                ' -Format json' .
                ' -output ' . escapeshellarg($niktoFile) .
                ' -nointeractive -maxtime 120';
            exec("({$niktoCmd} > /dev/null 2>{$niktoLog}) &");
        }

        // Launch testssl for https targets
        if (str_starts_with($targetUrl, 'https://') && $this->binaryExists($this->testsslPath)) {
            $host = parse_url($targetUrl, PHP_URL_HOST);
            $testsslLog = $this->outputDir . '/' . $scanKey . '_testssl.log';
            $testsslCmd = escapeshellarg($this->testsslPath) .
                ' --jsonfile ' . escapeshellarg($testsslFile) .
                ' --quiet --warnings off ' . escapeshellarg($host);
            exec("({$testsslCmd} > {$testsslLog} 2>&1) &");
        }

        // Store scan metadata in cache for polling
        Cache::put("scan_meta:{$scanKey}", [
            'scan_id' => $scan->id,
            'target_url' => $targetUrl,
            'output_file' => $outputFile,
            'nikto_file' => $niktoFile,
            'testssl_file' => $testsslFile,
            'pid_file' => $pidFile,
            'started_at' => now()->toISOString(),
            'seen_lines' => 0,
            'seen_nikto' => false,
            'seen_testssl' => false,
        ], now()->addHours(2));

        Cache::put("scan_key:{$scan->id}", $scanKey, now()->addHours(2));

        return ['scan_id' => $scanKey];
    }

    // ── Poll Status ────────────────────────────────────────────────────────────
    /**
     * Reads new lines from Nuclei's JSONL output file.
     * Merges Nikto + testssl results once they finish.
     * Returns the same shape as the old ZAP status endpoint.
     */
    public function pollStatus(Scan $scan, ?string $scanKey = null): array
    {
        $scanKey = $scanKey ?? Cache::get("scan_key:{$scan->id}");

        if (!$scanKey) {
            return ['progress' => 0, 'status' => 'idle', 'new_vulns' => []];
        }

        $meta = Cache::get("scan_meta:{$scanKey}");
        if (!$meta) {
            return ['progress' => 100, 'status' => 'completed', 'new_vulns' => []];
        }

        $outputFile = $meta['output_file'];
        $seenLines = $meta['seen_lines'] ?? 0;

        $newVulns = [];
        $totalLines = 0;
        $isCompleted = false;

        if (file_exists($outputFile)) {
            $lines = file($outputFile, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
            $totalLines = count($lines);

            foreach (array_slice($lines, $seenLines) as $line) {
                if (trim($line) === 'DONE') {
                    $isCompleted = true;
                    continue;
                }

                $result = json_decode($line, true);
                if (!$result)
                    continue;

                $vuln = $this->normalizeNucleiResult($result);
                if ($vuln)
                    $newVulns[] = $vuln;
            }
        }

        // Check Nikto results (once complete)
        if (!$meta['seen_nikto'] && file_exists($meta['nikto_file'])) {
            $niktoVulns = $this->parseNiktoResults($meta['nikto_file']);
            $newVulns = array_merge($newVulns, $niktoVulns);
            $meta['seen_nikto'] = true;
        }

        // Check testssl results (once complete)
        if (!$meta['seen_testssl'] && file_exists($meta['testssl_file'])) {
            $sslVulns = $this->parseTestsslResults($meta['testssl_file']);
            $newVulns = array_merge($newVulns, $sslVulns);
            $meta['seen_testssl'] = true;
        }

        // Update seen line count
        $meta['seen_lines'] = $totalLines;
        Cache::put("scan_meta:{$scanKey}", $meta, now()->addHours(2));

        // Estimate progress:
        // Nuclei doesn't expose percentage natively.
        // We use: if scan still running → ramp up to 90%, complete → 100%
        $pid = $this->getScanPid($meta['pid_file'] ?? '');
        $running = $pid && $this->processIsRunning($pid);
        $progress = $isCompleted || (!$running && $totalLines > 0) ? 100 : $this->estimateProgress($meta);

        // Current URL being scanned (last nuclei result's matched-at)
        $currentUrl = null;
        if ($newVulns) {
            $currentUrl = $newVulns[count($newVulns) - 1]['url'] ?? null;
        }

        return [
            'progress' => $progress,
            'status' => ($progress >= 100) ? 'completed' : 'running',
            'spider_done' => true,   // Nuclei doesn't have a separate spider phase
            'new_vulns' => $newVulns,
            'current_url' => $currentUrl,
            'requests_sent' => $totalLines * 3,   // rough approximation
            'urls_discovered' => max(1, $totalLines),
        ];
    }

    // ── Stop Scan ─────────────────────────────────────────────────────────────
    public function stopScan(Scan $scan): void
    {
        $scanKey = Cache::get("scan_key:{$scan->id}");
        if (!$scanKey)
            return;

        $meta = Cache::get("scan_meta:{$scanKey}");
        if (!$meta)
            return;

        $pid = $this->getScanPid($meta['pid_file'] ?? '');
        if ($pid) {
            exec("kill -TERM {$pid} 2>/dev/null");
            sleep(1);
            exec("kill -KILL {$pid} 2>/dev/null");
        }

        Cache::forget("scan_meta:{$scanKey}");
        Cache::forget("scan_key:{$scan->id}");
    }

    // ── Parse Nuclei JSONL result → normalized vuln ───────────────────────────
    private function normalizeNucleiResult(array $result): ?array
    {
        $info = $result['info'] ?? [];
        $severity = strtolower($info['severity'] ?? 'low');
        $matchedAt = $result['matched-at'] ?? $result['host'] ?? '';

        if (empty($matchedAt))
            return null;

        // Map Nuclei severity to our 4 levels
        $severity = match ($severity) {
            'critical' => 'critical',
            'high' => 'high',
            'medium' => 'medium',
            'low', 'info', 'unknown' => 'low',
            default => 'low',
        };

        $name = $info['name'] ?? $result['template-id'] ?? 'Unknown Finding';
        $cveRefs = $info['classification']['cve-id'] ?? [];
        $cve = is_array($cveRefs) && count($cveRefs) > 0 ? $cveRefs[0] : null;

        return [
            'id' => md5($matchedAt . $name),
            'name' => $name,
            'url' => $matchedAt,
            'severity' => $severity,
            'cve' => $cve,
            'tags' => $info['tags'] ?? [],
            'source' => 'nuclei',
        ];
    }

    // ── Parse Nikto JSON results ──────────────────────────────────────────────
    private function parseNiktoResults(string $file): array
    {
        $vulns = [];
        try {
            $data = json_decode(file_get_contents($file), true);
            $host = $data['host'] ?? '';
            foreach ($data['vulnerabilities'] ?? [] as $v) {
                $desc = $v['msg'] ?? $v['message'] ?? 'Nikto finding';
                $vuln = [
                    'id' => md5($host . $desc),
                    'name' => $this->niktoMsgToName($desc),
                    'url' => rtrim($host, '/') . ($v['url'] ?? '/'),
                    'severity' => $this->niktoSeverity($v),
                    'cve' => $v['osvdbid'] ? 'OSVDB-' . $v['osvdbid'] : null,
                    'source' => 'nikto',
                ];
                $vulns[] = $vuln;
            }
        } catch (\Exception $e) {
            Log::warning('Nikto parse error: ' . $e->getMessage());
        }
        return $vulns;
    }

    // ── Parse testssl JSON results ────────────────────────────────────────────
    private function parseTestsslResults(string $file): array
    {
        $vulns = [];
        try {
            $data = json_decode(file_get_contents($file), true);
            // testssl outputs an array of finding objects
            $findings = $data['findings'] ?? (is_array($data) ? $data : []);
            foreach ($findings as $f) {
                $severity = strtolower($f['severity'] ?? 'low');
                if ($severity === 'ok' || $severity === 'info')
                    continue; // skip passing checks

                $vuln = [
                    'id' => md5(($f['id'] ?? '') . ($f['finding'] ?? '')),
                    'name' => 'SSL/TLS: ' . ($f['id'] ?? 'Configuration Issue'),
                    'url' => $f['ip'] ?? '',
                    'severity' => in_array($severity, ['critical', 'high', 'medium', 'low']) ? $severity : 'low',
                    'cve' => $f['cve'] ?? null,
                    'source' => 'testssl',
                ];
                $vulns[] = $vuln;
            }
        } catch (\Exception $e) {
            Log::warning('testssl parse error: ' . $e->getMessage());
        }
        return $vulns;
    }

    // ── Helpers ───────────────────────────────────────────────────────────────
    private function binaryExists(string $path): bool
    {
        if (file_exists($path) && is_executable($path))
            return true;
        // Try system PATH
        exec("which " . escapeshellarg($path) . " 2>/dev/null", $out, $ret);
        return $ret === 0;
    }

    private function getScanPid(string $pidFile): ?int
    {
        if (!$pidFile || !file_exists($pidFile))
            return null;
        $pid = trim(file_get_contents($pidFile));
        return is_numeric($pid) ? (int) $pid : null;
    }

    private function processIsRunning(int $pid): bool
    {
        exec("kill -0 {$pid} 2>/dev/null", $out, $ret);
        return $ret === 0;
    }

    private function estimateProgress(array $meta): int
    {
        // Ramp from 5% → 90% over 3 minutes
        $elapsed = now()->diffInSeconds(\Carbon\Carbon::parse($meta['started_at']));
        $maxSecs = 180;
        $pct = min(90, max(5, (int) (($elapsed / $maxSecs) * 90)));
        return $pct;
    }

    private function niktoMsgToName(string $msg): string
    {
        // Shorten common Nikto messages into a human-readable vuln name
        if (stripos($msg, 'X-Frame-Options') !== false)
            return 'Missing X-Frame-Options Header';
        if (stripos($msg, 'clickjacking') !== false)
            return 'Clickjacking Vulnerability';
        if (stripos($msg, 'X-Content-Type') !== false)
            return 'Missing X-Content-Type-Options';
        if (stripos($msg, 'directory index') !== false)
            return 'Directory Listing Enabled';
        if (stripos($msg, 'default file') !== false)
            return 'Default File Exposed';
        if (stripos($msg, 'server banner') !== false)
            return 'Server Version Disclosure';
        if (stripos($msg, 'phpinfo') !== false)
            return 'PHPInfo Page Exposed';
        if (stripos($msg, 'robots.txt') !== false)
            return 'Sensitive Paths in robots.txt';
        if (stripos($msg, 'SQL') !== false)
            return 'Potential SQL Injection';
        // Default: truncate long message
        return strlen($msg) > 60 ? substr($msg, 0, 60) . '…' : $msg;
    }

    private function niktoSeverity(array $finding): string
    {
        $method = strtoupper($finding['method'] ?? '');
        $msg = strtolower($finding['msg'] ?? '');

        if (stripos($msg, 'sql') !== false || stripos($msg, 'injection') !== false)
            return 'high';
        if (stripos($msg, 'xss') !== false || stripos($msg, 'script') !== false)
            return 'high';
        if (stripos($msg, 'phpinfo') !== false || stripos($msg, 'exposed') !== false)
            return 'medium';
        if (stripos($msg, 'header') !== false || stripos($msg, 'missing') !== false)
            return 'low';

        return 'low';
    }
}
