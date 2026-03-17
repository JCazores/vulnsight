<?php

namespace App\Console\Commands;

use App\Models\Scan;
use App\Models\ScanTarget;
use App\Services\Scanner\ScanOrchestrator;
use App\Services\Scanner\ScanExporter;
use Illuminate\Console\Command;
use Illuminate\Support\Facades\Log;

/**
 * WAVS CI/CD Scanner Command
 *
 * Usage:
 *   php artisan wavs:scan https://staging.yourapp.com
 *   php artisan wavs:scan https://staging.yourapp.com --intensity=standard --fail-on=high
 *   php artisan wavs:scan https://staging.yourapp.com --output=junit --output-file=results.xml
 */
class RunScanCommand extends Command
{
    protected $signature = 'wavs:scan
        {url                    : Target URL to scan (must be staging/test environment)}
        {--intensity=standard   : Scan intensity: passive | standard | aggressive}
        {--depth=2              : Crawl depth (1-5, keep low in CI)}
        {--rps=5                : Max requests per second (keep conservative in CI)}
        {--timeout=15           : HTTP request timeout in seconds}
        {--output=json          : Output format: json | junit | summary}
        {--output-file=         : File to write results to (defaults to stdout)}
        {--fail-on=high         : Fail the build on: none | low | medium | high | critical}
        {--exclude=             : Comma-separated URL patterns to exclude (e.g. /logout,/admin)}
        {--label=               : Label for this scan (e.g. pr-123, nightly, release-v2)}
        {--ci                   : CI mode: suppress progress output, only show final result}';

    protected $description = 'Run a WAVS security scan against a target URL (designed for CI/CD pipelines)';

    // Severity order for comparison
    private array $severityOrder = [
        'info' => 0,
        'low' => 1,
        'medium' => 2,
        'high' => 3,
        'critical' => 4,
    ];

    public function handle(ScanOrchestrator $orchestrator, ScanExporter $exporter): int
    {
        $url = $this->argument('url');
        $intensity = $this->option('intensity');
        $failOn = $this->option('fail-on');
        $ciMode = $this->option('ci');

        // ── 1. Validate inputs ────────────────────────────────────────────
        if (!filter_var($url, FILTER_VALIDATE_URL)) {
            $this->error("❌ Invalid URL: {$url}");
            return self::FAILURE;
        }

        if (!in_array($intensity, ['passive', 'standard', 'aggressive'])) {
            $this->error("❌ Invalid intensity. Use: passive | standard | aggressive");
            return self::FAILURE;
        }

        if (!in_array($failOn, ['none', 'low', 'medium', 'high', 'critical'])) {
            $this->error("❌ Invalid --fail-on value. Use: none | low | medium | high | critical");
            return self::FAILURE;
        }

        // ── 2. Safety check — refuse to scan production-like domains ──────
        if ($this->looksLikeProduction($url)) {
            $this->error("❌ The URL '{$url}' looks like a production environment.");
            $this->error("   WAVS CI scans should only target staging/test environments.");
            $this->error("   If this is genuinely a staging URL, set WAVS_ALLOW_PROD=true in your .env");
            if (!config('wavs.allow_prod', false)) {
                return self::FAILURE;
            }
            $this->warn("⚠  WAVS_ALLOW_PROD is enabled — proceeding anyway.");
        }

        // ── 3. Parse exclusions ───────────────────────────────────────────
        $exclusions = [];
        if ($this->option('exclude')) {
            $exclusions = array_map('trim', explode(',', $this->option('exclude')));
        }

        // ── 4. Create the Scan record ─────────────────────────────────────
        if (!$ciMode) {
            $this->info("🔍 WAVS Security Scanner — CI Mode");
            $this->info("   Target    : {$url}");
            $this->info("   Intensity : {$intensity}");
            $this->info("   Fail on   : {$failOn}+");
            $this->line('');
        }

        try {
            $scan = Scan::create([
                'name' => $this->option('label') ?: ('CI Scan — ' . now()->format('Y-m-d H:i')),
                'status' => 'running',
                'intensity' => $intensity,
                'crawl_depth' => (int) $this->option('depth'),
                'max_rps' => (int) $this->option('rps'),
                'request_timeout' => (int) $this->option('timeout'),
                'follow_redirects' => true,
                'exclusion_rules' => $exclusions,
                'progress' => 0,
                'started_at' => now(),
                'current_phase' => 'Starting CI scan…',
                // CI scans run synchronously — no queue needed
                'ci_mode' => true,
                'ci_label' => $this->option('label') ?: null,
            ]);

            // Attach the target
            $scan->targets()->create(['url' => $url]);

        } catch (\Throwable $e) {
            $this->error("❌ Failed to create scan record: " . $e->getMessage());
            $this->error("   Is your database migrated? Run: php artisan migrate");
            return self::FAILURE;
        }

        // ── 5. Run the scan synchronously ────────────────────────────────
        if (!$ciMode) {
            $this->output->write("   Running");
        }

        $progressCallback = function (string $phase, int $progress) use ($ciMode) {
            if (!$ciMode) {
                $this->output->write('.');
            }
            Log::info("[WAVS CI] {$phase} ({$progress}%)");
        };

        try {
            // Run synchronously (not via queue) so CI waits for completion
            $orchestrator->executeWithCallback($scan, $progressCallback);
        } catch (\Throwable $e) {
            $this->error("\n❌ Scan crashed: " . $e->getMessage());
            Log::error("[WAVS CI] Scan #{$scan->id} crashed: " . $e->getMessage());
            return self::FAILURE;
        }

        if (!$ciMode) {
            $this->line('');
            $this->line('');
        }

        // ── 6. Collect results ────────────────────────────────────────────
        $scan->refresh();
        $vulnerabilities = $scan->vulnerabilities()
            ->where('status', '!=', 'false_positive')
            ->orderByRaw("FIELD(severity, 'critical','high','medium','low','info')")
            ->get();

        // ── 7. Output results ─────────────────────────────────────────────
        $outputFormat = $this->option('output');
        $outputFile = $this->option('output-file');

        $output = match ($outputFormat) {
            'junit' => $exporter->toJunit($scan, $vulnerabilities),
            'summary' => $exporter->toSummaryText($scan, $vulnerabilities),
            default => $exporter->toJson($scan, $vulnerabilities),
        };

        if ($outputFile) {
            file_put_contents($outputFile, $output);
            if (!$ciMode) {
                $this->info("   Results written to: {$outputFile}");
            }
        } else {
            // Only print raw output to stdout if no file specified
            // (so it can be piped / captured by the CI system)
            echo $output . PHP_EOL;
        }

        // ── 8. Print human summary to stderr (visible in CI logs) ─────────
        $this->printSummary($vulnerabilities, $scan);

        // ── 9. Determine exit code ────────────────────────────────────────
        return $this->resolveExitCode($vulnerabilities, $failOn);
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /**
     * Print a human-readable summary to the console (not captured by pipes).
     */
    private function printSummary($vulnerabilities, Scan $scan): void
    {
        $counts = [
            'critical' => 0,
            'high' => 0,
            'medium' => 0,
            'low' => 0,
            'info' => 0,
        ];

        foreach ($vulnerabilities as $v) {
            $counts[$v->severity] = ($counts[$v->severity] ?? 0) + 1;
        }

        $total = $vulnerabilities->count();
        $duration = $scan->started_at
            ? now()->diffInSeconds($scan->started_at) . 's'
            : 'unknown';

        $this->line("┌─────────────────────────────────────────┐");
        $this->line("│         WAVS Scan — Results Summary      │");
        $this->line("├─────────────────────────────────────────┤");
        $this->line("│  URLs scanned : {$this->pad($scan->urls_discovered ?? 0, 25)}│");
        $this->line("│  Requests sent: {$this->pad($scan->requests_sent ?? 0, 25)}│");
        $this->line("│  Duration     : {$this->pad($duration, 25)}│");
        $this->line("├─────────────────────────────────────────┤");

        $this->line("│  🔴 Critical  : {$this->pad($counts['critical'], 25)}│");
        $this->line("│  🟠 High      : {$this->pad($counts['high'], 25)}│");
        $this->line("│  🟡 Medium    : {$this->pad($counts['medium'], 25)}│");
        $this->line("│  🔵 Low       : {$this->pad($counts['low'], 25)}│");
        $this->line("│  ⚪ Info      : {$this->pad($counts['info'], 25)}│");
        $this->line("├─────────────────────────────────────────┤");
        $this->line("│  Total        : {$this->pad($total, 25)}│");
        $this->line("└─────────────────────────────────────────┘");

        // List critical and high findings
        if ($total > 0) {
            $this->line('');
            $this->line("Top Findings:");
            foreach ($vulnerabilities->take(10) as $v) {
                $icon = match ($v->severity) {
                    'critical' => '🔴',
                    'high' => '🟠',
                    'medium' => '🟡',
                    'low' => '🔵',
                    default => '⚪',
                };
                $this->line("  {$icon} [{$v->severity}] {$v->name}");
                $this->line("     URL: {$v->url}");
                $this->line("     Param: {$v->parameter}");
                $this->line('');
            }

            if ($total > 10) {
                $this->line("  ... and " . ($total - 10) . " more. See the full report.");
            }
        }
    }

    /**
     * Determine exit code based on --fail-on threshold.
     * Returns 1 (failure) if any finding meets or exceeds the threshold.
     */
    private function resolveExitCode($vulnerabilities, string $failOn): int
    {
        if ($failOn === 'none') {
            return self::SUCCESS;
        }

        $threshold = $this->severityOrder[$failOn] ?? 3;

        foreach ($vulnerabilities as $v) {
            $severity = $this->severityOrder[$v->severity] ?? 0;
            if ($severity >= $threshold) {
                $this->error("❌ Build failed: found " . strtoupper($v->severity) . " severity vulnerability: {$v->name}");
                return self::FAILURE;
            }
        }

        $this->info("✅ No findings at or above '{$failOn}' severity. Build passed.");
        return self::SUCCESS;
    }

    /**
     * Heuristic check: does this URL look like a production environment?
     * We refuse to scan production automatically to prevent accidents.
     */
    private function looksLikeProduction(string $url): bool
    {
        $host = strtolower(parse_url($url, PHP_URL_HOST) ?? '');

        // Pass-through: local dev and common staging patterns
        $safePatterns = [
            'localhost',
            '127.0.0.1',
            '0.0.0.0',
            '.local',
            '.test',
            '.dev',
            '.internal',
            'staging.',
            'stage.',
            'stg.',
            'preview.',
            'sandbox.',
            'qa.',
            'uat.',
            'test.',
            '.staging',
            '.stage',
            '.stg',
        ];

        foreach ($safePatterns as $pattern) {
            if (str_contains($host, $pattern)) {
                return false; // Looks safe
            }
        }

        // Flag as production if none of the safe patterns match
        // and it's a real TLD (not an IP)
        return !filter_var($host, FILTER_VALIDATE_IP)
            && preg_match('/\.(com|io|net|org|co|app|dev|ai|cloud)$/', $host);
    }

    private function pad(mixed $value, int $length): string
    {
        return str_pad((string) $value, $length);
    }
}
