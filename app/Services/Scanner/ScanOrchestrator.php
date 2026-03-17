<?php

namespace App\Services\Scanner;

use App\Models\Scan;
use App\Models\ScanLog;
use App\Models\Vulnerability;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Log;

/**
 * ScanOrchestrator
 *
 * Coordinates all scanners: Nuclei → Nikto → HeaderScanner → ExposedPathScanner → DependencyScanner
 * Saves all findings to the vulnerabilities table, linked to a ScanLog row.
 * Updates scan progress in DB as each phase completes so the frontend poll sees it live.
 *
 * Called by RunScanJob:
 *   $orchestrator->start($scan);
 */
class ScanOrchestrator
{
    private NucleiScanner $nuclei;
    private NiktoScanner $nikto;
    private HeaderScanner $headers;
    private ExposedPathScanner $paths;
    private DependencyScanner $deps;

    public function __construct(
        NucleiScanner $nuclei,
        NiktoScanner $nikto,
        HeaderScanner $headers,
        ExposedPathScanner $paths,
        DependencyScanner $deps
    ) {
        $this->nuclei = $nuclei;
        $this->nikto = $nikto;
        $this->headers = $headers;
        $this->paths = $paths;
        $this->deps = $deps;
    }
    /**
     * Run a full scan against all targets on $scan.
     * Returns the completed ScanLog.
     */
    /**
     * Discover all scannable URLs from Laravel route list + base URL.
     */
    private function resolveUrls(string $baseUrl): array
    {
        $base = rtrim($baseUrl, '/');
        $urls = [$base];

        foreach (\Illuminate\Support\Facades\Route::getRoutes() as $route) {
            if (!in_array('GET', $route->methods()))
                continue;
            $uri = $route->uri();
            if (str_contains($uri, '{'))
                continue;        // skip dynamic routes
            if (str_starts_with($uri, '_'))
                continue;     // skip internals
            if (str_starts_with($uri, 'sanctum'))
                continue;
            if (str_starts_with($uri, 'storage'))
                continue;
            if ($uri === 'up')
                continue;
            $full = $base . '/' . ltrim($uri, '/');
            if ($full !== $base) {
                $urls[] = $full;
            }
        }

        return array_unique($urls);
    }

    public function start(Scan $scan): ScanLog
    {
        // Get ALL targets — not just the first one
        $targets = $scan->targets()->pluck('url')->map(fn($u) => rtrim($u, '/'))->filter()->values()->toArray();

        if (empty($targets)) {
            $targets = ['http://localhost:8000'];
        }

        $primaryTarget = $targets[0];

        $log = ScanLog::firstOrCreate(
            ['scan_id' => $scan->id, 'status' => 'running'],
            [
                'user_id' => $scan->user_id,
                'target_url' => implode(', ', $targets),
                'status' => 'running',
                'started_at' => now(),
                'progress' => 0,
            ]
        );

        $scan->update(['status' => 'running', 'progress' => 0]);
        Log::info("ScanOrchestrator: starting scan #{$scan->id} against " . count($targets) . " target(s): " . implode(', ', $targets));

        try {
            $totalTargets = count($targets);

            foreach ($targets as $targetIndex => $base) {
                $bandStart = (int) (($targetIndex / $totalTargets) * 90);
                $bandEnd = (int) ((($targetIndex + 1) / $totalTargets) * 90);
                $bandSize = $bandEnd - $bandStart;

                Log::info("ScanOrchestrator: scanning target " . ($targetIndex + 1) . "/{$totalTargets}: {$base}");

                $allUrls = $this->resolveUrls($base);

                // ── Phase 1: Exposed path probe ───────────────────────────────
                $p1 = $bandStart + (int) ($bandSize * 0.10);
                $this->runPhase($scan, $log, "[$base] Probing exposed paths…", $p1, function () use ($base) {
                    return $this->paths->scan($base);
                });

                // ── Phase 2: Security headers — every discovered URL ──────────
                $totalUrls = count($allUrls);
                foreach ($allUrls as $i => $url) {
                    $pct = $bandStart + (int) ($bandSize * 0.10) + (int) (($i + 1) / $totalUrls * $bandSize * 0.40);
                    $label = "[$base] Checking headers [" . ($i + 1) . "/{$totalUrls}] {$url}";
                    $this->runPhase($scan, $log, $label, $pct, function () use ($url) {
                        return $this->headers->scan($url);
                    });
                }

                // ── Phase 3: Nikto ────────────────────────────────────────────
                $p3 = $bandStart + (int) ($bandSize * 0.70);
                $abort = $this->abortChecker($scan, $log);
                $this->runPhase($scan, $log, "[$base] Running Nikto web server scan…", $p3, function () use ($base, $abort) {
                    return $this->nikto->scan($base, maxTime: 90, shouldAbort: $abort);
                });

                // ── Phase 4: Nuclei ───────────────────────────────────────────
                $p4 = $bandStart + (int) ($bandSize * 0.90);
                $this->runPhase($scan, $log, "[$base] Running Nuclei vulnerability scan…", $p4, function () use ($base, $abort) {
                    return $this->nuclei->scan($base, maxTime: 300, shouldAbort: $abort);
                });
            }

            // ── Phase 5: Dependency audit (90→100%) — runs once for all targets
            $this->runPhase($scan, $log, 'Auditing PHP dependencies…', 100, function () {
                return $this->deps->scan();
            });

            Cache::forget("scan_stop_{$scan->id}");
            $log->markCompleted();
            $scan->update(['status' => 'completed', 'progress' => 100]);
            Log::info("ScanOrchestrator: scan #{$scan->id} completed — {$log->vuln_total} findings across " . count($targets) . " target(s)");

        } catch (\Throwable $e) {
            // __SCAN_STOPPED__ is thrown by runPhase when the user force-stops mid-scan.
            // Treat it as a clean stop — don't mark as failed, don't re-throw.
            if ($e->getMessage() === '__SCAN_STOPPED__') {
                Cache::forget("scan_stop_{$scan->id}");
                Log::info("ScanOrchestrator: scan #{$scan->id} was force-stopped by user");
                $log->update([
                    'status' => 'stopped',
                    'completed_at' => now(),
                    'duration_seconds' => $log->started_at ? (int) $log->started_at->diffInSeconds(now()) : null,
                ]);
                $log->syncVulnCounts();
                return $log->fresh();
            }

            Log::error("ScanOrchestrator: scan #{$scan->id} failed: " . $e->getMessage());
            $log->update([
                'status' => 'failed',
                'completed_at' => now(),
                'duration_seconds' => $log->started_at ? (int) $log->started_at->diffInSeconds(now()) : null,
            ]);
            $scan->update(['status' => 'failed', 'progress' => 0]);
            throw $e;
        }

        return $log->fresh();
    }

    /**
     * Resume a paused scan — re-runs all phases.
     */
    public function resume(Scan $scan): ScanLog
    {
        return $this->start($scan);
    }

    // ─────────────────────────────────────────────────────────────────────────

    /**
     * Check if the scan was force-stopped by the user while this job was running.
     * Checks cache flag first (instant), then DB as fallback.
     */
    private function isStopped(Scan $scan, ScanLog $log): bool
    {
        if (Cache::get("scan_stop_{$scan->id}")) {
            return true;
        }
        $freshScan = $scan->fresh();
        $freshLog = $log->fresh();
        return in_array($freshScan?->status, ['stopped', 'idle'], true)
            || in_array($freshLog?->status, ['stopped', 'failed'], true);
    }

    /**
     * Returns a closure passed into long-running scanners (Nikto/Nuclei).
     * They call it every second to check if they should abort mid-execution.
     */
    private function abortChecker(Scan $scan, ScanLog $log): \Closure
    {
        return fn() => $this->isStopped($scan, $log);
    }

    /**
     * Run one scanner phase, save all findings, update progress.
     * Aborts immediately if the scan was force-stopped between phases.
     */
    private function runPhase(
        Scan $scan,
        ScanLog $log,
        string $phaseLabel,
        int $progressTo,
        callable $scanner
    ): void {
        // Bail out if the user force-stopped the scan between phases
        if ($this->isStopped($scan, $log)) {
            Log::info("ScanOrchestrator: [{$scan->id}] aborting phase '{$phaseLabel}' — scan was stopped");
            throw new \RuntimeException('__SCAN_STOPPED__');
        }

        $scan->update(['current_phase' => $phaseLabel]);
        $log->update(['status' => 'running']);

        Log::info("ScanOrchestrator: [{$scan->id}] {$phaseLabel}");

        try {
            $findings = $scanner();
        } catch (\Throwable $e) {
            Log::warning("ScanOrchestrator: phase '{$phaseLabel}' threw: " . $e->getMessage());
            $findings = [];
        }

        if (!empty($findings)) {
            $this->saveFindings($scan, $log, $findings);
        }

        $scan->update(['progress' => $progressTo]);
        $log->update(['progress' => $progressTo]);

        Log::info("ScanOrchestrator: [{$scan->id}] {$phaseLabel} done — " . count($findings) . " findings");
    }

    /**
     * Persist an array of findings to the vulnerabilities table.
     * Deduplicates by name+url within the same scan log.
     * Each vuln gets its own detected_at timestamp so the frontend
     * shows when it was actually found, not the bulk-insert time.
     */
    private function saveFindings(Scan $scan, ScanLog $log, array $findings): void
    {
        $saved = 0;

        foreach ($findings as $f) {
            $name = $f['name'] ?? 'Unknown';
            $url = $f['url'] ?? '';

            // Skip duplicates within this scan run
            $exists = Vulnerability::where('scan_log_id', $log->id)
                ->where('name', $name)
                ->where('url', $url)
                ->exists();

            if ($exists) {
                continue;
            }

            Vulnerability::create([
                'scan_id' => $scan->id,
                'scan_log_id' => $log->id,
                'name' => $name,
                'url' => $url,
                'severity' => $f['severity'] ?? 'low',
                'method' => $f['method'] ?? 'GET',
                'parameter' => $f['parameter'] ?? null,
                'payload' => $f['payload'] ?? null,
                'evidence' => $f['evidence'] ?? null,
                'cve' => $f['cve'] ?? null,
                'description' => $f['description'] ?? null,
                'remediation' => $f['solution'] ?? null,
                'solution' => $f['solution'] ?? null,
                'confidence' => $f['confidence'] ?? 1,
                'status' => 'open',
                'is_new' => true,
                'detected_at' => now(), // ← stamped individually per vuln as it's saved
            ]);

            $saved++;
        }

        if ($saved > 0) {
            $log->syncVulnCounts();
            $log->increment('requests_sent', count($findings) * 3);
            $log->increment('urls_discovered', 1);
        }
    }
}
