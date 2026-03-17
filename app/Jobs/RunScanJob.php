<?php

namespace App\Jobs;

use App\Models\Scan;
use App\Services\Scanner\ScanOrchestrator;
use Illuminate\Bus\Queueable;
use Illuminate\Contracts\Queue\ShouldQueue;
use Illuminate\Foundation\Bus\Dispatchable;
use Illuminate\Queue\InteractsWithQueue;
use Illuminate\Queue\SerializesModels;
use Illuminate\Support\Facades\Log;

/**
 * RunScanJob
 *
 * Dispatched when a user starts a scan. Runs in the background
 * via Laravel Queue so the HTTP response returns immediately.
 *
 * Dispatch:
 *   RunScanJob::dispatch($scan);
 *
 * Queue worker:
 *   php artisan queue:work --timeout=600 --tries=1
 *
 * The job is marked as ShouldQueue but can also be run synchronously
 * in development by setting QUEUE_CONNECTION=sync in .env
 */
class RunScanJob implements ShouldQueue
{
    use Dispatchable, InteractsWithQueue, Queueable, SerializesModels;

    /**
     * Maximum time this job is allowed to run (10 minutes).
     * Increase for large apps or when ZAP is enabled.
     */
    public int $timeout = 600;

    /**
     * Only try once — a failed scan should not retry automatically
     * as it may re-probe the target unnecessarily.
     */
    public int $tries = 1;

    public function __construct(
        private readonly Scan $scan
    ) {
    }

    /**
     * Execute the job.
     */
    public function handle(ScanOrchestrator $orchestrator): void
    {
        Log::info("RunScanJob: starting scan #{$this->scan->id}");

        try {
            $log = $orchestrator->start($this->scan);

            Log::info("RunScanJob: scan #{$this->scan->id} completed", [
                'scan_log_id' => $log->id,
                'vuln_total' => $log->vuln_total,
                'vuln_critical' => $log->vuln_critical,
                'status' => $log->status,
            ]);
        } catch (\Throwable $e) {
            Log::error("RunScanJob: scan #{$this->scan->id} threw exception: " . $e->getMessage());

            // Mark scan as failed so UI doesn't stay "running" forever
            $this->scan->update(['status' => 'failed', 'progress' => 0]);

            throw $e; // Re-throw so Laravel marks the job as failed
        }
    }

    /**
     * Handle a job failure.
     */
    public function failed(\Throwable $exception): void
    {
        Log::error("RunScanJob: job failed for scan #{$this->scan->id}: " . $exception->getMessage());

        $this->scan->update(['status' => 'failed', 'progress' => 0]);
    }
}
