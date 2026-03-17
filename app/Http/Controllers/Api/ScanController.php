<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Scan;
use App\Models\Vulnerability;
use Illuminate\Http\Request;
use App\Services\Scanner\ScanOrchestrator;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;

class ScanController extends Controller
{
    public function index(): JsonResponse
    {
        $scans = Auth::user()->scans()
            ->withCount(['vulnerabilities', 'discoveredUrls'])
            ->orderByDesc('created_at')
            ->get();

        return response()->json($scans);
    }

    public function store(Request $request)
    {
        $request->validate([
            'target_url' => 'nullable|string',
        ]);

        $scan = $request->user()->scans()->create([
            'name' => 'New Scan ' . now()->format('Y-m-d H:i'),
            'status' => 'idle',
            'progress' => 0,
        ]);

        return response()->json($scan, 201);
    }

    public function show(Scan $scan): JsonResponse
    {
        $this->authorize('view', $scan);

        $scan->load(['targets', 'vulnerabilities']);
        $scan->loadCount(['vulnerabilities', 'discoveredUrls']);

        $counts = $scan->vulnCountBySeverity();

        return response()->json([
            ...$scan->toArray(),
            'vuln_counts' => [
                'critical' => $counts['critical'] ?? 0,
                'high' => $counts['high'] ?? 0,
                'medium' => $counts['medium'] ?? 0,
                'low' => $counts['low'] ?? 0,
            ],
        ]);
    }

    // ─────────────────────────────────────────────────────────
    //  UPDATE — PATCH /api/scans/{scan}
    //  Called by the frontend scanner to sync progress & status.
    // ─────────────────────────────────────────────────────────
    public function update(Request $request, Scan $scan): JsonResponse
    {
        $this->authorize('update', $scan);

        $data = $request->validate([
            'status' => ['sometimes', 'in:idle,running,paused,completed,failed'],
            'progress' => ['sometimes', 'integer', 'min:0', 'max:100'],
        ]);

        $scan->update($data);
        $scan->loadCount('vulnerabilities');

        return response()->json([
            'id' => $scan->id,
            'status' => $scan->status,
            'progress' => (int) $scan->progress,
            'vulnerabilities_count' => (int) $scan->vulnerabilities_count,
        ]);
    }

    // ─────────────────────────────────────────────────────────
    //  STORE VULNERABILITY — POST /api/scans/{scan}/vulnerabilities
    //  Called once per finding during the scan tick.
    //  THIS WAS THE MISSING PIECE — vulns were shown in UI
    //  but never saved to the database.
    // ─────────────────────────────────────────────────────────
    public function storeVulnerability(Request $request, Scan $scan): JsonResponse
    {
        $this->authorize('update', $scan);

        $data = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'url' => ['nullable', 'string', 'max:2048'],
            'severity' => ['required', 'in:critical,high,medium,low'],
            'cve' => ['nullable', 'string', 'max:50'],
        ]);

        $vuln = $scan->vulnerabilities()->create([
            'name' => $data['name'],
            'url' => $data['url'] ?? null,
            'severity' => $data['severity'],
            'cve' => $data['cve'] ?? null,
            'is_new' => true,
        ]);

        return response()->json(['id' => $vuln->id, 'ok' => true], 201);
    }

    // ─────────────────────────────────────────────────────────
    //  LIST VULNERABILITIES — GET /api/scans/{scan}/vulnerabilities
    //  Lets the frontend restore persisted vulns after page refresh.
    // ─────────────────────────────────────────────────────────
    public function listVulnerabilities(Scan $scan): JsonResponse
    {
        $this->authorize('view', $scan);

        $vulns = $scan->vulnerabilities()
            ->orderByDesc('created_at')
            ->get(['id', 'name', 'url', 'severity', 'cve', 'created_at']);

        return response()->json($vulns);
    }

    public function start(Scan $scan, ScanOrchestrator $orchestrator): JsonResponse
    {
        $this->authorize('update', $scan);

        if ($scan->status === 'running') {
            return response()->json(['message' => 'Scan already running'], 409);
        }

        // If the frontend sent a target_url, make sure it's linked to this scan
        $targetUrl = request('target_url');
        if ($targetUrl && !$scan->targets()->where('url', $targetUrl)->exists()) {
            $scan->targets()->create([
                'url' => $targetUrl,
                'type' => 'Web Application',
                'status' => 'active',
            ]);
        }

        if (!$scan->targets()->exists()) {
            return response()->json(['message' => 'Add at least one target before starting'], 422);
        }

        $orchestrator->start($scan);

        return response()->json(['message' => 'Scan started', 'scan' => $scan->fresh()]);
    }

    public function pause(Scan $scan): JsonResponse
    {
        $this->authorize('update', $scan);

        if ($scan->status !== 'running') {
            return response()->json(['message' => 'Scan is not running'], 409);
        }

        $scan->update(['status' => 'paused']);

        return response()->json(['message' => 'Scan paused', 'scan' => $scan]);
    }

    public function resume(Scan $scan, ScanOrchestrator $orchestrator): JsonResponse
    {
        $this->authorize('update', $scan);

        if ($scan->status !== 'paused') {
            return response()->json(['message' => 'Scan is not paused'], 409);
        }

        $orchestrator->resume($scan);

        return response()->json(['message' => 'Scan resumed', 'scan' => $scan->fresh()]);
    }

    public function stop(Scan $scan): JsonResponse
    {
        $this->authorize('update', $scan);

        $scan->update(['status' => 'idle', 'progress' => 0, 'current_phase' => null]);

        return response()->json(['message' => 'Scan stopped']);
    }

    public function updateConfig(Request $request, Scan $scan): JsonResponse
    {
        $this->authorize('update', $scan);

        $data = $request->validate([
            'intensity' => 'sometimes|in:passive,standard,aggressive',
            'max_requests_per_second' => 'sometimes|integer|min:1|max:200',
            'request_timeout' => 'sometimes|integer|min:5|max:120',
            'crawl_depth' => 'sometimes|integer|min:1|max:20',
            'follow_redirects' => 'sometimes|boolean',
            'javascript_execution' => 'sometimes|boolean',
            'exclusion_rules' => 'sometimes|array',
            'exclusion_rules.*' => 'string|max:255',
        ]);

        $scan->update([
            'intensity' => $data['intensity'] ?? $scan->intensity,
            'max_rps' => $data['max_requests_per_second'] ?? $scan->max_rps,
            'request_timeout' => $data['request_timeout'] ?? $scan->request_timeout,
            'crawl_depth' => $data['crawl_depth'] ?? $scan->crawl_depth,
            'follow_redirects' => $data['follow_redirects'] ?? $scan->follow_redirects,
            'javascript_execution' => $data['javascript_execution'] ?? $scan->javascript_execution,
            'exclusion_rules' => $data['exclusion_rules'] ?? $scan->exclusion_rules,
        ]);

        return response()->json($scan);
    }

    public function status(Scan $scan): JsonResponse
    {
        $this->authorize('view', $scan);

        $counts = $scan->vulnCountBySeverity();

        return response()->json([
            'id' => $scan->id,
            'status' => $scan->status,
            'progress' => $scan->progress,
            'current_phase' => $scan->current_phase,
            'requests_sent' => $scan->requests_sent,
            'urls_discovered' => $scan->urls_discovered,
            'vuln_counts' => [
                'critical' => $counts['critical'] ?? 0,
                'high' => $counts['high'] ?? 0,
                'medium' => $counts['medium'] ?? 0,
                'low' => $counts['low'] ?? 0,
                'total' => array_sum($counts),
            ],
            'new_vulns' => $scan->vulnerabilities()
                ->where('is_new', true)
                ->orderByDesc('created_at')
                ->limit(10)
                ->get(['id', 'name', 'severity', 'url', 'cve', 'created_at']),
        ]);
    }

    public function destroy(Scan $scan): JsonResponse
    {
        $this->authorize('delete', $scan);
        $scan->delete();
        return response()->json(null, 204);
    }
}
