<?php

namespace App\Http\Controllers;

use App\Models\Scan;
use App\Models\User;
use App\Models\Vulnerability;
use Carbon\Carbon;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\DB;
use Illuminate\Support\Facades\Hash;

class AdminController extends Controller
{
    public function __construct()
    {
        $this->middleware('auth');
        $this->middleware(function ($request, $next) {
            $user = $request->user();
            if ($user->role !== 'admin' && !$user->is_admin) {
                return response()->json(['message' => 'Forbidden'], 403);
            }
            return $next($request);
        });
    }

    public function stats(): JsonResponse
    {
        $totalUsers = User::count();
        $totalScans = Scan::count();
        $totalVulns = Vulnerability::count();
        $todayUsers = User::whereDate('created_at', today())->count();
        $todayVulns = Vulnerability::whereDate('created_at', today())->count();
        $runningScans = Scan::where('status', 'running')->count();
        $criticalVulns = Vulnerability::where('severity', 'critical')->count();

        $vulnBySeverity = Vulnerability::select('severity', DB::raw('count(*) as total'))
            ->groupBy('severity')
            ->pluck('total', 'severity');

        $scanActivity = Scan::select(
            DB::raw('DATE(created_at) as day'),
            DB::raw('count(*) as total')
        )
            ->where('created_at', '>=', now()->subDays(14)->startOfDay())
            ->groupBy('day')
            ->orderBy('day')
            ->get()
            ->keyBy('day')
            ->map(fn($r) => $r->total);

        $activity = [];
        for ($i = 13; $i >= 0; $i--) {
            $day = now()->subDays($i)->toDateString();
            $activity[] = $scanActivity[$day] ?? 0;
        }

        return response()->json([
            'total_users' => $totalUsers,
            'total_scans' => $totalScans,
            'total_vulnerabilities' => $totalVulns,
            'today_users' => $todayUsers,
            'today_vulns' => $todayVulns,
            'running_scans' => $runningScans,
            'critical_alerts' => $criticalVulns,
            'vuln_by_severity' => [
                'critical' => $vulnBySeverity['critical'] ?? 0,
                'high' => $vulnBySeverity['high'] ?? 0,
                'medium' => $vulnBySeverity['medium'] ?? 0,
                'low' => $vulnBySeverity['low'] ?? 0,
            ],
            'scan_activity_14d' => $activity,
        ]);
    }

    public function users(Request $request): JsonResponse
    {
        $query = User::withCount('scans')->orderBy('created_at', 'desc');

        if ($request->filled('search')) {
            $q = $request->search;
            $query->where(fn($q2) => $q2->where('name', 'like', "%{$q}%")->orWhere('email', 'like', "%{$q}%"));
        }

        if ($request->filled('role') && $request->role !== 'all') {
            $query->where('role', $request->role);
        }

        $users = $query->get()->map(fn(User $u) => [
            'id' => $u->id,
            'name' => $u->name,
            'email' => $u->email,
            'role' => $u->role ?? 'user',
            'is_admin' => (bool) ($u->is_admin ?? false),
            'plan' => $u->plan ?? 'free',
            'scans' => $u->scans_count,
            'status' => $u->banned_at ? 'banned'
                : ($u->last_active_at && Carbon::parse($u->last_active_at)->gt(now()->subMinutes(3)) ? 'active' : 'inactive'),
            'last_active_human' => $u->last_active_at
                ? Carbon::parse($u->last_active_at)->diffForHumans()
                : ($u->updated_at ? Carbon::parse($u->updated_at)->diffForHumans() : '—'),
            'created_at' => $u->created_at?->toISOString(),
            'created_at_human' => $u->created_at?->diffForHumans() ?? '—',
        ]);

        return response()->json($users);
    }

    public function createUser(Request $request): JsonResponse
    {
        $data = $request->validate([
            'name' => ['required', 'string', 'max:255'],
            'email' => ['required', 'email', 'unique:users,email'],
            'password' => ['required', 'min:8'],
            'role' => ['sometimes', 'in:user,admin'],
            'plan' => ['sometimes', 'in:free,pro,enterprise'],
        ]);

        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
            'role' => $data['role'] ?? 'user',
            'is_admin' => ($data['role'] ?? 'user') === 'admin',
            'plan' => $data['plan'] ?? 'free',
        ]);

        return response()->json([
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
            'role' => $user->role,
            'plan' => $user->plan,
        ], 201);
    }

    public function banUser(int $id): JsonResponse
    {
        $user = User::findOrFail($id);

        // 1. Set banned_at timestamp
        $user->update(['banned_at' => now()]);

        // 2. Kill ALL active sessions (database session driver)
        DB::table('sessions')
            ->where('user_id', $user->id)
            ->delete();

        // 3. Revoke ALL Sanctum API tokens
        $user->tokens()->delete();

        return response()->json(['ok' => true]);
    }

    public function unbanUser(int $id): JsonResponse
    {
        $user = User::findOrFail($id);
        $user->update(['banned_at' => null]);
        return response()->json(['ok' => true]);
    }

    public function updateUser(Request $request, int $id): JsonResponse
    {
        $user = User::findOrFail($id);
        $data = $request->validate([
            'name' => ['sometimes', 'string', 'max:255'],
            'email' => ['sometimes', 'email', 'max:255'],
            'role' => ['sometimes', 'in:user,admin'],

            'password' => ['sometimes', 'nullable', 'min:8'],
        ]);

        if (isset($data['role'])) {
            $data['is_admin'] = $data['role'] === 'admin';
        }
        if (!empty($data['password'])) {
            $data['password'] = Hash::make($data['password']);
        } else {
            unset($data['password']);
        }

        $user->update($data);
        return response()->json(['ok' => true]);
    }

    public function scans(Request $request): JsonResponse
    {
        $query = Scan::with('user')->withCount('vulnerabilities')->orderBy('created_at', 'desc');

        if ($request->filled('status') && $request->status !== 'all') {
            $query->where('status', $request->status);
        }

        $scans = $query->get()->map(fn(Scan $s) => [
            'id' => $s->id,
            'owner_name' => $s->user?->name ?? '—',
            'owner_email' => $s->user?->email ?? '—',
            'target_url' => $s->name ?? '—',
            'status' => $s->status ?? 'unknown',
            'progress' => (int) ($s->getAttribute('progress') ?? ($s->status === 'completed' ? 100 : 0)),
            'vulnerabilities_count' => $s->vulnerabilities_count ?? 0,
            'created_at_human' => $s->created_at?->diffForHumans() ?? '—',
            'created_at' => $s->created_at?->toISOString(),
        ]);

        return response()->json($scans);
    }

    public function scan(int $id): JsonResponse
    {
        $s = Scan::with('user')->withCount('vulnerabilities')->findOrFail($id);
        return response()->json([
            'id' => $s->id,
            'owner_name' => $s->user?->name ?? '—',
            'target_url' => $s->name ?? '—',
            'status' => $s->status ?? 'unknown',
            'progress' => (int) ($s->getAttribute('progress') ?? ($s->status === 'completed' ? 100 : 0)),
            'vulnerabilities_count' => $s->vulnerabilities_count ?? 0,
            'created_at_human' => $s->created_at?->diffForHumans() ?? '—',
        ]);
    }

    public function scanVulnerabilities(int $id): JsonResponse
    {
        $scan = Scan::with('user')->findOrFail($id);

        $vulns = $scan->vulnerabilities()
            ->orderByDesc('created_at')
            ->get()
            ->map(fn(Vulnerability $v) => [
                'id' => $v->id,
                'name' => $v->name,
                'url' => $v->url ?? '—',
                'severity' => $v->severity,
                'cve' => $v->cve ?? null,
                'status' => $v->status ?? 'open',
                'owner_name' => $scan->user?->name ?? '—',
                'owner_email' => $scan->user?->email ?? '—',
                'scan_id' => $scan->id,
                'detected_at' => $v->created_at?->diffForHumans() ?? '—',
                'created_at' => $v->created_at?->toDateTimeString() ?? '—',
            ]);

        return response()->json($vulns);
    }

    public function stopScan(int $id): JsonResponse
    {
        Scan::findOrFail($id)->update(['status' => 'failed']);
        return response()->json(['ok' => true]);
    }

    public function retryScan(int $id): JsonResponse
    {
        Scan::findOrFail($id)->update(['status' => 'running', 'progress' => 0]);
        return response()->json(['ok' => true]);
    }

    public function pauseAllScans(): JsonResponse
    {
        Scan::where('status', 'running')->update(['status' => 'paused']);
        return response()->json(['ok' => true]);
    }

    public function vulnerabilities(Request $request): JsonResponse
    {
        $query = Vulnerability::with('scan.user')->orderBy('created_at', 'desc')->limit(500);

        if ($request->filled('severity') && $request->severity !== 'all') {
            $query->where('severity', $request->severity);
        }
        if ($request->filled('user_id')) {
            $query->whereHas('scan', fn($q) => $q->where('user_id', $request->user_id));
        }

        $vulns = $query->get()->map(fn(Vulnerability $v) => [
            'name' => $v->name,
            'url' => $v->url,
            'severity' => $v->severity,
            'cve' => $v->cve ?? null,   // null instead of '—' so JS can detect missing
            'owner_name' => $v->scan?->user?->name ?? '—',
            'owner_email' => $v->scan?->user?->email ?? '—',
            'scan_id' => $v->scan_id,
            'detected_at' => $v->created_at?->diffForHumans() ?? '—',
            'detected_at_absolute' => $v->created_at?->toDateTimeString() ?? '—',
        ]);

        return response()->json($vulns);
    }

    public function vulnerabilitiesByUser(): JsonResponse
    {
        $vulns = Vulnerability::with('scan.user')->orderBy('created_at', 'desc')->get();

        $grouped = $vulns->groupBy(fn($v) => $v->scan?->user_id ?? 0)
            ->map(function ($items) {
                $user = $items->first()?->scan?->user;
                return [
                    'user_id' => $user?->id ?? 0,
                    'user_name' => $user?->name ?? '—',
                    'user_email' => $user?->email ?? '—',
                    'total' => $items->count(),
                    'critical' => $items->where('severity', 'critical')->count(),
                    'high' => $items->where('severity', 'high')->count(),
                    'medium' => $items->where('severity', 'medium')->count(),
                    'low' => $items->where('severity', 'low')->count(),
                    'findings' => $items->map(fn($v) => [
                        'name' => $v->name,
                        'url' => $v->url,
                        'severity' => $v->severity,
                        'cve' => $v->cve ?? null,
                        'detected_at' => $v->created_at?->diffForHumans() ?? '—',
                    ])->values(),
                ];
            })
            ->sortByDesc('critical')
            ->values();

        return response()->json($grouped);
    }

    public function health(): JsonResponse
    {
        $services = [];

        try {
            $start = microtime(true);
            DB::select('SELECT 1');
            $latency = round((microtime(true) - $start) * 1000, 1) . 'ms';
            $services[] = ['name' => 'Database', 'status' => 'operational', 'latency' => $latency];
        } catch (\Throwable) {
            $services[] = ['name' => 'Database', 'status' => 'down', 'latency' => '—'];
        }

        try {
            $start = microtime(true);
            cache()->set('_health_ping', 1, 5);
            $latency = round((microtime(true) - $start) * 1000, 1) . 'ms';
            $services[] = ['name' => 'Cache', 'status' => 'operational', 'latency' => $latency];
        } catch (\Throwable) {
            $services[] = ['name' => 'Cache', 'status' => 'down', 'latency' => '—'];
        }

        try {
            $failedRecent = DB::table('failed_jobs')->where('failed_at', '>=', now()->subHour())->count();
            $services[] = ['name' => 'Queue', 'status' => $failedRecent > 5 ? 'degraded' : 'operational', 'latency' => '—'];
        } catch (\Throwable) {
            $services[] = ['name' => 'Queue', 'status' => 'unknown', 'latency' => '—'];
        }

        try {
            $free = disk_free_space(storage_path());
            $total = disk_total_space(storage_path());
            $usedPct = round(($total - $free) / $total * 100);
            $services[] = ['name' => 'Storage', 'status' => $usedPct > 90 ? 'degraded' : 'operational', 'latency' => '—'];
        } catch (\Throwable) {
            $services[] = ['name' => 'Storage', 'status' => 'unknown', 'latency' => '—'];
        }

        return response()->json($services);
    }

    public function flushCache(): JsonResponse
    {
        cache()->flush();
        return response()->json(['ok' => true]);
    }

    public function getSettings(): JsonResponse
    {
        $defaults = [
            'platform_name' => 'VulnSight',
            'support_email' => 'support@vulnsight.io',
            'scan_intensity' => 'standard',
            'max_concurrent_scans' => 16,
            'max_scans_per_user' => 10,
            'open_registration' => true,
            'rate_limiting' => true,
            'maintenance_mode' => false,
            'alert_email' => '',
            'email_on_critical' => true,
        ];

        $saved = cache()->get('platform_settings', []);

        // Always return all keys so JS form fields populate correctly
        return response()->json(array_merge($defaults, $saved));
    }

    public function saveSettings(Request $request): JsonResponse
    {
        $data = $request->validate([
            'platform_name' => ['sometimes', 'string', 'max:100'],
            'support_email' => ['sometimes', 'email', 'max:255'],
            'scan_intensity' => ['sometimes', 'in:passive,standard,aggressive'],
            'max_concurrent_scans' => ['sometimes', 'integer', 'min:1', 'max:100'],
            'max_scans_per_user' => ['sometimes', 'integer', 'min:1', 'max:1000'],
            'open_registration' => ['sometimes', 'boolean'],
            'rate_limiting' => ['sometimes', 'boolean'],
            'maintenance_mode' => ['sometimes', 'boolean'],
            'alert_email' => ['sometimes', 'nullable', 'email', 'max:255'],
            'email_on_critical' => ['sometimes', 'boolean'],
        ]);

        $existing = cache()->get('platform_settings', []);
        $merged = array_merge($existing, $data);
        cache()->put('platform_settings', $merged, now()->addYear());

        // Return flat merged object — JS reads fields directly off the response
        return response()->json($merged);
    }

    public function purgeScans(): JsonResponse
    {
        \App\Models\Vulnerability::truncate();
        \App\Models\Target::truncate();
        \App\Models\Scan::truncate();
        return response()->json(['ok' => true, 'message' => 'All scan data purged']);
    }
}
