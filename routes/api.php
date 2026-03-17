<?php

use App\Http\Controllers\AdminController;
use App\Jobs\RunScanJob;
use App\Models\Scan;
use App\Models\ScanLog;
use App\Models\User;
use App\Models\Vulnerability;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Route;
use Illuminate\Validation\ValidationException;

// ─────────────────────────────────────────────────────────────
//  OTP ENDPOINTS (public — no auth required)
// ─────────────────────────────────────────────────────────────
Route::post('/otp/send', function (Request $request) {
    $data = $request->validate(['email' => ['required', 'email']]);
    $email = strtolower(trim($data['email']));
    $rateLimitKey = "otp_rate_{$email}";
    if (Cache::has($rateLimitKey)) {
        return response()->json(['message' => 'Please wait before requesting another code.'], 429);
    }
    $code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    Cache::put("otp_{$email}", $code, now()->addMinutes(10));
    Cache::put($rateLimitKey, true, now()->addSeconds(60));
    try {
        Mail::raw(
            "Your VulnSight verification code is: {$code}\n\nThis code expires in 10 minutes.\n\nIf you did not request this, ignore this email.",
            function ($message) use ($email, $code) {
                $message->to($email)->subject("VulnSight — Your verification code: {$code}");
            }
        );
    } catch (\Exception $e) {
        Log::warning("OTP email failed to send to {$email}: " . $e->getMessage());
        Log::info("OTP code for {$email}: {$code}");
    }
    return response()->json(['ok' => true]);
});

Route::post('/otp/verify', function (Request $request) {
    $data = $request->validate([
        'email' => ['required', 'email'],
        'code' => ['required', 'string', 'size:6'],
    ]);
    $email = strtolower(trim($data['email']));
    $stored = Cache::get("otp_{$email}");
    if (!$stored || $stored !== $data['code']) {
        throw ValidationException::withMessages(['code' => ['Invalid or expired verification code.']]);
    }
    Cache::forget("otp_{$email}");
    return response()->json(['verified' => true]);
});

// ─────────────────────────────────────────────────────────────
//  PLATFORM STATUS (public — no auth required)
//  Used by the frontend maintenance check on every page load.
//  Must stay OUTSIDE all middleware groups so guests can reach it.
// ─────────────────────────────────────────────────────────────
Route::get('/status', function (\Illuminate\Http\Request $request) {
    // Check both session and Bearer token auth
    $user = auth('sanctum')->user() ?? auth('web')->user();

    // Admins always bypass maintenance
    if ($user && ($user->is_admin || $user->role === 'admin')) {
        return response()->json(['maintenance' => false]);
    }

    $settings = Cache::get('platform_settings', []);
    $isMaintenance = (bool) ($settings['maintenance_mode'] ?? false);

    return response()->json(['maintenance' => $isMaintenance]);
});

// ─────────────────────────────────────────────────────────────
//  AUTH ENDPOINTS
// ─────────────────────────────────────────────────────────────
Route::post('/register', function (Request $request) {
    // Respect open_registration platform setting
    $settings = Cache::get('platform_settings', []);
    if (array_key_exists('open_registration', $settings) && $settings['open_registration'] === false) {
        return response()->json(['message' => 'Registration is currently closed.'], 403);
    }

    $data = $request->validate([
        'name' => ['required', 'string', 'max:255'],
        'email' => ['required', 'email', 'unique:users,email'],
        'password' => ['required', 'min:8', 'confirmed'],
    ]);
    $user = User::create([
        'name' => $data['name'],
        'email' => $data['email'],
        'password' => Hash::make($data['password']),
    ]);
    Auth::login($user, remember: true);
    $request->session()->regenerate();
    return response()->json([
        'id' => $user->id,
        'name' => $user->name,
        'email' => $user->email,
        'role' => $user->role ?? 'user',
        'is_admin' => (bool) ($user->is_admin ?? false),
    ]);
});

Route::post('/login', function (Request $request) {
    $credentials = $request->validate([
        'email' => ['required', 'email'],
        'password' => ['required'],
    ]);
    if (!Auth::attempt($credentials, remember: true)) {
        throw ValidationException::withMessages(['email' => ['Invalid email or password.']]);
    }
    $request->session()->regenerate();
    $user = Auth::user();
    $user->forceFill(['last_active_at' => now()])->save();
    return response()->json([
        'id' => $user->id,
        'name' => $user->name,
        'email' => $user->email,
        'role' => $user->role ?? 'user',
        'is_admin' => (bool) ($user->is_admin ?? false),
    ]);
});

Route::get('/me', function (Request $request) {
    if (!Auth::check()) {
        return response()->json(['message' => 'Unauthenticated.'], 401);
    }
    $user = Auth::user();
    // If user is banned, kill their session immediately on this request
    if ($user->banned_at !== null) {
        Auth::logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();
        return response()->json(['message' => 'Your account has been suspended.', 'banned' => true], 403);
    }
    return response()->json([
        'id' => $user->id,
        'name' => $user->name,
        'email' => $user->email,
        'role' => $user->role ?? 'user',
        'is_admin' => (bool) ($user->is_admin ?? false),
    ]);
});

Route::post('/logout', function (Request $request) {
    if (Auth::check()) {
        Auth::user()->forceFill(['last_active_at' => null])->save();
    }
    Auth::logout();
    $request->session()->invalidate();
    $request->session()->regenerateToken();
    return response()->json(['ok' => true]);
});

// ─────────────────────────────────────────────────────────────
//  AUTHENTICATED SCAN ENDPOINTS
// ─────────────────────────────────────────────────────────────
Route::middleware(['auth:sanctum,web'])->group(function () {

    Route::post('/heartbeat', function (Request $request) {
        $user = Auth::user();
        // Banned check on every heartbeat — fastest way to kick an active user
        if ($user->banned_at !== null) {
            Auth::logout();
            $request->session()->invalidate();
            $request->session()->regenerateToken();
            return response()->json(['message' => 'Your account has been suspended.', 'banned' => true], 403);
        }
        $user->forceFill(['last_active_at' => now()])->save();
        return response()->json(['ok' => true]);
    });

    // ── Scans CRUD ────────────────────────────────────────────────────────────
    Route::get('/scans', function () {
        return response()->json(Auth::user()->scans()->latest()->get());
    });

    Route::post('/scans', function (Request $request) {
        $data = $request->validate(['name' => ['required', 'string', 'max:500']]);
        $scan = Auth::user()->scans()->create([
            'name' => $data['name'],
            'status' => 'idle',
        ]);
        return response()->json($scan, 201);
    });

    Route::patch('/scans/{scan}', function (Request $request, Scan $scan) {
        if ($scan->user_id !== Auth::id())
            abort(403);
        $scan->update(array_filter([
            'status' => $request->input('status'),
            'progress' => $request->input('progress'),
        ], fn($v) => $v !== null));
        return response()->json(['ok' => true]);
    });

    // ── Targets ───────────────────────────────────────────────────────────────
    Route::get('/scans/{scan}/targets', function (Scan $scan) {
        if ($scan->user_id !== Auth::id())
            abort(403);
        return response()->json($scan->targets()->get());
    });

    Route::post('/scans/{scan}/targets', function (Request $request, Scan $scan) {
        if ($scan->user_id !== Auth::id())
            abort(403);
        $data = $request->validate(['url' => ['required', 'url', 'max:2048'], 'type' => ['sometimes']]);
        return response()->json($scan->targets()->create($data), 201);
    });

    Route::delete('/scans/{scan}/targets/{targetId}', function (Scan $scan, int $targetId) {
        if ($scan->user_id !== Auth::id())
            abort(403);
        $scan->targets()->where('id', $targetId)->delete();
        return response()->json(null, 204);
    });

    // ── Credentials ───────────────────────────────────────────────────────────
    Route::post('/scans/{scan}/credentials', function (Request $request, Scan $scan) {
        if ($scan->user_id !== Auth::id())
            abort(403);
        $key = "scan_{$scan->id}_credentials";
        $creds = cache()->get($key, []);
        $creds[] = $request->only(['name', 'type', 'token']);
        cache()->put($key, $creds, now()->addDays(7));
        return response()->json(['ok' => true], 201);
    });

    // ── Config ────────────────────────────────────────────────────────────────
    Route::put('/scans/{scan}/config', function (Request $request, Scan $scan) {
        if ($scan->user_id !== Auth::id())
            abort(403);
        $scan->config()->updateOrCreate(
            ['scan_id' => $scan->id],
            $request->only([
                'intensity',
                'max_requests_per_second',
                'request_timeout',
                'crawl_depth',
                'follow_redirects',
                'javascript_execution',
                'exclusion_rules',
            ])
        );
        return response()->json(['ok' => true]);
    });

    // ── Vulnerabilities (per scan) ────────────────────────────────────────────
    Route::post('/scans/{scan}/vulnerabilities', function (Request $request, Scan $scan) {
        if ($scan->user_id !== Auth::id())
            abort(403);
        $vulns = $request->input('vulnerabilities', []);
        foreach ($vulns as $v) {
            $scan->vulnerabilities()->create([
                'name' => $v['name'] ?? 'Unknown',
                'url' => $v['url'] ?? '—',
                'severity' => $v['severity'] ?? 'low',
                'cve' => $v['cve'] ?? null,
                'evidence' => $v['evidence'] ?? null,
                'solution' => $v['solution'] ?? null,
            ]);
        }
        return response()->json(['ok' => true, 'stored' => count($vulns)]);
    });

    // ─────────────────────────────────────────────────────────────────────────
    //  SCAN ENGINE
    // ─────────────────────────────────────────────────────────────────────────

    Route::post('/scans/{scan}/start', function (Request $request, Scan $scan) {
        if ($scan->user_id !== Auth::id()) {
            return response()->json(['message' => 'Forbidden'], 403);
        }
        if ($scan->status === 'running') {
            return response()->json(['message' => 'Scan already running'], 409);
        }

        // Accept all_target_urls array or fall back to single target_url
        $allTargetUrls = $request->input('all_target_urls', []);
        if (empty($allTargetUrls)) {
            $single = $request->input('target_url') ?? $scan->targets()->value('url');
            $allTargetUrls = $single ? [$single] : [];
        }
        // Merge with any targets already saved on this scan
        $savedUrls = $scan->targets()->pluck('url')->toArray();
        $allTargetUrls = array_values(array_unique(array_merge($allTargetUrls, $savedUrls)));

        if (empty($allTargetUrls)) {
            return response()->json(['message' => 'No target URLs set on this scan'], 422);
        }

        // Validate every URL
        foreach ($allTargetUrls as $url) {
            $host = strtolower(parse_url($url, PHP_URL_HOST) ?? '');
            if (!env('WAVS_ALLOW_PROD', false)) {
                $isSafe = in_array($host, ['localhost', '127.0.0.1', '::1'], true)
                    || str_ends_with($host, '.local') || str_ends_with($host, '.test')
                    || str_ends_with($host, '.invalid')
                    || preg_match('/^192\.168\./', $host)
                    || preg_match('/^10\./', $host)
                    || preg_match('/^172\.(1[6-9]|2\d|3[01])\./', $host);
                if (!$isSafe) {
                    return response()->json([
                        'message' => "Production scanning disabled for {$host}. Set WAVS_ALLOW_PROD=true to override.",
                    ], 403);
                }
            }
        }

        // Save all targets to the scan so the orchestrator picks them all up
        foreach ($allTargetUrls as $url) {
            if (!$scan->targets()->where('url', $url)->exists()) {
                $scan->targets()->create(['url' => $url, 'type' => 'Web Application']);
            }
        }

        $log = ScanLog::create([
            'scan_id' => $scan->id,
            'user_id' => Auth::id(),
            'target_url' => implode(', ', $allTargetUrls),
            'status' => 'running',
            'progress' => 0,
            'started_at' => now(),
        ]);

        $scan->update(['status' => 'running', 'progress' => 0]);

        RunScanJob::dispatch($scan);

        Log::info("Scan #{$scan->id} started", [
            'targets' => $allTargetUrls,
            'scan_log_id' => $log->id,
        ]);

        return response()->json([
            'scan_log_id' => $log->id,
            'target_url' => $allTargetUrls[0],
            'all_target_urls' => $allTargetUrls,
            'message' => 'Scan started',
        ]);
    });

    Route::get('/scans/{scan}/status', function (Request $request, Scan $scan) {
        if ($scan->user_id !== Auth::id()) {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        $log = ScanLog::where('scan_id', $scan->id)
            ->orderByDesc('id')
            ->first();

        if (!$log) {
            return response()->json([
                'progress' => 0,
                'status' => 'idle',
                'new_vulns' => [],
                'requests_sent' => 0,
                'urls_discovered' => 0,
                'scan_log_id' => null,
            ]);
        }

        $lastSeenId = (int) $request->query('last_seen_id', 0);

        $newVulns = Vulnerability::where('scan_log_id', $log->id)
            ->where('id', '>', $lastSeenId)
            ->orderBy('id')
            ->get(['id', 'name', 'url', 'severity', 'cve', 'evidence', 'description', 'remediation', 'created_at'])
            ->map(fn($v) => [
                'id' => $v->id,
                'name' => $v->name,
                'url' => $v->url,
                'severity' => $v->severity,
                'sev' => $v->severity,
                'cve' => $v->cve,
                'evidence' => $v->evidence,
                'description' => $v->description,
                'solution' => $v->remediation,
                'detected_at' => ($v->detected_at ?? $v->created_at)?->toISOString(),
                'time' => ($v->detected_at ?? $v->created_at)?->toISOString(),
            ])
            ->values()
            ->all();

        return response()->json([
            'scan_log_id' => $log->id,
            'progress' => (int) $log->progress,
            'status' => $log->status,
            'current_phase' => $scan->current_phase ?? null,
            'new_vulns' => $newVulns,
            'requests_sent' => (int) $log->requests_sent,
            'urls_discovered' => (int) $log->urls_discovered,
            'spider_done' => true,
        ]);
    });

    Route::post('/scans/{scan}/stop', function (Scan $scan) {
        if ($scan->user_id !== Auth::id()) {
            return response()->json(['message' => 'Forbidden'], 403);
        }
        $scan->update(['status' => 'idle', 'progress' => 0, 'current_phase' => null]);
        ScanLog::where('scan_id', $scan->id)
            ->where('status', 'running')
            ->update(['status' => 'stopped', 'completed_at' => now()]);
        return response()->json(['message' => 'Scan stopped']);
    });

    // ─────────────────────────────────────────────────────────────────────────
    //  RECOVER — POST /api/scans/{scan}/recover
    //  Re-dispatches a stuck "running" scan after a page refresh or server restart.
    //  Safe to call multiple times — only acts if scan is truly stuck.
    // ─────────────────────────────────────────────────────────────────────────
    Route::post('/scans/{scan}/recover', function (Scan $scan) {
        if ($scan->user_id !== Auth::id()) {
            return response()->json(['message' => 'Forbidden'], 403);
        }

        // Only recover scans that are stuck in running state
        if ($scan->status !== 'running') {
            return response()->json(['message' => 'Scan is not stuck', 'status' => $scan->status]);
        }

        // Re-dispatch the scan job
        RunScanJob::dispatch($scan);

        Log::info("Scan #{$scan->id} recovered and re-dispatched");

        return response()->json(['message' => 'Scan recovered and re-dispatched', 'scan' => $scan->fresh()]);
    });
});

// ─────────────────────────────────────────────────────────────
//  SCAN LOG ROUTES
// ─────────────────────────────────────────────────────────────
Route::middleware(['auth:sanctum,web'])->group(function () {

    Route::get('/scan-logs', function () {
        try {
            $logs = ScanLog::with(['vulnerabilities', 'scan'])
                ->where('user_id', Auth::id())
                ->orderByDesc('created_at')
                ->limit(100)
                ->get();

            return response()->json($logs->map(function ($l) {
                try {
                    return $l->toFrontend();
                } catch (\Throwable $e) {
                    Log::warning('ScanLog::toFrontend() failed #' . $l->id . ': ' . $e->getMessage());
                    return [
                        'id' => $l->id,
                        'scan_id' => $l->scan_id,
                        'target_url' => $l->target_url ?? '',
                        'status' => $l->status ?? 'unknown',
                        'created_at' => optional($l->created_at)->toISOString(),
                    ];
                }
            }));
        } catch (\Throwable $e) {
            Log::error('GET /api/scan-logs failed: ' . $e->getMessage());
            return response()->json(['message' => 'Failed to load scan history.'], 500);
        }
    });

    Route::post('/scan-logs', function (Request $request) {
        $validated = $request->validate([
            'scan_id' => 'required|integer|exists:scans,id',
            'target_url' => 'required|string|max:2048',
        ]);
        $log = ScanLog::create([
            'scan_id' => $validated['scan_id'],
            'user_id' => Auth::id(),
            'target_url' => $validated['target_url'],
            'status' => 'running',
            'started_at' => now(),
        ]);
        return response()->json(['scan_log_id' => $log->id]);
    });

    Route::get('/scan-logs/{id}', function ($id) {
        $log = ScanLog::with('vulnerabilities')
            ->where('id', $id)
            ->where('user_id', Auth::id())
            ->firstOrFail();
        return response()->json($log->toFrontend());
    });

    Route::patch('/scan-logs/{id}', function (Request $request, $id) {
        $log = ScanLog::where('id', $id)
            ->where('user_id', Auth::id())
            ->firstOrFail();

        $data = $request->only([
            'status',
            'progress',
            'requests_sent',
            'urls_discovered',
        ]);
        $log->update($data);

        if (isset($data['status']) && $data['status'] === 'completed') {
            $log->markCompleted();
        } elseif (isset($data['status']) && in_array($data['status'], ['failed', 'stopped'])) {
            $now = now();
            $log->update([
                'completed_at' => $now,
                'duration_seconds' => $log->started_at
                    ? (int) $log->started_at->diffInSeconds($now)
                    : null,
            ]);
            $log->syncVulnCounts();
        }

        return response()->json(['ok' => true]);
    });

    Route::post('/scan-logs/{id}/vulnerabilities', function (Request $request, $id) {
        $log = ScanLog::where('id', $id)
            ->where('user_id', Auth::id())
            ->firstOrFail();

        $vulns = $request->input('vulnerabilities', []);
        if (empty($vulns)) {
            return response()->json(['saved' => 0]);
        }

        $saved = 0;
        foreach ($vulns as $v) {
            $exists = Vulnerability::where('scan_log_id', $log->id)
                ->where('name', $v['name'] ?? '')
                ->where('url', $v['url'] ?? '')
                ->exists();

            if (!$exists) {
                Vulnerability::create([
                    'scan_id' => $log->scan_id,
                    'scan_log_id' => $log->id,
                    'name' => $v['name'] ?? 'Unknown',
                    'url' => $v['url'] ?? '',
                    'severity' => $v['severity'] ?? 'low',
                    'cve' => $v['cve'] ?? null,
                    'evidence' => $v['evidence'] ?? null,
                    'remediation' => $v['solution'] ?? null,
                    'description' => $v['description'] ?? null,
                    'status' => 'open',
                    'is_new' => true,
                ]);
                $saved++;
            }
        }

        $log->syncVulnCounts();
        return response()->json(['saved' => $saved]);
    });

    Route::get('/scan-logs/{id}/vulnerabilities', function ($id) {
        $log = ScanLog::where('id', $id)
            ->where('user_id', Auth::id())
            ->firstOrFail();

        $vulns = Vulnerability::where('scan_log_id', $log->id)
            ->orderBy('id', 'desc')
            ->get()
            ->map(fn($v) => [
                'id' => $v->id,
                'name' => $v->name,
                'type' => $v->name,
                'severity' => $v->severity,
                'url' => $v->url,
                'endpoint' => $v->url,
                'method' => $v->method,
                'parameter' => $v->parameter,
                'payload' => $v->payload,
                'evidence' => $v->evidence,
                'description' => $v->description,
                'solution' => $v->solution ?? $v->remediation,
                'cve' => $v->cve,
                'status' => 'open',
                'detected_at' => ($v->detected_at ?? $v->created_at)?->toISOString(),
            ]);

        return response()->json($vulns);
    });

    Route::delete('/scan-logs/{id}', function ($id) {
        $log = ScanLog::where('id', $id)
            ->where('user_id', Auth::id())
            ->firstOrFail();

        Vulnerability::where('scan_log_id', $log->id)->update(['scan_log_id' => null]);
        $log->delete();

        return response()->json(['ok' => true]);
    });
});

// ─────────────────────────────────────────────────────────────
//  ADMIN ENDPOINTS
// ─────────────────────────────────────────────────────────────
Route::prefix('admin')->middleware(['auth:sanctum,web'])->group(function () {

    Route::get('/stats', [AdminController::class, 'stats']);
    Route::get('/users', [AdminController::class, 'users']);
    Route::post('/users', [AdminController::class, 'createUser']);
    Route::patch('/users/{id}', [AdminController::class, 'updateUser']);
    Route::put('/users/{id}', [AdminController::class, 'updateUser']);
    Route::post('/users/{id}/ban', [AdminController::class, 'banUser']);
    Route::post('/users/{id}/unban', [AdminController::class, 'unbanUser']);

    Route::get('/scans', [AdminController::class, 'scans']);
    Route::delete('/scans/purge', [AdminController::class, 'purgeScans']);
    Route::get('/scans/{id}', [AdminController::class, 'scan']);
    Route::get('/scans/{id}/vulnerabilities', [AdminController::class, 'scanVulnerabilities']);
    Route::post('/scans/{id}/stop', [AdminController::class, 'stopScan']);
    Route::post('/scans/{id}/retry', [AdminController::class, 'retryScan']);
    Route::post('/scans/pause-all', [AdminController::class, 'pauseAllScans']);

    Route::get('/vulnerabilities', [AdminController::class, 'vulnerabilities']);
    Route::get('/health', [AdminController::class, 'health']);
    Route::post('/cache/flush', [AdminController::class, 'flushCache']);
    Route::get('/settings', [AdminController::class, 'getSettings']);
    Route::put('/settings', [AdminController::class, 'saveSettings']);

    Route::post('/settings/maintenance', function (Request $request) {
        $enabled = $request->boolean('enabled');
        $settings = Cache::get('platform_settings', []);
        $settings['maintenance_mode'] = $enabled;
        Cache::put('platform_settings', $settings);
        return response()->json(['maintenance_mode' => $enabled]);
    });

    Route::get('/audit-log', function () {
        $cacheKey = 'admin_audit_log';
        if (!Cache::has($cacheKey)) {
            $entries = collect();
            Scan::with('user')->latest()->limit(50)->get()->each(function ($scan) use (&$entries) {
                if ($scan->status === 'completed') {
                    $entries->push([
                        'ts' => $scan->updated_at?->format('Y-m-d H:i:s') ?? now()->format('Y-m-d H:i:s'),
                        'actor' => $scan->user?->email ?? 'system',
                        'action' => "Scan completed — {$scan->name}",
                        'sev' => 'info',
                    ]);
                } elseif ($scan->status === 'failed') {
                    $entries->push([
                        'ts' => $scan->updated_at?->format('Y-m-d H:i:s') ?? now()->format('Y-m-d H:i:s'),
                        'actor' => $scan->user?->email ?? 'system',
                        'action' => "Scan failed — {$scan->name}",
                        'sev' => 'critical',
                    ]);
                }
            });
            $sorted = $entries->sortByDesc('ts')->values()->toArray();
            Cache::put($cacheKey, $sorted, now()->addDays(30));
        }
        return response()->json(Cache::get($cacheKey, []));
    });

    Route::post('/audit-log', function (Request $request) {
        $cacheKey = 'admin_audit_log';
        $entry = [
            'ts' => now()->format('Y-m-d H:i:s'),
            'actor' => $request->input('actor', Auth::user()?->email ?? 'system'),
            'action' => $request->input('action', ''),
            'sev' => $request->input('sev', 'info'),
        ];
        $existing = Cache::get($cacheKey, []);
        array_unshift($existing, $entry);
        Cache::put($cacheKey, array_slice($existing, 0, 1000), now()->addDays(30));
        return response()->json(null, 201);
    });

    Route::delete('/audit-log', function () {
        Cache::forget('admin_audit_log');
        return response()->json(['ok' => true]);
    });
});

Route::middleware(['auth:sanctum,web'])->post('/email-report', function (Illuminate\Http\Request $request) {
    $request->validate(['email' => 'required|email', 'scan_id' => 'required', 'vulns' => 'required|array']);

    $email     = $request->input('email');
    $scanId    = $request->input('scan_id');
    $vulns     = $request->input('vulns');
    $targets   = $request->input('targets', 'N/A');
    $startedAt = $request->input('started_at', now()->toDateTimeString());
    $user      = $request->user();

    $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0];
    foreach ($vulns as $v) {
        $sev = strtolower($v['severity'] ?? $v['sev'] ?? 'low');
        if (isset($counts[$sev])) $counts[$sev]++;
    }

    Mail::send([], [], function ($message) use ($email, $scanId, $vulns, $targets, $startedAt, $counts, $user) {
        $message->to($email)->subject('VulnSight Scan Report — ' . $targets)->html(
            view('emails.scan_report', compact('vulns', 'targets', 'startedAt', 'counts', 'scanId', 'user'))->render()
        );
    });

    return response()->json(['message' => 'Report sent successfully']);
});
