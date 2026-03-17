<?php

use App\Models\User;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Hash;
use Illuminate\Support\Facades\Log;
use Illuminate\Support\Facades\Mail;
use Illuminate\Support\Facades\Route;
use Illuminate\Http\Request;
use Illuminate\Validation\ValidationException;
use Laravel\Socialite\Facades\Socialite;

// ─────────────────────────────────────────────────────────────
// HELPER — supports both Bearer token (Sanctum) and session auth
// ─────────────────────────────────────────────────────────────
if (!function_exists('adminGuard')) {
    function adminGuard(): ?\Illuminate\Http\JsonResponse
    {
        $user = auth('sanctum')->user() ?? auth('web')->user();
        if (!$user) {
            return response()->json(['message' => 'Unauthenticated.'], 401);
        }
        if ($user->role !== 'admin' && !$user->is_admin) {
            return response()->json(['message' => 'Forbidden.'], 403);
        }
        return null;
    }
}

// ─────────────────────────────────────────────────────────────
// OTP
// ─────────────────────────────────────────────────────────────
Route::post('/api/otp/send', function (Request $request) {
    $data = $request->validate(['email' => ['required', 'email']]);
    $email = strtolower(trim($data['email']));
    $rateLimitKey = "otp_rate_{$email}";
    if (Cache::has($rateLimitKey)) {
        $ttl = Cache::getStore() instanceof \Illuminate\Cache\RedisStore
            ? (int) Cache::getStore()->connection()->ttl(Cache::getPrefix() . $rateLimitKey)
            : 30;
        return response()->json(['message' => 'Please wait ' . max(1, $ttl) . 's before requesting another code.'], 429);
    }
    $code = str_pad(random_int(0, 999999), 6, '0', STR_PAD_LEFT);
    Cache::put("otp_{$email}", $code, now()->addMinutes(10));
    Cache::put($rateLimitKey, true, now()->addSeconds(30));
    Mail::raw(
        "Your VulnSight verification code is: {$code}\n\nThis code expires in 10 minutes.\n\nIf you did not request this, ignore this email.",
        function ($message) use ($email, $code) {
            $message->to($email)->subject("VulnSight — Your verification code: {$code}");
        }
    );
    return response()->json(['ok' => true]);
});

Route::post('/api/otp/verify', function (Request $request) {
    $data = $request->validate(['email' => ['required', 'email'], 'code' => ['required', 'string', 'size:6']]);
    $email = strtolower(trim($data['email']));
    $stored = Cache::get("otp_{$email}");
    if (!$stored || $stored !== $data['code']) {
        throw ValidationException::withMessages(['code' => ['Invalid or expired verification code.']]);
    }
    Cache::forget("otp_{$email}");
    return response()->json(['verified' => true]);
});

// ─────────────────────────────────────────────────────────────
// VIEWS
// ─────────────────────────────────────────────────────────────
Route::get('/', function () {
    return view('wavs');
});
Route::get('/admin/{any?}', function () {
    return view('wavs_admin');
})->where('any', 'system|users|scans|reports|audit|settings');

Route::get('/auto-login', function (Request $request) {
    $token = $request->query('token');
    $email = $request->query('email');
    $secret = config('vulnsight.bridge_secret', env('UPTIMEBOT_BRIDGE_SECRET', ''));

    if (!$secret || $token !== $secret)
        abort(403);
    if (!$email)
        abort(422);

    $adminEmail = config('vulnsight.admin_email', env('VULNSIGHT_ADMIN_EMAIL', ''));
    $isAdmin = $adminEmail && strtolower($email) === strtolower($adminEmail);

    $user = \App\Models\User::where('email', $email)->first();
    if (!$user) {
        $user = \App\Models\User::create([
            'name' => explode('@', $email)[0],
            'email' => $email,
            'password' => \Illuminate\Support\Facades\Hash::make($secret . $email),
            'role' => $isAdmin ? 'admin' : 'user',
            'is_admin' => $isAdmin,
        ]);
    } elseif ($isAdmin && ($user->role !== 'admin' || !$user->is_admin)) {
        $user->forceFill(['role' => 'admin', 'is_admin' => true])->save();
        $user->refresh();
    }

    $user->tokens()->where('name', 'uptimebot-iframe')->delete();
    $apiToken = $user->createToken('uptimebot-iframe')->plainTextToken;
    Auth::login($user, true);
    request()->session()->regenerate();
    $nonce = app('csp-nonce');
    $proxyBase = config('vulnsight.proxy_base', env('VULNSIGHT_PROXY_BASE', 'http://localhost:8000/vulnsight'));
    $dest = ($user->role === 'admin' || $user->is_admin) ? '/admin' : '/';
    $destination = rtrim($proxyBase, '/') . $dest;

    return response(<<<HTML
<!DOCTYPE html><html><head><title>Authenticating…</title></head><body>
<script nonce="{$nonce}">
  localStorage.setItem('token', '{$apiToken}');
  window.location.replace('{$destination}');
</script>
</body></html>
HTML, 200)->header('Content-Type', 'text/html');
});

// ── Bridge routes for UpTimeBot user sync ────────────────────
Route::get('/bridge/user-exists', function (\Illuminate\Http\Request $request) {
    $secret = $request->header('X-Bridge-Secret');
    if ($secret !== config('vulnsight.bridge_secret', env('UPTIMEBOT_BRIDGE_SECRET', ''))) {
        abort(403);
    }
    $exists = \App\Models\User::where('email', $request->query('email'))->exists();
    return response()->json(['exists' => $exists]);
});

Route::post('/bridge/create-user', function (\Illuminate\Http\Request $request) {
    $secret = $request->header('X-Bridge-Secret');
    if ($secret !== config('vulnsight.bridge_secret', env('UPTIMEBOT_BRIDGE_SECRET', ''))) {
        abort(403);
    }
    $user = \App\Models\User::firstOrCreate(
        ['email' => $request->input('email')],
        [
            'name' => $request->input('name', 'User'),
            'password' => \Illuminate\Support\Facades\Hash::make(
                $request->input('password', 'defaultpass')
            ),
            'role' => 'user',
            'is_admin' => false,
        ]
    );
    return response()->json(['ok' => true, 'id' => $user->id]);
});

// ─────────────────────────────────────────────────────────────
// AUTH ENDPOINTS
// ─────────────────────────────────────────────────────────────
Route::post('/api/register', function (Request $request) {
    $data = $request->validate([
        'name' => ['required', 'string', 'max:255'],
        'email' => ['required', 'email', 'unique:users,email'],
        'password' => ['required', 'min:8', 'confirmed'],
    ]);
    $user = User::create([
        'name' => $data['name'],
        'email' => $data['email'],
        'password' => Hash::make($data['password']),
        'role' => 'user',
        'is_admin' => false,
    ]);
    Auth::login($user, remember: true);
    $request->session()->regenerate();
    $isAdmin = ($user->role === 'admin' || $user->is_admin);
    $permissions = $isAdmin ? ['monitors', 'vapt', 'system_health'] : ($user->permissions ?? ['monitors', 'vapt', 'system_health']);
    return response()->json([
        'id' => $user->id,
        'name' => $user->name,
        'email' => $user->email,
        'role' => $user->role ?? 'user',
        'is_admin' => (bool) ($user->is_admin ?? false),
        'permissions' => $permissions,
    ]);
});

Route::post('/api/login', function (Request $request) {
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
})->middleware('throttle:5,1');

Route::get('/api/me', function (Request $request) {
    try {
        $user = auth('sanctum')->user() ?? auth('web')->user();
    } catch (\Throwable $e) {
        $user = null;
    }
    if (!$user)
        return response()->json(['message' => 'Unauthenticated.'], 401);
    $isAdmin = ($user->role === 'admin' || $user->is_admin);
    $permissions = $isAdmin ? ['monitors', 'vapt', 'system_health'] : ($user->permissions ?? ['monitors', 'vapt', 'system_health']);
    return response()->json([
        'id' => $user->id,
        'name' => $user->name,
        'email' => $user->email,
        'role' => $user->role ?? 'user',
        'is_admin' => (bool) ($user->is_admin ?? false),
        'permissions' => $permissions,
    ]);
});

Route::post('/api/logout', function (Request $request) {
    $user = auth('sanctum')->user() ?? auth('web')->user();
    if ($user) {
        $user->forceFill(['last_active_at' => null])->save();
        $user->tokens()->where('name', 'uptimebot-iframe')->delete();
    }
    Auth::logout();
    $request->session()->invalidate();
    $request->session()->regenerateToken();
    return response()->json(['ok' => true]);
});

// ─────────────────────────────────────────────────────────────
// GOOGLE OAUTH — public, outside auth middleware
// ─────────────────────────────────────────────────────────────
Route::get('/auth/google', function () {
    return Socialite::driver('google')->redirect();
});

Route::get('/auth/google/callback', function () {
    try {
        $googleUser = Socialite::driver('google')->user();
    } catch (\Exception $e) {
        return redirect('/')->withErrors(['google' => 'Authentication failed.']);
    }
    $user = User::firstOrCreate(
        ['email' => $googleUser->getEmail()],
        [
            'name' => $googleUser->getName(),
            'password' => Hash::make(str()->random(24)),
            'role' => 'user',
            'is_admin' => false,
        ]
    );
    Auth::login($user, remember: true);
    request()->session()->regenerate();
    $destination = ($user->role === 'admin') ? '/admin' : '/';
    return redirect()->to($destination);
});

// ─────────────────────────────────────────────────────────────
// AUTHENTICATED ROUTES
// ─────────────────────────────────────────────────────────────

Route::middleware(['auth:sanctum,web'])->group(function () {

    Route::get('/wavs-track-poll', function () {
        $file = storage_path('app/wavs_log.json');
        if (!file_exists($file))
            return response()->json([]);
        $entries = json_decode(file_get_contents($file), true) ?? [];
        $since = request('since');
        if ($since) {
            $entries = array_values(array_filter($entries, fn($e) => ($e['ts'] ?? '') > $since));
        } else {
            $entries = array_slice($entries, -100);
        }
        return response()->json($entries);
    });

    Route::delete('/wavs-track-clear', function () {
        $file = storage_path('app/wavs_log.json');
        if (file_exists($file))
            file_put_contents($file, json_encode([]));
        return response()->json(['ok' => true]);
    });

    // ── User-scoped scan vulnerabilities ─────────────────
    Route::get('/api/scan-logs/{id}/vulnerabilities', function ($id) {
        $user = auth('sanctum')->user() ?? auth('web')->user();
        $log = \App\Models\ScanLog::where('id', $id)
            ->where('user_id', $user->id)
            ->firstOrFail();
        $vulns = \DB::table('vulnerabilities')
            ->where('scan_log_id', $log->id)
            ->select('id', 'name', 'severity', 'url', 'method', 'parameter', 'payload', 'evidence', 'solution', 'cve', 'status', 'description', 'confidence', 'created_at')
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
                'solution' => $v->solution,
                'cve' => $v->cve,
                'status' => $v->status ?? 'open',
                'description' => $v->description,
                'confidence' => $v->confidence,
                'detected_at' => $v->created_at,
            ]);
        return response()->json($vulns);
    });
});

// ─────────────────────────────────────────────────────────────
// ADMIN API ROUTES
// ─────────────────────────────────────────────────────────────

Route::get('/api/admin/users', function () {
    if ($err = adminGuard())
        return $err;
    return response()->json(
        User::orderBy('created_at', 'desc')->get()->map(fn($u) => [
            'id' => $u->id,
            'name' => $u->name,
            'email' => $u->email,
            'role' => $u->role ?? 'user',
            'plan' => $u->plan ?? 'free',
            'status' => $u->banned_at ? 'banned'
                : ($u->last_active_at && \Carbon\Carbon::parse($u->last_active_at)->gt(now()->subMinutes(3)) ? 'active' : 'inactive'),
            'scans_count' => \DB::table('scan_logs')->where('user_id', $u->id)->count(),
            'last_active' => $u->last_active_at ? \Carbon\Carbon::parse($u->last_active_at)->diffForHumans() : '—',
            'last_active_human' => $u->last_active_at ? \Carbon\Carbon::parse($u->last_active_at)->diffForHumans() : '—',
            'created_at' => $u->created_at,
        ])
    );
});

Route::post('/api/admin/users', function (Request $request) {
    if ($err = adminGuard())
        return $err;
    $data = $request->validate([
        'name' => ['required', 'string', 'max:255'],
        'email' => ['required', 'email', 'unique:users,email'],
        'password' => ['required', 'min:8'],
        'password_confirmation' => ['required'],
        'role' => ['sometimes', 'in:user,admin'],
        'plan' => ['sometimes', 'nullable', 'string'],
    ]);
    $columns = \DB::getSchemaBuilder()->getColumnListing('users');
    $insert = ['name' => $data['name'], 'email' => $data['email'], 'password' => Hash::make($data['password'])];
    if (isset($data['role']) && in_array('role', $columns))
        $insert['role'] = $data['role'];
    if (isset($data['plan']) && in_array('plan', $columns))
        $insert['plan'] = $data['plan'];
    $user = User::create($insert);
    return response()->json([
        'id' => $user->id,
        'name' => $user->name,
        'email' => $user->email,
        'role' => $user->role ?? 'user',
        'plan' => $user->plan ?? 'free',
        'status' => 'inactive',
        'scans_count' => 0,
        'last_active' => '—',
        'last_active_human' => '—',
        'created_at' => $user->created_at,
    ], 201);
});

Route::patch('/api/admin/users/{id}', function (Request $request, $id) {
    if ($err = adminGuard())
        return $err;
    $user = User::findOrFail($id);
    $data = $request->validate([
        'name' => ['sometimes', 'string', 'max:255'],
        'email' => ['sometimes', 'email', 'unique:users,email,' . $id],
        'role' => ['sometimes', 'in:user,admin'],
        'plan' => ['sometimes', 'nullable', 'string'],
        'password' => ['sometimes', 'min:8'],
    ]);
    if (isset($data['password']))
        $data['password'] = Hash::make($data['password']);
    $columns = \DB::getSchemaBuilder()->getColumnListing('users');
    $filtered = array_filter($data, fn($key) => in_array($key, $columns), ARRAY_FILTER_USE_KEY);
    $user->fill($filtered)->save();
    return response()->json(['ok' => true, 'id' => $user->id, 'name' => $user->name, 'email' => $user->email, 'role' => $user->role]);
});

Route::post('/api/admin/users/{id}/ban', function ($id) {
    if ($err = adminGuard())
        return $err;
    $user = User::findOrFail($id);
    $user->forceFill(['banned_at' => now(), 'last_active_at' => null])->save();
    $user->tokens()->delete();
    \DB::table('sessions')->where('user_id', $id)->delete();
    return response()->json(['ok' => true]);
});

Route::post('/api/admin/users/{id}/unban', function ($id) {
    if ($err = adminGuard())
        return $err;
    $user = User::findOrFail($id);
    $user->forceFill(['banned_at' => null])->save();
    return response()->json(['ok' => true]);
});

Route::delete('/api/admin/users/{id}', function ($id) {
    if ($err = adminGuard())
        return $err;
    if ((string) Auth::id() === (string) $id) {
        return response()->json(['message' => 'You cannot delete your own account.'], 403);
    }
    $user = User::findOrFail($id);
    \DB::table('sessions')->where('user_id', $id)->delete();
    $user->delete();
    return response()->json(['ok' => true]);
});

// ── Scans ───────────────────────────────────────────────────────
Route::get('/api/admin/scans', function () {
    if ($err = adminGuard())
        return $err;
    return response()->json(
        \DB::table('scan_logs')
            ->join('users', 'scan_logs.user_id', '=', 'users.id')
            ->select(
                'scan_logs.id',
                'scan_logs.target_url',
                'scan_logs.status',
                'scan_logs.progress',
                'scan_logs.vuln_total as vuln_count',
                'scan_logs.vuln_critical',
                'scan_logs.vuln_high',
                'scan_logs.vuln_medium',
                'scan_logs.vuln_low',
                'scan_logs.started_at',
                'scan_logs.completed_at',
                'scan_logs.created_at',
                'scan_logs.updated_at',
                'users.id as owner_id',
                'users.name as owner_name',
                'users.email as owner_email'
            )
            ->orderBy('scan_logs.created_at', 'desc')->limit(500)->get()
    );
});

Route::get('/api/admin/scans/{id}', function ($id) {
    if ($err = adminGuard())
        return $err;
    $scan = \DB::table('scan_logs')->join('users', 'scan_logs.user_id', '=', 'users.id')
        ->select(
            'scan_logs.id',
            'scan_logs.target_url',
            'scan_logs.status',
            'scan_logs.progress',
            'scan_logs.vuln_total as vuln_count',
            'scan_logs.vuln_critical',
            'scan_logs.vuln_high',
            'scan_logs.vuln_medium',
            'scan_logs.vuln_low',
            'scan_logs.started_at',
            'scan_logs.completed_at',
            'scan_logs.created_at',
            'scan_logs.updated_at',
            'users.name as owner_name',
            'users.email as owner_email'
        )
        ->where('scan_logs.id', $id)->firstOrFail();
    return response()->json($scan);
});

Route::post('/api/admin/scans/{id}/stop', function ($id) {
    if ($err = adminGuard())
        return $err;
    \DB::table('scan_logs')->where('id', $id)->update(['status' => 'stopped', 'updated_at' => now()]);
    return response()->json(['ok' => true]);
});

Route::post('/api/admin/scans/{id}/retry', function ($id) {
    if ($err = adminGuard())
        return $err;
    \DB::table('scan_logs')->where('id', $id)->update(['status' => 'queued', 'progress' => 0, 'updated_at' => now()]);
    return response()->json(['ok' => true]);
});

Route::get('/api/admin/scans/{id}/vulnerabilities', function ($id) {
    if ($err = adminGuard())
        return $err;
    $vulns = \DB::table('vulnerabilities')->where('scan_log_id', $id)
        ->select('id', 'name', 'severity', 'url', 'method', 'parameter', 'payload', 'evidence', 'solution', 'cve', 'status', 'description', 'confidence', 'created_at')
        ->orderBy('id', 'desc')->get()
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
            'solution' => $v->solution,
            'cve' => $v->cve,
            'status' => $v->status ?? 'open',
            'description' => $v->description,
            'confidence' => $v->confidence,
            'detected_at' => $v->created_at,
        ]);
    return response()->json($vulns);
});

// ── Vulnerabilities ─────────────────────────────────────────────
Route::get('/api/admin/vulnerabilities', function () {
    if ($err = adminGuard())
        return $err;
    return response()->json(
        \DB::table('vulnerabilities')
            ->join('scan_logs', 'vulnerabilities.scan_log_id', '=', 'scan_logs.id')
            ->join('users', 'scan_logs.user_id', '=', 'users.id')
            ->select(
                'vulnerabilities.id',
                'vulnerabilities.name',
                'vulnerabilities.severity',
                'vulnerabilities.url',
                'vulnerabilities.method',
                'vulnerabilities.parameter',
                'vulnerabilities.payload',
                'vulnerabilities.evidence',
                'vulnerabilities.solution',
                'vulnerabilities.cve',
                'vulnerabilities.status',
                'vulnerabilities.description',
                'vulnerabilities.confidence',
                'vulnerabilities.created_at',
                'scan_logs.target_url',
                'users.id as owner_id',
                'users.name as owner_name',
                'users.email as owner_email'
            )
            ->orderBy('vulnerabilities.id', 'desc')->limit(1000)->get()
    );
});

// ── Stats ───────────────────────────────────────────────────────
Route::get('/api/admin/stats', function () {
    if ($err = adminGuard())
        return $err;
    $totalUsers = User::count();
    $totalScans = \DB::table('scan_logs')->count();
    $totalVulns = \DB::table('vulnerabilities')->count();
    $criticalAlerts = \DB::table('vulnerabilities')->where('severity', 'critical')->count();
    $todayUsers = User::whereDate('created_at', today())->count();
    $todayVulns = \DB::table('vulnerabilities')->whereDate('created_at', today())->count();
    $runningScans = \DB::table('scan_logs')->where('status', 'running')->count();
    $vulnBySeverity = \DB::table('vulnerabilities')->selectRaw('severity, COUNT(*) as count')->groupBy('severity')->pluck('count', 'severity');
    $activity = [];
    for ($i = 13; $i >= 0; $i--) {
        $date = now()->subDays($i)->toDateString();
        $activity[] = \DB::table('scan_logs')->whereDate('created_at', $date)->count();
    }
    return response()->json([
        'total_users' => $totalUsers,
        'total_scans' => $totalScans,
        'total_vulnerabilities' => $totalVulns,
        'critical_alerts' => $criticalAlerts,
        'today_users' => $todayUsers,
        'today_vulns' => $todayVulns,
        'running_scans' => $runningScans,
        'vuln_by_severity' => [
            'critical' => $vulnBySeverity['critical'] ?? 0,
            'high' => $vulnBySeverity['high'] ?? 0,
            'medium' => $vulnBySeverity['medium'] ?? 0,
            'low' => $vulnBySeverity['low'] ?? 0,
        ],
        'scan_activity_14d' => $activity,
    ]);
});

// ── System Health ───────────────────────────────────────────────
Route::get('/api/admin/health', function () {
    if ($err = adminGuard())
        return $err;
    $services = [];
    $services[] = ['name' => 'Web Server', 'status' => 'operational', 'latency' => '—'];
    try {
        $start = microtime(true);
        \DB::select('SELECT 1');
        $ms = round((microtime(true) - $start) * 1000);
        $services[] = ['name' => 'Database', 'status' => 'operational', 'latency' => $ms . 'ms'];
    } catch (\Exception $e) {
        $services[] = ['name' => 'Database', 'status' => 'down', 'latency' => '—'];
    }
    try {
        $start = microtime(true);
        Cache::put('_health_ping', 1, 5);
        Cache::get('_health_ping');
        $ms = round((microtime(true) - $start) * 1000);
        $services[] = ['name' => 'Cache', 'status' => 'operational', 'latency' => $ms . 'ms'];
    } catch (\Exception $e) {
        $services[] = ['name' => 'Cache', 'status' => 'down', 'latency' => '—'];
    }
    try {
        $heartbeat = Cache::get('queue_heartbeat');
        $hasJobsTable = \Schema::hasTable('jobs');
        $pending = $hasJobsTable ? \DB::table('jobs')->count() : 0;
        if (!$heartbeat || now()->timestamp - $heartbeat > 120) {
            $services[] = ['name' => 'Queue Worker', 'status' => 'down', 'latency' => $pending . ' pending'];
        } else {
            $stuckJobs = $hasJobsTable ? \DB::table('jobs')->where('created_at', '<', now()->subMinutes(10)->getTimestamp())->count() : 0;
            $services[] = ['name' => 'Queue Worker', 'status' => $stuckJobs > 0 ? 'degraded' : 'operational', 'latency' => $pending . ' pending'];
        }
    } catch (\Exception $e) {
        $services[] = ['name' => 'Queue Worker', 'status' => 'down', 'latency' => '—'];
    }
    try {
        $path = storage_path('app/.health_check');
        $start = microtime(true);
        file_put_contents($path, '1');
        $val = file_get_contents($path);
        unlink($path);
        $ms = round((microtime(true) - $start) * 1000);
        $services[] = $val === '1'
            ? ['name' => 'Storage', 'status' => 'operational', 'latency' => $ms . 'ms']
            : ['name' => 'Storage', 'status' => 'degraded', 'latency' => '—'];
    } catch (\Exception $e) {
        $services[] = ['name' => 'Storage', 'status' => 'down', 'latency' => '—'];
    }
    return response()->json($services);
});

// ── Audit Log ───────────────────────────────────────────────────
Route::get('/api/admin/audit-log', function () {
    if ($err = adminGuard())
        return $err;
    $scans = \DB::table('scan_logs')->join('users', 'scan_logs.user_id', '=', 'users.id')
        ->select(
            'scan_logs.created_at as ts',
            'users.email as actor',
            \DB::raw("CONCAT('Scan completed — ', scan_logs.target_url) as action"),
            \DB::raw("'info' as sev")
        )
        ->where('scan_logs.status', 'completed')->orderBy('scan_logs.created_at', 'desc')->limit(300)->get()
        ->map(fn($e) => ['ts' => \Carbon\Carbon::parse($e->ts)->format('Y-m-d H:i:s'), 'actor' => $e->actor, 'action' => $e->action, 'sev' => $e->sev]);
    $registrations = User::select(
        'created_at as ts',
        'email as actor',
        \DB::raw("CONCAT('New user registered — ', email) as action"),
        \DB::raw("'info' as sev")
    )
        ->orderBy('created_at', 'desc')->limit(100)->get()
        ->map(fn($e) => ['ts' => \Carbon\Carbon::parse($e->ts)->format('Y-m-d H:i:s'), 'actor' => $e->actor, 'action' => $e->action, 'sev' => $e->sev]);
    $adminActions = Cache::get('admin_audit_log', []);
    $all = $scans->concat($registrations)->concat(collect($adminActions))->sortByDesc('ts')->values()->take(500);
    return response()->json($all);
});

Route::post('/api/admin/audit-log', function (Request $request) {
    if ($err = adminGuard())
        return $err;
    $data = $request->validate(['ts' => ['required', 'string'], 'actor' => ['required', 'string'], 'action' => ['required', 'string'], 'sev' => ['required', 'in:info,warn,critical']]);
    try {
        $data['ts'] = \Carbon\Carbon::parse($data['ts'])->format('Y-m-d H:i:s');
    } catch (\Exception $e) {
    }
    $existing = Cache::get('admin_audit_log', []);
    array_unshift($existing, $data);
    Cache::forever('admin_audit_log', array_slice($existing, 0, 200));
    return response()->json(['ok' => true]);
});

// ── Platform Settings ───────────────────────────────────────────
Route::get('/api/admin/settings', function () {
    if ($err = adminGuard())
        return $err;
    $defaults = ['platform_name' => 'VulnSight', 'support_email' => 'support@vulnsight.io', 'open_registration' => true, 'rate_limiting' => true, 'maintenance_mode' => false];
    $saved = Cache::get('admin_settings', []);
    return response()->json(array_merge($defaults, $saved));
});

Route::put('/api/admin/settings', function (Request $request) {
    if ($err = adminGuard())
        return $err;
    $data = $request->validate(['platform_name' => ['sometimes', 'string', 'max:100'], 'support_email' => ['sometimes', 'email'], 'open_registration' => ['sometimes', 'boolean'], 'rate_limiting' => ['sometimes', 'boolean'], 'maintenance_mode' => ['sometimes', 'boolean']]);
    $current = Cache::get('admin_settings', []);
    Cache::forever('admin_settings', array_merge($current, $data));
    return response()->json(['ok' => true]);
});

Route::post('/api/admin/settings/maintenance', function (Request $request) {
    if ($err = adminGuard())
        return $err;
    $data = $request->validate(['enabled' => ['required', 'boolean']]);
    $current = Cache::get('admin_settings', []);
    $current['maintenance_mode'] = $data['enabled'];
    Cache::forever('admin_settings', $current);
    return response()->json(['ok' => true]);
});

// ── Cache Flush ─────────────────────────────────────────────────
Route::post('/api/admin/cache/flush', function () {
    if ($err = adminGuard())
        return $err;
    Cache::flush();
    return response()->json(['ok' => true]);
});

// ─────────────────────────────────────────────────────────────
// NAMED ROUTES
// ─────────────────────────────────────────────────────────────
Route::get('/login', function () {
    return redirect('/');
})->name('login');

Route::get('/demo-vulnerable', function () {
    return response('<h1>Vulnerable Demo Page</h1>', 200)
        ->withHeaders([
            'Content-Security-Policy' => "default-src *; script-src * 'unsafe-inline' 'unsafe-eval'",
            'X-Powered-By' => 'PHP/8.3.6',
            'Server' => 'Apache/2.4.51',
        ]);
});

// ─────────────────────────────────────────────────────────────
// SPA CATCH-ALL
// ─────────────────────────────────────────────────────────────
Route::get('/{any}', function () {
    return view('wavs');
})->where('any', '^(?!api|admin|auth|sanctum|_ignition|livewire|auto-login).*$');

Route::get('/{file}', function () {
    abort(404);
})->where('file', '\.env.*|\.git.*|.*\.sql|.*\.zip|.*\.log|composer\.(json|lock)|package\.json');
