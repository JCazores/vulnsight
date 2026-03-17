<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Cache;
use Symfony\Component\HttpFoundation\Response;

class CheckMaintenance
{
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        // Admins always pass through — they can use the app during maintenance
        if ($user && ($user->role === 'admin' || $user->is_admin)) {
            return $next($request);
        }

        $settings = Cache::get('platform_settings', []);

        if (!empty($settings['maintenance_mode'])) {
            return response()->json([
                'maintenance' => true,
                'message' => 'The platform is currently under maintenance. Please try again later.',
            ], 503);
        }

        return $next($request);
    }
}
