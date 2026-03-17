<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Symfony\Component\HttpFoundation\Response;

class UpdateLastActive
{
    public function handle(Request $request, Closure $next): Response
    {
        if (Auth::check()) {
            // Throttle DB writes to once per minute to avoid hammering on every request
            $user = Auth::user();
            $lastUpdated = $user->last_active_at;

            if (!$lastUpdated || now()->diffInMinutes($lastUpdated) >= 1) {
                $user->timestamps = false; // don't bump updated_at
                $user->last_active_at = now();
                $user->save();
                $user->timestamps = true;
            }
        }

        return $next($request);
    }
}
