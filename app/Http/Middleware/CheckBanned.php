<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class CheckBanned
{
    public function handle(Request $request, Closure $next): Response
    {
        $user = $request->user();

        if ($user && $user->banned_at !== null) {
            // Revoke all Sanctum tokens on every attempt
            $user->tokens()->delete();

            // Kill the web session
            if ($request->hasSession()) {
                $request->session()->invalidate();
                $request->session()->regenerateToken();
            }

            if ($request->expectsJson() || str_starts_with($request->path(), 'api/')) {
                return response()->json([
                    'message' => 'Your account has been suspended.',
                    'banned' => true,
                ], 403);
            }

            auth()->logout();
            return redirect('/')->with('error', 'Your account has been suspended.');
        }

        return $next($request);
    }
}
