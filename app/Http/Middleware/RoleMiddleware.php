<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class RoleMiddleware
{
    public function handle(Request $request, Closure $next, string $role): Response
    {
        $user = $request->user();

        if (!$user) {
            return request()->expectsJson()
                ? response()->json(['message' => 'Unauthenticated.'], 401)
                : redirect('/');
        }

        if ($user->role !== $role) {
            return request()->expectsJson()
                ? response()->json(['message' => 'Forbidden. Insufficient role.'], 403)
                : abort(403, 'Forbidden.');
        }

        return $next($request);
    }
}
