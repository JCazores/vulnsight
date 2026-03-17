<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;

class ContentSecurityPolicy
{
    public function handle(Request $request, Closure $next)
    {
        // ── Skip for demo vulnerable route
        if ($request->is('demo-vulnerable')) {
            return $next($request);
        }

        // Generate a unique nonce for each request
        $nonce = base64_encode(random_bytes(16));

        // Share nonce with all views
        view()->share('cspNonce', $nonce);

        $response = $next($request);

        // Set the CSP header
        $response->headers->set(
            'Content-Security-Policy',
            "script-src 'self' 'nonce-{$nonce}'; style-src 'self' 'nonce-{$nonce}'; object-src 'none';"
        );

        return $response;
    }
}
