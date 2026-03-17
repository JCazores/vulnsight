<?php

namespace App\Http\Middleware;

use Closure;
use Illuminate\Http\Request;
use Symfony\Component\HttpFoundation\Response;

class SecurityHeaders
{
    public function handle(Request $request, Closure $next): Response
    {
        // ── Generate nonce BEFORE $next() so Blade can use csp_nonce() during render
        $nonce = base64_encode(random_bytes(16));
        app()->instance('csp-nonce', $nonce);

        if ($request->is('demo-vulnerable')) {
            return $next($request);
        }

        $response = $next($request);

        $appUrl = rtrim(env('APP_URL', 'http://localhost'), '/');
        $viteHost = env('VITE_HOST', '127.0.0.1');
        $vitePort = env('VITE_PORT', '5173');
        $viteOrigin = "http://{$viteHost}:{$vitePort}";
        $viteWs = "ws://{$viteHost}:{$vitePort}";

        $extraOrigins = array_filter(
            explode(',', env('CSP_EXTRA_ORIGINS', '')),
            fn($o) => trim($o) !== ''
        );
        $extraStr = implode(' ', array_map('trim', $extraOrigins));

        $isDevBuild = app()->environment('local', 'development')
            || env('VITE_DEV_SERVER_URL') !== null
            || file_exists(public_path('hot'));

        // ── Remove fingerprinting headers
        header_remove('X-Powered-By');
        $response->headers->remove('X-Powered-By');
        $response->headers->remove('Server');

        // ── Security headers
        $response->headers->set('X-Content-Type-Options', 'nosniff');
        $response->headers->set('X-Frame-Options', 'DENY');
        $response->headers->set('Referrer-Policy', 'strict-origin-when-cross-origin');
        $response->headers->set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');

        // ── CSP directives
        if ($isDevBuild) {
            $scriptSrc = "script-src 'self' 'nonce-{$nonce}' {$viteOrigin} https://cdn.jsdelivr.net https://cdnjs.cloudflare.com {$extraStr}";
            $styleSrc = "style-src 'self' 'unsafe-inline' {$viteOrigin} https://cdn.jsdelivr.net {$extraStr}";
            $connectSrc = "connect-src 'self' {$appUrl} {$viteOrigin} {$viteWs} ws://127.0.0.1:* {$extraStr}";
            $imgSrc = "img-src 'self' data: https: blob: {$viteOrigin}";
        } else {
            $scriptSrc = "script-src 'self' 'nonce-{$nonce}' https://cdn.jsdelivr.net https://cdnjs.cloudflare.com {$extraStr}";
            $styleSrc = "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net {$extraStr}";
            $connectSrc = "connect-src 'self' {$appUrl} {$extraStr}";
            $imgSrc = "img-src 'self' data: https: blob:";
        }

        $response->headers->set('Content-Security-Policy', implode('; ', array_filter([
            "default-src 'self'",
            $scriptSrc,
            $styleSrc,
            "font-src 'self' data: {$appUrl}",
            $imgSrc,
            $connectSrc,
            "worker-src 'self' blob:",
            "frame-ancestors 'self' http://localhost:5173 http://localhost:5174 http://localhost:8000",
            "base-uri 'self'",
            "form-action 'self'",
            "object-src 'none'",
        ])));

        // ── Harden XSRF-TOKEN cookie (HttpOnly = true)
        foreach ($response->headers->getCookies() as $cookie) {
            if ($cookie->getName() === 'XSRF-TOKEN') {
                $response->headers->setCookie(
                    new \Symfony\Component\HttpFoundation\Cookie(
                        $cookie->getName(),
                        $cookie->getValue(),
                        $cookie->getExpiresTime(),
                        $cookie->getPath(),
                        $cookie->getDomain(),
                        $cookie->isSecure(),
                        true,
                        false,
                        $cookie->getSameSite()
                    )
                );
            }
        }

        return $response;
    }
}
