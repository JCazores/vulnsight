<?php

use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        web: __DIR__ . '/../routes/web.php',
        api: __DIR__ . '/../routes/api.php',
        commands: __DIR__ . '/../routes/console.php',
        health: '/up',
    )
    ->withMiddleware(function (Middleware $middleware) {
        $middleware->statefulApi();
        $middleware->redirectGuestsTo('/');
        $middleware->alias(['role' => \App\Http\Middleware\RoleMiddleware::class]);
        $middleware->append(\App\Http\Middleware\SecurityHeaders::class);
        $middleware->prepend(\App\Http\Middleware\BlockSensitivePaths::class);

        $middleware->web(append: [
            \App\Http\Middleware\ContentSecurityPolicy::class,
            \App\Http\Middleware\CheckBanned::class,  // ← kicks banned users out of web sessions
        ]);
        $middleware->validateCsrfTokens(except: [
            'api/*',
            'api/heartbeat',
            'api/login',
            'api/logout',
            'sanctum/csrf-cookie',
        ]);
        $middleware->api(append: [
            \App\Http\Middleware\CheckBanned::class,  // ← blocks banned users from API calls
        ]);

        $middleware->validateCsrfTokens(except: [
            'api/*',
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        $exceptions->render(function (\Symfony\Component\HttpKernel\Exception\NotFoundHttpException $e, $request) {
            if ($request->expectsJson() || str_starts_with($request->path(), 'api/')) {
                return response()->json(['message' => 'Not found.'], 404);
            }
        });
    })->create();
