<?php

namespace App\Services\Scanner;

use Illuminate\Support\Facades\Log;

/**
 * PsalmScanner — Stub
 *
 * Psalm cannot be installed on this environment:
 *  - PHP 8.3.6 (Psalm requires 8.3.16+)
 *  - Laravel 12 conflicts with psalm/plugin-laravel
 *
 * This stub gracefully skips without errors.
 * Static code analysis is handled by StaticCodeScanner instead.
 */
class PsalmScanner
{
    public function isAvailable(): bool
    {
        return false;
    }

    public function isPsalmConfigured(): bool
    {
        return false;
    }

    public function scan(): array
    {
        Log::info('PsalmScanner: skipped — not available on PHP 8.3.6 / Laravel 12');
        return [];
    }
}
