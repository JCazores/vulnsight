<?php

namespace App\Services;

use Illuminate\Support\Facades\Http;
use Illuminate\Support\Facades\Log;

class OwnershipVerifier
{
    public function check(string $targetUrl, string $token): array
    {
        $base = rtrim($targetUrl, '/');

        if ($this->isPrivateOrLocalhost($targetUrl)) {
            return [
                'verified' => true,
                'method' => 'localhost',
                'message' => 'Target is localhost or private network — ownership assumed.',
                'token' => $token,
            ];
        }

        $metaResult = $this->checkMetaTag($base, $token);
        if ($metaResult['found']) {
            return [
                'verified' => true,
                'method' => 'meta_tag',
                'message' => 'Ownership verified via meta tag.',
                'token' => $token,
            ];
        }

        $fileResult = $this->checkTextFile($base, $token);
        if ($fileResult['found']) {
            return [
                'verified' => true,
                'method' => 'text_file',
                'message' => 'Ownership verified via verification file.',
                'token' => $token,
            ];
        }

        return [
            'verified' => false,
            'method' => null,
            'message' => 'Ownership not verified. Place the token using one of the methods.',
            'token' => $token,
        ];
    }

    private function checkMetaTag(string $base, string $token): array
    {
        try {
            $response = Http::timeout(10)
                ->withHeaders(['User-Agent' => 'VulnSight-OwnershipVerifier/1.0'])
                ->get($base);

            if (!$response->successful()) {
                return ['found' => false];
            }

            $html = $response->body();
            $pattern = '/<meta[^>]+name=["\']vulnsight-verification["\'][^>]+content=["\']' . preg_quote($token, '/') . '["\'][^>]*>/i';
            $pattern2 = '/<meta[^>]+content=["\']' . preg_quote($token, '/') . '["\'][^>]+name=["\']vulnsight-verification["\'][^>]*>/i';

            if (preg_match($pattern, $html) || preg_match($pattern2, $html)) {
                return ['found' => true];
            }

            return ['found' => false];

        } catch (\Throwable $e) {
            return ['found' => false];
        }
    }

    private function checkTextFile(string $base, string $token): array
    {
        try {
            $response = Http::timeout(10)
                ->withHeaders(['User-Agent' => 'VulnSight-OwnershipVerifier/1.0'])
                ->get($base . '/vulnsight-verify.txt');

            if ($response->status() !== 200) {
                return ['found' => false];
            }

            if (str_contains(trim($response->body()), $token)) {
                return ['found' => true];
            }

            return ['found' => false];

        } catch (\Throwable $e) {
            return ['found' => false];
        }
    }

    public function isPrivateOrLocalhost(string $url): bool
    {
        $host = parse_url($url, PHP_URL_HOST) ?? '';

        if (in_array($host, ['localhost', '127.0.0.1', '::1'], true))
            return true;
        if (str_ends_with($host, '.local'))
            return true;
        if (str_ends_with($host, '.test'))
            return true;
        if (str_ends_with($host, '.internal'))
            return true;
        if (preg_match('/^192\.168\./', $host))
            return true;
        if (preg_match('/^10\./', $host))
            return true;
        if (preg_match('/^172\.(1[6-9]|2\d|3[01])\./', $host))
            return true;

        return false;
    }

    public static function generateToken(string $targetUrl, int $userId): string
    {
        return 'vulnsight-' . hash('sha256', $targetUrl . $userId . config('app.key'));
    }
}
