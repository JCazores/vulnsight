<?php

namespace App\Services\Scanner;

use Illuminate\Support\Facades\Log;

/**
 * DependencyScanner
 *
 * Runs `composer audit` against your project and maps the output
 * into the app's standard vulnerability format.
 *
 * Finds real CVEs in your exact installed package versions —
 * something ZAP can never do because it only sees HTTP traffic.
 */
class DependencyScanner
{
    /**
     * Run composer audit and return findings.
     */
    public function scan(): array
    {
        $findings = [];

        try {
            $output = $this->runComposerAudit();

            if (empty($output)) {
                Log::info('DependencyScanner: composer audit returned no output');
                return [];
            }

            $data = json_decode($output, true);

            if (json_last_error() !== JSON_ERROR_NONE) {
                Log::warning('DependencyScanner: composer audit output was not valid JSON: ' . substr($output, 0, 500));
                return [];
            }

            // composer audit --format=json returns:
            // { "advisories": { "vendor/package": [ { "advisoryId", "packageName", "title", "link", "cve", "affectedVersions", "reportedAt", "sources" } ] } }
            $advisories = $data['advisories'] ?? [];

            foreach ($advisories as $packageName => $packageAdvisories) {
                foreach ($packageAdvisories as $advisory) {
                    $cve = $advisory['cve'] ?? null;
                    $title = $advisory['title'] ?? 'Security Advisory';
                    $link = $advisory['link'] ?? null;
                    $affected = $advisory['affectedVersions'] ?? null;
                    $reported = $advisory['reportedAt'] ?? null;

                    // Estimate severity from CVE score if available, otherwise high
                    $severity = $this->estimateSeverity($advisory);

                    $findings[] = [
                        'name' => "Vulnerable Dependency: {$packageName}" . ($cve ? " ({$cve})" : ''),
                        'url' => "composer://{$packageName}",
                        'severity' => $severity,
                        'description' => "{$title}\n\nPackage: {$packageName}"
                            . ($affected ? "\nAffected versions: {$affected}" : '')
                            . ($reported ? "\nReported: {$reported}" : ''),
                        'solution' => "Run `composer update {$packageName}` to install a patched version.",
                        'steps' => [
                            "Run: composer update {$packageName}",
                            "Check if a non-breaking patched version exists: composer outdated {$packageName}",
                            $link ? "Full advisory: {$link}" : "Search Packagist for patched version.",
                            "After updating, run composer audit again to verify no remaining issues.",
                        ],
                        'cve' => $cve,
                        'evidence' => "Installed package {$packageName} has a known security advisory."
                            . ($affected ? " Affected: {$affected}." : ''),
                        'method' => 'DEPENDENCY',
                        'source' => 'dependency_scanner',
                        'reference' => $link,
                    ];
                }
            }

            Log::info('DependencyScanner: found ' . count($findings) . ' vulnerable packages');

        } catch (\Throwable $e) {
            Log::error('DependencyScanner failed: ' . $e->getMessage());
        }

        return $findings;
    }

    /**
     * Run composer audit and return raw JSON output string.
     */
    private function runComposerAudit(): string
    {
        $composerPath = base_path();

        // Try to find composer binary
        $composer = $this->findComposer();

        // Run with --format=json and --no-ansi for clean output
        // 2>&1 captures stderr too (composer sometimes puts warnings there)
        $cmd = "cd " . escapeshellarg($composerPath) . " && {$composer} audit --format=json --no-ansi 2>&1";
        $output = shell_exec($cmd);

        return $output ?? '';
    }

    /**
     * Find the composer executable on this system.
     */
    private function findComposer(): string
    {
        // Check if composer.phar exists in project root
        if (file_exists(base_path('composer.phar'))) {
            return 'php ' . escapeshellarg(base_path('composer.phar'));
        }

        // Check common locations
        foreach (['/usr/local/bin/composer', '/usr/bin/composer'] as $path) {
            if (file_exists($path)) {
                return escapeshellarg($path);
            }
        }

        // Fall back to PATH lookup
        return 'composer';
    }

    /**
     * Estimate severity from advisory data.
     * composer audit doesn't always include CVSS scores, so we infer.
     */
    private function estimateSeverity(array $advisory): string
    {
        $title = strtolower($advisory['title'] ?? '');

        // High-severity keywords
        if (
            str_contains($title, 'remote code execution')
            || str_contains($title, 'rce')
            || str_contains($title, 'sql injection')
            || str_contains($title, 'arbitrary code')
        ) {
            return 'critical';
        }

        if (
            str_contains($title, 'xss')
            || str_contains($title, 'cross-site scripting')
            || str_contains($title, 'csrf')
            || str_contains($title, 'authentication bypass')
            || str_contains($title, 'privilege escalation')
        ) {
            return 'high';
        }

        if (
            str_contains($title, 'information disclosure')
            || str_contains($title, 'open redirect')
            || str_contains($title, 'path traversal')
        ) {
            return 'medium';
        }

        return 'high'; // default to high for any unclassified advisory
    }
}
