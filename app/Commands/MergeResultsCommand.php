<?php

namespace App\Console\Commands;

use App\Models\Scan;
use App\Services\Scanner\ScanExporter;
use Illuminate\Console\Command;

/**
 * Merges WAVS scan results with ZAP scan results into a single unified report.
 *
 * Usage:
 *   php artisan wavs:merge-results wavs-results.json merged-report.json zap_report.json
 *   php artisan wavs:merge-results wavs-results.json merged-report.json zap_report.json --format=html
 */
class MergeResultsCommand extends Command
{
    protected $signature = 'wavs:merge-results
        {wavs-file              : Path to WAVS JSON output file}
        {output-file            : Path to write merged results}
        {zap-file?              : Path to ZAP JSON report (optional)}
        {--format=json          : Output format: json | html | junit}
        {--fail-on=high         : Exit with code 1 if findings at this severity or above exist}
        {--deduplicate          : Remove duplicate findings across tools (same URL + type)}';

    protected $description = 'Merge WAVS and ZAP scan results into a unified security report';

    public function handle(ScanExporter $exporter): int
    {
        $wavsFile = $this->argument('wavs-file');
        $outputFile = $this->argument('output-file');
        $zapFile = $this->argument('zap-file');

        // ── 1. Load WAVS results ──────────────────────────────────────────
        if (!file_exists($wavsFile)) {
            $this->error("❌ WAVS results file not found: {$wavsFile}");
            return self::FAILURE;
        }

        $wavsData = json_decode(file_get_contents($wavsFile), true);
        if (!$wavsData) {
            $this->error("❌ Could not parse WAVS results file. Is it valid JSON?");
            return self::FAILURE;
        }

        $wavsFindings = $wavsData['findings'] ?? [];
        $this->info("✓ Loaded " . count($wavsFindings) . " WAVS findings");

        // ── 2. Load ZAP results (optional) ───────────────────────────────
        $zapFindings = [];
        if ($zapFile && file_exists($zapFile)) {
            $zapRaw = json_decode(file_get_contents($zapFile), true);
            if ($zapRaw) {
                $zapFindings = $this->normalizeZapFindings($zapRaw);
                $this->info("✓ Loaded " . count($zapFindings) . " ZAP findings");
            } else {
                $this->warn("⚠  Could not parse ZAP file — skipping ZAP results");
            }
        } elseif ($zapFile) {
            $this->warn("⚠  ZAP file not found: {$zapFile} — skipping");
        }

        // ── 3. Merge findings ─────────────────────────────────────────────
        $allFindings = array_merge(
            $this->tagFindings($wavsFindings, 'wavs'),
            $this->tagFindings($zapFindings, 'zap')
        );

        // ── 4. Deduplicate if requested ───────────────────────────────────
        if ($this->option('deduplicate')) {
            $before = count($allFindings);
            $allFindings = $this->deduplicate($allFindings);
            $removed = $before - count($allFindings);
            if ($removed > 0) {
                $this->info("✓ Removed {$removed} duplicate findings");
            }
        }

        // ── 5. Sort by severity ───────────────────────────────────────────
        $severityOrder = ['critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4];
        usort($allFindings, function ($a, $b) use ($severityOrder) {
            $aOrder = $severityOrder[$a['severity']] ?? 5;
            $bOrder = $severityOrder[$b['severity']] ?? 5;
            return $aOrder <=> $bOrder;
        });

        // ── 6. Build merged report ────────────────────────────────────────
        $counts = $this->countBySeverity($allFindings);

        $report = [
            'generated_at' => now()->toIso8601String(),
            'scan_label' => $wavsData['scan']['label'] ?? 'CI Scan',
            'target' => $wavsData['scan']['target'] ?? 'unknown',
            'tools_used' => array_filter(['wavs', $zapFile ? 'zap' : null]),
            'summary' => [
                'total' => count($allFindings),
                'critical' => $counts['critical'],
                'high' => $counts['high'],
                'medium' => $counts['medium'],
                'low' => $counts['low'],
                'info' => $counts['info'],
            ],
            'wavs_meta' => $wavsData['scan'] ?? [],
            'findings' => $allFindings,
        ];

        // ── 7. Write output ───────────────────────────────────────────────
        $format = $this->option('format');
        $output = match ($format) {
            'html' => $exporter->mergedToHtml($report),
            'junit' => $exporter->mergedToJunit($report),
            default => json_encode($report, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES),
        };

        file_put_contents($outputFile, $output);
        $this->info("✓ Merged report written to: {$outputFile}");

        // ── 8. Print summary ──────────────────────────────────────────────
        $this->line('');
        $this->line("Merged Report Summary:");
        $this->line("  🔴 Critical : {$counts['critical']}");
        $this->line("  🟠 High     : {$counts['high']}");
        $this->line("  🟡 Medium   : {$counts['medium']}");
        $this->line("  🔵 Low      : {$counts['low']}");
        $this->line("  ⚪ Info     : {$counts['info']}");
        $this->line("  Total       : " . count($allFindings));

        // ── 9. Exit code ──────────────────────────────────────────────────
        $failOn = $this->option('fail-on');
        $severityThreshold = $severityOrder[$failOn] ?? 1;

        foreach ($allFindings as $finding) {
            $sev = $severityOrder[$finding['severity']] ?? 5;
            if ($sev <= $severityThreshold) {
                $this->error("❌ Failing: found " . strtoupper($finding['severity']) . " finding: {$finding['name']}");
                return self::FAILURE;
            }
        }

        $this->info("✅ No findings at or above '{$failOn}' severity.");
        return self::SUCCESS;
    }

    // ── Helpers ───────────────────────────────────────────────────────────

    /**
     * Normalize ZAP's JSON report format into our unified finding format.
     * ZAP outputs: { site: [{ alerts: [{ name, riskdesc, desc, solution, ... }] }] }
     */
    private function normalizeZapFindings(array $zapReport): array
    {
        $findings = [];
        $sites = $zapReport['site'] ?? [];

        foreach ($sites as $site) {
            $alerts = $site['alerts'] ?? [];
            foreach ($alerts as $alert) {
                $severity = $this->zapRiskToSeverity($alert['riskcode'] ?? '1');
                $instances = $alert['instances'] ?? [['uri' => $site['@name'] ?? '', 'param' => '', 'evidence' => '']];

                foreach ($instances as $instance) {
                    $findings[] = [
                        'name' => $alert['name'] ?? 'Unknown',
                        'type' => $alert['pluginid'] ?? 'zap_finding',
                        'severity' => $severity,
                        'url' => $instance['uri'] ?? '',
                        'method' => $instance['method'] ?? 'GET',
                        'parameter' => $instance['param'] ?? '',
                        'payload' => $instance['attack'] ?? '',
                        'evidence' => $instance['evidence'] ?? '',
                        'description' => strip_tags($alert['desc'] ?? ''),
                        'recommendation' => strip_tags($alert['solution'] ?? ''),
                        'owasp_ref' => $alert['wascid'] ?? '',
                        'cvss_score' => null,
                        'cve' => null,
                    ];
                }
            }
        }

        return $findings;
    }

    /**
     * Map ZAP risk codes to our severity strings.
     * ZAP: 3=High, 2=Medium, 1=Low, 0=Informational
     */
    private function zapRiskToSeverity(string $riskCode): string
    {
        return match ($riskCode) {
            '3' => 'high',
            '2' => 'medium',
            '1' => 'low',
            '0' => 'info',
            default => 'low',
        };
    }

    /**
     * Tag each finding with its source tool.
     */
    private function tagFindings(array $findings, string $tool): array
    {
        return array_map(function ($f) use ($tool) {
            $f['source'] = $tool;
            return $f;
        }, $findings);
    }

    /**
     * Remove duplicate findings based on same URL + vulnerability type.
     * Prefers WAVS findings over ZAP when both detect the same issue
     * (WAVS has more context: payload, raw request/response).
     */
    private function deduplicate(array $findings): array
    {
        $seen = [];
        $unique = [];

        foreach ($findings as $finding) {
            // Fingerprint: URL + type + parameter
            $key = md5(
                strtolower($finding['url']) . '|' .
                strtolower($finding['type']) . '|' .
                strtolower($finding['parameter'] ?? '')
            );

            if (!isset($seen[$key])) {
                $seen[$key] = true;
                $unique[] = $finding;
            }
            // If already seen, skip (WAVS comes first so it wins)
        }

        return $unique;
    }

    private function countBySeverity(array $findings): array
    {
        $counts = ['critical' => 0, 'high' => 0, 'medium' => 0, 'low' => 0, 'info' => 0];
        foreach ($findings as $f) {
            $sev = $f['severity'] ?? 'info';
            $counts[$sev] = ($counts[$sev] ?? 0) + 1;
        }
        return $counts;
    }
}
