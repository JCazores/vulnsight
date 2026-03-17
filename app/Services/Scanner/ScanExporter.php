<?php

namespace App\Services\Scanner;

use App\Models\Scan;
use Illuminate\Support\Collection;

/**
 * Converts scan results into various output formats for CI/CD consumption.
 *
 * Formats supported:
 *  - JSON       : Machine-readable, for storage and merging
 *  - JUnit XML  : For GitHub Actions test reporter, Jenkins, GitLab CI
 *  - HTML       : Human-readable report for email / artifact upload
 *  - Summary    : Plain text for console output
 */
class ScanExporter
{
    // ── WAVS native formats ───────────────────────────────────────────────

    public function toJson(Scan $scan, Collection $vulnerabilities): string
    {
        $data = [
            'scan' => [
                'id' => $scan->id,
                'label' => $scan->ci_label ?? $scan->name,
                'target' => $scan->targets()->first()?->url ?? 'unknown',
                'intensity' => $scan->intensity,
                'status' => $scan->status,
                'started_at' => $scan->started_at?->toIso8601String(),
                'completed_at' => $scan->completed_at?->toIso8601String(),
                'urls_discovered' => $scan->urls_discovered ?? 0,
                'requests_sent' => $scan->requests_sent ?? 0,
            ],
            'summary' => $this->buildSummary($vulnerabilities),
            'findings' => $vulnerabilities->map(fn($v) => [
                'id' => $v->id,
                'name' => $v->name,
                'type' => $v->type,
                'severity' => $v->severity,
                'url' => $v->url,
                'method' => $v->method,
                'parameter' => $v->parameter,
                'payload' => $v->payload,
                'evidence' => $v->evidence,
                'description' => $v->description,
                'recommendation' => $v->recommendation,
                'owasp_ref' => $v->owasp_ref,
                'cvss_score' => $v->cvss_score,
                'cve' => $v->cve,
                'request_raw' => $v->request_raw,
                'response_raw' => $v->response_raw,
            ])->toArray(),
        ];

        return json_encode($data, JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES);
    }

    public function toJunit(Scan $scan, Collection $vulnerabilities): string
    {
        $target = $scan->targets()->first()?->url ?? 'unknown';
        $total = $vulnerabilities->count();
        $failures = $vulnerabilities->whereIn('severity', ['critical', 'high'])->count();

        $xml = '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
        $xml .= '<testsuites>' . "\n";
        $xml .= sprintf(
            '  <testsuite name="WAVS Security Scan" tests="%d" failures="%d" timestamp="%s" hostname="%s">' . "\n",
            max(1, $total),
            $failures,
            now()->toIso8601String(),
            parse_url($target, PHP_URL_HOST) ?? 'unknown'
        );

        if ($total === 0) {
            $xml .= '    <testcase name="No vulnerabilities found" classname="wavs.security"/>' . "\n";
        }

        foreach ($vulnerabilities as $v) {
            $testName = htmlspecialchars("[{$v->severity}] {$v->name} — {$v->parameter}", ENT_XML1);
            $className = 'wavs.' . $v->type;

            $xml .= "    <testcase name=\"{$testName}\" classname=\"{$className}\">\n";

            // Critical and High are treated as failures (block CI)
            if (in_array($v->severity, ['critical', 'high'])) {
                $message = htmlspecialchars("{$v->name} at {$v->url}", ENT_XML1);
                $body = htmlspecialchars(
                    "URL: {$v->url}\nParameter: {$v->parameter}\nPayload: {$v->payload}\n\nEvidence:\n{$v->evidence}\n\nRecommendation:\n{$v->recommendation}",
                    ENT_XML1
                );
                $xml .= "      <failure message=\"{$message}\" type=\"{$v->severity}\">{$body}</failure>\n";
            }

            $xml .= "    </testcase>\n";
        }

        $xml .= "  </testsuite>\n";
        $xml .= "</testsuites>\n";

        return $xml;
    }

    public function toSummaryText(Scan $scan, Collection $vulnerabilities): string
    {
        $target = $scan->targets()->first()?->url ?? 'unknown';
        $summary = $this->buildSummary($vulnerabilities);
        $lines = [];

        $lines[] = "WAVS Security Scan Report";
        $lines[] = str_repeat('=', 50);
        $lines[] = "Target    : {$target}";
        $lines[] = "Intensity : {$scan->intensity}";
        $lines[] = "Completed : " . ($scan->completed_at?->format('Y-m-d H:i:s') ?? 'N/A');
        $lines[] = str_repeat('-', 50);
        $lines[] = "CRITICAL  : {$summary['critical']}";
        $lines[] = "HIGH      : {$summary['high']}";
        $lines[] = "MEDIUM    : {$summary['medium']}";
        $lines[] = "LOW       : {$summary['low']}";
        $lines[] = "INFO      : {$summary['info']}";
        $lines[] = "TOTAL     : {$summary['total']}";
        $lines[] = str_repeat('=', 50);
        $lines[] = '';

        foreach ($vulnerabilities as $v) {
            $lines[] = "[{$v->severity}] {$v->name}";
            $lines[] = "  URL      : {$v->url}";
            $lines[] = "  Method   : {$v->method}";
            $lines[] = "  Parameter: {$v->parameter}";
            $lines[] = "  Evidence : " . substr($v->evidence, 0, 120);
            $lines[] = '';
        }

        return implode("\n", $lines);
    }

    // ── Merged report formats ─────────────────────────────────────────────

    public function mergedToHtml(array $report): string
    {
        $findings = $report['findings'];
        $summary = $report['summary'];
        $target = htmlspecialchars($report['target']);
        $label = htmlspecialchars($report['scan_label']);
        $tools = implode(' + ', array_map('strtoupper', $report['tools_used']));
        $genAt = $report['generated_at'];

        $rows = '';
        foreach ($findings as $f) {
            $sev = htmlspecialchars($f['severity']);
            $name = htmlspecialchars($f['name']);
            $url = htmlspecialchars($f['url']);
            $param = htmlspecialchars($f['parameter'] ?? '');
            $source = htmlspecialchars(strtoupper($f['source'] ?? ''));
            $desc = htmlspecialchars($f['description'] ?? '');
            $rec = htmlspecialchars($f['recommendation'] ?? '');

            $sevClass = match ($sev) {
                'critical' => 'sev-critical',
                'high' => 'sev-high',
                'medium' => 'sev-medium',
                'low' => 'sev-low',
                default => 'sev-info',
            };

            $rows .= <<<ROW
            <tr>
                <td><span class="badge {$sevClass}">{$sev}</span></td>
                <td>{$name}</td>
                <td class="mono small">{$url}</td>
                <td>{$param}</td>
                <td><span class="tool-badge">{$source}</span></td>
                <td class="small">{$desc}<br><br><strong>Fix:</strong> {$rec}</td>
            </tr>
            ROW;
        }

        return <<<HTML
        <!DOCTYPE html>
        <html lang="en">
        <head>
            <meta charset="UTF-8">
            <meta name="viewport" content="width=device-width, initial-scale=1.0">
            <title>Security Scan Report — {$label}</title>
            <style>
                body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; margin: 0; background: #f5f7fa; color: #1a202c; }
                .header { background: #1a202c; color: white; padding: 24px 32px; }
                .header h1 { margin: 0; font-size: 22px; font-weight: 600; }
                .header p { margin: 4px 0 0; opacity: .7; font-size: 13px; }
                .container { max-width: 1200px; margin: 0 auto; padding: 24px 32px; }
                .summary-grid { display: grid; grid-template-columns: repeat(5, 1fr); gap: 12px; margin-bottom: 24px; }
                .summary-card { background: white; border-radius: 8px; padding: 16px; text-align: center; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
                .summary-card .count { font-size: 32px; font-weight: 700; line-height: 1; }
                .summary-card .label { font-size: 12px; text-transform: uppercase; letter-spacing: .05em; margin-top: 4px; opacity: .6; }
                .critical { color: #e53e3e; } .high { color: #dd6b20; } .medium { color: #d69e2e; }
                .low { color: #3182ce; } .info { color: #718096; }
                table { width: 100%; border-collapse: collapse; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,.1); }
                th { background: #2d3748; color: white; padding: 12px 16px; text-align: left; font-size: 12px; text-transform: uppercase; letter-spacing: .05em; }
                td { padding: 12px 16px; border-bottom: 1px solid #e2e8f0; vertical-align: top; font-size: 13px; }
                tr:last-child td { border-bottom: none; }
                tr:hover td { background: #f7fafc; }
                .badge { display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 11px; font-weight: 600; text-transform: uppercase; }
                .sev-critical { background: #fed7d7; color: #c53030; }
                .sev-high { background: #feebc8; color: #c05621; }
                .sev-medium { background: #fefcbf; color: #b7791f; }
                .sev-low { background: #bee3f8; color: #2b6cb0; }
                .sev-info { background: #e2e8f0; color: #4a5568; }
                .tool-badge { background: #e2e8f0; color: #4a5568; padding: 1px 6px; border-radius: 3px; font-size: 11px; font-weight: 600; }
                .mono { font-family: 'SFMono-Regular', Consolas, monospace; word-break: break-all; }
                .small { font-size: 12px; }
                .meta { font-size: 13px; color: #718096; margin-bottom: 20px; }
            </style>
        </head>
        <body>
            <div class="header">
                <h1>🔍 Security Scan Report</h1>
                <p>{$label} &nbsp;·&nbsp; {$target} &nbsp;·&nbsp; {$tools} &nbsp;·&nbsp; {$genAt}</p>
            </div>
            <div class="container">
                <div class="summary-grid">
                    <div class="summary-card"><div class="count critical">{$summary['critical']}</div><div class="label">Critical</div></div>
                    <div class="summary-card"><div class="count high">{$summary['high']}</div><div class="label">High</div></div>
                    <div class="summary-card"><div class="count medium">{$summary['medium']}</div><div class="label">Medium</div></div>
                    <div class="summary-card"><div class="count low">{$summary['low']}</div><div class="label">Low</div></div>
                    <div class="summary-card"><div class="count info">{$summary['info']}</div><div class="label">Info</div></div>
                </div>

                <table>
                    <thead>
                        <tr>
                            <th style="width:90px">Severity</th>
                            <th>Vulnerability</th>
                            <th>URL</th>
                            <th>Parameter</th>
                            <th>Tool</th>
                            <th>Details &amp; Recommendation</th>
                        </tr>
                    </thead>
                    <tbody>
                        {$rows}
                    </tbody>
                </table>
            </div>
        </body>
        </html>
        HTML;
    }

    public function mergedToJunit(array $report): string
    {
        $findings = $report['findings'];
        $total = count($findings);
        $failures = count(array_filter($findings, fn($f) => in_array($f['severity'], ['critical', 'high'])));

        $xml = '<?xml version="1.0" encoding="UTF-8"?>' . "\n";
        $xml .= "<testsuites>\n";
        $xml .= sprintf(
            '  <testsuite name="Security Scan (%s)" tests="%d" failures="%d" timestamp="%s">' . "\n",
            implode('+', $report['tools_used']),
            max(1, $total),
            $failures,
            $report['generated_at']
        );

        if ($total === 0) {
            $xml .= '    <testcase name="No vulnerabilities found" classname="security"/>' . "\n";
        }

        foreach ($findings as $f) {
            $name = htmlspecialchars("[{$f['severity']}] {$f['name']} ({$f['source']})", ENT_XML1);
            $class = 'security.' . ($f['type'] ?? 'finding');
            $xml .= "    <testcase name=\"{$name}\" classname=\"{$class}\">\n";

            if (in_array($f['severity'], ['critical', 'high'])) {
                $msg = htmlspecialchars("{$f['name']} at {$f['url']}", ENT_XML1);
                $body = htmlspecialchars("URL: {$f['url']}\nParam: {$f['parameter']}\n\n{$f['description']}\n\nFix: {$f['recommendation']}", ENT_XML1);
                $xml .= "      <failure message=\"{$msg}\" type=\"{$f['severity']}\">{$body}</failure>\n";
            }

            $xml .= "    </testcase>\n";
        }

        $xml .= "  </testsuite>\n</testsuites>\n";
        return $xml;
    }

    // ── Private helpers ───────────────────────────────────────────────────

    private function buildSummary(Collection $vulnerabilities): array
    {
        return [
            'total' => $vulnerabilities->count(),
            'critical' => $vulnerabilities->where('severity', 'critical')->count(),
            'high' => $vulnerabilities->where('severity', 'high')->count(),
            'medium' => $vulnerabilities->where('severity', 'medium')->count(),
            'low' => $vulnerabilities->where('severity', 'low')->count(),
            'info' => $vulnerabilities->where('severity', 'info')->count(),
        ];
    }
}
