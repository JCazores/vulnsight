<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class ScanLog extends Model
{
    protected $fillable = [
        'scan_id',
        'user_id',
        'target_url',
        'status',
        'progress',
        'requests_sent',
        'urls_discovered',
        'vuln_total',
        'vuln_critical',
        'vuln_high',
        'vuln_medium',
        'vuln_low',
        'started_at',
        'completed_at',
        'duration_seconds',
    ];

    protected $casts = [
        'started_at' => 'datetime',
        'completed_at' => 'datetime',
    ];

    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function vulnerabilities(): HasMany
    {
        return $this->hasMany(Vulnerability::class);
    }

    public function markCompleted(): void
    {
        $now = now();
        $this->update([
            'status' => 'completed',
            'progress' => 100,
            'completed_at' => $now,
            'duration_seconds' => $this->started_at
                ? (int) $this->started_at->diffInSeconds($now)
                : null,
        ]);
        $this->syncVulnCounts();
    }

    public function syncVulnCounts(): void
    {
        $counts = $this->vulnerabilities()
            ->selectRaw('severity, count(*) as cnt')
            ->groupBy('severity')
            ->pluck('cnt', 'severity');

        $this->update([
            'vuln_critical' => $counts['critical'] ?? 0,
            'vuln_high' => $counts['high'] ?? 0,
            'vuln_medium' => $counts['medium'] ?? 0,
            'vuln_low' => $counts['low'] ?? 0,
            'vuln_total' => $counts->sum(),
        ]);
    }

    public function toFrontend(): array
    {
        return [
            'id' => $this->id,
            'scan_id' => $this->scan_id,
            'name' => 'Scan — ' . $this->target_url,
            'target' => $this->target_url,
            'target_url' => $this->target_url,
            'status' => $this->status,
            'progress' => $this->progress,
            'requests_sent' => $this->requests_sent,
            'urls_discovered' => $this->urls_discovered,
            'vuln_total' => $this->vuln_total,
            'vuln_critical' => $this->vuln_critical,
            'vuln_high' => $this->vuln_high,
            'vuln_medium' => $this->vuln_medium,
            'vuln_low' => $this->vuln_low,
            'started_at' => $this->started_at?->toISOString(),
            'completed_at' => $this->completed_at?->toISOString(),
            'duration_seconds' => $this->duration_seconds,
            'startedAt' => $this->started_at?->toISOString(),
            'completedAt' => $this->completed_at?->toISOString(),
            'current_phase' => $this->relationLoaded('scan') ? $this->scan?->current_phase : null,
            'stats' => [
                'requestsSent' => $this->requests_sent,
                'urlsDiscovered' => $this->urls_discovered,
                'criticalIssues' => $this->vuln_critical,
                'highIssues' => $this->vuln_high,
                'mediumIssues' => $this->vuln_medium,
                'lowIssues' => $this->vuln_low,
            ],
            'vulns' => $this->relationLoaded('vulnerabilities')
                ? $this->vulnerabilities->map(fn($v) => [
                    'id' => $v->id,
                    'name' => $v->name,
                    'url' => $v->url,
                    'severity' => $v->severity,
                    'sev' => $v->severity,
                    'badge' => 'badge-' . $v->severity,
                    'cve' => $v->cve,
                    'evidence' => $v->evidence,
                    'solution' => $v->solution ?? $v->remediation,
                    'description' => $v->description,
                    'detected_at' => ($v->detected_at ?? $v->created_at)?->toISOString(),
                    'time' => ($v->detected_at ?? $v->created_at)?->toISOString(),
                ])->values()->all()
                : [],
        ];
    }
}
