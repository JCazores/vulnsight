<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Factories\HasFactory;
use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;
use Illuminate\Database\Eloquent\Relations\HasOne;

class Scan extends Model
{
    use HasFactory;

    protected $fillable = [
        'user_id',
        'name',
        'status',         // idle | running | paused | completed | failed
        'progress',       // 0–100
        'current_phase',  // human-readable phase label shown in UI
    ];

    protected $casts = [
        'progress' => 'integer',
    ];

    public function user(): BelongsTo
    {
        return $this->belongsTo(User::class);
    }

    public function targets(): HasMany
    {
        return $this->hasMany(Target::class);
    }

    public function vulnerabilities(): HasMany
    {
        return $this->hasMany(Vulnerability::class);
    }

    public function config(): HasOne
    {
        return $this->hasOne(ScanConfig::class);
    }

    public function scanLogs(): HasMany
    {
        return $this->hasMany(ScanLog::class);
    }

    public function vulnCountBySeverity(): array
    {
        return $this->vulnerabilities()
            ->selectRaw('severity, count(*) as total')
            ->groupBy('severity')
            ->pluck('total', 'severity')
            ->toArray();
    }

    public function discoveredUrls(): HasMany
    {
        return $this->hasMany(Target::class);
    }
}
