<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;
use Illuminate\Database\Eloquent\Relations\HasMany;

class DiscoveredUrl extends Model
{
    protected $fillable = [
        'scan_id',
        'url',
        'method',
        'status_code',
        'response_time_ms',
        'response_body',
        'response_headers',
        'parameters',
        'forms',
        'depth',
        'scanned',
    ];

    protected $casts = [
        'response_headers' => 'array',
        'parameters' => 'array',
        'forms' => 'array',
        'scanned' => 'boolean',
    ];

    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }
    public function vulnerabilities(): HasMany
    {
        return $this->hasMany(Vulnerability::class);
    }
}
