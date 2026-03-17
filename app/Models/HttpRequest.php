<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class HttpRequest extends Model
{
    public $timestamps = false;

    protected $fillable = [
        'scan_id',
        'method',
        'url',
        'status_code',
        'response_time_ms',
        'module',
        'payload',
        'flagged',
        'flag_reason',
        'sent_at',
    ];

    protected $casts = [
        'flagged' => 'boolean',
        'sent_at' => 'datetime',
    ];

    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }
}
