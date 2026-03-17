<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class Target extends Model
{
    protected $fillable = ['scan_id', 'url', 'type', 'status'];

    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }
}
