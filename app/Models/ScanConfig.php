<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;

class ScanConfig extends Model
{
    protected $fillable = [
        'scan_id',
        'intensity',
        'max_requests_per_second',
        'request_timeout',
        'crawl_depth',
        'follow_redirects',
        'javascript_execution',
        'exclusion_rules',
    ];

    protected $casts = [
        'exclusion_rules' => 'array',
        'follow_redirects' => 'boolean',
        'javascript_execution' => 'boolean',
    ];
}
