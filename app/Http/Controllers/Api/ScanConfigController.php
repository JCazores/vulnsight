<?php

namespace App\Http\Controllers;

use App\Models\Scan;
use Illuminate\Http\Request;
use Illuminate\Http\JsonResponse;

class ScanConfigController extends Controller
{
    public function show(Scan $scan): JsonResponse
    {
        return response()->json($scan->config);
    }

    public function update(Request $request, Scan $scan): JsonResponse
    {
        $data = $request->validate([
            'intensity' => 'in:low,medium,high',
            'max_requests_per_second' => 'integer|min:1|max:10000',
            'request_timeout' => 'integer|min:1|max:300',
            'crawl_depth' => 'integer|min:1|max:20',
            'follow_redirects' => 'boolean',
            'javascript_execution' => 'boolean',
            'exclusion_rules' => 'array',
        ]);

        $scan->config()->updateOrCreate(
            ['scan_id' => $scan->id],
            $data
        );

        return response()->json(['message' => 'Configuration saved.', 'config' => $scan->config]);
    }
}
