<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Scan;
use App\Models\Target;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;

class TargetController extends Controller
{
    public function index(Scan $scan): JsonResponse
    {
        abort_if($scan->user_id !== Auth::id(), 403);

        return response()->json($scan->targets()->get());
    }

    public function store(Request $request, Scan $scan): JsonResponse
    {
        abort_if($scan->user_id !== Auth::id(), 403);

        $data = $request->validate([
            'url' => ['required', 'url', 'max:2048'],
            'type' => ['sometimes', 'nullable', 'string', 'max:100'],
        ]);

        // Prevent duplicate targets on the same scan
        if ($scan->targets()->where('url', $data['url'])->exists()) {
            return response()->json(['message' => 'Target already added'], 409);
        }

        $target = $scan->targets()->create($data);

        return response()->json($target, 201);
    }

    public function destroy(Scan $scan, Target $target): JsonResponse
    {
        abort_if($scan->user_id !== Auth::id(), 403);
        abort_if($target->scan_id !== $scan->id, 404);

        $target->delete();

        return response()->json(null, 204);
    }
}
