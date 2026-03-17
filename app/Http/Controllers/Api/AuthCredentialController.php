<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Scan;
use App\Models\AuthCredential;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;

class AuthCredentialController extends Controller
{
    // app/Http/Controllers/Api/AuthCredentialController.php

    public function index(Scan $scan): JsonResponse
    {
        // This looks for 'view' method in ScanPolicy
        $this->authorize('view', $scan);

        return response()->json($scan->credentials);
    }

    public function store(Request $request, Scan $scan): JsonResponse
    {
        // This looks for 'update' method in ScanPolicy
        $this->authorize('update', $scan);

        $data = $request->validate([
            'name' => 'required|string',
            'type' => 'required',
            'token' => 'nullable|string',
        ]);

        $cred = $scan->credentials()->create($data);
        return response()->json($cred, 201);
    }

    public function destroy(Scan $scan, AuthCredential $credential): JsonResponse
    {
        // You are deleting a credential, but the permission depends on the Scan ownership
        $this->authorize('delete', $scan);

        $credential->delete();
        return response()->json(null, 204);
    }
}
