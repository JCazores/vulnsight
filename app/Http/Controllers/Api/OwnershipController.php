<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\Scan;
use App\Services\OwnershipVerifier;
use Illuminate\Http\JsonResponse;
use Illuminate\Support\Facades\Auth;

class OwnershipController extends Controller
{
    public function __construct(private readonly OwnershipVerifier $verifier)
    {
    }

    public function getToken(Scan $scan, int $targetId): JsonResponse
    {
        if ($scan->user_id !== Auth::id())
            abort(403);

        $target = $scan->targets()->findOrFail($targetId);
        $token = OwnershipVerifier::generateToken($target->url, Auth::id());

        $isPrivate = $this->verifier->isPrivateOrLocalhost($target->url);

        return response()->json([
            'target_id' => $target->id,
            'target_url' => $target->url,
            'token' => $token,
            'is_verified' => (bool) $target->ownership_verified,
            'is_private' => $isPrivate,
            'skip_verify' => $isPrivate,
            'methods' => $isPrivate ? [] : [
                [
                    'id' => 'meta_tag',
                    'name' => 'HTML Meta Tag (Recommended)',
                    'description' => 'Add this tag inside the <head> of your homepage:',
                    'code' => "<meta name=\"vulnsight-verification\" content=\"{$token}\">",
                    'instructions' => [
                        'Open your homepage template or layout file',
                        'Paste the meta tag inside the <head> section',
                        'Deploy/save the change',
                        'Click Verify below',
                    ],
                ],
                [
                    'id' => 'text_file',
                    'name' => 'Verification File',
                    'description' => 'Upload a text file to your web root:',
                    'code' => $token,
                    'filename' => 'vulnsight-verify.txt',
                    'path' => rtrim($target->url, '/') . '/vulnsight-verify.txt',
                    'instructions' => [
                        'Create a file named vulnsight-verify.txt',
                        "Paste this token as the file content: {$token}",
                        'Upload it to your web root (same folder as index.php)',
                        'Click Verify below',
                    ],
                ],
            ],
        ]);
    }

    public function verify(Scan $scan, int $targetId): JsonResponse
    {
        if ($scan->user_id !== Auth::id())
            abort(403);

        $target = $scan->targets()->findOrFail($targetId);
        $token = OwnershipVerifier::generateToken($target->url, Auth::id());
        $result = $this->verifier->check($target->url, $token);

        if ($result['verified']) {
            $target->update([
                'ownership_verified' => true,
                'ownership_verified_at' => now(),
                'ownership_verified_method' => $result['method'],
            ]);
        }

        return response()->json([
            'verified' => $result['verified'],
            'method' => $result['method'],
            'message' => $result['message'],
            'token' => $token,
            'target_url' => $target->url,
        ], $result['verified'] ? 200 : 422);
    }
}
