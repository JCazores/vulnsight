<?php

namespace App\Http\Controllers\Api;

use App\Http\Controllers\Controller;
use App\Models\User;
use Illuminate\Http\JsonResponse;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Auth;
use Illuminate\Support\Facades\Hash;
use Illuminate\Validation\ValidationException;

class AuthController extends Controller
{
    // ─────────────────────────────────────────────
    // Shared helper — always return the same shape
    // so the frontend never gets a missing field.
    // ─────────────────────────────────────────────
    private function userPayload(User $user): array
    {
        return [
            'id' => $user->id,
            'name' => $user->name,
            'email' => $user->email,
            'role' => $user->role ?? 'user',          // 'admin' | 'user'
            'is_admin' => ($user->role ?? 'user') === 'admin',
        ];
    }

    // ─────────────────────────────────────────────
    // POST /api/register
    // ─────────────────────────────────────────────
    public function register(Request $request): JsonResponse
    {
        $data = $request->validate([
            'name' => 'required|string|max:255',
            'email' => 'required|email|unique:users,email',
            'password' => 'required|string|min:8|confirmed',
        ]);

        $user = User::create([
            'name' => $data['name'],
            'email' => $data['email'],
            'password' => Hash::make($data['password']),
            'role' => 'user',   // new accounts are always regular users
        ]);

        Auth::login($user);
        $request->session()->regenerate();

        return response()->json($this->userPayload($user), 201);
    }

    // ─────────────────────────────────────────────
    // POST /api/login
    // ─────────────────────────────────────────────
    public function login(Request $request): JsonResponse
    {
        $data = $request->validate([
            'email' => 'required|email',
            'password' => 'required|string',
        ]);

        if (!Auth::attempt(['email' => $data['email'], 'password' => $data['password']], true)) {
            throw ValidationException::withMessages([
                'email' => ['The provided credentials are incorrect.'],
            ]);
        }

        $request->session()->regenerate();

        /** @var User $user */
        $user = Auth::user();

        return response()->json($this->userPayload($user));
    }

    // ─────────────────────────────────────────────
    // POST /api/logout
    // ─────────────────────────────────────────────
    public function logout(Request $request): JsonResponse
    {
        Auth::guard('web')->logout();
        $request->session()->invalidate();
        $request->session()->regenerateToken();

        return response()->json(['message' => 'Logged out']);
    }

    // ─────────────────────────────────────────────
    // GET /api/me  — session restore on page reload
    // ─────────────────────────────────────────────
    public function me(Request $request): JsonResponse
    {
        /** @var User $user */
        $user = $request->user();

        if (!$user) {
            return response()->json(['message' => 'Unauthenticated'], 401);
        }

        return response()->json($this->userPayload($user));
    }
}
