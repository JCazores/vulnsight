<?php

namespace App\Models;

use Illuminate\Database\Eloquent\Model;
use Illuminate\Database\Eloquent\Relations\BelongsTo;

class AuthCredential extends Model
{
    protected $fillable = ['scan_id', 'name', 'type', 'token', 'username', 'password'];
    protected $hidden = ['token', 'password'];

    public function scan(): BelongsTo
    {
        return $this->belongsTo(Scan::class);
    }

    // Return auth headers ready to attach to Guzzle requests
    public function toHeaders(): array
    {
        return match ($this->type) {
            'bearer' => ['Authorization' => 'Bearer ' . $this->token],
            'basic' => ['Authorization' => 'Basic ' . base64_encode($this->username . ':' . $this->password)],
            'cookie' => ['Cookie' => $this->token],
            default => [],
        };
    }
}
