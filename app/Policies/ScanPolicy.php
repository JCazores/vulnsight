<?php

namespace App\Policies;

use App\Models\Scan;
use App\Models\User;

class ScanPolicy
{
    public function before(User $user, string $ability): bool|null
    {
        return $user->is_admin ? true : null;
    }

    public function view(User $user, Scan $scan): bool
    {
        return $this->owns($user, $scan);
    }

    public function update(User $user, Scan $scan): bool
    {
        return $this->owns($user, $scan);
    }

    public function delete(User $user, Scan $scan): bool
    {
        return $this->owns($user, $scan);
    }

    public function create(User $user): bool
    {
        return true;
    }

    private function owns(User $user, Scan $scan): bool
    {
        return $scan->user_id === $user->id;
    }
}
