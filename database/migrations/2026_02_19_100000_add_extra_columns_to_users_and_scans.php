<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        // 1. Update Users Table (Safety Checks)
        Schema::table('users', function (Blueprint $table) {
            if (!Schema::hasColumn('users', 'role')) {
                $table->string('role')->default('user')->after('email');
            }
            if (!Schema::hasColumn('users', 'avatar')) {
                $table->string('avatar')->nullable()->after('role');
            }
        });

        // 2. Update Scans Table (Safety Checks Added Here)
        Schema::table('scans', function (Blueprint $table) {
            if (!Schema::hasColumn('scans', 'target_url')) {
                $table->string('target_url')->after('id');
            }
            if (!Schema::hasColumn('scans', 'status')) {
                $table->string('status')->default('pending')->after('target_url');
            }
            if (!Schema::hasColumn('scans', 'results')) {
                $table->text('results')->nullable()->after('status');
            }
        });
    }

    public function down(): void
    {
        Schema::table('users', function (Blueprint $table) {
            $table->dropColumn(['role', 'avatar']);
        });

        Schema::table('scans', function (Blueprint $table) {
            $table->dropColumn(['target_url', 'status', 'results']);
        });
    }
};
