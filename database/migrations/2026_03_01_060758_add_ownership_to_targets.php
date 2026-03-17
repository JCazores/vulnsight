<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::table('targets', function (Blueprint $table) {
            if (!Schema::hasColumn('targets', 'ownership_verified')) {
                $table->boolean('ownership_verified')->default(false)->after('url');
            }
            if (!Schema::hasColumn('targets', 'ownership_verified_at')) {
                $table->timestamp('ownership_verified_at')->nullable()->after('ownership_verified');
            }
            if (!Schema::hasColumn('targets', 'ownership_verified_method')) {
                $table->string('ownership_verified_method', 32)->nullable()->after('ownership_verified_at');
            }
        });
    }

    public function down(): void
    {
        Schema::table('targets', function (Blueprint $table) {
            foreach (['ownership_verified', 'ownership_verified_at', 'ownership_verified_method'] as $col) {
                if (Schema::hasColumn('targets', $col)) {
                    $table->dropColumn($col);
                }
            }
        });
    }
};
