<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::table('scans', function (Blueprint $table) {
            if (Schema::hasColumn('scans', 'target_url')) {
                $table->dropColumn('target_url');
            }
        });
    }

    public function down(): void
    {
        Schema::table('scans', function (Blueprint $table) {
            if (!Schema::hasColumn('scans', 'target_url')) {
                $table->string('target_url', 2048)->nullable()->after('name');
            }
        });
    }
};
