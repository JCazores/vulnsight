<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::table('scans', function (Blueprint $table) {
            // Check if column exists to prevent "Duplicate column" errors
            if (!Schema::hasColumn('scans', 'progress')) {
                $table->integer('progress')->default(0)->after('status');
            }
        });
    }

    public function down(): void
    {
        Schema::table('scans', function (Blueprint $table) {
            $table->dropColumn('progress');
        });
    }
};
