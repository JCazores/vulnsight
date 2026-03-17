<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    /**
     * Run the migrations.
     */
    public function up(): void
    {
        Schema::table('vulnerabilities', function (Blueprint $table) {
            //
            // in the migration up():
            $table->timestamp('detected_at')->nullable()->after('scan_log_id');
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::table('vulnerabilities', function (Blueprint $table) {
            //
        });
    }
};
