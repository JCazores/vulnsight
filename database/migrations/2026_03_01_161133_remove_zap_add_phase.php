<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        // Remove ZAP columns from scans table
        Schema::table('scans', function (Blueprint $table) {
            $columns = ['zap_spider_id', 'zap_scan_id', 'zap_target'];
            foreach ($columns as $col) {
                if (Schema::hasColumn('scans', $col)) {
                    $table->dropColumn($col);
                }
            }

            // Add current_phase for live phase label shown in UI
            if (!Schema::hasColumn('scans', 'current_phase')) {
                $table->string('current_phase')->nullable()->after('progress');
            }
        });

        // Remove ZAP columns from scan_logs table
        Schema::table('scan_logs', function (Blueprint $table) {
            $columns = ['zap_spider_id', 'zap_scan_id'];
            foreach ($columns as $col) {
                if (Schema::hasColumn('scan_logs', $col)) {
                    $table->dropColumn($col);
                }
            }
        });
    }

    public function down(): void
    {
        Schema::table('scans', function (Blueprint $table) {
            $table->string('zap_spider_id')->nullable();
            $table->string('zap_scan_id')->nullable();
            $table->string('zap_target')->nullable();
            $table->dropColumn('current_phase');
        });

        Schema::table('scan_logs', function (Blueprint $table) {
            $table->string('zap_spider_id')->nullable();
            $table->string('zap_scan_id')->nullable();
        });
    }
};
