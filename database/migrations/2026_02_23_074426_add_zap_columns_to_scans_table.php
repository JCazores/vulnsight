<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::table('scans', function (Blueprint $table) {
            // ZAP scan state — stored in DB so /zap/status doesn't need the frontend
            // to pass scan IDs back on every poll (was the bug causing lost context).
            if (!Schema::hasColumn('scans', 'zap_spider_id')) {
                $table->string('zap_spider_id')->nullable()->after('progress');
            }
            if (!Schema::hasColumn('scans', 'zap_scan_id')) {
                $table->string('zap_scan_id')->nullable()->after('zap_spider_id');
            }
            if (!Schema::hasColumn('scans', 'zap_target')) {
                $table->string('zap_target', 2048)->nullable()->after('zap_scan_id');
            }
        });

        // Add evidence + solution columns to vulnerabilities if not present
        Schema::table('vulnerabilities', function (Blueprint $table) {
            if (!Schema::hasColumn('vulnerabilities', 'evidence')) {
                $table->text('evidence')->nullable()->after('cve');
            }
            if (!Schema::hasColumn('vulnerabilities', 'solution')) {
                $table->text('solution')->nullable()->after('evidence');
            }
        });
    }

    public function down(): void
    {
        Schema::table('scans', function (Blueprint $table) {
            $table->dropColumn(['zap_spider_id', 'zap_scan_id', 'zap_target']);
        });
        Schema::table('vulnerabilities', function (Blueprint $table) {
            $table->dropColumn(['evidence', 'solution']);
        });
    }
};
