<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        if (Schema::hasTable('scan_logs')) {
            Schema::table('scan_logs', function (Blueprint $table) {
                if (!Schema::hasColumn('scan_logs', 'zap_spider_id'))
                    $table->string('zap_spider_id')->nullable();
                if (!Schema::hasColumn('scan_logs', 'zap_scan_id'))
                    $table->string('zap_scan_id')->nullable();
                if (!Schema::hasColumn('scan_logs', 'vuln_total'))
                    $table->unsignedInteger('vuln_total')->default(0);
                if (!Schema::hasColumn('scan_logs', 'vuln_critical'))
                    $table->unsignedSmallInteger('vuln_critical')->default(0);
                if (!Schema::hasColumn('scan_logs', 'vuln_high'))
                    $table->unsignedSmallInteger('vuln_high')->default(0);
                if (!Schema::hasColumn('scan_logs', 'vuln_medium'))
                    $table->unsignedSmallInteger('vuln_medium')->default(0);
                if (!Schema::hasColumn('scan_logs', 'vuln_low'))
                    $table->unsignedSmallInteger('vuln_low')->default(0);
                if (!Schema::hasColumn('scan_logs', 'duration_seconds'))
                    $table->unsignedInteger('duration_seconds')->nullable();
            });
            return;
        }

        Schema::create('scan_logs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->unsignedBigInteger('scan_id')->nullable()->index();
            $table->string('target_url');
            $table->string('status')->default('running');
            $table->unsignedTinyInteger('progress')->default(0);
            $table->unsignedInteger('requests_sent')->default(0);
            $table->unsignedInteger('urls_discovered')->default(0);
            $table->string('zap_spider_id')->nullable();
            $table->string('zap_scan_id')->nullable();
            $table->unsignedInteger('vuln_total')->default(0);
            $table->unsignedSmallInteger('vuln_critical')->default(0);
            $table->unsignedSmallInteger('vuln_high')->default(0);
            $table->unsignedSmallInteger('vuln_medium')->default(0);
            $table->unsignedSmallInteger('vuln_low')->default(0);
            $table->timestamp('started_at')->nullable();
            $table->timestamp('completed_at')->nullable();
            $table->unsignedInteger('duration_seconds')->nullable();
            $table->timestamps();
        });
    }
};
