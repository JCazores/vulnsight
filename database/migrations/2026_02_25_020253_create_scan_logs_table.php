<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        // ── scan_logs — one row per scan run ─────────────────────────────────
        Schema::create('scan_logs', function (Blueprint $table) {
            $table->id();

            // tie to existing scans table
            $table->foreignId('scan_id')
                ->constrained('scans')
                ->onDelete('cascade');

            // tie to existing users table
            $table->foreignId('user_id')
                ->nullable()
                ->constrained('users')
                ->onDelete('set null');

            $table->string('target_url', 2048);
            $table->string('status', 32)->default('running');
            // status values: running | completed | failed | stopped | paused

            $table->unsignedTinyInteger('progress')->default(0); // 0–100

            // live counters
            $table->unsignedInteger('requests_sent')->default(0);
            $table->unsignedInteger('urls_discovered')->default(0);

            // vuln counts — updated by syncVulnCounts()
            $table->unsignedSmallInteger('vuln_total')->default(0);
            $table->unsignedSmallInteger('vuln_critical')->default(0);
            $table->unsignedSmallInteger('vuln_high')->default(0);
            $table->unsignedSmallInteger('vuln_medium')->default(0);
            $table->unsignedSmallInteger('vuln_low')->default(0);

            // ZAP references
            $table->string('zap_spider_id')->nullable();
            $table->string('zap_scan_id')->nullable();

            // timing
            $table->timestamp('started_at')->nullable();
            $table->timestamp('completed_at')->nullable();
            $table->unsignedInteger('duration_seconds')->nullable();

            $table->timestamps();

            $table->index(['user_id', 'created_at']);
            $table->index('status');
        });

        // ── scan_log_vulnerabilities — one row per finding per scan run ───────
        Schema::create('scan_log_vulnerabilities', function (Blueprint $table) {
            $table->id();

            $table->foreignId('scan_log_id')
                ->constrained('scan_logs')
                ->onDelete('cascade');

            $table->foreignId('scan_id')
                ->constrained('scans')
                ->onDelete('cascade');

            $table->string('name', 512);
            $table->string('url', 2048);
            $table->string('severity', 16);   // critical | high | medium | low
            $table->string('cve', 64)->nullable();
            $table->text('evidence')->nullable();
            $table->text('solution')->nullable();
            $table->text('description')->nullable();
            $table->unsignedInteger('plugin_id')->nullable();
            $table->string('confidence', 32)->nullable();
            $table->string('risk_label', 32)->nullable();

            $table->timestamps();

            $table->index(['scan_log_id', 'severity']);
            $table->index('scan_id');
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('scan_log_vulnerabilities');
        Schema::dropIfExists('scan_logs');
    }
};
