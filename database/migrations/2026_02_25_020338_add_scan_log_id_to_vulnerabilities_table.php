<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::table('vulnerabilities', function (Blueprint $table) {
            $table->foreignId('scan_log_id')
                ->nullable()
                ->after('scan_id')
                ->constrained('scan_logs')
                ->onDelete('set null');
        });
    }

    public function down(): void
    {
        Schema::table('vulnerabilities', function (Blueprint $table) {
            $table->dropForeign(['scan_log_id']);
            $table->dropColumn('scan_log_id');
        });
    }
};
