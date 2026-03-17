<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('scan_vulnerabilities', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_log_id')->constrained('scan_logs')->cascadeOnDelete();
            $table->string('name', 500);
            $table->string('url', 2048);
            $table->string('severity');                      // critical|high|medium|low
            $table->unsignedTinyInteger('severity_order');   // 0=critical, 3=low (for ORDER BY)
            $table->string('cve', 100)->nullable();
            $table->string('source')->default('nuclei');     // nuclei|nikto|testssl|wavs
            $table->string('status')->default('open');
            $table->string('dedup_hash', 64)->nullable()->index(); // prevents duplicate inserts
            $table->timestamp('detected_at')->nullable();
            $table->timestamps();

            $table->index(['scan_log_id', 'severity']);
        });
    }
    public function down(): void
    {
        Schema::dropIfExists('scan_vulnerabilities');
    }
};
