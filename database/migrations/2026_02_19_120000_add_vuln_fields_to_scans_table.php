<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        // Add progress to scans if missing
        Schema::table('scans', function (Blueprint $table) {
            if (!Schema::hasColumn('scans', 'progress')) {
                $table->unsignedTinyInteger('progress')->default(0)->after('status');
            }
        });

        // Create vulnerabilities table if missing
        if (!Schema::hasTable('vulnerabilities')) {
            Schema::create('vulnerabilities', function (Blueprint $table) {
                $table->id();
                $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
                $table->string('name');
                $table->string('url')->nullable();
                $table->string('severity')->default('low'); // critical, high, medium, low
                $table->string('cve')->nullable();
                $table->timestamps();
            });
        } else {
            Schema::table('vulnerabilities', function (Blueprint $table) {
                if (!Schema::hasColumn('vulnerabilities', 'scan_id')) {
                    $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
                }
                if (!Schema::hasColumn('vulnerabilities', 'name')) {
                    $table->string('name');
                }
                if (!Schema::hasColumn('vulnerabilities', 'url')) {
                    $table->string('url')->nullable();
                }
                if (!Schema::hasColumn('vulnerabilities', 'severity')) {
                    $table->string('severity')->default('low');
                }
                if (!Schema::hasColumn('vulnerabilities', 'cve')) {
                    $table->string('cve')->nullable();
                }
            });
        }
    }

    public function down(): void
    {
        Schema::dropIfExists('vulnerabilities');
    }
};
