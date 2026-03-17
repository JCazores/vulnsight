<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('vulnerabilities', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
            $table->string('name');
            $table->string('severity')->default('low'); // critical, high, medium, low
            $table->string('url');
            $table->string('method', 10)->default('GET');
            $table->string('parameter')->nullable();
            $table->text('payload')->nullable();
            $table->text('evidence')->nullable();
            $table->string('cve')->nullable();
            $table->string('status')->default('open');
            $table->boolean('is_new')->default(true);
            $table->text('description')->nullable();
            $table->text('remediation')->nullable();
            $table->timestamps();
        });
    }

    public function down(): void
    {
        Schema::dropIfExists('vulnerabilities');
    }
};
