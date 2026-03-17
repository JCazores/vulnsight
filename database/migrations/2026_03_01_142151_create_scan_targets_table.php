<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('scan_targets', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
            $table->string('url', 2048);
            $table->string('type')->default('Web Application');
            $table->timestamps();
        });
    }
    public function down(): void
    {
        Schema::dropIfExists('scan_targets');
    }
};
