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
        Schema::create('scan_configs', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
            $table->string('intensity')->default('standard');
            $table->unsignedInteger('max_requests_per_second')->default(10);
            $table->unsignedInteger('request_timeout')->default(30);
            $table->unsignedInteger('crawl_depth')->default(5);
            $table->boolean('follow_redirects')->default(true);
            $table->boolean('javascript_execution')->default(false);
            $table->json('exclusion_rules')->nullable();
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scan_configs');
    }
};
