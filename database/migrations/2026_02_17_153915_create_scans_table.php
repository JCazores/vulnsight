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
        Schema::create('scans', function (Blueprint $table) {
            $table->id();
            $table->foreignId('user_id')->constrained()->cascadeOnDelete();
            $table->string('name');
            $table->string('status')->default('idle'); // idle, running, paused, completed, failed
            $table->unsignedInteger('progress')->default(0);
            $table->string('current_phase')->nullable();
            $table->string('intensity')->default('standard');
            $table->unsignedInteger('max_rps')->default(10);
            $table->unsignedInteger('request_timeout')->default(30);
            $table->unsignedInteger('crawl_depth')->default(5);
            $table->boolean('follow_redirects')->default(true);
            $table->boolean('javascript_execution')->default(false);
            $table->json('exclusion_rules')->nullable();
            $table->unsignedInteger('requests_sent')->default(0);
            $table->unsignedInteger('urls_discovered')->default(0);
            $table->timestamps();
        });
    }

    /**
     * Reverse the migrations.
     */
    public function down(): void
    {
        Schema::dropIfExists('scans');
    }
};
