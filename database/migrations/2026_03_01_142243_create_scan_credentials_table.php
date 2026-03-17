<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::create('scan_credentials', function (Blueprint $table) {
            $table->id();
            $table->foreignId('scan_id')->constrained()->cascadeOnDelete();
            $table->string('name');
            $table->string('type');          // cookie|bearer|basic|oauth
            $table->text('token')->nullable(); // encrypted
            $table->timestamps();
        });
    }
    public function down(): void
    {
        Schema::dropIfExists('scan_credentials');
    }
};
