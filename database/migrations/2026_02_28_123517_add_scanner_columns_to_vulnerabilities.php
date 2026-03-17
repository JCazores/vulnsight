<?php

use Illuminate\Database\Migrations\Migration;
use Illuminate\Database\Schema\Blueprint;
use Illuminate\Support\Facades\Schema;

return new class extends Migration {
    public function up(): void
    {
        Schema::table('vulnerabilities', function (Blueprint $table) {
            if (!Schema::hasColumn('vulnerabilities', 'description')) {
                $table->text('description')->nullable()->after('remediation');
            }
            if (!Schema::hasColumn('vulnerabilities', 'plugin_id')) {
                $table->unsignedInteger('plugin_id')->nullable()->after('description');
            }
            if (!Schema::hasColumn('vulnerabilities', 'confidence')) {
                $table->string('confidence', 32)->nullable()->after('plugin_id');
            }
            if (!Schema::hasColumn('vulnerabilities', 'risk_label')) {
                $table->string('risk_label', 32)->nullable()->after('confidence');
            }
        });
    }

    public function down(): void
    {
        Schema::table('vulnerabilities', function (Blueprint $table) {
            foreach (['description', 'plugin_id', 'confidence', 'risk_label'] as $col) {
                if (Schema::hasColumn('vulnerabilities', $col)) {
                    $table->dropColumn($col);
                }
            }
        });
    }
};
