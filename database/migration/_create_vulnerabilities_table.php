public function up(): void
{
Schema::create('vulnerabilities', function (Blueprint $table) {
$table->id();
$table->foreignId('scan_id')->constrained()->onDelete('cascade');
$table->string('type');
$table->string('url');
$table->enum('severity', ['critical','high','medium','low']);
$table->text('description')->nullable();
$table->text('remediation')->nullable();
$table->boolean('confirmed')->default(false);
$table->timestamps();
});
}
