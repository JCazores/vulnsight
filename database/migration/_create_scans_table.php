public function up(): void
{
Schema::create('scans', function (Blueprint $table) {
$table->id();
// ADD THIS LINE: It links the scan to a specific user
$table->foreignId('user_id')->constrained()->onDelete('cascade');

$table->string('name')->nullable();
$table->enum('status', ['idle','running','paused','completed','failed'])->default('idle');

// Ensure you have a field for the URL being scanned!
$table->string('target_url')->nullable();

$table->integer('progress')->default(0);
$table->integer('requests_sent')->default(0);
$table->integer('urls_discovered')->default(0);
$table->integer('vulnerabilities_found')->default(0);
$table->integer('critical_issues')->default(0);
$table->integer('high_issues')->default(0);
$table->integer('medium_issues')->default(0);
$table->integer('low_issues')->default(0);
$table->timestamp('started_at')->nullable();
$table->timestamp('completed_at')->nullable();
$table->timestamps();
});
}