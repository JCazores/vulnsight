public function up(): void
{
Schema::create('scan_configs', function (Blueprint $table) {
$table->id();
$table->foreignId('scan_id')->constrained()->onDelete('cascade');
$table->enum('intensity', ['low','medium','high'])->default('medium');
$table->integer('max_requests_per_second')->default(1000);
$table->integer('request_timeout')->default(30);
$table->integer('crawl_depth')->default(5);
$table->boolean('follow_redirects')->default(true);
$table->boolean('javascript_execution')->default(true);
$table->json('exclusion_rules')->nullable();
$table->timestamps();
});
}
