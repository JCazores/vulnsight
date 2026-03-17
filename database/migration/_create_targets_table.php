public function up(): void
{
Schema::create('targets', function (Blueprint $table) {
$table->id();
$table->foreignId('scan_id')->constrained()->onDelete('cascade');
$table->string('url');
$table->enum('status', ['queued','scanning','completed','failed'])->default('queued');
$table->integer('requests_sent')->default(0);
$table->integer('urls_found')->default(0);
$table->integer('vulnerabilities')->default(0);
$table->timestamps();
});
}