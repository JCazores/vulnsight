public function up(): void
{
Schema::create('auth_credentials', function (Blueprint $table) {
$table->id();
$table->foreignId('scan_id')->constrained()->onDelete('cascade');
$table->string('name');
$table->enum('type', ['basic','bearer','cookie','oauth2']);
$table->text('token')->nullable();
$table->timestamp('last_used_at')->nullable();
$table->timestamps();
});
}