<?php
namespace App\Providers;
use Illuminate\Foundation\Support\Providers\AuthServiceProvider as ServiceProvider;
use App\Services\Scanner\DependencyScanner;
use App\Services\Scanner\ExposedPathScanner;
use App\Services\Scanner\HeaderScanner;
use App\Services\Scanner\NiktoScanner;
use App\Services\Scanner\NucleiScanner;
use App\Services\Scanner\ScanOrchestrator;
use App\Services\Scanner\StaticCodeScanner;
use Illuminate\Support\Facades\Queue;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Vite;
class AppServiceProvider extends ServiceProvider
{
    protected $policies = [
        \App\Models\Scan::class => \App\Policies\ScanPolicy::class,
    ];
    public function register(): void
    {
        $this->app->singleton(ScanOrchestrator::class, function () {
            return new ScanOrchestrator(
                new NucleiScanner(),
                new NiktoScanner(),
                new HeaderScanner(),
                new ExposedPathScanner(),
                new DependencyScanner(),
            );
        });
    }
    public function boot(): void
    {
        // Pass string directly, not a closure — older Laravel versions don't accept closures here
        $nonce = app()->has('csp-nonce') ? (string) app('csp-nonce') : '';
        Vite::useCspNonce($nonce);

        // Queue worker heartbeat — writes timestamp on every worker loop iteration
        // Health check reads this to determine if queue:work is actually running
        Queue::looping(function () {
            Cache::put('queue_heartbeat', now()->timestamp, 300);
        });
    }
}
