<?php

namespace App\Services\Scanner;

use Illuminate\Support\Facades\File;
use Illuminate\Support\Facades\Log;

/**
 * StaticCodeScanner
 *
 * Scans your own PHP and Blade files for vulnerability patterns.
 * Unlike ZAP (black-box), this sees the actual source code —
 * it finds SQLi, XSS, mass assignment, and dangerous functions
 * that a network scanner would never detect.
 *
 * Usage:
 *   $scanner  = new StaticCodeScanner();
 *   $findings = $scanner->scan(app_path());
 */
class StaticCodeScanner
{
    /**
     * Patterns to search for.
     * Each rule: regex, name, severity, description, solution, steps
     */
    private array $rules = [

        // ── SQL Injection ────────────────────────────────────────────────────

        'sqli_raw_select' => [
            'pattern'     => '/DB::select\s*\(\s*["\'].*\$(?!\()/m',
            'name'        => 'SQL Injection: Raw DB::select with Variable',
            'severity'    => 'critical',
            'description' => 'DB::select() is called with a string that contains a PHP variable. '
                . 'If the variable contains user input, this is a SQL injection vulnerability.',
            'solution'    => 'Use parameterised queries: DB::select("SELECT * FROM users WHERE id = ?", [$id])',
            'steps'       => [
                'Replace string interpolation with ? placeholders.',
                'Pass values as the second argument array to DB::select().',
                'Use Eloquent ORM instead of raw queries where possible.',
            ],
        ],

        'sqli_raw_statement' => [
            'pattern'     => '/DB::statement\s*\(\s*["\'].*\$(?!\()/m',
            'name'        => 'SQL Injection: Raw DB::statement with Variable',
            'severity'    => 'critical',
            'description' => 'DB::statement() called with an unparameterised variable.',
            'solution'    => 'Use parameterised bindings: DB::statement("UPDATE users SET role = ? WHERE id = ?", [$role, $id])',
            'steps'       => ['Use ? placeholders and pass values as second array argument.'],
        ],

        'sqli_where_raw' => [
            'pattern'     => '/->whereRaw\s*\(\s*["\'][^"\']*\$(?!\()/m',
            'name'        => 'SQL Injection: whereRaw with Variable',
            'severity'    => 'critical',
            'description' => 'whereRaw() is called with a string containing an interpolated PHP variable. '
                . 'whereRaw() does not escape its input — this is SQL injectable.',
            'solution'    => 'Pass variables as bindings: ->whereRaw("id = ?", [$id])',
            'steps'       => [
                'Never interpolate variables directly into whereRaw().',
                'Use the second argument: ->whereRaw("column = ?", [$value])',
            ],
        ],

        'sqli_order_raw' => [
            'pattern'     => '/->orderByRaw\s*\(\s*["\'][^"\']*\$(?!\()/m',
            'name'        => 'SQL Injection: orderByRaw with Variable',
            'severity'    => 'high',
            'description' => 'orderByRaw() contains a PHP variable. ORDER BY injection can be used '
                . 'to extract data via timing or error-based techniques.',
            'solution'    => 'Whitelist allowed sort columns and directions.',
            'steps'       => [
                'Whitelist: $allowed = [\'name\', \'created_at\']; if(!in_array($col, $allowed)) abort(400);',
                'Then use ->orderBy($col, $dir) with whitelisted values.',
            ],
        ],

        // ── Cross-Site Scripting (XSS) ────────────────────────────────────────

        'xss_unescaped_blade' => [
            'pattern'     => '/\{!!\s*\$[a-zA-Z_][a-zA-Z0-9_]*\s*!!\}/',
            'name'        => 'XSS: Unescaped Output in Blade Template {!! !!}',
            'severity'    => 'high',
            'description' => 'Blade\'s {!! !!} syntax outputs raw HTML without escaping. '
                . 'If the variable contains user-controlled input, this is a XSS vulnerability.',
            'solution'    => 'Use {{ $variable }} instead of {!! $variable !!} for user-controlled data.',
            'steps'       => [
                'Replace {!! $var !!} with {{ $var }} for any user-controlled content.',
                'Only use {!! !!} for trusted HTML (e.g. Markdown you generated, not user input).',
            ],
        ],

        'xss_echo_direct' => [
            'pattern'     => '/echo\s+\$_(?:GET|POST|REQUEST|COOKIE)\s*\[/m',
            'name'        => 'XSS: Direct Echo of Superglobal',
            'severity'    => 'critical',
            'description' => 'PHP superglobal ($_GET, $_POST, etc.) is echoed directly without escaping.',
            'solution'    => 'Always escape: echo htmlspecialchars($_GET[\'q\'], ENT_QUOTES, \'UTF-8\')',
            'steps'       => ['Wrap output in htmlspecialchars() or use Blade {{ }} syntax.'],
        ],

        'xss_echo_request' => [
            'pattern'     => '/echo\s+\$request->(?:get|input|query|post)\s*\(/m',
            'name'        => 'XSS: Direct Echo of Request Input',
            'severity'    => 'high',
            'description' => 'Request input is echoed directly without escaping.',
            'solution'    => 'Escape output: echo e($request->input(\'q\'))',
            'steps'       => ['Use Laravel\'s e() helper or htmlspecialchars() before echoing user input.'],
        ],

        // ── Mass Assignment ───────────────────────────────────────────────────

        'mass_assignment_all' => [
            'pattern'     => '/->(?:create|update|fill)\s*\(\s*\$request->all\s*\(\s*\)\s*\)/m',
            'name'        => 'Mass Assignment: $request->all() passed to Eloquent',
            'severity'    => 'high',
            'description' => '$request->all() is passed directly to an Eloquent create/update/fill. '
                . 'This allows attackers to set any column including role, is_admin, password, etc.',
            'solution'    => 'Use $request->only([\'field1\', \'field2\']) or validate first.',
            'steps'       => [
                'Replace $request->all() with $request->only([\'allowed_field1\', ...]).',
                'Or use $request->validated() after calling $request->validate([...]).',
                'Ensure $fillable in your Model does NOT include sensitive columns like role, is_admin.',
            ],
        ],

        'mass_assignment_except' => [
            'pattern'     => '/->(?:create|update|fill)\s*\(\s*\$request->except\s*\(\s*\[/m',
            'name'        => 'Mass Assignment: $request->except() — whitelist preferred',
            'severity'    => 'medium',
            'description' => '$request->except() uses a blacklist approach. New fields added to the '
                . 'model later may inadvertently become mass-assignable if not added to the except list.',
            'solution'    => 'Prefer $request->only([...]) — explicit whitelist is safer than a blacklist.',
            'steps'       => [
                'Switch from $request->except([...]) to $request->only([...]).',
                'List exactly the fields that should be settable by users.',
            ],
        ],

        // ── Dangerous Functions ───────────────────────────────────────────────

        'eval_usage' => [
            'pattern'     => '/\beval\s*\(/m',
            'name'        => 'Dangerous Function: eval()',
            'severity'    => 'critical',
            'description' => 'eval() executes arbitrary PHP code. If any user input reaches eval(), '
                . 'it is Remote Code Execution (RCE).',
            'solution'    => 'Remove all eval() calls. There is almost never a legitimate use for eval().',
            'steps'       => [
                'Remove the eval() call entirely.',
                'If you need dynamic behavior, use a strategy pattern or configuration array.',
            ],
        ],

        'exec_with_input' => [
            'pattern'     => '/\b(?:exec|shell_exec|system|passthru|popen)\s*\(\s*[^)]*\$(?!this)[^)]*\)/m',
            'name'        => 'Command Injection: Shell Function with Variable',
            'severity'    => 'critical',
            'description' => 'A shell execution function (exec, shell_exec, system, etc.) is called '
                . 'with a variable in its argument. If the variable contains user input, this is '
                . 'Remote Code Execution.',
            'solution'    => 'Never pass user input to shell functions. If unavoidable, use escapeshellarg().',
            'steps'       => [
                'Add escapeshellarg() around any variable: exec(\'cmd \' . escapeshellarg($arg))',
                'Prefer PHP native functions over shelling out whenever possible.',
            ],
        ],

        'unserialize_usage' => [
            'pattern'     => '/\bunserialize\s*\(\s*(?!\s*\')/m',
            'name'        => 'Insecure Deserialization: unserialize()',
            'severity'    => 'high',
            'description' => 'unserialize() on untrusted data can lead to Remote Code Execution '
                . 'via PHP Object Injection if the codebase has gadget chains.',
            'solution'    => 'Use json_decode() instead of unserialize() for user-controlled data.',
            'steps'       => [
                'Replace unserialize() with json_decode().',
                'If you must use unserialize(), add: unserialize($data, [\'allowed_classes\' => false])',
            ],
        ],

        // ── Open Redirect ─────────────────────────────────────────────────────

        'open_redirect' => [
            'pattern'     => '/redirect\s*\(\s*\$(?:request->|_GET|_POST|_REQUEST)/m',
            'name'        => 'Open Redirect: User-Controlled Redirect Target',
            'severity'    => 'medium',
            'description' => 'redirect() is called with a user-controlled URL. Attackers can redirect '
                . 'victims to phishing pages by crafting a URL like: '
                . 'https://yoursite.com/redirect?url=https://evil.com',
            'solution'    => 'Validate redirect targets against a whitelist of allowed URLs.',
            'steps'       => [
                'Whitelist allowed redirect URLs or use named routes.',
                'Validate: if(!str_starts_with($url, config(\'app.url\'))) abort(400)',
                'Use route(\'name\') instead of redirect($request->input(\'url\'))',
            ],
        ],

        // ── Hardcoded Secrets ─────────────────────────────────────────────────

        'hardcoded_secret' => [
            'pattern'     => '/(?:password|secret|api_key|apikey|access_token)\s*=\s*["\'][^"\']{8,}["\']/im',
            'name'        => 'Hardcoded Credential or Secret',
            'severity'    => 'critical',
            'description' => 'A credential or secret appears to be hardcoded in source code. '
                . 'Anyone with repo access can see these values.',
            'solution'    => 'Move secrets to .env and access via env() or config().',
            'steps'       => [
                'Move the value to .env: SECRET_KEY=your_value',
                'Access via: config(\'app.secret\') or env(\'SECRET_KEY\')',
                'Rotate the exposed credential immediately.',
            ],
        ],

        // ── CSRF ─────────────────────────────────────────────────────────────

        'csrf_excluded' => [
            'pattern'     => '/->withoutMiddleware\s*\(\s*\[?\s*[^)]*VerifyCsrfToken/m',
            'name'        => 'CSRF Protection Disabled on Route',
            'severity'    => 'high',
            'description' => 'A route has CSRF verification explicitly disabled via withoutMiddleware. '
                . 'This allows Cross-Site Request Forgery attacks against this endpoint.',
            'solution'    => 'Remove withoutMiddleware(VerifyCsrfToken) unless this is an intentional '
                . 'webhook endpoint that verifies via signature instead.',
            'steps'       => [
                'Remove ->withoutMiddleware([VerifyCsrfToken::class])',
                'For webhooks: verify the payload signature instead of using CSRF tokens.',
            ],
        ],

        // ── Debug/Info Exposure ────────────────────────────────────────────────

        'dd_in_code' => [
            'pattern'     => '/\bdd\s*\(/m',
            'name'        => 'Debug Code Left in Production: dd()',
            'severity'    => 'medium',
            'description' => 'dd() (dump and die) is present in code. If this executes in production, '
                . 'it will dump application internals to the browser.',
            'solution'    => 'Remove all dd() calls before deploying to production.',
            'steps'       => ['Remove dd() call or gate behind: if(app()->environment(\'local\')) dd($var)'],
        ],

        'var_dump_in_code' => [
            'pattern'     => '/\bvar_dump\s*\(/m',
            'name'        => 'Debug Code Left in Production: var_dump()',
            'severity'    => 'low',
            'description' => 'var_dump() is present in code and may output sensitive data.',
            'solution'    => 'Remove all var_dump() calls.',
            'steps'       => ['Remove var_dump() calls from production code.'],
        ],
    ];

    /**
     * Directories to exclude from scanning.
     */
    private array $excludeDirs = [
        'vendor',
        'node_modules',
        '.git',
        'storage',
        'bootstrap/cache',
        'public/build',
    ];

    /**
     * Scan a directory recursively.
     *
     * @param string $directory  Absolute path to scan (e.g. app_path(), base_path())
     * @param array  $extensions File extensions to scan
     * @return array             Array of findings
     */
    public function scan(string $directory, array $extensions = ['php']): array
    {
        $findings = [];

        if (!is_dir($directory)) {
            Log::warning("StaticCodeScanner: directory not found: {$directory}");
            return [];
        }

        $files = $this->getFiles($directory, $extensions);

        foreach ($files as $file) {
            try {
                $content  = file_get_contents($file);
                $relative = ltrim(str_replace(base_path(), '', $file), '/');

                foreach ($this->rules as $ruleId => $rule) {
                    if (preg_match_all($rule['pattern'], $content, $matches, PREG_OFFSET_CAPTURE)) {
                        foreach ($matches[0] as [$match, $offset]) {
                            $line    = substr_count(substr($content, 0, $offset), "\n") + 1;
                            $snippet = trim($match);

                            // Skip if this looks like a comment or test file
                            if ($this->isInComment($content, $offset)) continue;

                            $findings[] = [
                                'name'        => $rule['name'],
                                'url'         => "file://{$relative}:{$line}",
                                'severity'    => $rule['severity'],
                                'description' => $rule['description'],
                                'solution'    => $rule['solution'],
                                'steps'       => $rule['steps'],
                                'cve'         => null,
                                'evidence'    => "In {$relative} on line {$line}: " . mb_substr($snippet, 0, 200),
                                'method'      => 'STATIC',
                                'parameter'   => "{$relative}:{$line}",
                                'source'      => 'static_scanner',
                                'rule_id'     => $ruleId,
                            ];
                        }
                    }
                }
            } catch (\Throwable $e) {
                Log::debug("StaticCodeScanner: failed to read {$file}: " . $e->getMessage());
            }
        }

        Log::info("StaticCodeScanner: scanned " . count($files) . " files, found " . count($findings) . " issues");

        return $findings;
    }

    // ─────────────────────────────────────────────────────────────

    /**
     * Recursively get all matching files, excluding unwanted directories.
     */
    private function getFiles(string $directory, array $extensions): array
    {
        $files = [];

        try {
            $iterator = new \RecursiveIteratorIterator(
                new \RecursiveDirectoryIterator($directory, \RecursiveDirectoryIterator::SKIP_DOTS),
                \RecursiveIteratorIterator::LEAVES_ONLY
            );

            foreach ($iterator as $file) {
                $path = $file->getPathname();

                // Skip excluded directories
                foreach ($this->excludeDirs as $excluded) {
                    if (str_contains($path, DIRECTORY_SEPARATOR . $excluded . DIRECTORY_SEPARATOR)) {
                        continue 2;
                    }
                }

                if (!in_array($file->getExtension(), $extensions, true)) continue;

                $files[] = $path;
            }
        } catch (\Throwable $e) {
            Log::warning("StaticCodeScanner getFiles failed: " . $e->getMessage());
        }

        return $files;
    }

    /**
     * Check if a match offset is inside a PHP comment.
     * Prevents false positives from commented-out code.
     */
    private function isInComment(string $content, int $offset): bool
    {
        // Get the line the match is on
        $lineStart = strrpos(substr($content, 0, $offset), "\n");
        $lineStart = $lineStart === false ? 0 : $lineStart + 1;
        $line      = substr($content, $lineStart, $offset - $lineStart);

        // Single-line comment
        if (preg_match('~^\s*//~', $line)) return true;
        if (preg_match('~^\s*\*~', $line)) return true; // inside /** */

        return false;
    }
}
