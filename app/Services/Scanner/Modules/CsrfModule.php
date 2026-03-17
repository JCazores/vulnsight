<?php

namespace App\Services\Modules;

use App\Models\DiscoveredUrl;

class CsrfModule extends BaseModule
{
    public function name(): string
    {
        return 'csrf';
    }

    public function run(DiscoveredUrl $discoveredUrl): void
    {
        $forms = $discoveredUrl->forms ?? [];

        foreach ($forms as $form) {
            if (!$this->isRunning())
                return;
            if ($form['method'] !== 'POST')
                continue;
            $this->testForm($discoveredUrl, $form);
        }
    }

    private function testForm(DiscoveredUrl $discoveredUrl, array $form): void
    {
        $fields = $form['fields'] ?? [];
        $fieldNames = array_column($fields, 'name');

        // Check if the form has a CSRF token field
        $hasCsrfField = false;
        foreach ($fieldNames as $name) {
            if (preg_match('/csrf|_token|xsrf|nonce/i', $name)) {
                $hasCsrfField = true;
                break;
            }
        }

        if ($hasCsrfField)
            return; // CSRF token present — not vulnerable

        // Try submitting the form WITHOUT a CSRF token from a different origin
        $data = [];
        foreach ($fields as $field) {
            $data[$field['name']] = $field['value'] ?: 'test';
        }

        // Send with a wrong Referer header to simulate cross-origin request
        $result = $this->http->send(
            'POST',
            $form['action'],
            [
                'form_params' => $data,
                'headers' => [
                    'Referer' => 'https://evil.com/csrf-attack',
                    'Origin' => 'https://evil.com',
                ],
            ],
            'csrf',
            'no_token'
        );

        if (!$result)
            return;

        // If the server accepted the request (2xx or 3xx redirect) without a CSRF token → vulnerable
        if ($result['status'] < 400) {
            $this->report(
                discoveredUrl: $discoveredUrl,
                type: 'csrf',
                name: 'Cross-Site Request Forgery (CSRF)',
                severity: 'medium',
                url: $form['action'],
                method: 'POST',
                parameter: '_token',
                payload: 'No CSRF token submitted; Origin: https://evil.com',
                evidence: "Form at {$form['action']} accepted a POST request with no CSRF token and a forged Origin header. Server responded: HTTP {$result['status']}",
                requestRaw: $this->buildRequestRaw('POST', $form['action'], $data, [
                    'Referer' => 'https://evil.com/csrf-attack',
                    'Origin' => 'https://evil.com',
                ]),
                responseRaw: substr($result['body'], 0, 1000),
                description: "The form at {$form['action']} does not require a CSRF synchronizer token and accepted a forged cross-origin POST request. An attacker can trick authenticated users into submitting this form from their site.",
                recommendation: "Add Laravel's @csrf Blade directive to all forms. Verify the X-CSRF-TOKEN on all state-changing requests. Set SameSite=Lax (or Strict) on session cookies.",
                owasp: 'https://owasp.org/www-community/attacks/csrf',
                cvss: 60,
            );
        }
    }
}
