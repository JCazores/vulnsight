<?php

if (!function_exists('csp_nonce')) {
    /**
     * Return the current request's CSP nonce.
     * Set by App\Http\Middleware\SecurityHeaders on every request.
     */
    function csp_nonce(): string
    {
        return app()->has('csp-nonce') ? app('csp-nonce') : '';
    }
}
