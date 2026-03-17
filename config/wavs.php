<?php

/**
 * WAVS Scanner Configuration
 * All scanner behaviour is controlled here. Override in .env.
 * No hardcoded values anywhere in the scanner — everything flows from here.
 */

return [

    // ── HTTP Client ───────────────────────────────────────────────────────

    'user_agent' => env('WAVS_USER_AGENT', 'VulnSight/1.0 (security scanner; contact security@yourcompany.com)'),
    'connect_timeout' => (int) env('WAVS_CONNECT_TIMEOUT', 10),
    'max_redirects' => (int) env('WAVS_MAX_REDIRECTS', 5),
    'verify_ssl' => (bool) env('WAVS_VERIFY_SSL', false),
    'max_response_body' => (int) env('WAVS_MAX_RESPONSE_BODY', 200000),
    'max_evidence_body' => (int) env('WAVS_MAX_EVIDENCE_BODY', 5000),

    // ── Open Redirect ─────────────────────────────────────────────────────

    // .invalid is an IANA-reserved TLD — free, no purchase, never resolves to a real site
    'canary_domain' => env('WAVS_CANARY_DOMAIN', 'https://wavs-canary.invalid'),

    // ── XSS ──────────────────────────────────────────────────────────────

    // Unique string embedded in XSS payloads to confirm reflection
    // Change this in .env so it is unique to your installation
    'xss_marker' => env('WAVS_XSS_MARKER', 'WAVS_XSS_PROBE_7x9k'),

    // ── CSRF ─────────────────────────────────────────────────────────────

    // Simulated attacker origin for CSRF testing
    'csrf_evil_origin' => env('WAVS_CSRF_EVIL_ORIGIN', 'https://csrf-test.invalid'),

    // ── SQL Injection Timing ──────────────────────────────────────────────

    // Seconds the DB sleeps when a time-based payload is injected
    'time_delay_seconds' => (int) env('WAVS_TIME_DELAY', 3),

    // Minimum response time (seconds) to flag as a time-based blind SQLi hit
    // Must be less than time_delay_seconds to account for network jitter
    'time_threshold_seconds' => (float) env('WAVS_TIME_THRESHOLD', 2.5),

    // ── IDOR Detection ────────────────────────────────────────────────────

    // Minimum byte difference between baseline and test response to flag
    'idor_min_diff_bytes' => (int) env('WAVS_IDOR_MIN_DIFF', 150),

    // Maximum content similarity (0.0–1.0) before flagging as different resource
    // 0.85 = responses must be less than 85% similar to flag
    'idor_max_similarity' => (float) env('WAVS_IDOR_MAX_SIMILARITY', 0.85),

    // ── CVSS Score → Severity Mapping ────────────────────────────────────
    //
    // These control how a numeric CVSS score maps to a severity label.
    // Findings are labelled based on which band their score falls into:
    //
    //   score >= WAVS_CVSS_CRITICAL  → critical
    //   score >= WAVS_CVSS_HIGH      → high
    //   score >= WAVS_CVSS_MEDIUM    → medium
    //   score >= WAVS_CVSS_LOW       → low
    //
    // Defaults follow the official CVSS v3.1 severity rating scale:
    //   Critical: 9.0–10.0
    //   High:     7.0–8.9
    //   Medium:   4.0–6.9
    //   Low:      0.1–3.9
    //
    // Raise thresholds to be stricter (fewer findings flagged as critical/high).
    // Lower thresholds to be more sensitive.

    'cvss_critical' => (int) env('WAVS_CVSS_CRITICAL', 90),  // 9.0 × 10
    'cvss_high' => (int) env('WAVS_CVSS_HIGH', 70),      // 7.0 × 10
    'cvss_medium' => (int) env('WAVS_CVSS_MEDIUM', 40),    // 4.0 × 10
    'cvss_low' => (int) env('WAVS_CVSS_LOW', 0),        // 0.1 × 10

    // ── Production Guard ──────────────────────────────────────────────────

    // Prevents the CLI scanner from running against production-looking URLs
    // Never set to true in CI environments
    'allow_prod' => (bool) env('WAVS_ALLOW_PROD', false),

];
