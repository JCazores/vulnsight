<?php

return [
    'bridge_secret' => env('UPTIMEBOT_BRIDGE_SECRET', ''),
    'admin_email'   => env('VULNSIGHT_ADMIN_EMAIL', ''),
    'proxy_base'    => env('VULNSIGHT_PROXY_BASE', 'http://localhost:8000/vulnsight'),
    'url'           => env('VULNSIGHT_URL', 'http://localhost:8001'),
];
