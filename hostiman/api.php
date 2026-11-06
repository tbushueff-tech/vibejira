<?php
/**
 * Helper by bushueff — HostiMan PHP API relay (PHP 7.4+).
 *
 * Upload this file as public_html/api.php. It is NOT an independent
 * database/backend: HostiMan must be able to reach the Cloudflare Worker.
 * Example: /api.php?route=%2Fauth%2Fme
 */
declare(strict_types=1);

const HELPER_ORIGIN = 'https://tbushueff-tech.github.io';
const HELPER_UPSTREAM = 'https://vibejira.t-bushueff.workers.dev';

// Only the existing Helper endpoints can be relayed. No arbitrary URL proxy.
$routes = [
    '/auth/register' => ['POST'],
    '/auth/login' => ['POST'],
    '/auth/me' => ['GET'],
    '/auth/logout' => ['POST'],
    '/auth/password' => ['POST'],
    '/auth/profile' => ['POST'],
    '/auth/crypto' => ['POST'],
    '/' => ['GET', 'POST'],
];

function reply(int $status, array $payload): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
}

$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin === HELPER_ORIGIN) {
    header('Access-Control-Allow-Origin: ' . HELPER_ORIGIN);
    header('Vary: Origin');
    header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
    header('Access-Control-Allow-Headers: Authorization, Content-Type, X-Buffer-Key');
    header('Access-Control-Max-Age: 86400');
}
header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');

if ($origin !== '' && $origin !== HELPER_ORIGIN) {
    reply(403, ['ok' => false, 'error' => 'Origin not allowed']);
    exit;
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'OPTIONS') {
    reply($origin === HELPER_ORIGIN ? 204 : 403, []);
    exit;
}
if ($method !== 'GET' && $method !== 'POST') {
    reply(405, ['ok' => false, 'error' => 'Method not allowed']);
    exit;
}

$route = $_GET['route'] ?? '/';
if (!is_string($route) || !array_key_exists($route, $routes)
    || !in_array($method, $routes[$route], true)) {
    reply(404, ['ok' => false, 'error' => 'Unknown API route']);
    exit;
}
// Keep a local health check independent of Cloudflare.
if (!function_exists('curl_init')) {
    reply(503, ['ok' => false, 'error' => 'PHP cURL extension is not available']);
    exit;
}

$headers = [
    'Accept: application/json',
    'Cache-Control: no-store',
];
// Pass through the caller's validated Origin. Worker requires it for POST auth.
if ($origin !== '') $headers[] = 'Origin: ' . $origin;
if (isset($_SERVER['HTTP_AUTHORIZATION'])) {
    $headers[] = 'Authorization: ' . $_SERVER['HTTP_AUTHORIZATION'];
} elseif (isset($_SERVER['REDIRECT_HTTP_AUTHORIZATION'])) {
    $headers[] = 'Authorization: ' . $_SERVER['REDIRECT_HTTP_AUTHORIZATION'];
}
if (isset($_SERVER['HTTP_X_BUFFER_KEY'])) {
    $headers[] = 'X-Buffer-Key: ' . $_SERVER['HTTP_X_BUFFER_KEY'];
}
if (isset($_SERVER['CONTENT_TYPE'])) {
    $headers[] = 'Content-Type: ' . $_SERVER['CONTENT_TYPE'];
}
if ($method === 'POST' && $origin !== HELPER_ORIGIN) {
    reply(403, ['ok' => false, 'error' => 'Origin not allowed']);
    exit;
}
$body = '';
if ($method === 'POST') {
    $body = file_get_contents('php://input', false, null, 0, 262145);
    if ($body === false || strlen($body) > 262144) {
        reply(413, ['ok' => false, 'error' => 'Request too large']);
        exit;
    }
}

$upstream = HELPER_UPSTREAM . $route;
$ch = curl_init($upstream);
curl_setopt_array($ch, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CUSTOMREQUEST => $method,
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_CONNECTTIMEOUT => 6,
    CURLOPT_TIMEOUT => 18,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_MAXREDIRS => 0,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
    CURLOPT_USERAGENT => 'Helper-HostiMan-Relay/1.0',
]);
if ($method === 'POST') curl_setopt($ch, CURLOPT_POSTFIELDS, $body);
$result = curl_exec($ch);
$status = (int) curl_getinfo($ch, CURLINFO_HTTP_CODE);
$curlError = curl_error($ch);
curl_close($ch);

if ($result === false || $status < 100) {
    // Do not surface detailed internal connectivity or credentials to browsers.
    error_log('Helper relay upstream unavailable: ' . $curlError);
    reply(502, ['ok' => false, 'error' => 'Upstream API temporarily unavailable']);
    exit;
}
http_response_code($status);
header('Content-Type: application/json; charset=utf-8');
echo $result;
