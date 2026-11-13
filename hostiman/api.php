<?php
declare(strict_types=1);

// Deploy as https://tbhelper.h1n.ru/api.php on PHP 7.4+ with cURL.
const HELPER_SITE_ORIGIN = 'https://tbushueff-tech.github.io';
const HELPER_WORKER = 'https://vibejira.t-bushueff.workers.dev';

function jsonError(int $status, string $message): void {
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['ok' => false, 'error' => $message], JSON_UNESCAPED_UNICODE);
    exit;
}

header('Cache-Control: no-store, private');
header('X-Content-Type-Options: nosniff');
$origin = $_SERVER['HTTP_ORIGIN'] ?? '';
if ($origin !== '' && $origin !== HELPER_SITE_ORIGIN) jsonError(403, 'Origin not allowed');
if ($origin === HELPER_SITE_ORIGIN) {
    header('Access-Control-Allow-Origin: ' . HELPER_SITE_ORIGIN);
    header('Vary: Origin');
    header('Access-Control-Allow-Methods: GET, POST, DELETE, OPTIONS');
    header('Access-Control-Allow-Headers: Accept, Authorization, Content-Type');
    header('Access-Control-Max-Age: 3600');
}

$method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
if ($method === 'OPTIONS') {
    http_response_code($origin === HELPER_SITE_ORIGIN ? 204 : 403);
    exit;
}

$authPaths = [
    '/auth/login' => ['POST'],
    '/auth/register' => ['POST'],
    '/auth/me' => ['GET'],
    '/auth/logout' => ['POST'],
    '/auth/crypto' => ['POST'],
    '/auth/password' => ['POST'],
    '/auth/profile' => ['POST'],
    '/' => ['GET', 'POST'],
    '/library' => ['GET', 'POST'],
];
$route = $_GET['route'] ?? '';
if (!is_string($route)) jsonError(404, 'Unknown API route');
$allowed = isset($authPaths[$route]) && in_array($method, $authPaths[$route], true);
if (!$allowed && preg_match('~^/library/[A-Za-z0-9._~-]{1,150}$~D', $route)) {
    $allowed = in_array($method, ['GET', 'DELETE'], true);
}
if (!$allowed) jsonError(404, 'Unknown API route');

$query = [];
foreach (['meta', 'chunk', 'cursor', 'revision'] as $key) {
    if (!isset($_GET[$key])) continue;
    if (!is_string($_GET[$key]) || strlen($_GET[$key]) > 512) jsonError(400, 'Invalid query');
    $query[$key] = $_GET[$key];
}
if (isset($query['chunk']) && !ctype_digit($query['chunk'])) jsonError(400, 'Invalid chunk');
if (isset($query['revision']) && !ctype_digit($query['revision'])) jsonError(400, 'Invalid revision');

if ($method === 'POST' && $origin !== HELPER_SITE_ORIGIN) jsonError(403, 'Origin not allowed');
if (!function_exists('curl_init')) jsonError(503, 'PHP cURL extension required');
$headers = ['Accept: application/json', 'Cache-Control: no-store'];
if ($origin !== '') $headers[] = 'Origin: ' . $origin;
$authorization = $_SERVER['HTTP_AUTHORIZATION'] ?? $_SERVER['REDIRECT_HTTP_AUTHORIZATION'] ?? '';
if ($authorization !== '') $headers[] = 'Authorization: ' . $authorization;
$body = null;
if ($method === 'POST') {
    $body = file_get_contents('php://input', false, null, 0, 262145);
    if ($body === false || strlen($body) > 262144) jsonError(413, 'Request too large');
    $headers[] = 'Content-Type: text/plain;charset=UTF-8';
}
$url = HELPER_WORKER . $route . ($query ? '?' . http_build_query($query, '', '&', PHP_QUERY_RFC3986) : '');
$curl = curl_init($url);
curl_setopt_array($curl, [
    CURLOPT_RETURNTRANSFER => true,
    CURLOPT_CUSTOMREQUEST => $method,
    CURLOPT_HTTPHEADER => $headers,
    CURLOPT_CONNECTTIMEOUT => 10,
    CURLOPT_TIMEOUT => $method === 'POST' ? 105 : 50,
    CURLOPT_FOLLOWLOCATION => false,
    CURLOPT_SSL_VERIFYPEER => true,
    CURLOPT_SSL_VERIFYHOST => 2,
    CURLOPT_USERAGENT => 'JiraHelper-Explicit-RU-Relay/2.0',
]);
if ($body !== null) curl_setopt($curl, CURLOPT_POSTFIELDS, $body);
$response = curl_exec($curl);
$status = (int) curl_getinfo($curl, CURLINFO_HTTP_CODE);
$error = curl_error($curl);
curl_close($curl);
if ($response === false || $status < 100 || $status > 599) {
    error_log('Helper upstream unavailable: ' . $error);
    jsonError(502, 'Upstream API unavailable');
}
http_response_code($status);
header('Content-Type: application/json; charset=utf-8');
echo $response;
