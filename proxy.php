<?php
// ==================================================
// PHP CORS-ANYWHERE + HLS/VIDEO STREAMING PROXY
// Работает как secure-ridge (CORS прокси)
// + проксирует M3U8, TS, MP4 с Range поддержкой
// ==================================================

// Отключаем ограничения
set_time_limit(0);
ini_set('memory_limit', '512M');

// ========== ОБРАБОТКА CORS-ЗАПРОСОВ (как в оригинале) ==========
function send_help() {
    header('Content-Type: text/plain');
    echo "This API enables cross-origin requests to anywhere.\n\n";
    echo "Usage:\n";
    echo "/               Shows help\n";
    echo "/iscorsneeded   This resource is served without CORS headers\n";
    echo "/<url>          Create a request to <url>, includes CORS headers\n\n";
    echo "Supports HLS (.m3u8, .ts) and video streaming with Range requests.\n";
    exit;
}

function send_cors_headers() {
    header('Access-Control-Allow-Origin: *');
    header('Access-Control-Allow-Methods: GET, POST, PUT, DELETE, PATCH, OPTIONS');
    header('Access-Control-Allow-Headers: Origin, X-Requested-With, Content-Type, Accept, Range');
    header('Access-Control-Expose-Headers: X-Request-URL, X-Final-URL, X-CORS-Redirect-*, Content-Range, Accept-Ranges');
}

// Обработка preflight (OPTIONS)
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    send_cors_headers();
    exit;
}

// Получаем путь запроса
$request_uri = parse_url($_SERVER['REQUEST_URI'], PHP_URL_PATH);
$request_uri = rtrim($request_uri, '/');

// Корень — справка
if ($request_uri === '' || $request_uri === '/') {
    send_help();
    exit;
}

// /iscorsneeded — без CORS (как в оригинале)
if ($request_uri === '/iscorsneeded') {
    echo "CORS not needed here.";
    exit;
}

// Извлекаем URL из запроса: /https://example.com или /http://example.com
$target_url = substr($request_uri, 1);
if (empty($target_url)) {
    http_response_code(400);
    echo "Missing URL parameter";
    exit;
}

// Если протокол не указан, ставим http (как в оригинале)
if (!preg_match('/^https?:\/\//i', $target_url)) {
    $target_url = 'http://' . $target_url;
}

// Проверяем обязательные заголовки (как в оригинале)
if (!isset($_SERVER['HTTP_ORIGIN']) && !isset($_SERVER['HTTP_X_REQUESTED_WITH'])) {
    http_response_code(403);
    echo "Forbidden: Missing Origin or X-Requested-With header";
    exit;
}

// Добавляем CORS заголовки к ответу
send_cors_headers();

// ========== ОПРЕДЕЛЯЕМ ТИП КОНТЕНТА И ВЫБИРАЕМ РЕЖИМ ==========
$ext = strtolower(pathinfo(parse_url($target_url, PHP_URL_PATH), PATHINFO_EXTENSION));

// --- РЕЖИМ 1: HLS плейлист (M3U8) ---
if ($ext === 'm3u8') {
    $m3u8_content = @file_get_contents($target_url);
    if ($m3u8_content === false) {
        http_response_code(502);
        echo "Failed to fetch M3U8";
        exit;
    }
    
    $base_url = dirname($target_url) . '/';
    $script_url = (isset($_SERVER['HTTPS']) ? 'https://' : 'http://') . $_SERVER['HTTP_HOST'] . $_SERVER['SCRIPT_NAME'];
    
    $lines = explode("\n", $m3u8_content);
    foreach ($lines as &$line) {
        $line = rtrim($line);
        if (empty($line) || $line[0] === '#') continue;
        
        // Пропускаем строки с EXT-тегами (они уже обработаны условием выше)
        if (strpos($line, '#') === 0) continue;
        
        // Преобразуем относительные пути в абсолютные
        if (strpos($line, 'http') !== 0) {
            $line = $base_url . $line;
        }
        
        // Заменяем на проксированный URL
        $line = $script_url . '/' . urlencode($line);
    }
    
    header('Content-Type: application/vnd.apple.mpegurl');
    header('Cache-Control: no-cache');
    echo implode("\n", $lines);
    exit;
}

// --- РЕЖИМ 2: TS фрагмент (HLS сегмент) ---
if ($ext === 'ts') {
    header('Content-Type: video/MP2T');
    header('Cache-Control: no-cache');
    
    $fp = @fopen($target_url, 'rb');
    if ($fp === false) {
        http_response_code(502);
        echo "Failed to fetch TS segment";
        exit;
    }
    fpassthru($fp);
    fclose($fp);
    exit;
}

// --- РЕЖИМ 3: Видеофайлы с поддержкой Range (MP4, WebM, MKV, AVI) ---
$video_exts = ['mp4', 'webm', 'mkv', 'avi', 'mov', 'flv'];
if (in_array($ext, $video_exts)) {
    // Получаем заголовки от источника
    $head = @get_headers($target_url, 1);
    if (!$head || strpos($head[0], '200') === false) {
        http_response_code(502);
        echo "Failed to fetch video file";
        exit;
    }
    
    $file_size = isset($head['Content-Length']) ? $head['Content-Length'] : 0;
    
    // Обработка Range запроса
    if (isset($_SERVER['HTTP_RANGE'])) {
        preg_match('/bytes=(\d+)-(\d*)/', $_SERVER['HTTP_RANGE'], $matches);
        $start = (int)$matches[1];
        $end = isset($matches[2]) && $matches[2] !== '' ? (int)$matches[2] : $file_size - 1;
        $length = $end - $start + 1;
        
        header('HTTP/1.1 206 Partial Content');
        header("Content-Range: bytes $start-$end/$file_size");
        header("Content-Length: $length");
        header('Accept-Ranges: bytes');
        
        $ch = curl_init();
        curl_setopt($ch, CURLOPT_URL, $target_url);
        curl_setopt($ch, CURLOPT_RANGE, "$start-$end");
        curl_setopt($ch, CURLOPT_RETURNTRANSFER, false);
        curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
        curl_exec($ch);
        curl_close($ch);
    } else {
        header('HTTP/1.1 200 OK');
        header("Content-Length: $file_size");
        header('Accept-Ranges: bytes');
        header('Content-Type: ' . get_video_mime($ext));
        
        readfile($target_url);
    }
    exit;
}

// --- РЕЖИМ 4: Обычный CORS-прокси (как оригинальный secure-ridge) ---
// Отслеживаем редиректы
$redirects = [];
$redirect_count = 0;

$ch = curl_init();
curl_setopt($ch, CURLOPT_URL, $target_url);
curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
curl_setopt($ch, CURLOPT_FOLLOWLOCATION, true);
curl_setopt($ch, CURLOPT_MAXREDIRS, 5);
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_HEADERFUNCTION, function($curl, $header_line) use (&$redirects, &$redirect_count, $target_url) {
    if (stripos($header_line, 'Location:') !== false) {
        $redirect_count++;
        preg_match('/Location: (.*)/i', $header_line, $matches);
        if (isset($matches[1])) {
            $redirects["X-CORS-Redirect-$redirect_count"] = trim($matches[1]);
        }
    }
    return strlen($header_line);
});

// Отключаем куки (как в оригинале)
curl_setopt($ch, CURLOPT_COOKIEFILE, '');
curl_setopt($ch, CURLOPT_COOKIEJAR, '');

// Копируем метод запроса
$method = $_SERVER['REQUEST_METHOD'];
curl_setopt($ch, CURLOPT_CUSTOMREQUEST, $method);

// Для POST/PUT/PATCH передаём тело
if (in_array($method, ['POST', 'PUT', 'PATCH'])) {
    curl_setopt($ch, CURLOPT_POSTFIELDS, file_get_contents('php://input'));
}

// Копируем заголовки (кроме Host и Connection)
$headers = [];
foreach ($_SERVER as $name => $value) {
    if (strpos($name, 'HTTP_') === 0 && $name !== 'HTTP_HOST' && $name !== 'HTTP_CONNECTION') {
        $header_name = str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))));
        $headers[] = "$header_name: $value";
    }
}
if (!empty($headers)) {
    curl_setopt($ch, CURLOPT_HTTPHEADER, $headers);
}

$response = curl_exec($ch);
$info = curl_getinfo($ch);
$http_code = curl_getinfo($ch, CURLINFO_HTTP_CODE);
curl_close($ch);

// Добавляем заголовки как в оригинале
header("X-Request-URL: $target_url");
if (isset($info['url'])) {
    header("X-Final-URL: " . $info['url']);
}
foreach ($redirects as $name => $value) {
    header("$name: $value");
}

http_response_code($http_code);
echo $response;
exit;

function get_video_mime($ext) {
    $mimes = [
        'mp4' => 'video/mp4',
        'webm' => 'video/webm',
        'mkv' => 'video/x-matroska',
        'avi' => 'video/x-msvideo',
        'mov' => 'video/quicktime',
        'flv' => 'video/x-flv'
    ];
    return $mimes[$ext] ?? 'application/octet-stream';
}
?>
