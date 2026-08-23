<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli') {
    http_response_code(404);
    exit;
}
if (!class_exists('ZipArchive')) throw new RuntimeException('ZipArchive is required.');

$root = dirname(__DIR__);
$manifest = json_decode((string)file_get_contents($root . '/plugin.json'), true, 512, JSON_THROW_ON_ERROR);
$name = (string)($manifest['name'] ?? '');
$version = (string)($manifest['version'] ?? '');
if ($name !== 'smtp-jyavani' || preg_match('/\A\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?\z/', $version) !== 1) {
    throw new RuntimeException('Invalid plugin identity or version.');
}

$output = (string)($argv[1] ?? (sys_get_temp_dir() . '/smtp-jyavani-' . $version . '.zip'));
if (!str_ends_with(strtolower($output), '.zip')) throw new RuntimeException('Output must use the .zip extension.');
$parent = realpath(dirname($output));
if ($parent === false || !is_dir($parent) || !is_writable($parent)) throw new RuntimeException('Output directory is not writable.');
$output = $parent . DIRECTORY_SEPARATOR . basename($output);
$rootReal = realpath($root);
if ($rootReal === false || $output === $rootReal || str_starts_with($output, $rootReal . DIRECTORY_SEPARATOR)) {
    throw new RuntimeException('Output must be outside the source repository.');
}
if (file_exists($output) || is_link($output)) throw new RuntimeException('Output already exists.');
$temporary = $output . '.tmp-' . bin2hex(random_bytes(5));
register_shutdown_function(static function () use ($temporary): void {
    if (is_file($temporary) || is_link($temporary)) unlink($temporary);
});

$packageFiles = [
    'CHANGELOG.md', 'LICENSE', 'README.md', 'icon.svg', 'plugin.json', 'plugin.php',
    'admin/save.php', 'admin/settings.php', 'assets/css/admin.css',
    'includes/config.php', 'includes/smtp-client.php', 'languages/de.php', 'languages/id.php',
];
$files = [];
foreach ($packageFiles as $relative) {
    $path = $root . '/' . $relative;
    if (str_contains($relative, '\\') || str_contains($relative, "\0") || str_starts_with($relative, '/')
        || in_array('.', explode('/', $relative), true) || in_array('..', explode('/', $relative), true)) {
        throw new RuntimeException('Unsafe package path: ' . $relative);
    }
    if (!is_file($path) || is_link($path)) throw new RuntimeException('Required package file is missing or unsafe: ' . $relative);
    $files[$relative] = $path;
}
ksort($files, SORT_STRING);
foreach ($manifest['admin']['pages'] ?? [] as $page) {
    if (!isset($files[(string)($page['file'] ?? '')])) throw new RuntimeException('Manifest route file is not packaged.');
}
if (!isset($files[(string)($manifest['icon'] ?? '')])) throw new RuntimeException('Manifest icon is not packaged.');
foreach ($manifest['static']['copy'] ?? [] as $copy) {
    if (!isset($files[(string)($copy['from'] ?? '')])) throw new RuntimeException('Manifest static source is not packaged.');
}

$zip = new ZipArchive();
if ($zip->open($temporary, ZipArchive::CREATE | ZipArchive::EXCL) !== true) throw new RuntimeException('Unable to create package.');
foreach ($files as $relative => $path) {
    if (!$zip->addFile($path, $relative)) throw new RuntimeException('Unable to add ' . $relative);
}
if (!$zip->close()) throw new RuntimeException('Unable to finalize package.');

$verify = new ZipArchive();
if ($verify->open($temporary) !== true) throw new RuntimeException('Unable to reopen package.');
$seen = [];
for ($index = 0; $index < $verify->numFiles; $index++) {
    $entry = (string)$verify->getNameIndex($index);
    if ($entry === '' || isset($seen[$entry]) || str_starts_with($entry, '/') || str_contains($entry, '\\') || str_contains($entry, "\0")
        || in_array('.', explode('/', $entry), true) || in_array('..', explode('/', $entry), true)) {
        throw new RuntimeException('Unsafe or duplicate package entry.');
    }
    $seen[$entry] = true;
}
$embedded = json_decode((string)$verify->getFromName('plugin.json'), true, 512, JSON_THROW_ON_ERROR);
$verify->close();
if (($embedded['name'] ?? '') !== $name || ($embedded['version'] ?? '') !== $version) throw new RuntimeException('Embedded manifest mismatch.');

if (!rename($temporary, $output)) throw new RuntimeException('Unable to publish candidate atomically.');
echo json_encode([
    'path' => $output,
    'version' => $version,
    'entries' => count($files),
    'bytes' => filesize($output),
    'sha256' => hash_file('sha256', $output),
], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), PHP_EOL;
