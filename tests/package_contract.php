<?php
declare(strict_types=1);

if (!class_exists('ZipArchive')) throw new RuntimeException('ZipArchive is required.');
$root = dirname(__DIR__);
$manifest = json_decode((string)file_get_contents($root . '/plugin.json'), true, 512, JSON_THROW_ON_ERROR);
$zipPath = $argv[1] ?? '';
if (!is_string($zipPath) || $zipPath === '' || !is_file($zipPath)) throw new RuntimeException('Pass the built package path.');
$zip = new ZipArchive();
if ($zip->open($zipPath) !== true) throw new RuntimeException('Unable to open package.');
$entries = [];
for ($index = 0; $index < $zip->numFiles; $index++) {
    $entry = (string)$zip->getNameIndex($index);
    if ($entry === '' || isset($entries[$entry]) || str_starts_with($entry, '/') || str_contains($entry, '\\') || str_contains($entry, "\0")
        || in_array('.', explode('/', $entry), true) || in_array('..', explode('/', $entry), true)) {
        throw new RuntimeException('Unsafe or duplicate package entry: ' . $entry);
    }
    if (str_starts_with($entry, 'tests/') || str_starts_with($entry, 'tools/') || str_starts_with($entry, '.git') || $entry === 'AGENTS.md') {
        throw new RuntimeException('Development-only entry was packaged: ' . $entry);
    }
    $entries[$entry] = true;
}
$embedded = json_decode((string)$zip->getFromName('plugin.json'), true, 512, JSON_THROW_ON_ERROR);
$zip->close();
if (($embedded['name'] ?? '') !== 'smtp-jyavani' || ($embedded['version'] ?? '') !== ($manifest['version'] ?? '')) {
    throw new RuntimeException('Embedded plugin identity/version mismatch.');
}
foreach (['plugin.php', 'admin/settings.php', 'admin/save.php', 'includes/config.php', 'includes/smtp-client.php', 'assets/css/admin.css', 'icon.svg'] as $required) {
    if (!isset($entries[$required])) throw new RuntimeException('Required package entry missing: ' . $required);
}
foreach ($embedded['admin']['pages'] ?? [] as $page) {
    if (!isset($entries[(string)($page['file'] ?? '')])) throw new RuntimeException('Route file missing from package.');
}
foreach ($embedded['static']['copy'] ?? [] as $copy) {
    if (!isset($entries[(string)($copy['from'] ?? '')])) throw new RuntimeException('Static source missing from package.');
}
echo json_encode([
    'ok' => true,
    'version' => $embedded['version'],
    'entries' => count($entries),
    'bytes' => filesize($zipPath),
    'sha256' => hash_file('sha256', $zipPath),
], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), PHP_EOL;
