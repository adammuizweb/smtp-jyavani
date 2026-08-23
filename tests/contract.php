<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$failures = [];
$checks = 0;
$check = static function (bool $condition, string $message) use (&$failures, &$checks): void {
    $checks++;
    echo ($condition ? 'PASS' : 'FAIL') . ' ' . $message . PHP_EOL;
    if (!$condition) $failures[] = $message;
};

$manifest = json_decode((string)file_get_contents($root . '/plugin.json'), true, 512, JSON_THROW_ON_ERROR);
$check(($manifest['name'] ?? '') === 'smtp-jyavani', 'manifest uses the stable smtp-jyavani identity');
$check(($manifest['version'] ?? '') === '1.0.0', 'manifest publishes version 1.0.0');
$check(($manifest['requires']['jyavani'] ?? '') === '>=2.3.82', 'manifest requires the Core Mail API release');
$requiredExtensions = $manifest['requires']['extensions'] ?? [];
foreach (['json', 'mbstring', 'openssl', 'pdo', 'sodium'] as $extension) {
    $check(in_array($extension, $requiredExtensions, true), 'manifest requires ' . $extension);
}
$check(($manifest['requires']['plugins'] ?? null) === [], 'manifest plugin requirements decode as an empty object');

$pages = $manifest['admin']['pages'] ?? [];
$nav = $manifest['admin']['nav'] ?? [];
$check(count($pages) === 2 && count($nav) === 1, 'manifest declares settings, save action, and navigation');
foreach (array_merge($pages, $nav) as $entry) {
    $check(($entry['site_owner'] ?? false) === true && ($entry['roles'] ?? []) === ['admin'], 'every SMTP admin entry is Site Owner-only');
    $check(!isset($entry['permission']), 'Site Owner entries do not combine plugin permissions');
}
foreach ($pages as $page) $check(is_file($root . '/' . $page['file']), 'manifest route file exists: ' . $page['file']);
$copy = $manifest['static']['copy'][0] ?? [];
$check(($copy['to'] ?? '') === 'static/plugins/smtp-jyavani/admin.css', 'static CSS stays inside the plugin namespace');
$check(is_file($root . '/' . ($copy['from'] ?? '')), 'declared static CSS source exists');

$plugin = (string)file_get_contents($root . '/plugin.php');
$check(str_contains($plugin, "const JYSMTP_VERSION = '1.0.0'"), 'runtime version matches the manifest');
$check(str_contains($plugin, "jy_mail_register_transport('smtp'"), 'plugin registers the smtp Core transport directly at entrypoint load');
$check(str_contains($plugin, "'available' => 'jysmtp_transport_available'"), 'transport exposes a side-effect-free availability callback');

if ($failures !== []) {
    fwrite(STDERR, count($failures) . " contract checks failed.\n");
    exit(1);
}
echo "SMTP Jyavani contract passed ({$checks} checks).\n";
