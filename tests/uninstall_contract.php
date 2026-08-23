<?php
declare(strict_types=1);

define('BACKEND_PATH', dirname(__DIR__));
$GLOBALS['jysmtp_test_actions'] = [];
function add_action(string $hook, callable|string $callback): void { $GLOBALS['jysmtp_test_actions'][$hook][] = $callback; }
function jy_mail_register_transport(string $name, callable|string $sender, array $metadata = []): bool { return $name === 'smtp'; }
require_once dirname(__DIR__) . '/plugin.php';

$failures = [];
$checks = 0;
$check = static function (bool $condition, string $message) use (&$failures, &$checks): void {
    $checks++;
    echo ($condition ? 'PASS' : 'FAIL') . ' ' . $message . PHP_EOL;
    if (!$condition) $failures[] = $message;
};

$check(in_array('jysmtp_uninstall', $GLOBALS['jysmtp_test_actions']['plugin_uninstall'] ?? [], true), 'plugin registers credential cleanup on complete uninstall');
$pdo = new PDO('sqlite::memory:');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec('CREATE TABLE settings (`key` TEXT PRIMARY KEY, `value` TEXT, `autoload` INTEGER)');
$pdo->prepare('INSERT INTO settings (`key`, `value`, `autoload`) VALUES (?, ?, 1)')->execute([JYSMTP_SETTING_KEY, '{"password_encrypted":"ciphertext"}']);
$GLOBALS['pdo'] = $pdo;
$GLOBALS['__jy_settings_autoload_cache'] = [JYSMTP_SETTING_KEY => 'cached'];
jysmtp_uninstall('another-plugin');
$check((int)$pdo->query('SELECT COUNT(*) FROM settings')->fetchColumn() === 1, 'uninstall callback ignores other plugins');
jysmtp_uninstall('smtp-jyavani');
$check((int)$pdo->query('SELECT COUNT(*) FROM settings')->fetchColumn() === 0, 'complete uninstall deletes encrypted SMTP configuration');
$check(!isset($GLOBALS['__jy_settings_autoload_cache']), 'complete uninstall invalidates the settings cache');

if ($failures !== []) {
    fwrite(STDERR, count($failures) . " uninstall checks failed.\n");
    exit(1);
}
echo "SMTP uninstall contract passed ({$checks} checks).\n";
