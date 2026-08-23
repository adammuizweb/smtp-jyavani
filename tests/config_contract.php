<?php
declare(strict_types=1);

const JYSMTP_SETTING_KEY = 'smtp_jyavani_config';
function jysmtp_t(string $source, mixed ...$args): string { return $args === [] ? $source : sprintf($source, ...$args); }
function settings_get(PDO $pdo, string $key, ?string $default = null): ?string
{
    $stmt = $pdo->prepare('SELECT value FROM settings WHERE key = ?');
    $stmt->execute([$key]);
    $value = $stmt->fetchColumn();
    return is_string($value) ? $value : $default;
}
function settings_set(PDO $pdo, string $key, ?string $value, int $autoload = 1): bool
{
    $stmt = $pdo->prepare('INSERT OR REPLACE INTO settings (key, value, autoload) VALUES (?, ?, ?)');
    return $stmt->execute([$key, $value, $autoload]);
}
require_once dirname(__DIR__) . '/includes/config.php';

$failures = [];
$checks = 0;
$check = static function (bool $condition, string $message) use (&$failures, &$checks): void {
    $checks++;
    echo ($condition ? 'PASS' : 'FAIL') . ' ' . $message . PHP_EOL;
    if (!$condition) $failures[] = $message;
};

putenv('SMTP_JYAVANI_KEY=' . str_repeat('k', 48));
$check(jysmtp_crypto_available(), 'credential encryption is available with an explicit plugin key');
$encryptedA = jysmtp_encrypt_password('contract-secret');
$encryptedB = jysmtp_encrypt_password('contract-secret');
$check($encryptedA !== $encryptedB && !str_contains($encryptedA, 'contract-secret'), 'password encryption is randomized and hides plaintext');
$check(jysmtp_decrypt_password($encryptedA) === 'contract-secret', 'encrypted password decrypts with the configured key');
putenv('SMTP_JYAVANI_KEY=' . str_repeat('x', 48));
$check(jysmtp_decrypt_password($encryptedA) === null, 'password decryption fails closed after key rotation');
putenv('SMTP_JYAVANI_KEY=' . str_repeat('k', 48));

foreach (['smtp.example.com', '127.0.0.1', '2001:db8::1', 'localhost'] as $host) {
    $check(jysmtp_host_is_valid($host), 'valid SMTP host accepted: ' . $host);
}
foreach (['', 'smtp', 'https://smtp.example.com', "smtp.example.com\r\nX-Test: yes", 'smtp.example.com/path', '-smtp.example.com'] as $host) {
    $check(!jysmtp_host_is_valid($host), 'unsafe or malformed SMTP host rejected');
}

$current = jysmtp_default_config();
$input = [
    'host' => 'smtp.example.com',
    'port' => '587',
    'encryption' => 'starttls',
    'authentication' => '1',
    'username' => 'mailer@example.com',
    'password' => 'contract-secret',
    'timeout' => '10',
];
$configured = jysmtp_config_from_input($input, $current);
$check(jysmtp_config_errors($configured) === [] && jysmtp_config_is_ready($configured), 'valid authenticated STARTTLS configuration is ready');
$retained = jysmtp_config_from_input(array_replace($input, ['password' => '']), $configured);
$check($retained['password_encrypted'] === $configured['password_encrypted'], 'blank password retains the encrypted credential');
try {
    jysmtp_config_from_input(array_replace($input, ['encryption' => 'none']), $configured);
    $check(false, 'plaintext authenticated SMTP is rejected');
} catch (DomainException $error) {
    $check(str_contains($error->getMessage(), 'requires TLS'), 'plaintext authenticated SMTP is rejected');
}
$relay = jysmtp_config_from_input([
    'host' => '127.0.0.1', 'port' => '2525', 'encryption' => 'none', 'timeout' => '5', 'clear_password' => '1',
], $configured);
$check($relay['authentication'] === false && $relay['password_encrypted'] === '' && jysmtp_config_is_ready($relay), 'unauthenticated local relay is allowed without retaining credentials');

$pdo = new PDO('sqlite::memory:');
$pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
$pdo->exec('CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT, autoload INTEGER NOT NULL)');
$check(jysmtp_save_config($pdo, $configured), 'validated SMTP configuration saves atomically');
$stored = (string)settings_get($pdo, JYSMTP_SETTING_KEY, '');
$check(!str_contains($stored, 'contract-secret') && str_contains($stored, 'password_encrypted'), 'persisted configuration contains ciphertext and no plaintext password');
$check(jysmtp_load_config($pdo)['host'] === 'smtp.example.com', 'saved SMTP configuration loads through the namespaced setting');

if ($failures !== []) {
    fwrite(STDERR, count($failures) . " configuration checks failed.\n");
    exit(1);
}
echo "SMTP configuration contract passed ({$checks} checks).\n";
