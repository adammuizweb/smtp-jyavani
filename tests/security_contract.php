<?php
declare(strict_types=1);

$root = dirname(__DIR__);
$settings = (string)file_get_contents($root . '/admin/settings.php');
$save = (string)file_get_contents($root . '/admin/save.php');
$config = (string)file_get_contents($root . '/includes/config.php');
$client = (string)file_get_contents($root . '/includes/smtp-client.php');
$plugin = (string)file_get_contents($root . '/plugin.php');
$failures = [];
$checks = 0;
$check = static function (bool $condition, string $message) use (&$failures, &$checks): void {
    $checks++;
    echo ($condition ? 'PASS' : 'FAIL') . ' ' . $message . PHP_EOL;
    if (!$condition) $failures[] = $message;
};

$check(str_contains($settings, 'adiwira_require_site_owner($pdo, false)')
    && str_contains($save, 'adiwira_require_site_owner($pdo, false)'), 'settings and mutation routes repeat the Site Owner guard');
$method = strpos($save, 'REQUEST_METHOD');
$csrf = strpos($save, 'csrf_check(');
$input = strpos($save, 'jysmtp_config_from_input(');
$write = strpos($save, 'jysmtp_save_config(');
$check($method !== false && $csrf !== false && $input !== false && $write !== false
    && $method < $csrf && $csrf < $input && $input < $write, 'save route enforces POST and CSRF before validation and persistence');
$check(!str_contains($save, 'HTTP_REFERER') && str_contains($save, "ADMIN_BASE_PATH"), 'save route returns only to its fixed dashboard page');
$check(str_contains($settings, 'autocomplete="new-password"') && !preg_match('/name="password"[^>]+value=/', $settings), 'stored SMTP password is never rendered into the form');
$check(str_contains($config, 'sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')
    && str_contains($config, 'random_bytes(') && str_contains($config, 'password_encrypted'), 'password storage uses authenticated randomized encryption');
$check(str_contains($config, "['SMTP_JYAVANI_KEY', 'APP_KEY', 'SESSION_SECRET']"), 'credential key resolution prefers a plugin-specific secret');
$check(str_contains($config, "Authenticated SMTP requires TLS or STARTTLS."), 'configuration rejects authenticated plaintext SMTP');
$check(str_contains($client, "'verify_peer' => true") && str_contains($client, "'verify_peer_name' => true")
    && !str_contains($client, "'allow_self_signed' => true"), 'TLS peer and hostname verification cannot be disabled');
$check(str_contains($client, 'STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT')
    && !str_contains($client, 'STREAM_CRYPTO_METHOD_TLS_CLIENT,'), 'SMTP negotiation requires TLS 1.2 or newer');
$check(!preg_match('/@(?:stream|fwrite|fgets|mail|openssl|socket)/', $client), 'SMTP runtime does not suppress transport errors with the at operator');
$check(!str_contains($client, 'error_log(') && !str_contains($client, 'getMessage()'), 'SMTP runtime does not log raw failures or exception messages');
$check(str_contains($client, 'ambiguous') && str_contains($client, "'permanent_failure'"), 'ambiguous post-DATA failures suppress Core fallback');
$check(str_contains($plugin, "jy_mail_register_transport('smtp'") && !str_contains($plugin, 'add_action(\'plugins_loaded\''), 'transport registration occurs inside the rollback-protected plugin entrypoint');
$check(str_contains($plugin, "add_action('plugin_uninstall', 'jysmtp_uninstall')")
    && str_contains($plugin, 'DELETE FROM settings'), 'complete uninstall removes encrypted SMTP configuration');
$check(str_contains($client, '$payload . $terminator, $deadline)')
    && str_contains($client, 'jysmtp_read_response($stream, $deadline, true)'), 'only final-response uncertainty is classified as ambiguous delivery');
$check(!str_contains($settings, 'verify_peer') && !str_contains($settings, 'allow_self_signed'), 'dashboard exposes no unsafe TLS bypass');

if ($failures !== []) {
    fwrite(STDERR, count($failures) . " security checks failed.\n");
    exit(1);
}
echo "SMTP security contract passed ({$checks} checks).\n";
