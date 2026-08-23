<?php
declare(strict_types=1);

const JYSMTP_SETTING_KEY = 'smtp_jyavani_config';
require_once dirname(__DIR__) . '/includes/config.php';
require_once dirname(__DIR__) . '/includes/smtp-client.php';

$failures = [];
$checks = 0;
$check = static function (bool $condition, string $message) use (&$failures, &$checks): void {
    $checks++;
    echo ($condition ? 'PASS' : 'FAIL') . ' ' . $message . PHP_EOL;
    if (!$condition) $failures[] = $message;
};

putenv('SMTP_JYAVANI_KEY=' . str_repeat('s', 48));
$tlsPrefix = sys_get_temp_dir() . '/jysmtp-tls-' . bin2hex(random_bytes(6));
$tlsCertificate = $tlsPrefix . '.crt';
$tlsPrivateKey = $tlsPrefix . '.key';
$openssl = proc_open([
    'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
    '-keyout', $tlsPrivateKey, '-out', $tlsCertificate, '-days', '1',
    '-subj', '/CN=127.0.0.1', '-addext', 'subjectAltName=IP:127.0.0.1',
], [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $opensslPipes);
if (!is_resource($openssl)) throw new RuntimeException('Unable to start OpenSSL for TLS contract setup.');
fclose($opensslPipes[0]);
stream_get_contents($opensslPipes[1]);
stream_get_contents($opensslPipes[2]);
fclose($opensslPipes[1]);
fclose($opensslPipes[2]);
if (proc_close($openssl) !== 0 || !is_file($tlsCertificate) || !is_file($tlsPrivateKey)) {
    throw new RuntimeException('Unable to generate the TLS contract certificate.');
}
putenv('SMTP_JYAVANI_CA_FILE=' . $tlsCertificate);
$message = [
    'to' => ['recipient@example.test'],
    'subject' => 'Pesan pengujian ü',
    'body' => ".leading dot\nSecond line",
    'content_type' => 'text/plain',
    'from' => ['email' => 'sender@example.test', 'name' => 'Jyavani Mail'],
    'reply_to' => ['email' => 'reply@example.test', 'name' => 'Support'],
];
$context = ['id' => '0123456789abcdef01234567', 'transport' => 'smtp'];

$run = static function (string $mode, ?array $candidateMessage = null, array $configOverrides = []) use ($message, $context, $tlsCertificate, $tlsPrivateKey): array {
    $prefix = sys_get_temp_dir() . '/jysmtp-' . bin2hex(random_bytes(6));
    $ready = $prefix . '.ready';
    $capture = $prefix . '.json';
    $command = [PHP_BINARY, __DIR__ . '/fake_smtp_server.php', $mode, $ready, $capture];
    if (str_starts_with($mode, 'tls_') || str_starts_with($mode, 'starttls_')) {
        $command[] = $tlsCertificate;
        $command[] = $tlsPrivateKey;
    }
    $process = proc_open($command, [['pipe', 'r'], ['pipe', 'w'], ['pipe', 'w']], $pipes);
    if (!is_resource($process)) throw new RuntimeException('Unable to start fake SMTP server.');
    fclose($pipes[0]);
    $deadline = microtime(true) + 4;
    while (!is_file($ready) && microtime(true) < $deadline) usleep(20000);
    if (!is_file($ready)) throw new RuntimeException('Fake SMTP server did not become ready.');
    $port = (int)file_get_contents($ready);
    $config = array_replace([
        'host' => '127.0.0.1', 'port' => $port, 'encryption' => 'none', 'authentication' => false,
        'username' => '', 'password_encrypted' => '', 'timeout' => 3,
    ], $configOverrides);
    $result = jysmtp_deliver($config, $candidateMessage ?? $message, $context);
    stream_get_contents($pipes[1]);
    stream_get_contents($pipes[2]);
    fclose($pipes[1]);
    fclose($pipes[2]);
    proc_close($process);
    $transcript = is_file($capture) ? json_decode((string)file_get_contents($capture), true, 512, JSON_THROW_ON_ERROR) : [];
    foreach ([$ready, $capture] as $file) if (is_file($file)) unlink($file);
    return [$result, $transcript];
};

[$accepted, $transcript] = $run('accept');
$check($accepted === ['status' => 'accepted'], 'local SMTP relay accepts a normalized Core message');
$commands = $transcript['commands'] ?? [];
$data = implode("\n", $transcript['data'] ?? []);
$check(str_starts_with($commands[0] ?? '', 'EHLO '), 'SMTP session begins with EHLO');
$check(in_array('MAIL FROM:<sender@example.test>', $commands, true), 'SMTP envelope uses the normalized sender');
$check(in_array('RCPT TO:<recipient@example.test>', $commands, true), 'SMTP envelope uses the normalized recipient');
$check(in_array('DATA', $commands, true) && in_array('QUIT', $commands, true), 'SMTP DATA is accepted before a best-effort QUIT');
$check(str_contains($data, 'Subject: Pesan pengujian =?UTF-8?B?') && str_contains($data, 'Reply-To: "Support" <reply@example.test>'), 'MIME headers encode UTF-8 and preserve structured Reply-To');
$check(str_contains($data, ".leading dot\nSecond line"), 'SMTP dot-stuffing is reversed by the receiver without changing the body');

[$rejected, $rejectTranscript] = $run('reject_recipient');
$check($rejected === ['status' => 'permanent_failure'], 'SMTP 5xx recipient rejection is permanent');
$check(!in_array('DATA', $rejectTranscript['commands'] ?? [], true), 'recipient rejection aborts before DATA and partial delivery');
[$deferred, $deferTranscript] = $run('defer_recipient');
$check($deferred === ['status' => 'temporary_failure'], 'SMTP 4xx recipient deferral is retryable');
$check(!in_array('DATA', $deferTranscript['commands'] ?? [], true), 'recipient deferral aborts before DATA');
[$ambiguous] = $run('disconnect_after_data');
$check($ambiguous === ['status' => 'permanent_failure'], 'post-DATA disconnect fails closed to suppress duplicate fallback delivery');
[$heloFallback, $heloTranscript] = $run('ehlo_fallback');
$check($heloFallback === ['status' => 'accepted'] && str_starts_with($heloTranscript['commands'][1] ?? '', 'HELO '), 'unauthenticated relay falls back from EHLO to HELO');
[$accepted252] = $run('accept_252');
$check($accepted252 === ['status' => 'accepted'], 'SMTP RCPT 252 is accepted as a valid success response');
$terminalNewlineMessage = $message;
$terminalNewlineMessage['body'] = "Terminal newline\n";
[$terminalNewlineResult, $terminalNewlineTranscript] = $run('accept', $terminalNewlineMessage);
$terminalData = $terminalNewlineTranscript['data'] ?? [];
$check($terminalNewlineResult === ['status' => 'accepted'] && end($terminalData) === 'Terminal newline', 'terminal body newline does not acquire an extra blank line');
[$implicitTls] = $run('tls_accept', null, ['encryption' => 'tls']);
$check($implicitTls === ['status' => 'accepted'], 'implicit TLS completes with a trusted certificate and verified IP identity');
putenv('SMTP_JYAVANI_CA_FILE=' . $tlsPrivateKey);
[$untrustedTls] = $run('tls_accept', null, ['encryption' => 'tls']);
$check($untrustedTls === ['status' => 'permanent_failure'], 'TLS fails closed when the SMTP certificate is not trusted');
putenv('SMTP_JYAVANI_CA_FILE=' . $tlsCertificate);
[$startTls, $startTlsTranscript] = $run('starttls_accept', null, ['encryption' => 'starttls']);
$check($startTls === ['status' => 'accepted']
    && count(array_filter($startTlsTranscript['commands'] ?? [], static fn(string $command): bool => str_starts_with($command, 'EHLO '))) === 2
    && in_array('STARTTLS', $startTlsTranscript['commands'] ?? [], true), 'STARTTLS upgrades the socket and repeats EHLO over TLS');
$authConfig = [
    'encryption' => 'tls',
    'authentication' => true,
    'username' => 'mailer@example.test',
    'password_encrypted' => jysmtp_encrypt_password('smtp-contract-password'),
];
[$authPlain, $authPlainTranscript] = $run('tls_auth_plain', null, $authConfig);
$check($authPlain === ['status' => 'accepted'] && in_array('AUTH PLAIN [REDACTED]', $authPlainTranscript['commands'] ?? [], true), 'AUTH PLAIN runs only inside a verified TLS session');
[$authLogin, $authLoginTranscript] = $run('tls_auth_login', null, $authConfig);
$check($authLogin === ['status' => 'accepted']
    && in_array('[AUTH LOGIN USERNAME]', $authLoginTranscript['commands'] ?? [], true)
    && in_array('[AUTH LOGIN PASSWORD]', $authLoginTranscript['commands'] ?? [], true), 'AUTH LOGIN challenge flow runs only inside a verified TLS session');

$check(jysmtp_stream_target('2001:db8::1', 465, 'tls') === 'tls://[2001:db8::1]:465', 'implicit TLS target handles IPv6 safely');
$contextOptions = stream_context_get_options(jysmtp_tls_context('smtp.example.com'))['ssl'] ?? [];
$check(($contextOptions['verify_peer'] ?? false) === true && ($contextOptions['verify_peer_name'] ?? false) === true
    && ($contextOptions['peer_name'] ?? '') === 'smtp.example.com', 'TLS context enforces peer and hostname verification');
$method = jysmtp_tls_crypto_method();
$expectedMethod = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) $expectedMethod |= constant('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT');
$check($method === $expectedMethod && $method !== STREAM_CRYPTO_METHOD_TLS_CLIENT, 'TLS method excludes TLS 1.0 and 1.1 while requiring TLS 1.2');
$check(jysmtp_auth_mechanisms(['SIZE 1000', 'AUTH PLAIN LOGIN']) === ['PLAIN', 'LOGIN'], 'SMTP AUTH capability parsing supports PLAIN and LOGIN without trusting arbitrary text');

putenv('SMTP_JYAVANI_CA_FILE');
foreach ([$tlsCertificate, $tlsPrivateKey] as $file) if (is_file($file)) unlink($file);

if ($failures !== []) {
    fwrite(STDERR, count($failures) . " SMTP protocol checks failed.\n");
    exit(1);
}
echo "SMTP protocol contract passed ({$checks} checks).\n";
