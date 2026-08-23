<?php
declare(strict_types=1);

final class JySmtpProtocolException extends RuntimeException
{
    public function __construct(public readonly bool $retryable, public readonly bool $ambiguous = false)
    {
        parent::__construct('SMTP transport failed.');
    }
}

function jysmtp_encode_header(string $value): string
{
    if (preg_match('/^[\x20-\x7E]*$/', $value) === 1) return $value;
    return mb_encode_mimeheader($value, 'UTF-8', 'B', "\r\n", 9);
}

function jysmtp_format_mailbox(array $mailbox): string
{
    $email = (string)($mailbox['email'] ?? '');
    $name = (string)($mailbox['name'] ?? '');
    if ($name === '') return '<' . $email . '>';
    $display = preg_match('/^[\x20-\x7E]*$/', $name) === 1
        ? '"' . addcslashes($name, "\\\"") . '"'
        : jysmtp_encode_header($name);
    return $display . ' <' . $email . '>';
}

function jysmtp_fold_addresses(array $addresses): string
{
    return implode(",\r\n ", array_map(static fn(string $email): string => '<' . $email . '>', $addresses));
}

function jysmtp_normalize_body(string $body): string
{
    $body = str_replace(["\r\n", "\r"], "\n", $body);
    return str_replace("\n", "\r\n", $body);
}

function jysmtp_build_message(array $message, array $context): string
{
    $from = $message['from'];
    $domain = substr(strrchr((string)$from['email'], '@') ?: '@localhost', 1);
    $id = preg_replace('/[^a-zA-Z0-9.-]/', '', (string)($context['id'] ?? '')) ?: bin2hex(random_bytes(12));
    $headers = [
        'Date: ' . gmdate('D, d M Y H:i:s +0000'),
        'Message-ID: <' . $id . '@' . $domain . '>',
        'From: ' . jysmtp_format_mailbox($from),
        'To: ' . jysmtp_fold_addresses($message['to']),
        'Subject: ' . jysmtp_encode_header((string)$message['subject']),
        'MIME-Version: 1.0',
        'Content-Type: ' . $message['content_type'] . '; charset=UTF-8',
        'Content-Transfer-Encoding: quoted-printable',
    ];
    if (is_array($message['reply_to'] ?? null)) $headers[] = 'Reply-To: ' . jysmtp_format_mailbox($message['reply_to']);
    $body = quoted_printable_encode(jysmtp_normalize_body((string)$message['body']));
    $body = preg_replace('/\r\n|\r|\n/', "\r\n", $body) ?? $body;
    $payload = implode("\r\n", $headers) . "\r\n\r\n" . $body;
    if (strlen($payload) > 16 * 1024 * 1024) throw new JySmtpProtocolException(false);
    return preg_replace('/(?m)^\./', '..', $payload) ?? $payload;
}

function jysmtp_stream_target(string $host, int $port, string $encryption): string
{
    $targetHost = filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false ? '[' . $host . ']' : $host;
    return ($encryption === 'tls' ? 'tls://' : 'tcp://') . $targetHost . ':' . $port;
}

function jysmtp_tls_crypto_method(): int
{
    $method = STREAM_CRYPTO_METHOD_TLSv1_2_CLIENT;
    if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT')) {
        $method |= constant('STREAM_CRYPTO_METHOD_TLSv1_3_CLIENT');
    }
    return $method;
}

function jysmtp_tls_context(string $host): mixed
{
    $options = [
        'verify_peer' => true,
        'verify_peer_name' => true,
        'peer_name' => $host,
        'SNI_enabled' => true,
        'disable_compression' => true,
        'crypto_method' => jysmtp_tls_crypto_method(),
    ];
    $caFile = getenv('SMTP_JYAVANI_CA_FILE');
    if (is_string($caFile) && trim($caFile) !== '') {
        $caFile = trim($caFile);
        $absolute = str_starts_with($caFile, '/') || preg_match('/^[A-Za-z]:[\\\\\/]/', $caFile) === 1;
        if (!$absolute || !is_file($caFile) || !is_readable($caFile)) {
            throw new RuntimeException('Configured SMTP CA file is unavailable.');
        }
        $options['cafile'] = $caFile;
    }
    return stream_context_create(['ssl' => $options]);
}

function jysmtp_write_all(mixed $stream, string $data, float $deadline, bool $ambiguous = false): void
{
    $offset = 0;
    $length = strlen($data);
    while ($offset < $length) {
        if (microtime(true) >= $deadline) throw new JySmtpProtocolException(!$ambiguous, $ambiguous);
        $written = fwrite($stream, substr($data, $offset));
        if (!is_int($written) || $written < 1) throw new JySmtpProtocolException(!$ambiguous, $ambiguous);
        $offset += $written;
    }
}

function jysmtp_read_response(mixed $stream, float $deadline, bool $ambiguous = false): array
{
    $lines = [];
    $code = 0;
    $bytes = 0;
    while (count($lines) < 50 && $bytes < 65536) {
        if (microtime(true) >= $deadline) throw new JySmtpProtocolException(!$ambiguous, $ambiguous);
        $line = fgets($stream, 8192);
        if (!is_string($line)) throw new JySmtpProtocolException(!$ambiguous, $ambiguous);
        $bytes += strlen($line);
        if (preg_match('/^(\d{3})([ -])/', $line, $match) !== 1) throw new JySmtpProtocolException(false, $ambiguous);
        $lineCode = (int)$match[1];
        if ($code === 0) $code = $lineCode;
        if ($lineCode !== $code) throw new JySmtpProtocolException(false, $ambiguous);
        $lines[] = rtrim($line, "\r\n");
        if ($match[2] === ' ') return [$code, $lines];
    }
    throw new JySmtpProtocolException(false, $ambiguous);
}

function jysmtp_expect(mixed $stream, string $command, array $expected, float $deadline, bool $ambiguous = false): array
{
    if ($command !== '') jysmtp_write_all($stream, $command . "\r\n", $deadline, $ambiguous);
    [$code, $lines] = jysmtp_read_response($stream, $deadline, $ambiguous);
    if (!in_array($code, $expected, true)) throw new JySmtpProtocolException($code >= 400 && $code < 500, $ambiguous);
    return [$code, $lines];
}

function jysmtp_capabilities(array $lines): array
{
    $capabilities = [];
    foreach ($lines as $index => $line) {
        if ($index === 0 || strlen($line) < 4) continue;
        $value = strtoupper(trim(substr($line, 4)));
        if ($value !== '') $capabilities[] = $value;
    }
    return $capabilities;
}

function jysmtp_has_capability(array $capabilities, string $name): bool
{
    $name = strtoupper($name);
    foreach ($capabilities as $capability) {
        if ($capability === $name || str_starts_with($capability, $name . ' ')) return true;
    }
    return false;
}

function jysmtp_auth_mechanisms(array $capabilities): array
{
    $mechanisms = [];
    foreach ($capabilities as $capability) {
        if (preg_match('/^AUTH(?:=|\s+)(.+)$/', $capability, $match) !== 1) continue;
        foreach (preg_split('/\s+/', trim($match[1])) ?: [] as $mechanism) $mechanisms[] = strtoupper($mechanism);
    }
    return array_values(array_unique($mechanisms));
}

function jysmtp_authenticate(mixed $stream, array $config, array $capabilities, float $deadline): void
{
    $username = (string)$config['username'];
    $password = jysmtp_decrypt_password((string)$config['password_encrypted']);
    if ($password === null) throw new JySmtpProtocolException(false);
    $mechanisms = jysmtp_auth_mechanisms($capabilities);
    try {
        if (in_array('PLAIN', $mechanisms, true)) {
            jysmtp_expect($stream, 'AUTH PLAIN ' . base64_encode("\0" . $username . "\0" . $password), [235], $deadline);
            return;
        }
        if (in_array('LOGIN', $mechanisms, true)) {
            jysmtp_expect($stream, 'AUTH LOGIN', [334], $deadline);
            jysmtp_expect($stream, base64_encode($username), [334], $deadline);
            jysmtp_expect($stream, base64_encode($password), [235], $deadline);
            return;
        }
        throw new JySmtpProtocolException(false);
    } finally {
        sodium_memzero($password);
    }
}

function jysmtp_connect(array $config, float $deadline): mixed
{
    $warning = false;
    $warningMessage = '';
    $stream = false;
    set_error_handler(static function (int $severity, string $message) use (&$warning, &$warningMessage): bool {
        $warning = true;
        $warningMessage .= ' ' . $message;
        return true;
    });
    try {
        $remaining = max(1.0, min((float)$config['timeout'], $deadline - microtime(true)));
        $stream = stream_socket_client(
            jysmtp_stream_target((string)$config['host'], (int)$config['port'], (string)$config['encryption']),
            $errorCode,
            $errorMessage,
            $remaining,
            STREAM_CLIENT_CONNECT,
            jysmtp_tls_context((string)$config['host'])
        );
    } finally {
        restore_error_handler();
    }
    if ($warning || !is_resource($stream)) {
        $tlsVerificationFailure = $config['encryption'] === 'tls'
            && preg_match('/certificate|peer|verify locations|cafile|crypto enabling|ssl operation failed/i', $warningMessage) === 1;
        throw new JySmtpProtocolException(!$tlsVerificationFailure);
    }
    stream_set_blocking($stream, true);
    stream_set_timeout($stream, (int)$config['timeout']);
    return $stream;
}

function jysmtp_helo_name(): string
{
    $host = strtolower((string)gethostname());
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) return '[' . $host . ']';
    if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) return '[IPv6:' . $host . ']';
    if (jysmtp_host_is_valid($host) && $host !== 'localhost') return $host;
    $address = gethostbyname($host);
    return filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false ? '[' . $address . ']' : '[127.0.0.1]';
}

function jysmtp_smtp_greeting(mixed $stream, float $deadline, bool $allowHelo): array
{
    jysmtp_write_all($stream, 'EHLO ' . jysmtp_helo_name() . "\r\n", $deadline);
    [$code, $lines] = jysmtp_read_response($stream, $deadline);
    if ($code === 250) return jysmtp_capabilities($lines);
    if ($allowHelo && in_array($code, [500, 502, 504], true)) {
        jysmtp_expect($stream, 'HELO ' . jysmtp_helo_name(), [250], $deadline);
        return [];
    }
    throw new JySmtpProtocolException($code >= 400 && $code < 500);
}

function jysmtp_deliver(array $config, array $message, array $context): array
{
    if (!jysmtp_config_is_ready($config)) return ['status' => 'permanent_failure'];
    $deadline = microtime(true) + max(10, min(60, ((int)$config['timeout']) * 3));
    $stream = null;
    try {
        $stream = jysmtp_connect($config, $deadline);
        jysmtp_expect($stream, '', [220], $deadline);
        $capabilities = jysmtp_smtp_greeting(
            $stream,
            $deadline,
            $config['encryption'] !== 'starttls' && $config['authentication'] !== true
        );

        if ($config['encryption'] === 'starttls') {
            if (!jysmtp_has_capability($capabilities, 'STARTTLS')) throw new JySmtpProtocolException(false);
            jysmtp_expect($stream, 'STARTTLS', [220], $deadline);
            $warning = false;
            set_error_handler(static function () use (&$warning): bool {
                $warning = true;
                return true;
            });
            try {
                $secured = stream_socket_enable_crypto($stream, true, jysmtp_tls_crypto_method());
            } finally {
                restore_error_handler();
            }
            if ($warning || $secured !== true) throw new JySmtpProtocolException(false);
            $capabilities = jysmtp_smtp_greeting($stream, $deadline, $config['authentication'] !== true);
        }

        if ($config['authentication'] === true) jysmtp_authenticate($stream, $config, $capabilities, $deadline);
        jysmtp_expect($stream, 'MAIL FROM:<' . $message['from']['email'] . '>', [250], $deadline);
        foreach ($message['to'] as $recipient) {
            jysmtp_expect($stream, 'RCPT TO:<' . $recipient . '>', [250, 251, 252], $deadline);
        }
        jysmtp_expect($stream, 'DATA', [354], $deadline);
        $payload = jysmtp_build_message($message, $context);
        $terminator = str_ends_with($payload, "\r\n") ? ".\r\n" : "\r\n.\r\n";
        jysmtp_write_all($stream, $payload . $terminator, $deadline);
        [$dataCode] = jysmtp_read_response($stream, $deadline, true);
        if ($dataCode !== 250) throw new JySmtpProtocolException($dataCode >= 400 && $dataCode < 500);
        $meta = stream_get_meta_data($stream);
        if (($meta['timed_out'] ?? false) === true) throw new JySmtpProtocolException(false, true);
        try {
            jysmtp_expect($stream, 'QUIT', [221], $deadline);
        } catch (Throwable $quitError) {
            // A confirmed 250 after DATA is accepted even when QUIT cannot complete.
        }
        fclose($stream);
        return ['status' => 'accepted'];
    } catch (JySmtpProtocolException $error) {
        if (is_resource($stream)) fclose($stream);
        return ['status' => ($error->retryable && !$error->ambiguous) ? 'temporary_failure' : 'permanent_failure'];
    } catch (Throwable $error) {
        if (is_resource($stream)) fclose($stream);
        return ['status' => 'permanent_failure'];
    }
}
