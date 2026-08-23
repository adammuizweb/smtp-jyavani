<?php
declare(strict_types=1);

if (PHP_SAPI !== 'cli' || count($argv) < 4) exit(2);
[$script, $mode, $readyPath, $capturePath] = $argv;
$certificate = (string)($argv[4] ?? '');
$privateKey = (string)($argv[5] ?? '');
$usesImplicitTls = str_starts_with($mode, 'tls_');
$usesStartTls = str_starts_with($mode, 'starttls_');
$contextOptions = [];
if ($usesImplicitTls || $usesStartTls) {
    if (!is_file($certificate) || !is_file($privateKey)) exit(5);
    $serverCrypto = STREAM_CRYPTO_METHOD_TLSv1_2_SERVER;
    if (defined('STREAM_CRYPTO_METHOD_TLSv1_3_SERVER')) $serverCrypto |= constant('STREAM_CRYPTO_METHOD_TLSv1_3_SERVER');
    $contextOptions = ['ssl' => [
        'local_cert' => $certificate,
        'local_pk' => $privateKey,
        'verify_peer' => false,
        'allow_self_signed' => true,
        'crypto_method' => $serverCrypto,
    ]];
}
$context = stream_context_create($contextOptions);
$scheme = $usesImplicitTls ? 'tls' : 'tcp';
$server = stream_socket_server($scheme . '://127.0.0.1:0', $errorCode, $errorMessage, STREAM_SERVER_BIND | STREAM_SERVER_LISTEN, $context);
if (!is_resource($server)) exit(3);
$address = (string)stream_socket_get_name($server, false);
$port = (int)substr(strrchr($address, ':') ?: ':0', 1);
file_put_contents($readyPath, (string)$port, LOCK_EX);
$client = stream_socket_accept($server, 8);
if (!is_resource($client)) exit(4);
stream_set_timeout($client, 5);
fwrite($client, "220 fake.smtp.local ESMTP\r\n");
$commands = [];
$data = [];
$readingData = false;
$secured = $usesImplicitTls;
$authStage = '';
while (($line = fgets($client, 8192)) !== false) {
    $line = rtrim($line, "\r\n");
    if ($readingData) {
        if ($line === '.') {
            $readingData = false;
            if ($mode === 'disconnect_after_data') break;
            fwrite($client, "250 2.0.0 queued\r\n");
            continue;
        }
        $data[] = str_starts_with($line, '..') ? substr($line, 1) : $line;
        continue;
    }
    if ($authStage === 'username') {
        $commands[] = '[AUTH LOGIN USERNAME]';
        $authStage = 'password';
        fwrite($client, "334 UGFzc3dvcmQ6\r\n");
        continue;
    }
    if ($authStage === 'password') {
        $commands[] = '[AUTH LOGIN PASSWORD]';
        $authStage = '';
        fwrite($client, "235 2.7.0 authenticated\r\n");
        continue;
    }
    $commands[] = $line;
    $verb = strtoupper(strtok($line, ' ') ?: '');
    if ($verb === 'EHLO') {
        if ($mode === 'ehlo_fallback') {
            fwrite($client, "502 5.5.1 EHLO unsupported\r\n");
        } elseif ($usesStartTls && !$secured) {
            fwrite($client, "250-fake.smtp.local\r\n250 STARTTLS\r\n");
        } elseif ($mode === 'tls_auth_plain') {
            fwrite($client, "250-fake.smtp.local\r\n250 AUTH PLAIN LOGIN\r\n");
        } elseif ($mode === 'tls_auth_login') {
            fwrite($client, "250-fake.smtp.local\r\n250 AUTH LOGIN\r\n");
        } else {
            fwrite($client, "250-fake.smtp.local\r\n250 SIZE 16777216\r\n");
        }
    } elseif ($verb === 'HELO') {
        fwrite($client, "250 fake.smtp.local\r\n");
    } elseif ($verb === 'STARTTLS' && $usesStartTls && !$secured) {
        fwrite($client, "220 2.0.0 begin TLS\r\n");
        $secured = stream_socket_enable_crypto($client, true, $serverCrypto) === true;
        if (!$secured) break;
    } elseif ($verb === 'AUTH' && $mode === 'tls_auth_plain' && str_starts_with(strtoupper($line), 'AUTH PLAIN ')) {
        $commands[count($commands) - 1] = 'AUTH PLAIN [REDACTED]';
        fwrite($client, "235 2.7.0 authenticated\r\n");
    } elseif ($verb === 'AUTH' && $mode === 'tls_auth_login' && strtoupper($line) === 'AUTH LOGIN') {
        $authStage = 'username';
        fwrite($client, "334 VXNlcm5hbWU6\r\n");
    } elseif ($verb === 'MAIL') {
        fwrite($client, "250 2.1.0 sender ok\r\n");
    } elseif ($verb === 'RCPT') {
        if ($mode === 'reject_recipient') fwrite($client, "550 5.1.1 recipient rejected\r\n");
        elseif ($mode === 'defer_recipient') fwrite($client, "450 4.2.0 try later\r\n");
        elseif ($mode === 'accept_252') fwrite($client, "252 2.1.5 cannot verify but accepted\r\n");
        else fwrite($client, "250 2.1.5 recipient ok\r\n");
    } elseif ($verb === 'DATA') {
        fwrite($client, "354 end with dot\r\n");
        $readingData = true;
    } elseif ($verb === 'QUIT') {
        fwrite($client, "221 2.0.0 bye\r\n");
        break;
    } else {
        fwrite($client, "500 unsupported\r\n");
    }
}
file_put_contents($capturePath, json_encode(['commands' => $commands, 'data' => $data], JSON_THROW_ON_ERROR), LOCK_EX);
fclose($client);
fclose($server);
