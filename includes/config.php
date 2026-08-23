<?php
declare(strict_types=1);

function jysmtp_default_config(): array
{
    return [
        'host' => '',
        'port' => 587,
        'encryption' => 'starttls',
        'authentication' => true,
        'username' => '',
        'password_encrypted' => '',
        'timeout' => 10,
    ];
}

function jysmtp_host_is_valid(string $host): bool
{
    if ($host === '' || strlen($host) > 253 || preg_match('/[\x00-\x20\x7F\/?#\[\]@]/', $host) === 1) return false;
    if (filter_var($host, FILTER_VALIDATE_IP) !== false) return true;
    if (str_contains($host, ':')) return false;
    if ($host === 'localhost') return true;
    if (!str_contains($host, '.') || str_ends_with($host, '.')) return false;
    foreach (explode('.', $host) as $label) {
        if ($label === '' || strlen($label) > 63 || preg_match('/^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$/i', $label) !== 1) return false;
    }
    return true;
}

function jysmtp_username_is_valid(string $username): bool
{
    return $username !== '' && strlen($username) <= 320 && preg_match('/[\x00-\x1F\x7F]/', $username) !== 1;
}

function jysmtp_secret_source(): string
{
    foreach (['SMTP_JYAVANI_KEY', 'APP_KEY', 'SESSION_SECRET'] as $name) {
        $value = getenv($name);
        if (is_string($value) && strlen($value) >= 32) return $value;
    }
    return '';
}

function jysmtp_crypto_available(): bool
{
    return function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt') && jysmtp_secret_source() !== '';
}

function jysmtp_encryption_key(): string
{
    $secret = jysmtp_secret_source();
    if ($secret === '' || !function_exists('sodium_crypto_aead_xchacha20poly1305_ietf_encrypt')) {
        throw new RuntimeException('SMTP credential encryption is unavailable.');
    }
    return hash('sha256', "smtp-jyavani:v1\0" . $secret, true);
}

function jysmtp_base64url_encode(string $value): string
{
    return rtrim(strtr(base64_encode($value), '+/', '-_'), '=');
}

function jysmtp_base64url_decode(string $value): ?string
{
    if ($value === '' || preg_match('/^[A-Za-z0-9_-]+$/', $value) !== 1) return null;
    $padding = (4 - (strlen($value) % 4)) % 4;
    $decoded = base64_decode(strtr($value . str_repeat('=', $padding), '-_', '+/'), true);
    return is_string($decoded) ? $decoded : null;
}

function jysmtp_encrypt_password(string $password): string
{
    if ($password === '' || strlen($password) > 4096 || str_contains($password, "\0")) {
        throw new DomainException(jysmtp_t('Enter a valid SMTP password.'));
    }
    $nonce = random_bytes(SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES);
    $ciphertext = sodium_crypto_aead_xchacha20poly1305_ietf_encrypt(
        $password,
        'smtp-jyavani-config-v1',
        $nonce,
        jysmtp_encryption_key()
    );
    return 'v1:' . jysmtp_base64url_encode($nonce . $ciphertext);
}

function jysmtp_decrypt_password(string $encoded): ?string
{
    if (!str_starts_with($encoded, 'v1:')) return null;
    try {
        $payload = jysmtp_base64url_decode(substr($encoded, 3));
        $nonceBytes = SODIUM_CRYPTO_AEAD_XCHACHA20POLY1305_IETF_NPUBBYTES;
        if ($payload === null || strlen($payload) <= $nonceBytes) return null;
        $password = sodium_crypto_aead_xchacha20poly1305_ietf_decrypt(
            substr($payload, $nonceBytes),
            'smtp-jyavani-config-v1',
            substr($payload, 0, $nonceBytes),
            jysmtp_encryption_key()
        );
        return is_string($password) && $password !== '' ? $password : null;
    } catch (Throwable $error) {
        return null;
    }
}

function jysmtp_normalize_stored_config(mixed $value): array
{
    $defaults = jysmtp_default_config();
    if (is_string($value)) {
        try {
            $decoded = json_decode($value, true, 16, JSON_THROW_ON_ERROR);
            $value = is_array($decoded) ? $decoded : [];
        } catch (Throwable $error) {
            $value = [];
        }
    }
    if (!is_array($value)) $value = [];
    $config = array_merge($defaults, array_intersect_key($value, $defaults));
    $config['host'] = is_string($config['host']) ? strtolower(trim($config['host'])) : '';
    $config['port'] = is_int($config['port']) ? $config['port'] : (int)$config['port'];
    $config['encryption'] = is_string($config['encryption']) ? strtolower($config['encryption']) : 'starttls';
    $config['authentication'] = $config['authentication'] === true || $config['authentication'] === 1;
    $config['username'] = is_string($config['username']) ? trim($config['username']) : '';
    $config['password_encrypted'] = is_string($config['password_encrypted']) ? $config['password_encrypted'] : '';
    $config['timeout'] = is_int($config['timeout']) ? $config['timeout'] : (int)$config['timeout'];
    return $config;
}

function jysmtp_load_config(PDO $pdo): array
{
    $stored = function_exists('settings_get') ? settings_get($pdo, JYSMTP_SETTING_KEY, '') : '';
    return jysmtp_normalize_stored_config($stored);
}

function jysmtp_config_errors(array $config): array
{
    $errors = [];
    if (!jysmtp_host_is_valid((string)($config['host'] ?? ''))) $errors[] = 'host';
    $port = $config['port'] ?? null;
    if (!is_int($port) || $port < 1 || $port > 65535) $errors[] = 'port';
    $encryption = $config['encryption'] ?? null;
    if (!is_string($encryption) || !in_array($encryption, ['starttls', 'tls', 'none'], true)) $errors[] = 'encryption';
    $timeout = $config['timeout'] ?? null;
    if (!is_int($timeout) || $timeout < 2 || $timeout > 30) $errors[] = 'timeout';
    $authentication = ($config['authentication'] ?? false) === true;
    if ($authentication) {
        if ($encryption === 'none') $errors[] = 'insecure_authentication';
        if (!jysmtp_username_is_valid((string)($config['username'] ?? ''))) $errors[] = 'username';
        $encrypted = (string)($config['password_encrypted'] ?? '');
        if ($encrypted === '' || jysmtp_decrypt_password($encrypted) === null) $errors[] = 'password';
    }
    return array_values(array_unique($errors));
}

function jysmtp_config_is_ready(array $config): bool
{
    return extension_loaded('openssl')
        && extension_loaded('sodium')
        && extension_loaded('mbstring')
        && jysmtp_config_errors($config) === [];
}

function jysmtp_config_from_input(array $input, array $current): array
{
    $host = is_string($input['host'] ?? null) ? strtolower(trim($input['host'])) : '';
    $portRaw = is_string($input['port'] ?? null) ? trim($input['port']) : '';
    $timeoutRaw = is_string($input['timeout'] ?? null) ? trim($input['timeout']) : '';
    if ($portRaw === '' || preg_match('/^\d{1,5}$/', $portRaw) !== 1) throw new DomainException(jysmtp_t('Enter a valid SMTP port.'));
    if ($timeoutRaw === '' || preg_match('/^\d{1,2}$/', $timeoutRaw) !== 1) throw new DomainException(jysmtp_t('Enter a timeout between 2 and 30 seconds.'));
    if (!jysmtp_host_is_valid($host)) throw new DomainException(jysmtp_t('Enter a valid SMTP hostname or IP address.'));

    $encryption = is_string($input['encryption'] ?? null) ? strtolower($input['encryption']) : '';
    if (!in_array($encryption, ['starttls', 'tls', 'none'], true)) throw new DomainException(jysmtp_t('Select a valid SMTP encryption mode.'));
    $authentication = isset($input['authentication']) && (string)$input['authentication'] === '1';
    $username = is_string($input['username'] ?? null) ? trim($input['username']) : '';
    if ($authentication && $encryption === 'none') throw new DomainException(jysmtp_t('Authenticated SMTP requires TLS or STARTTLS.'));
    if ($authentication && !jysmtp_username_is_valid($username)) throw new DomainException(jysmtp_t('Enter a valid SMTP username.'));

    $clearPassword = isset($input['clear_password']) && (string)$input['clear_password'] === '1';
    $newPassword = is_string($input['password'] ?? null) ? $input['password'] : '';
    $passwordEncrypted = $clearPassword ? '' : (string)($current['password_encrypted'] ?? '');
    if ($newPassword !== '') {
        if (!jysmtp_crypto_available()) throw new DomainException(jysmtp_t('Credential encryption is unavailable. Configure SMTP_JYAVANI_KEY or an application secret.'));
        $passwordEncrypted = jysmtp_encrypt_password($newPassword);
    }
    if ($authentication && ($passwordEncrypted === '' || jysmtp_decrypt_password($passwordEncrypted) === null)) {
        throw new DomainException(jysmtp_t('Enter an SMTP password.'));
    }
    if (!$authentication) {
        $username = '';
        if ($clearPassword) $passwordEncrypted = '';
    }

    $config = [
        'host' => $host,
        'port' => (int)$portRaw,
        'encryption' => $encryption,
        'authentication' => $authentication,
        'username' => $username,
        'password_encrypted' => $passwordEncrypted,
        'timeout' => (int)$timeoutRaw,
    ];
    $errors = jysmtp_config_errors($config);
    if ($errors !== []) throw new DomainException(jysmtp_t('The SMTP configuration is incomplete or invalid.'));
    return $config;
}

function jysmtp_save_config(PDO $pdo, array $config): bool
{
    if (!function_exists('settings_set') || jysmtp_config_errors($config) !== []) return false;
    $ownsTransaction = !$pdo->inTransaction();
    try {
        if ($ownsTransaction) $pdo->beginTransaction();
        $json = json_encode($config, JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);
        if (!settings_set($pdo, JYSMTP_SETTING_KEY, $json, 1)) throw new RuntimeException('Settings write failed.');
        if ($ownsTransaction) $pdo->commit();
        return true;
    } catch (Throwable $error) {
        if ($ownsTransaction && $pdo->inTransaction()) $pdo->rollBack();
        unset($GLOBALS['__jy_settings_autoload_cache']);
        return false;
    }
}
