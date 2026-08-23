<?php
declare(strict_types=1);

if (!defined('BACKEND_PATH')) return;

const JYSMTP_VERSION = '1.0.0';
const JYSMTP_SETTING_KEY = 'smtp_jyavani_config';

function jysmtp_t(string $source, mixed ...$args): string
{
    $translated = function_exists('__') ? __($source) : $source;
    if ($translated === $source) {
        $locale = function_exists('get_locale') ? strtolower((string)get_locale()) : 'en';
        $locale = explode('-', str_replace('_', '-', $locale), 2)[0];
        if (in_array($locale, ['id', 'de'], true)) {
            static $catalogs = [];
            if (!isset($catalogs[$locale])) {
                $file = __DIR__ . '/languages/' . $locale . '.php';
                $catalog = is_file($file) ? require $file : [];
                $catalogs[$locale] = is_array($catalog) ? $catalog : [];
            }
            $translated = (string)($catalogs[$locale][$source] ?? $source);
        }
    }
    return $args === [] ? $translated : sprintf($translated, ...$args);
}

function jysmtp_h(mixed $value): string
{
    return htmlspecialchars((string)$value, ENT_QUOTES, 'UTF-8');
}

require_once __DIR__ . '/includes/config.php';
require_once __DIR__ . '/includes/smtp-client.php';

function jysmtp_transport_available(): bool
{
    $pdo = $GLOBALS['pdo'] ?? null;
    return $pdo instanceof PDO && jysmtp_config_is_ready(jysmtp_load_config($pdo));
}

function jysmtp_transport_send(array $message, array $context): array
{
    $pdo = $GLOBALS['pdo'] ?? null;
    if (!$pdo instanceof PDO) return ['status' => 'permanent_failure'];
    return jysmtp_deliver(jysmtp_load_config($pdo), $message, $context);
}

function jysmtp_admin_assets(): void
{
    $page = trim((string)($_GET['page'] ?? ''), '/');
    if ($page !== 'admin/settings/smtp-jyavani') return;
    echo '<link rel="stylesheet" href="/static/plugins/smtp-jyavani/admin.css?v=' . rawurlencode(JYSMTP_VERSION) . '">';
}

function jysmtp_uninstall(string $name): void
{
    if ($name !== 'smtp-jyavani') return;
    $pdo = $GLOBALS['pdo'] ?? null;
    if (!$pdo instanceof PDO) return;
    $stmt = $pdo->prepare('DELETE FROM settings WHERE `key` = ?');
    $stmt->execute([JYSMTP_SETTING_KEY]);
    unset($GLOBALS['__jy_settings_autoload_cache']);
}

if (!function_exists('jy_mail_register_transport')) {
    throw new RuntimeException('SMTP Jyavani requires Jyavani Core 2.3.82 or newer.');
}
if (!jy_mail_register_transport('smtp', 'jysmtp_transport_send', [
    'label' => 'SMTP',
    'available' => 'jysmtp_transport_available',
])) {
    throw new RuntimeException('SMTP Jyavani could not register its mail transport.');
}

add_action('admin_head', 'jysmtp_admin_assets');
add_action('plugin_uninstall', 'jysmtp_uninstall');
