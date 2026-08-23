<?php
declare(strict_types=1);

if (!defined('DASHBOARD_CONTEXT')) exit;

$pdo = $GLOBALS['pdo'] ?? null;
if (!$pdo instanceof PDO) {
    adiwira_render_404();
    return;
}
[$uid] = adiwira_require_site_owner($pdo, false);

$returnTo = rtrim((string)ADMIN_BASE_PATH, '/') . '/?page=admin/settings/smtp-jyavani';
if (!function_exists('adiwira_redirect_with_flash') && defined('DASH_PATH')) {
    require_once rtrim((string)DASH_PATH, DIRECTORY_SEPARATOR) . '/admin/_notify.php';
}
$redirect = static function (string $type, string $message) use ($returnTo): never {
    if (function_exists('adiwira_redirect_with_flash')) adiwira_redirect_with_flash($returnTo, $type, $message);
    header('Location: ' . $returnTo, true, 303);
    exit;
};

if (($_SERVER['REQUEST_METHOD'] ?? 'GET') !== 'POST') {
    adiwira_render_404();
    return;
}
if (!function_exists('csrf_check') || !csrf_check(is_string($_POST['csrf_token'] ?? null) ? $_POST['csrf_token'] : '')) {
    $redirect('error', jysmtp_t('The security token is invalid. Please try again.'));
}

try {
    $config = jysmtp_config_from_input($_POST, jysmtp_load_config($pdo));
    if (!jysmtp_save_config($pdo, $config)) throw new RuntimeException('Unable to save SMTP settings.');
    if (function_exists('authorization_audit')) {
        authorization_audit($pdo, 'smtp_jyavani.settings.updated', $uid, null, 'smtp-jyavani', null, [
            'encryption' => $config['encryption'],
            'authentication' => $config['authentication'],
        ]);
    }
    $redirect('success', jysmtp_t('SMTP settings saved. Select SMTP in Email Delivery to activate it.'));
} catch (DomainException $error) {
    $redirect('error', $error->getMessage());
} catch (Throwable $error) {
    $redirect('error', jysmtp_t('SMTP settings could not be saved.'));
}
