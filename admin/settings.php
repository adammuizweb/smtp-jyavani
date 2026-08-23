<?php
declare(strict_types=1);

if (!defined('DASHBOARD_CONTEXT')) exit;

$pdo = $GLOBALS['pdo'] ?? null;
if (!$pdo instanceof PDO) {
    adiwira_render_404();
    return;
}
adiwira_require_site_owner($pdo, false);

$config = jysmtp_load_config($pdo);
$ready = jysmtp_config_is_ready($config);
$cryptoReady = jysmtp_crypto_available();
$passwordConfigured = (string)$config['password_encrypted'] !== ''
    && jysmtp_decrypt_password((string)$config['password_encrypted']) !== null;
$base = rtrim((string)ADMIN_BASE_PATH, '/');
$saveUrl = $base . '/?page=admin/settings/smtp-jyavani/save';
$emailUrl = $base . '/?page=admin/settings/email';
?>
<section class="jysmtp-shell">
  <header class="jysmtp-hero">
    <div class="jysmtp-hero__mark" aria-hidden="true"><?= function_exists('svg_ico') ? svg_ico('mail') : 'SMTP' ?></div>
    <div class="jysmtp-hero__copy">
      <span><?= jysmtp_h(jysmtp_t('SECURE MAIL RELAY')) ?></span>
      <h1><?= jysmtp_h(jysmtp_t('SMTP Jyavani')) ?></h1>
      <p><?= jysmtp_h(jysmtp_t('Connect the Core Mail API to an authenticated SMTP provider or a trusted local relay.')) ?></p>
    </div>
    <div class="jysmtp-state <?= $ready ? 'is-ready' : 'is-pending' ?>">
      <b><?= jysmtp_h($ready ? jysmtp_t('Ready') : jysmtp_t('Setup required')) ?></b>
      <small><?= jysmtp_h($ready ? jysmtp_t('The SMTP transport can be selected in Email Delivery.') : jysmtp_t('Complete the required connection fields.')) ?></small>
    </div>
  </header>

  <div class="jysmtp-grid">
    <form class="jysmtp-panel jysmtp-panel--form" method="post" action="<?= jysmtp_h($saveUrl) ?>" autocomplete="off">
      <input type="hidden" name="csrf_token" value="<?= jysmtp_h(csrf_token()) ?>">
      <div class="jysmtp-panel__head">
        <div><span>01</span><h2><?= jysmtp_h(jysmtp_t('Connection')) ?></h2></div>
        <p><?= jysmtp_h(jysmtp_t('TLS certificate and hostname verification are always enforced.')) ?></p>
      </div>

      <div class="jysmtp-fields">
        <label class="jysmtp-field jysmtp-field--wide">
          <span><?= jysmtp_h(jysmtp_t('SMTP host')) ?></span>
          <input name="host" maxlength="253" required spellcheck="false" inputmode="url" placeholder="smtp.example.com" value="<?= jysmtp_h($config['host']) ?>">
          <small><?= jysmtp_h(jysmtp_t('Enter a hostname or IP address without a URL scheme.')) ?></small>
        </label>

        <label class="jysmtp-field">
          <span><?= jysmtp_h(jysmtp_t('Port')) ?></span>
          <input name="port" type="number" min="1" max="65535" required value="<?= (int)$config['port'] ?>">
        </label>

        <label class="jysmtp-field">
          <span><?= jysmtp_h(jysmtp_t('Encryption')) ?></span>
          <select name="encryption" required>
            <option value="starttls" <?= $config['encryption'] === 'starttls' ? 'selected' : '' ?>>STARTTLS</option>
            <option value="tls" <?= $config['encryption'] === 'tls' ? 'selected' : '' ?>><?= jysmtp_h(jysmtp_t('Implicit TLS')) ?></option>
            <option value="none" <?= $config['encryption'] === 'none' ? 'selected' : '' ?>><?= jysmtp_h(jysmtp_t('No encryption (unauthenticated relay only)')) ?></option>
          </select>
        </label>

        <label class="jysmtp-field">
          <span><?= jysmtp_h(jysmtp_t('Timeout')) ?></span>
          <div class="jysmtp-unit"><input name="timeout" type="number" min="2" max="30" required value="<?= (int)$config['timeout'] ?>"><em><?= jysmtp_h(jysmtp_t('seconds')) ?></em></div>
        </label>

        <label class="jysmtp-toggle jysmtp-field--wide">
          <input type="checkbox" name="authentication" value="1" <?= $config['authentication'] ? 'checked' : '' ?>>
          <span><b><?= jysmtp_h(jysmtp_t('SMTP authentication')) ?></b><small><?= jysmtp_h(jysmtp_t('Supports AUTH PLAIN and AUTH LOGIN after the connection is encrypted.')) ?></small></span>
        </label>

        <label class="jysmtp-field">
          <span><?= jysmtp_h(jysmtp_t('Username')) ?></span>
          <input name="username" maxlength="320" spellcheck="false" autocomplete="off" value="<?= jysmtp_h($config['username']) ?>">
        </label>

        <label class="jysmtp-field">
          <span><?= jysmtp_h(jysmtp_t('Password')) ?></span>
          <input name="password" type="password" maxlength="4096" autocomplete="new-password" placeholder="<?= jysmtp_h($passwordConfigured ? jysmtp_t('Stored securely - leave blank to keep') : jysmtp_t('Enter SMTP password')) ?>">
          <small><?= jysmtp_h(jysmtp_t('The stored password is never displayed again.')) ?></small>
        </label>

        <?php if ($passwordConfigured): ?>
        <label class="jysmtp-toggle jysmtp-toggle--danger jysmtp-field--wide">
          <input type="checkbox" name="clear_password" value="1">
          <span><b><?= jysmtp_h(jysmtp_t('Remove stored password')) ?></b><small><?= jysmtp_h(jysmtp_t('Disable authentication before removing its password.')) ?></small></span>
        </label>
        <?php endif; ?>
      </div>

      <div class="jysmtp-actions">
        <button class="adam-button" type="submit"><?= function_exists('svg_ico') ? svg_ico('save') : '' ?> <?= jysmtp_h(jysmtp_t('Save SMTP Settings')) ?></button>
        <a class="adam-button ghost" href="<?= jysmtp_h($emailUrl) ?>"><?= jysmtp_h(jysmtp_t('Open Email Delivery')) ?></a>
      </div>
    </form>

    <aside class="jysmtp-side">
      <article class="jysmtp-panel">
        <div class="jysmtp-panel__head"><div><span>02</span><h2><?= jysmtp_h(jysmtp_t('Security posture')) ?></h2></div></div>
        <ul class="jysmtp-checks">
          <li class="<?= $cryptoReady ? 'is-ok' : 'is-bad' ?>"><b><?= jysmtp_h(jysmtp_t('Credential encryption')) ?></b><small><?= jysmtp_h($cryptoReady ? jysmtp_t('Available') : jysmtp_t('Application secret missing')) ?></small></li>
          <li class="is-ok"><b><?= jysmtp_h(jysmtp_t('TLS verification')) ?></b><small><?= jysmtp_h(jysmtp_t('Peer and hostname verification enforced')) ?></small></li>
          <li class="<?= $passwordConfigured || !$config['authentication'] ? 'is-ok' : 'is-bad' ?>"><b><?= jysmtp_h(jysmtp_t('SMTP credential')) ?></b><small><?= jysmtp_h($passwordConfigured ? jysmtp_t('Encrypted at rest') : ($config['authentication'] ? jysmtp_t('Not configured') : jysmtp_t('Not required'))) ?></small></li>
        </ul>
      </article>

      <article class="jysmtp-panel jysmtp-guide">
        <div class="jysmtp-panel__head"><div><span>03</span><h2><?= jysmtp_h(jysmtp_t('Activation path')) ?></h2></div></div>
        <ol>
          <li><span>1</span><?= jysmtp_h(jysmtp_t('Save and validate the SMTP connection settings here.')) ?></li>
          <li><span>2</span><?= jysmtp_h(jysmtp_t('Open Email Delivery and select SMTP as the primary transport.')) ?></li>
          <li><span>3</span><?= jysmtp_h(jysmtp_t('Save a valid From address, then send a test email.')) ?></li>
        </ol>
        <p><?= jysmtp_h(jysmtp_t('Transport acceptance does not guarantee inbox delivery. Configure SPF, DKIM, and DMARC for the sender domain.')) ?></p>
      </article>
    </aside>
  </div>
</section>
