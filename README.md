# SMTP Jyavani

SMTP Jyavani adds a secure `smtp` transport to the transport-neutral Mail API introduced in Jyavani Core 2.3.82.

## Features

- Implicit TLS (SMTPS) and STARTTLS with mandatory certificate and hostname verification.
- `AUTH PLAIN` and `AUTH LOGIN` only after transport encryption is active.
- Trusted unencrypted relay mode without authentication for local mail infrastructure.
- Sodium-encrypted password storage. Stored credentials are never rendered back into the dashboard.
- Bounded connection, command, message, and overall delivery limits.
- Conservative failure handling that prevents Core fallback after ambiguous post-DATA disconnects.
- Site Owner-only settings, POST/CSRF protection, and redacted operational behavior.
- Indonesian and German dashboard translations.

## Requirements

- Jyavani Core 2.3.82 or newer.
- PHP 8.1 or newer.
- PHP extensions: JSON, mbstring, OpenSSL, PDO, and Sodium.
- A valid application secret of at least 32 bytes. The plugin uses the first available value from:
  1. `SMTP_JYAVANI_KEY`
  2. `APP_KEY`
  3. `SESSION_SECRET`

For independent credential rotation, add a random `SMTP_JYAVANI_KEY` to the protected Jyavani `.env` before saving the SMTP password. Changing that key later makes the existing encrypted password unreadable and requires entering it again.

Private SMTP certificate authorities can be supplied with an absolute readable `SMTP_JYAVANI_CA_FILE` path. Peer and hostname verification remain mandatory.

## Installation

1. Build or obtain the flat plugin ZIP.
2. Install and activate it through Jyavani Plugin Manager.
3. Open **Settings > SMTP** and save the connection details.
4. Open **Settings > Email**, select **SMTP** as the primary transport, and configure a valid From address.
5. Send a test email from Core Email Delivery.

The plugin does not add a public send endpoint. Feature plugins continue calling `jy_mail_send()` and remain independent of this adapter.

## Security Model

- Raw SMTP replies, credentials, recipients, subjects, and bodies are not logged or returned.
- Authentication over plaintext SMTP is rejected. Plaintext mode is only for an unauthenticated trusted relay.
- Certificate verification cannot be disabled through plugin settings.
- TLS 1.2 is the minimum negotiated protocol; TLS 1.3 is used when available.
- SMTP 4xx failures before acceptance are temporary; deterministic 5xx/configuration failures are permanent.
- A lost connection after DATA may have accepted a message. The plugin reports that ambiguous state as permanent to suppress fallback and avoid duplicate delivery.
- All recipients must be accepted before DATA begins, so a rejected recipient cannot produce partial delivery.
- Removing the plugin without retaining data deletes its encrypted SMTP configuration. Core cannot run cleanup hooks from a plugin that was already disabled before uninstall, so remove the stored setting manually if that exceptional workflow is used.

## Development

```bash
php tests/contract.php
php tests/config_contract.php
php tests/smtp_contract.php
php tests/security_contract.php
php tests/uninstall_contract.php
php tools/build-package.php /tmp/opencode/smtp-jyavani-1.0.0.zip
php tests/package_contract.php /tmp/opencode/smtp-jyavani-1.0.0.zip
```

## License

MIT
