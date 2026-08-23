# SMTP Jyavani Plugin

This repository is the authoritative source for the SMTP Jyavani plugin.

## Boundaries

- Keep `plugin.json` at the package root and release ZIPs flat.
- Use the `jysmtp_` prefix for functions, constants, and settings.
- Register only the `smtp` Core Mail API transport.
- Keep all public assets under `static/plugins/smtp-jyavani/`.
- Never log, render, or return SMTP credentials, message bodies, subjects, recipients, or raw server responses.
- Never allow authenticated SMTP over an unencrypted connection.
- Keep TLS peer and hostname verification enabled.
- Treat failures after sending SMTP DATA as non-retryable when acceptance is ambiguous.

## Verification

- Run PHP syntax checks for every PHP file.
- Run every `tests/*_contract.php` file.
- Build with `php tools/build-package.php <output>` and run the package contract against the ZIP.
- Exercise delivery against a local fake SMTP server before testing on an installed Jyavani site.
