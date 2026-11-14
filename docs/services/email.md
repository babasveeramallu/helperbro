# Email deployment

Use the [shared preflight](README.md#shared-preflight). Identify the actual
mail stack, domain/DNS, mailbox store, SMTP, POP/IMAP, webmail, authentication
provider, TLS and relay dependencies. Helperbro does not install or configure
the mail server.

## Inspect

On the mail host, identify services and listeners without restarting them:

```bash
hostname
sudo ss -lntup
sudo systemctl --failed
```

Compare actual ports with the live service/scoring requirements; do not assume
every protocol is enabled or unscored. Coordinate firewall, DNS, AD and
credential changes with their owners. Back up mail configuration and
mailboxes with a tested restore, preserving users and messages.

## Validate the actual service

From authorized clients, test the approved SMTP submission and delivery path,
then retrieve a test message using the expected POP/IMAP or webmail workflow.
Use designated test mailboxes; never put passwords in command arguments.
Confirm sender, recipient and message contents as well as TLS certificate
identity. The optional service probe checks only the initial plaintext banner;
it cannot validate encrypted mail, a login, delivery or mailbox contents.

Confirm mail logs reach the intended index if forwarding is configured.
Recheck the portal and all dependent login paths after each change. If mail
breaks, stop further changes and use the tested mail-specific restore; a host
firewall rollback does not restore mail data or credentials.
