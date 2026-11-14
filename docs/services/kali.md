# Outside test workstation

Use the [shared preflight](README.md#shared-preflight). This guide applies
only when an outside test workstation is provided and officials permit its
use. Helperbro does not provision Kali or authorize scanning.

## Confirm scope

1. Verify the workstation's actual address, route, time and user login.
   Record the approved test targets and the designated source network.
2. Obtain explicit authorization before connecting to any target. Do not
   scan other teams, infrastructure, organizers or unassigned public
   addresses. If a target or rule is unclear, stop and ask officials.
3. Keep console access and avoid changing the workstation's address, routes,
   firewall or tooling without a tested recovery.

## Test one approved service at a time

Coordinate with the owner, then use an approved client to verify the real
business/scoring transaction through the actual public/NAT path. For example,
validate web content, a test mailbox transfer, or an FTP file retrieval without
changing production data. Follow the relevant [service guide](README.md).

The optional [service probe](README.md#optional-service-probes) checks one
explicit target and does not discover hosts, authenticate, follow redirects or
prove scoring. Use the actual hostname for HTTPS certificate verification.
Record result, timestamp, source and destination; keep credentials and private
content out of shared logs.

After an approved service or network change, repeat the same authorized
transaction and verify the portal. A test failure should trigger the owning
team's tested recovery plan, not an automatic firewall or router change.
