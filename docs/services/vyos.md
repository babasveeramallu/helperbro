# VyOS router deployment

Use the [shared preflight](README.md#shared-preflight). Helperbro does not
configure VyOS. Confirm the running version, real interfaces, management
address, routes, NAT, firewall policy and logging destinations from the live
device; example team values are not proof of the assigned environment.

## Before any change

1. Keep console access and establish a second management path if available.
2. Save an approved copy of the active configuration and verify the actual
   restore procedure. Coordinate with other operators and review their
   pending changes before committing.
3. Practice the installed version's confirmed-commit and rollback semantics
   on a matching lab router. A timer or command from another release may not
   behave the same way.

## Change and validate

Apply one approved change at a time using the supported device workflow.
Keep official access, routing, return traffic, public scored services, ping,
NAT and required logging intact. Never change addresses or routes based only
on an old topology drawing.

From authorized clients, verify the default route, reachability through each
relevant path, actual service transactions and the scoring portal. Generate a
new router log and confirm receipt in Splunk. Before confirming a timed change,
verify both management and service traffic. If a check fails, use the
version-specific tested rollback and recheck all dependent paths.
