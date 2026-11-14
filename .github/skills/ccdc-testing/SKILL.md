---
name: ccdc-testing
description: Validate helperbro changes without modifying live competition services, firewalls, accounts, DNS or Splunk.
---

# Helperbro testing

1. Identify the changed role, supported OS, existing test and exact behavior.
   Record what needs a matching practice VM instead of assuming fixture tests
   prove real network, authentication, rollback or ingestion behavior.
2. Run the smallest existing regression suite covering the change. Use
   `windows\Test-ServiceProbe.ps1` and `linux/test-service-probe.sh` for probes;
   `windows\Test-AddnsGuard.ps1` for the AD/DNS authorization guard; and the
   existing firewall and Splunk tests for those components.
3. Use temporary fixtures and loopback only. Never apply firewall, AD, DNS,
   Splunk, account or appliance changes to the operator's machine or a
   competition system as a test. Preserve existing files and clean up only
   specific fixture paths created by the test.
4. Do not install tools or packages unless a chosen check fails because they
   are missing and installation is authorized. Report skipped checks and
   unverified live behavior. Never include event credentials or private
   planning data in public fixtures or test output.
