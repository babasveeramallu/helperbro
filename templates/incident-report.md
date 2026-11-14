# Security Incident Report

**Incident ID:** [IR-YYYYMMDD-##]  
**Prepared by / role:** [name, role]  
**Reported to:** [White Team / Orange Team / other authorized contact]  
**Report time and timezone:** [YYYY-MM-DD HH:MM TZ]  
**Status:** [Open / Contained / Monitoring / Closed]

> Write one report per real incident: group related alerts into it, and don't report ordinary scanning or your own misconfigurations. Before submitting, check that it gives source and destination addresses, a timeline, any passwords cracked, what was affected and a remediation plan. Competition rules commonly require all five (for example, Midwest CCDC invitational Scoring rule 5).

## Executive Summary

[In 2-4 sentences: what happened, which system/service was affected, current business and scoring impact, and present status. Write for a reader who was not present.]

## Timeline

| Time (with timezone) | Event / observation | Source or evidence ID | Action / owner |
| --- | --- | --- | --- |
| [HH:MM] | [Fact, not inference] | [log path, event ID, screenshot ID] | [action, person] |

## Source and Destination

| Source address | Destination host / address | Port / protocol | First seen | Last seen | Seen in |
| --- | --- | --- | --- | --- | --- |
| [attacker address] | [our host and address] | [e.g. TCP 80] | [HH:MM] | [HH:MM] | [log, firewall, Splunk search] |

[If NAT hides the outside address, say so, and give the address as the edge firewall saw it.]

## Credentials Compromised or Cracked

Never write the passwords themselves.

| Account | Where it works | How we know | Reset at | Change request / reference |
| --- | --- | --- | --- | --- |
| [account] | [host, domain, application] | [cracked / used by attacker / exposed in file] | [HH:MM, or not yet] | [reference] |

[If no credentials were affected, write "None found" and say what was checked.]

## Affected Systems and Services

| Host / IP | OS / role | Service / port | Availability before and after | Data or identity impact |
| --- | --- | --- | --- | --- |
| [host] | [role] | [service] | [probe result and times] | [known / unknown] |

## Detection and Evidence

- **Detection source:** [event log, SIEM search, service monitor, user report]
- **Attacker activity observed:** [source address, account, process, file, timestamps; distinguish verified facts from hypotheses]
- **Evidence preserved:** [path, hash, collection time, collector; do not attach secrets]
- **Related Splunk search / alert ID:** [search, index/sourcetype, time range]

## Impact

- **Confidentiality / integrity / availability:** [known effects; state what has not been established]
- **Scoring-service impact:** [service probe, source, port, result, interval]
- **Business inject / SLA impact:** [inject ID, deadline, customer-facing effect]
- **Systems not yet assessed:** [list]

## Response Actions

| Action | Time | Operator | Result / verification | Rollback or follow-up |
| --- | --- | --- | --- | --- |
| [containment / credential disable / firewall rule] | [time] | [name] | [measured result] | [details] |

## Recovery and Validation

1. [Restore or patch from trusted source; record version/hash.]  
2. [Validate configuration, dependencies, and data integrity.]  
3. [Verify service from scoring network and team admin path; record exact probe and result.]  
4. [Monitor for recurrence through time / search.]  
5. [Notify White/Orange Team and record acknowledgement.]

## Remediation Plan

How the way in is closed so it can't happen again, not only how service came back.

- **Root cause:** [how the attacker got in: weak password, planted key, unpatched service; or "not yet known"]
- **Done:** [each fix, with time and who; e.g. "removed planted SSH key, 10:52, J."]
- **Still planned:** [each fix, owner, and when]
- **How we'll know it worked:** [the check or search that would show a repeat]

## Open Questions and Next Actions

| Question / task | Owner | Due time | Status |
| --- | --- | --- | --- |
| [item] | [name] | [time] | [open] |

## Approvals / Handoff

**Prepared by:** [name / time]  
**Reviewed by:** [name / time]  
**White Team acknowledgement or incident reference:** [reference]
