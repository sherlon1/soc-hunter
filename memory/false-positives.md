# Known False Positive Patterns

> Analyst-confirmed false positives from past hunts. Consult during CHECK phase.
>
> **NEVER auto-dismiss a match** — always present to the analyst with the source hunt ID and ask
> for confirmation. Conditions change (personnel, infrastructure, new threat intel). A pattern
> that was benign in H-0001 may be malicious today.
>
> Format per entry:
> - **Pattern**: what the query result looks like
> - **Source hunt**: H-XXXX (hunt where this was confirmed)
> - **Data source**: SIEM index, EDR, or MCP tool
> - **Reason**: why this is benign
> - **Caveats**: when this might NOT be benign

---

<!-- Add entries below after analyst confirmation. Examples:

## Service account svc_backup authenticating to all file servers

- Source hunt: H-0003
- Data source: <auth_index>
- Reason: Backup job runs nightly; touches all file servers by design
- Caveats: If seen outside maintenance window (02:00–04:00 UTC), investigate. If new hosts appear, investigate.

## EDR agent on ACME-JUMPBOX01 spawning cmd.exe → net.exe

- Source hunt: H-0007
- Data source: EDR
- Reason: Helpdesk runbook uses net commands for account resets from the jump box
- Caveats: If source user is not in the helpdesk AD group, this is NOT benign.

-->
