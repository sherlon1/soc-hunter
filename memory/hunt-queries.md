# Hunt Query Library

> Proven queries from past hunts. Reference these in the LEARN phase before generating new queries.
> Consult this file before writing new queries — reuse what worked.
>
> Format per entry:
> - **Data source**: SIEM index, EDR tool, or MCP tool
> - **Hunt**: H-XXXX (source hunt ID)
> - **Tags**: MITRE tactic/technique, free-form
> - **Query**: the actual query
> - **Notes**: field names, filters, caveats

---

<!-- Add entries below as you run hunts. Examples:

## SIEM — Service account auth to unusual hosts

- Hunt: H-0001
- Tags: lateral-movement, T1078.002, service-accounts
- Query: `index=<auth_index> user="svc_*" | stats dc(dest) as unique_hosts by user | where unique_hosts > 5`
- Notes: Adjust threshold based on your service account baseline. Cross-reference with LDAP group membership.

## EDR — Encoded PowerShell execution on endpoints

- Hunt: H-0002
- Tags: execution, T1059.001
- Query: (generated via EDR AI query tool) "Find process creation events where command line contains '-enc' or '-EncodedCommand' in the last 7 days"
- Notes: High noise on developer workstations — filter by host role if available.

-->
