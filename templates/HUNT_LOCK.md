---
hunt_id: H-XXXX
title: "[Hunt Title]"
status: planning
date: YYYY-MM-DD
hunter: "[Your Name]"
platform: "[Windows/Linux/macOS/Cloud/Multi-Platform]"
tactics: []
techniques: []
data_sources:
  siem: []
  vm_mcp: []
  edr: []
  cspm: []
  casb: []
  ldap: []
  log_analytics: []
  scm: []
  code_search: []
related_hunts: []
baselines: []
findings_count: 0
true_positives: 0
false_positives: 0
inconclusive: 0
tags: []
---

# H-XXXX: [Hunt Title]

**Hunt Metadata**

- **Date:** YYYY-MM-DD
- **Hunter:** [Your Name]
- **Status:** Planning
- **MITRE ATT&CK:** [Tactic] / [Technique ID] — [Technique Name]

---

## LEARN: Prepare the Hunt

### Hypothesis Statement

[One sentence, testable: "Adversaries use [behavior] to [goal] on [target system]"]

### Threat Context

[What threat actor, malware, TTP, or anomaly motivates this hunt? Why now?]

### ABLE Scoping

| Field | Value |
|-------|-------|
| **Actor** *(Optional)* | [Threat actor or malware family] |
| **Behavior** | [TTP or behavior pattern — focus on top of Pyramid of Pain] |
| **Location** | [Systems, networks, environments, cloud accounts to hunt] |
| **Evidence** | [Data sources, indexes, key fields to examine] |

### Threat Intel & Research

- **MITRE ATT&CK Techniques:** [List with IDs]
- **CTI Sources:** [Links to reports, advisories, blogs]
- **Related Past Hunts:** [H-XXXX references with lessons learned]

### Related Tickets

| Team | Ticket/Details |
|------|----------------|
| SOC/IR | [Ticket numbers or N/A] |

---

## OBSERVE: Expected Behaviors

### What Normal Looks Like

[Describe legitimate activity that should NOT trigger alerts]

### What Suspicious Looks Like

[Describe adversary behavior patterns to hunt for]

### Expected Observables

- **Processes:** [Process names, command lines, parent-child relationships]
- **Network:** [Connections, protocols, domains, ports]
- **Files:** [File paths, extensions, sizes, hashes]
- **Authentication:** [Login patterns, service accounts, MFA status]
- **Cloud:** [API calls, IAM changes, resource modifications]

---

## CHECK: Execute & Analyze

### Data Source Information

- **Time Range:** [Start — End]
- **Events Analyzed:** [Approximate count after execution]
- **Data Quality:** [Assessment of completeness and gaps]

### Query 1: SIEM — [Description]

**Index:** [index name from memory/siem-indexes.md]
**Purpose:** [What this query looks for]

```spl
[Query with time bounds and row limits]
```

**Count Result:** [N events matched]
**Analysis:** [What did this return? Suspicious? Expected?]

### Query 2: EDR — [Description]

**Generated via:** [EDR AI query tool]
**Purpose:** [What this query looks for]

```
[Generated EDR query]
```

**Count Result:** [N events matched]
**Analysis:** [What did this return?]

### Query 3: VM Inventory — [Description] *(MANDATORY)*

**Source:** Layer 3a (VM MCP) or Layer 3b (SIEM <vm_inventory_index>)
**Purpose:** [Software inventory, process list, browser extensions, plugin output search]

```
[VM MCP tool call or SIEM query against <vm_inventory_index>]
```

**Count Result:** [N events matched]
**Analysis:** [What did this return?]

### Query 4: LDAP / Active Directory — [Description] *(if AD/identity involved)*

**Purpose:** [Group membership, computer accounts, SID resolution]

```
[LDAP filter and results]
```

**Analysis:** [Findings — authoritative AD state]

### Query 5: CSPM — [Description] *(if cloud involved)*

**Purpose:** [Cloud posture or risk context]

```
[CSPM query]
```

**Analysis:** [Findings, risks, misconfigurations]

### Query 6: CASB — [Description] *(if shadow IT / exfil involved)*

**Event Type:** [alert / application / network / dlp]
**Purpose:** [CASB/SSE context]

**Analysis:** [Findings]

### Query 7: Log Analytics — [Description] *(if cloud audit involved)*

**Log Source:** [cloud audit log source]
**Purpose:** [Cloud API / IAM cross-account analysis]

```
[Log analytics query]
```

**Analysis:** [Findings]

### Query 8: Code Search — [Description] *(if supply chain / credential exposure / IaC involved)*

**Tool:** [search_code / query_dependencies / search_infra / search_services]
**Purpose:** [Dependency blast radius, hardcoded secret search, IaC misconfiguration]

**Query:** [Natural language query used]

**Results:**

| Repo | File | Match | Context |
|------|------|-------|---------|
| | | | |

**Analysis:** [What did this return? Cross-reference with runtime data (CSPM, VM inventory, EDR)]

### Query 9: IOC Enrichment — [Description] *(if applicable)*

**Sources:** [VT / GreyNoise / OTX / Your TIP]
**IOCs Enriched:** [List]

**Results:**

| IOC | Type | VT Score | GreyNoise | OTX Pulses | Verdict |
|-----|------|----------|-----------|------------|---------|
| | | | | | |

### Correlation Analysis

[How do findings across data sources connect? Timeline? Common entities?]

### Query Performance

**What Worked Well:**
- [Effective filters or techniques]

**What Didn't Work:**
- [Challenges, gaps, limitations]

---

## KEEP: Findings & Response

### Executive Summary

[2-3 sentences: what was hunted, what was found, what action is needed]

### Findings

| # | Finding | Verdict | Severity | Ticket |
|---|---------|---------|----------|--------|
| 1 | [Description] | TP/FP/Inconclusive | High/Med/Low | [TICKET-XXXX] |

**True Positives:** [Count]
**False Positives:** [Count]
**Inconclusive:** [Count]

### Detection Opportunity

**Can this become an automated detection?** [Yes/No — explain]

**Proposed Detection Rule:**

```
[Detection query or correlation rule if applicable]
```

### Lessons Learned

**What Worked Well:**
- [Successes]

**What Could Be Improved:**
- [Areas for improvement]

**Telemetry Gaps Identified:**
- [Missing data sources, fields, or visibility]

**False Positive Filters for Future:**
- [Known-good patterns to exclude next time]

### Follow-up Actions

- [ ] Upload IOCs to EDR (`/ioc-uploader`)
- [ ] Create ticket (`/ticketing-skill`)
- [ ] Escalate to IR (`/ir-triage`)
- [ ] Create detection rule
- [ ] Schedule recurring hunt
- [ ] [Additional actions]

### Follow-up Hunts

- [Related hunt ideas for future investigation]

---

**Hunt Completed:** YYYY-MM-DD
**Next Review:** [Date for recurring hunt, or N/A]
