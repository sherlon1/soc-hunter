---
research_id: R-XXXX
title: "[Research Topic]"
technique: "[TXXXX or TXXXX.XXX]"
tactics: []
date: YYYY-MM-DD
researcher: "[Your Name]"
status: draft
spawned_hunts: []
tags: []
---

# R-XXXX: [Research Topic]

**Technique:** [MITRE ATT&CK ID] — [Technique Name]
**Date:** YYYY-MM-DD
**Status:** draft | complete

---

## 1. System Research

[How does the targeted system/service/protocol normally work? What is the legitimate use case?]

## 2. Adversary Tradecraft

[How do adversaries abuse this? Known TTPs, threat actors, malware families, real-world examples from CTI.]

## 3. Telemetry Mapping

[What data sources capture this behavior in your environment?]

| Observable | Data Source | Index / MCP Tool | Field(s) | Coverage |
|-----------|------------|-----------------|----------|----------|
| [Process execution] | [EDR] | [EDR AI query] | [cmd_line, parent_process] | [Full / Partial / None] |
| [Auth event] | [SIEM] | [<auth_index>] | [user, outcome] | [Full / Partial / None] |

## 4. Related Work

[Past hunts, investigations, or external research on this topic:]

| Source | Reference | Key Takeaway |
|--------|-----------|-------------|
| [H-XXXX] | [Internal hunt] | [What was found / lessons learned] |
| [CTI report] | [URL or title] | [Relevant IOCs, TTPs, context] |

## 5. Synthesis & Recommendation

**Hypothesis:** [One testable sentence for a formal hunt]

**Feasibility:** [High / Medium / Low — based on telemetry coverage]

**Recommended Hunt Scope:**
- **Tactic:** [MITRE tactic]
- **Technique:** [MITRE technique ID]
- **Platform:** [Windows / Linux / Cloud / Multi]
- **Primary Data Sources:** [Top 2-3 sources]
- **Estimated Effort:** [Light / Medium / Heavy]

**Decision:** [Proceed to hunt / Defer / Insufficient telemetry / Already covered by H-XXXX]
