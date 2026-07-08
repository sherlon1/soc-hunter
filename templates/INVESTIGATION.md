---
investigation_id: I-XXXX
title: "[Investigation Title]"
type: exploratory
date: YYYY-MM-DD
investigator: "[Your Name]"
status: open
tags: []
related_hunts: []
reference_guide: null
promoted_to: null
---

# I-XXXX: [Investigation Title]

**Type:** exploratory | finding | triage | validation
**Date:** YYYY-MM-DD
**Status:** open | closed | promoted
**Reference Guide:** [Guide name if used, or "none"]

---

## Trigger

[What prompted this investigation? An alert, a question, a hunch, a Slack/Teams thread? One sentence.]

## Recon

[Quick context: who/what is involved? User profile, asset context, prior hunts. 1-2 queries max.]

## Assess

[What did you find? Targeted queries, results, observations. Follow the evidence — no minimum or maximum.]

### Queries Run

[Document queries executed with time ranges and results.]

## Conclude

[What was the outcome? Must pick one:]
- **No action needed** — benign / expected behavior
- **Needs formal hunt** — promote to H-XXXX with `/soc-hunter hunt`
- **Needs escalation** — hand off to `/ir-triage`
- **Informational** — useful context for future reference

## Emit

[What concrete action leaves this investigation?]
- [ ] [Action item — e.g., promote to H-XXXX, file ticket, update detection rule, update false-positives.md, close]
