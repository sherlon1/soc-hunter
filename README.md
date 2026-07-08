# SOC-Hunter

> Proactive threat hunting using the LOCK pattern across your security data sources.

## What It Does

SOC-Hunter brings structured, hypothesis-driven hunting to your IR workstation. Instead of reacting to alerts (`/ir-triage`), you proactively search for adversary behavior that automated detections miss.

The skill uses the **LOCK pattern** (Learn, Observe, Check, Keep) adapted from the [Agentic Threat Hunting Framework](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework) and orchestrates queries across your SIEM, EDR, Vulnerability Management, CSPM, CASB, Log Analytics, IPAM, and Code Search platforms via MCP.

**Features:**
- Seven hunting modes (hunt, research, execute, review, baseline, investigate, lookup)
- Multi-source correlation (SIEM → EDR → Code Search → CSPM → CASB → Enrichment)
- MITRE ATT&CK mapping with **live STIX coverage analysis**
- Persistent hunt memory in `hunts/`, research in `research/`, investigations in `investigations/`
- Hunt quality tools — similarity search, validation, ATT&CK lookup
- Pluggable tech stack — configure your own MCP servers, indexes, and credentials via `CONFIG.md`
- Integration with /ioc-analyst, /ioc-uploader, /ticketing-skill, /ir-triage

---

## Requirements

### Claude Code Version

Claude Code >= 1.0.0

### MCP Servers

Configure your actual MCP server names in `CONFIG.md`. The following **types** of MCP servers are needed:

| Type | Examples | Required For |
|--------|----------|-------------|
| `siem-mcp` | Splunk MCP, Elastic MCP, Sentinel MCP | SIEM log queries |
| `edr-mcp` | SentinelOne Purple AI, CrowdStrike Falcon MCP, Defender MCP | Endpoint telemetry, AI query generation |
| `vm-mcp` | Tenable MCP, Qualys MCP, Rapid7 MCP | Asset inventory, CVE exposure, software |
| `cspm-mcp` | Wiz MCP, Prisma MCP, Orca MCP | Cloud posture, findings, IAM |
| `casb-mcp` | Netskope MCP, Zscaler MCP | DLP, app events, network events |
| `log-analytics-mcp` | Coralogix MCP, Datadog MCP | Cloud audit logs (CloudTrail, etc.) |
| `code-search-mcp` | Sourcegraph MCP, GitHub Code Search MCP | Source code, dependencies, IaC |
| `ipam-mcp` | NetBox MCP, Infoblox MCP | IP address context, subnet ownership |

Not all MCP servers are required — the skill works with whatever is available and reports which sources are unavailable.

### Memory Files

| File | Purpose |
|------|---------|
| `memory/siem-indexes.md` | Your SIEM index name reference |
| `memory/hunt-queries.md` | Saved queries for reuse |
| `memory/false-positives.md` | Known FP patterns from past hunts |
| `memory/attack-coverage.md` | MITRE ATT&CK technique coverage matrix |
| `memory/telemetry-gaps.md` | Consolidated telemetry gaps by severity |
| `memory/detections.md` | Recommended detection rules from hunts |

---

## Setup

> **Start with step 1 (CONFIG.md).** Without it the agent will call MCP tools with placeholder
> names (`mcp__vm-mcp__`, `<auth_index>`, etc.) that won't match your installation.
> All other steps can be done in any order — step 1 must come first.

### 0. Install the Skill

```bash
# Symlink into Claude Code's skill directory (recommended — stays current with updates)
ln -s "$PWD" ~/.claude/skills/soc-hunter

# Or copy it
cp -r "$PWD" ~/.claude/skills/soc-hunter

# Verify Claude Code sees it
ls ~/.claude/skills/soc-hunter/skill.json
```

The skill is invoked as `/soc-hunter` in any Claude Code session.

### 1. Configure Your Tech Stack ← **do this first**

```bash
cp CONFIG.md CONFIG.local.md   # Keep your config local — never commit this
# Edit CONFIG.local.md — work through all 10 sections to map placeholders to your actual values
```

`CONFIG.md` covers: MCP server names, SIEM index names, SIEM query language (if not Splunk),
EDR platform, VM platform, LDAP credentials, IOC enrichment API keys, hunt file storage,
hunt index tracking, and unavailable sources to skip.

### 2. Create Working Directories and Populate Memory Files

```bash
mkdir -p memory hunts research investigations baselines

# memory/siem-indexes.md ships with a blank template — fill in your index names
# memory/hunt-queries.md — start empty; populate as you run hunts
# memory/false-positives.md — start empty; populate after confirmed FPs
```

### 3. Install Python Dependencies

```bash
pip install scikit-learn ldap3 pyyaml requests
```

| Package | Used by |
|---|---|
| `scikit-learn` | `hunt-similar.py` (TF-IDF duplicate detection) |
| `ldap3` | LDAP/AD queries during hunts |
| `pyyaml` | `hunt-validate.py --fix` (frontmatter auto-repair) |
| `requests` | `scripts/ir/ioc-enrich.py` (IOC enrichment) |

### 4. Download MITRE ATT&CK STIX Bundle

```bash
python3 scripts/attack-lookup.py --update
# Downloads ~43 MB to data/enterprise-attack.json
# Required for lookup, review, and coverage modes
```

### 5. Configure IOC Enrichment API Keys (optional)

```bash
# Add to ~/.bashrc or ~/.zshrc — leave blank to skip that source
export VT_API_KEY="your-virustotal-key"
export GREYNOISE_API_KEY="your-greynoise-key"
export OTX_API_KEY="your-otx-key"
```

Get free API keys at: [VirusTotal](https://www.virustotal.com/gui/my-apikey) · [GreyNoise](https://viz.greynoise.io/account/api-key) · [OTX](https://otx.alienvault.com/api)

### 6. Test

```bash
claude /soc-hunter research T1078.002
```

---

## Usage

### Mode 1: hunt — Full LOCK Cycle

```
/soc-hunter hunt T1078.002 -- Valid accounts: domain accounts
/soc-hunter hunt Qakbot DLL sideloading campaign
/soc-hunter hunt suspicious service account behavior in Azure
/soc-hunter hunt LSASS credential dumping
```

**What happens:**
1. **LEARN**: Forms hypothesis, checks past hunts, presents ABLE scoping table
2. **OBSERVE**: Defines normal vs suspicious behavior, maps observables to data sources
3. **CHECK**: Executes queries (count-first, one at a time, with approval)
4. **KEEP**: Writes hunt file to `hunts/H-XXXX.md`, classifies findings, offers follow-up actions

### Mode 2: research — Structured Pre-Hunt Research

5-skill research methodology that produces a persistent R-XXXX document in `research/`.

```
/soc-hunter research Kerberoasting in hybrid Azure AD
/soc-hunter research supply chain attacks via npm packages
/soc-hunter research T1003 credential dumping sub-techniques
```

### Mode 3: execute — Re-run Existing Hunt

```
/soc-hunter execute H-0003
/soc-hunter execute H-0015 -- last 24 hours only
```

### Mode 4: review — Coverage Gap Analysis

```
/soc-hunter review
/soc-hunter review -- focus on credential access
/soc-hunter review -- top 5 gaps
```

Powered by `attack-lookup.py` — visual coverage bars, prioritized gap recommendations.

### Mode 5: baseline — Deviation Detection

```
/soc-hunter baseline establish service-accounts -- last 30 days
/soc-hunter baseline compare service-accounts -- current week
/soc-hunter baseline list
/soc-hunter baseline show B-0003
```

### Mode 6: investigate — TRACE Framework

Lightweight structured investigations (Trigger, Recon, Assess, Conclude, Emit). Produces I-XXXX documents in `investigations/`.

```
/soc-hunter investigate weird DNS queries from ACME-PC01
/soc-hunter investigate is the Domain Admins group membership unchanged?
/soc-hunter investigate Slack report of suspicious email attachment
```

### Mode 7: lookup — ATT&CK Quick Reference

```
/soc-hunter lookup T1003.001
/soc-hunter lookup --tactic credential-access
/soc-hunter lookup --gaps --tactic lateral-movement
```

---

## Data Source Layers

```
Layer 0:   IOC Recon Sweep (fast bloom-filter — identifies where to focus)
Layer 1:   SIEM (broadest reach — auth, network, endpoint, cloud)
Layer 1b:  LDAP / Active Directory (definitive identity answers)
Layer 1c:  IPAM (network asset context for IP addresses)
Layer 2:   EDR (endpoint forensics)
Layer 2b:  Code Search (source code & IaC) [conditional]
Layer 3a:  VM MCP [MANDATORY every hunt] (real-time asset/vuln/software)
Layer 3b:  SIEM VM Inventory [MANDATORY every hunt] (full-text plugin output sweep)
Layer 4:   CSPM (cloud posture) [conditional]
Layer 5:   CASB (DLP, app events) [conditional]
Layer 6:   Log Analytics (cloud audit) [conditional]
Layer 7:   IOC Enrichment (VT, GreyNoise, OTX, or your TIP) [inline]
```

---

## The LOCK Pattern

| Phase | Purpose | Key Question |
|-------|---------|-------------|
| **Learn** | Prepare the hunt | What are we looking for and why? |
| **Observe** | Define expectations | What does normal vs suspicious look like? |
| **Check** | Execute and analyze | What does the data actually show? |
| **Keep** | Document and act | What did we find and what do we do about it? |

Adapted from the [Agentic Threat Hunting Framework](https://github.com/Nebulock-Inc/agentic-threat-hunting-framework) by Nebulock Inc.

---

## How It Works with Other Skills

| When... | Use... | Source |
|---------|--------|--------|
| Hunt finds IOCs to analyze | `/ioc-analyst` | internal skill |
| Hunt confirms IOCs to block | `/ioc-uploader` | internal skill |
| Hunt is complete and needs a ticket | `/ticketing-skill` | your org's ticketing skill |
| Hunt finding escalates to active incident | `/ir-triage` | internal skill |
| Hunt involves supply chain TTPs | `/supply-chain-skill` | internal skill |

The agent will suggest these integrations at the appropriate time but never invokes them without your approval.

These are optional — the skill works standalone without any of them.

---

## siem-field-schemas.json

`siem-field-schemas.json` ships with a generic template. It tells the agent which field names exist in each SIEM index so it can construct valid queries on the first attempt without wasting a round-trip on field discovery.

**How to populate it:**

1. Run your SIEM's field discovery against each index:
   - Splunk: `index=<name> | fieldsummary | table field count`
   - Elastic: `GET /<index>/_mapping`
   - Sentinel: `<Table> | getschema`
2. Update `siem-field-schemas.json` with the actual field names from your environment.
3. The `_meta.how_to_populate` key in the file explains this inline.

You do **not** need to populate every field to use the skill. Start with your highest-value indexes (`<vm_inventory_index>`, `<auth_index>`, `<edr_index>`) and add more as you run hunts.

---

## Hunt Quality Tools

### hunt-similar.py — Duplicate Detection

```bash
python3 scripts/hunt-similar.py "OAuth token abuse in SaaS"
python3 scripts/hunt-similar.py --hunt H-0015
python3 scripts/hunt-similar.py "supply chain npm" --json
```

### hunt-validate.py — Frontmatter Schema Validation

```bash
python3 scripts/hunt-validate.py
python3 scripts/hunt-validate.py H-0019 --fix
python3 scripts/hunt-validate.py --stats
```

### attack-lookup.py — MITRE ATT&CK STIX Reference

```bash
python3 scripts/attack-lookup.py T1003.001
python3 scripts/attack-lookup.py --coverage
python3 scripts/attack-lookup.py --gaps --tactic credential-access
python3 scripts/attack-lookup.py --update   # Download/refresh STIX bundle
```

---

## Troubleshooting

### "No results found"
Normal — not every hunt finds adversary activity. The agent will suggest adjusting time range, broadening filters, or trying different data sources. Negative results are documented and count toward coverage.

### "MCP server not configured"
The agent works with whatever servers are available. If a server is down, it reports which source is unavailable and continues with remaining sources.

### "Code search returns no results"
Check `get_index_stats` to verify the language/repo is indexed. Fall back to artifact registry CLI for supply chain or CSPM for cloud posture.

---

## Best Practices

1. **Start with research mode** for unfamiliar TTPs before committing to a full hunt
2. **Check past hunts** — the agent does this automatically, but reviewing `hunts/` yourself helps build institutional knowledge
3. **Follow ABLE scoping** — well-scoped hunts have lower false positive rates
4. **Count before detail** — the agent enforces this
5. **Document everything** — even negative results prove coverage and help future hunts
6. **Convert findings to detections** — if a hunt finds real adversary behavior, create a SIEM correlation rule
7. **Schedule recurring hunts** — revisit successful hunts quarterly with updated filters

---

## Changelog

### v2.0.0
- Genericized from Tenable-specific implementation to pluggable multi-platform skill
- All MCP server references replaced with generic types (siem-mcp, edr-mcp, vm-mcp, etc.)
- All SIEM index names replaced with configurable placeholders
- All internal credentials/scripts replaced with generic patterns
- Added `CONFIG.md` for tech stack configuration
- Added `siem-field-schemas.json` template

### v1.4.0
- Added TRACE framework to `investigate` mode
- Added Investigation Guides

### v1.3.0
- Added `attack-lookup.py`, Investigation Documents, Research Documents
- New modes: `investigate` and `lookup`

### v1.2.0
- Added `hunt-similar.py` and `hunt-validate.py`

### v1.0.0
- Initial release: LOCK pattern, five hunting modes, multi-source correlation
