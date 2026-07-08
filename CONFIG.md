# SOC-Hunter — Configuration Guide

This file maps the generic placeholders used throughout the skill to your actual tech stack.
Copy this file, fill in your values, and keep it alongside the skill.

---

## 1. MCP Servers

Update `skill.json` `requires.mcp_servers` to match the names you registered in your Claude config.

| Placeholder | What it represents | Your MCP server name |
|---|---|---|
| `siem-mcp` | SIEM (Splunk, Elastic, Sentinel, etc.) | `________________` |
| `edr-mcp` | EDR (SentinelOne, CrowdStrike, Defender, etc.) | `________________` |
| `vm-mcp` | Vulnerability Management (Tenable, Qualys, Rapid7, etc.) | `________________` |
| `cspm-mcp` | Cloud Security Posture (Wiz, Prisma, Orca, Tenable CS, etc.) | `________________` |
| `casb-mcp` | CASB/SSE (Netskope, Zscaler, Menlo, etc.) | `________________` |
| `log-analytics-mcp` | Log Analytics (Coralogix, Datadog, Splunk, etc.) | `________________` |
| `code-search-mcp` | Code Search (Sourcegraph, GitHub Code Search, etc.) | `________________` |
| `ipam-mcp` | IPAM (NetBox, Infoblox, Men&Mice, etc.) | `________________` |

---

## 2. SIEM Index Names

Populate `memory/siem-indexes.md` with your actual index names. Replace the placeholders below:

| Placeholder | Category | Your index name(s) |
|---|---|---|
| `<auth_index>` | Authentication (IdP, SSO) | `________________` |
| `<endpoint_os_index>` | Windows/Linux OS event logs | `________________` |
| `<edr_index>` | EDR telemetry | `________________` |
| `<vm_inventory_index>` | VM scan results / plugin output | `________________` |
| `<ad_exposure_index>` | AD exposure / AD security scan results | `________________` |
| `<dns_index>` | DNS logs | `________________` |
| `<fw_index>` | Firewall / proxy / network | `________________` |
| `<casb_index>` | CASB events | `________________` |
| `<cloud_audit_index>` | Cloud API audit logs | `________________` |
| `<cloud_auth_index>` | Cloud identity / auth logs | `________________` |
| `<cloud_security_index>` | Cloud security/alert index | `________________` |
| `<email_index>` | Email security logs | `________________` |
| `<artifact_registry_index>` | Artifact registry (JFrog, Nexus, etc.) | `________________` |
| `<scm_audit_index>` | SCM audit (GitHub, GitLab, Bitbucket, etc.) | `________________` |
| `<linux_index>` | Linux syslog / auditd | `________________` |
| `<notable_index>` | SIEM notable events / alerts | `________________` |

---

## 3. SIEM Query Language

If your SIEM is **not Splunk**, update the count/detail/IOC-sweep query patterns in `SKILL.md`
under the **"SIEM Query Standards"** section (search for `## SIEM Query Standards`).

| SIEM | Count pattern | Detail pattern | IOC sweep pattern |
|---|---|---|---|
| Splunk | `index=X ... \| stats count` | `\| table _time, fields \| head 100` | `\| tstats ... TERM(<ioc>)` |
| Elastic | `GET /index/_count { "query": {...} }` | `GET /index/_search { "size": 100 }` | `GET /*/_search { "query": {"query_string": {"query": "<ioc>"}} }` |
| Sentinel | `TableName \| count` | `TableName \| take 100` | `union * \| where * has "<ioc>"` |
| Chronicle | `metadata.event_type = ... \| count()` | `... \| head 100` | YARA-L IOC rules |

---

## 4. EDR Platform

| Setting | Your value |
|---|---|
| EDR platform name | `________________` |
| MCP tool prefix | `mcp__<your-edr-mcp>__` |
| AI query generation tool name | `________________` |
| Windows Event Log field: event ID | `________________` |
| Windows Event Log field: description | `________________` |
| Windows Event Log base filter | `________________` |

---

## 5. VM Platform

| Setting | Your value |
|---|---|
| VM platform name | `________________` |
| MCP tool prefix | `mcp__<your-vm-mcp>__` |
| Asset lookup tool | `________________` |
| Findings/CVE search tool | `________________` |
| Software inventory tool | `________________` |

---

## 6. LDAP / Active Directory

```bash
# Add to your shell config (~/.bashrc or ~/.zshrc)
export AD_SERVER="ldap://<your-dc-ip>"
export AD_USERNAME="<svc-account@domain.com>"
export AD_BASE_DN="DC=corp,DC=example,DC=com"
```

Password command (replace with your secret manager):
```bash
# pass (unix password store)
pass ad/service-account-password

# AWS Secrets Manager
aws secretsmanager get-secret-value --secret-id ad/password --query SecretString --output text

# HashiCorp Vault
vault kv get -field=password secret/ad/service-account
```

---

## 7. IOC Enrichment (`ioc-enrich.py`)

Edit `scripts/ir/ioc-enrich.py` to configure your TIP sources:

```python
# Example integrations — enable/disable as needed:
SOURCES = {
    "virustotal":  True,   # VT_API_KEY env var or pass virustotal/api-key
    "greynoise":   True,   # GREYNOISE_API_KEY env var
    "otx":         True,   # OTX_API_KEY env var
    "your_tip":    False,  # Add your custom TIP integration here
}
```

---

## 8. Hunt File Storage

After completing a hunt, upload to your team's shared storage. Replace the command below with your upload tool:

```bash
# Example: AWS S3
aws s3 cp hunts/H-XXXX.md s3://<your-bucket>/hunts/H-XXXX.md

# Example: Google Drive via gws CLI
gws drive files create \
  --json '{"name": "H-XXXX.md", "parents": ["<your-folder-id>"]}' \
  --upload hunts/H-XXXX.md \
  --upload-content-type text/markdown

# Example: SharePoint via Graph API
# (configure your preferred upload method here)
```

---

## 9. Hunt Index Tracking

Append completed hunts to your tracking sheet/doc:

```bash
# Example: Google Sheets via gws CLI
gws sheets spreadsheets values append \
  --params '{"spreadsheetId": "<your-sheet-id>", "range": "Sheet1!A:C", "valueInputOption": "USER_ENTERED"}' \
  --json '{"values": [["H-XXXX", "<hunt title>", "<YYYY-MM-DD>"]]}'

# Example: Append to a local CSV
echo "H-XXXX,<hunt title>,<YYYY-MM-DD>" >> hunts/index.csv
```

---

## 10. Deprecated / Unavailable Sources

List any data sources you do NOT have so the agent skips them:

```
# Add to memory/siem-indexes.md under a "## Unavailable Sources" section:
# - <index_name>: reason (e.g., "product decommissioned", "not licensed")
```
