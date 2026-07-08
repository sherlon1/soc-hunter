# SIEM Index Reference

> Fill in your actual index names below. Used by SOC-Hunter to construct queries.
> See `CONFIG.md` section 2 for the full placeholder → your-value mapping table.

---

## Authentication / Identity

| Placeholder | Your Index Name | Notes |
|---|---|---|
| `<auth_index>` | | e.g., `index=okta`, `index=azure_ad sourcetype=azure:aad:signin` |
| `<cloud_auth_index>` | | e.g., `index=gcp sourcetype=google:gcp:iam`, `index=aws_cognito` |

## Endpoint

| Placeholder | Your Index Name | Notes |
|---|---|---|
| `<endpoint_os_index>` | | e.g., `index=windows sourcetype=XmlWinEventLog`, `index=sysmon` |
| `<edr_index>` | | e.g., `index=sentinelone`, `index=crowdstrike_fdr` |
| `<linux_index>` | | e.g., `index=linux sourcetype=syslog`, `index=auditd` |

## Network

| Placeholder | Your Index Name | Notes |
|---|---|---|
| `<dns_index>` | | e.g., `index=dns sourcetype=stream:dns` |
| `<fw_index>` | | e.g., `index=firewall`, `index=paloalto` |

## Vulnerability Management

| Placeholder | Your Index Name | Notes |
|---|---|---|
| `<vm_inventory_index>` | | e.g., `index=tenable_io`, `index=qualys_pc` |
| `<ad_exposure_index>` | | e.g., `index=tenable_ad`, `index=bloodhound` |

## Cloud

| Placeholder | Your Index Name | Notes |
|---|---|---|
| `<cloud_audit_index>` | | e.g., `index=cloudtrail`, `index=azure_activity`, `index=gcp_audit` |
| `<cloud_security_index>` | | e.g., `index=aws_guardduty`, `index=azure_defender` |

## Application / Communication

| Placeholder | Your Index Name | Notes |
|---|---|---|
| `<email_index>` | | e.g., `index=mimecast`, `index=proofpoint`, `index=o365_exchange` |
| `<casb_index>` | | e.g., `index=netskope`, `index=zscaler_zia` |
| `<notable_index>` | | e.g., `index=notable` (Splunk ES), `index=alerts` |

## Supply Chain / DevOps

| Placeholder | Your Index Name | Notes |
|---|---|---|
| `<artifact_registry_index>` | | e.g., `index=jfrog_artifactory`, `index=nexus_iq` |
| `<scm_audit_index>` | | e.g., `index=github_audit`, `index=gitlab_audit` |

---

## Unavailable Sources

<!-- List data sources you do NOT have so the agent skips them without asking. -->

| Source | Reason |
|---|---|
| | e.g., `<cspm_index>`: not licensed |
