# Investigation Guides

Domain-specific reference workflows used by the TRACE framework in SOC-Hunter's `investigate` mode.

These guides are loaded contextually when an investigation topic matches a known pattern. They provide expert workflow steps adapted to your data sources; TRACE remains the governing structure.

## Source

All guides are sourced from [Anthropic Cybersecurity Skills](https://github.com/mukul975/Anthropic-Cybersecurity-Skills) (Apache 2.0 license).

## Available Guides

| File | Investigation Pattern |
|------|----------------------|
| `performing-insider-threat-investigation.md` | Insider threat / data exfil / policy violation |
| `investigating-insider-threat-indicators.md` | DLP alerts, UEBA anomalies, departing employees |
| `triaging-security-incident.md` | Alert triage / severity classification |
| `triaging-security-incident-with-ir-playbook.md` | IR playbook-driven triage |
| `performing-cloud-forensics-investigation.md` | Cloud / AWS / CloudTrail investigation |
| `performing-endpoint-forensics-investigation.md` | Endpoint forensics |
| `investigating-phishing-email-incident.md` | Phishing email reports |

## Usage

Guides are **reference material**, not mandatory checklists. TRACE provides the structure; guides inform the Assess step. See `SKILL.md` Mode 6 for details.

## Adapting Guides to Your Environment

Each guide may reference platforms or tools you don't have (TheHive, Exabeam, Splunk-specific queries, etc.). When a guide step references an unavailable tool, skip or adapt it to your equivalent data source. The investigative logic and methodology remain valid regardless of platform.
