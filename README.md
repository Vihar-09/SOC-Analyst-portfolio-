# SOC Analyst Portfolio

Hands-on projects I completed while preparing for a Tier 1 SOC Analyst role and the Microsoft SC-200 (Security Operations Analyst) certification. Each project is documented with the tools used, the investigation steps, and the findings.

## Projects

### 1. [Microsoft Sentinel SOC Detection & Incident Response Lab](./01-microsoft-sentinel-soc-lab)
Built a Microsoft-based SOC lab to collect Windows security logs and endpoint telemetry in Microsoft Sentinel and Microsoft Defender. Wrote KQL detections for brute-force logons, suspicious PowerShell, account and privilege changes, and anomalous sign-ins, then investigated the alerts they produced.

**Tools:** Microsoft Sentinel, Microsoft Defender, Entra ID, KQL, MITRE ATT&CK

### 2. [Phishing Email Investigation & IOC Analysis](./02-phishing-email-investigation)
Investigated a simulated phishing attack from the TryHackMe "Phishing Unfolding" room. Traced the attack from a malicious email attachment through PowerShell execution to DNS data exfiltration, and enriched the indicators with threat-intelligence tools.

**Tools:** TryHackMe, Splunk, Sysmon, VirusTotal, MITRE ATT&CK

## Skills Demonstrated

- Alert triage and investigation
- Writing and tuning KQL detection queries
- Log analysis (Windows Security events, Sysmon, Entra ID sign-in logs)
- Phishing analysis and IOC enrichment
- Mapping activity to MITRE ATT&CK
- Documenting findings with a verdict and recommended action

## Repository Structure

```
.
├── README.md
├── 01-microsoft-sentinel-soc-lab/
│   ├── README.md
└── 02-phishing-email-investigation/
    ├── README.md
    
```

## Certifications

- Microsoft SC-200: Security Operations Analyst 

## Notes

All work was done in lab environments or on training platforms. No real organizational data is included, and indicators in the write-ups are defanged.
