# Phishing Email Investigation & IOC Analysis

Worked through the TryHackMe "Phishing Unfolding" room, which simulates a live phishing attack. I triaged the alerts in the queue, investigated them in Splunk, checked indicators with the room's threat-intel tool (TryDetectThis) and VirusTotal, and wrote up verdicts.

## Tools 
- TryHackMe
- Splunk
-  Sysmon logs
-  TryDetectThis
-  VirusTotal
-  MITRE ATT&CK.

## Attack Chain

1. Phishing email with a ZIP attachment reaches the user.
2. User opens the attachment. The ZIP contained a shortcut (.lnk) file disguised as a PDF.
3. PowerShell runs on the host.
4. PowerShell reads a ZIP file and sends it out through DNS queries to an attacker domain.

## Alert 1007: Suspicious Email Attachment (Low)

| Field | Value |
|---|---|
| Time | 2025-06-17 18:54 |
| Subject | Important: Pending Invioce! |
| Sender | john@hatmakereurope[.]xyz |
| Recipient | michael.ascot@tryhatme[.]com |
| Attachment | ImportantInvoice-Febrary.zip |

**Investigation**
- Checked the sender domain in TryDetectThis. It came back clean, so reputation alone wasn't enough to clear it.
- Searched Splunk for the attachment on the endpoint and found the user had interacted with it. Sysmon Event ID 15 showed an alternate data stream being created.
- The extracted file was named with a .pdf.lnk double extension. It looked like a PDF but was actually a shortcut file, a common malware delivery trick.
- Submitted the file to VirusTotal . It was flagged malicious.

**Verdict:** True positive. Severity should be raised, since the user opened the file.

**Remediation:** Quarantine the ZIP and LNK files, block the related domain and file hash, and check for other recipients of the same email.

## Alert 1027: Suspicious Parent-Child Process (High)

| Field | Value |
|---|---|
| Time | 2025-06-17 19:19 |
| Host | win-3450 |
| Process | nslookup.exe (PID 5520) |
| Parent | powershell.exe (PID 3728) |
| Working directory | C:\Users\michael.ascot\Downloads\exfiltration\ |
| Queried domain | haz4rdw4re[.]io |

**Investigation**
- nslookup is normally run by hand or by Windows itself. Being launched by PowerShell is unusual and points to a script.
- Searched Splunk for all events from the host (`index=* host=win-3450`) and found the PowerShell activity tied to the same user.
- The PowerShell script read the file `exfilt8me.zip` and sent its contents out in pieces as subdomains in nslookup requests to haz4rdw4re[.]io.

**Verdict:** True positive. DNS exfiltration from user michael.ascot.

**Remediation:** Isolate win-3450, block haz4rdw4re[.]io at the DNS and proxy level, reset the user's credentials, and review what data was in the ZIP.

## IOCs

| Type | Indicator |
|---|---|
| Sender domain | hatmakereurope[.]xyz |
| Sender address | john@hatmakereurope[.]xyz |
| Attachment | ImportantInvoice-Febrary.zip |
| Malicious file | .pdf.lnk shortcut |
| Exfil domain | haz4rdw4re[.]io |
| Exfiltrated file | exfilt8me.zip |
| Host / user | win-3450 / michael.ascot |

## MITRE ATT&CK

| Technique | Where it showed up |
|---|---|
| T1566.001 Phishing: Spearphishing Attachment | ZIP attachment in the email |
| T1204.002 User Execution: Malicious File | User opened the LNK file |
| T1036.007 Masquerading: Double File Extension | .pdf.lnk |
| T1059.001 PowerShell | Script that launched nslookup |
| T1048.003 Exfiltration Over Unencrypted Non-C2 Protocol | Data sent out through DNS queries |

## Takeaways

- The sender domain looked clean in the reputation check, but the file and the endpoint activity showed it was malicious. One clean result doesn't clear an email.
- A rare parent-child process pair (PowerShell spawning nslookup) was enough to catch the DNS exfiltration.
- Linking the email alert to the later endpoint alert showed the full attack chain, not just two separate alerts.
