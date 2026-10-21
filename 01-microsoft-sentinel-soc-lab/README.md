# Microsoft Sentinel SOC Detection & Incident Response Lab

Microsoft Sentinel lab for collecting Windows security logs and endpoint telemetry, writing KQL detections, and investigating the resulting alerts. Tools: Microsoft Sentinel, Microsoft Defender, Entra ID, KQL, MITRE ATT&CK. Test activity was generated manually in a lab tenant.

**Data sources:** Windows Security Events (AMA), Defender for Endpoint (`DeviceProcessEvents`), Entra ID (`SigninLogs`)

## Detections

| ID | Detection | Table | ATT&CK |
|---|---|---|---|
| DET-001 | Brute-force logon failures | SecurityEvent | T1110 |
| DET-002 | Suspicious PowerShell | DeviceProcessEvents | T1059.001 |
| DET-003 | Account / privilege changes | SecurityEvent | T1136, T1098 |
| DET-004 | Anomalous sign-in location | SigninLogs | T1078 |

**DET-001: Brute force.** 5+ failed logons (4625) per account and source IP in 15 minutes.
```kql
SecurityEvent
| where TimeGenerated > ago(30m) and EventID == 4625
| summarize Failures = count() by TargetAccount, IpAddress, bin(TimeGenerated, 15m)
| where Failures >= 5
```
Triage: check for a 4624 success from the same IP after the failures; check whether multiple accounts were hit . FPs: expired passwords, stale service credentials.

**DET-002: PowerShell.** Encoded, hidden, or download-cradle command lines.
```kql
DeviceProcessEvents
| where TimeGenerated > ago(30m)
| where FileName in~ ("powershell.exe", "pwsh.exe")
| where ProcessCommandLine has_any ("-enc", "FromBase64String", "DownloadString", "IEX", "-nop", "-w hidden", "bypass")
| project TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
```
Triage: decode the command, check the parent process, review follow-on network and file activity. FPs: admin scripts, deployment tools.

**DET-003: Account and privilege changes.** User creation (4720) and additions to privileged groups (4728, 4732, 4756).
```kql
SecurityEvent
| where TimeGenerated > ago(30m) and EventID in (4720, 4728, 4732, 4756)
| project TimeGenerated, EventID, Computer, SubjectUserName, TargetUserName, MemberName
```
Triage: confirm a change request exists, check who performed it and from where. FPs: planned admin work.

**DET-004: Anomalous sign-in.** Successful sign-in from a country not seen for that user in the previous 14 days.
```kql
let baseline = SigninLogs
    | where TimeGenerated between (ago(14d) .. ago(1d)) and ResultType == "0"
    | summarize Known = make_set(tostring(LocationDetails.countryOrRegion)) by UserPrincipalName;
SigninLogs
| where TimeGenerated > ago(1d) and ResultType == "0"
| extend Country = tostring(LocationDetails.countryOrRegion)
| join kind=inner baseline on UserPrincipalName
| where not(set_has_element(Known, Country))
| project TimeGenerated, UserPrincipalName, IPAddress, Country
```
Triage: check for VPN or known travel, check impossible travel, review post-sign-in activity. FPs: VPN exit nodes, travel.

## Example Investigation

**Alert:** DET-001 fired on `user1` from `192.168.1.25`, 8 failed logons (4625) within 5 minutes.

**Steps:**
1. Reviewed the incident in Sentinel and identified the affected account, source IP, and target host.
2. Queried `SecurityEvent` for 4625 and 4624 events from that IP and account over the previous 24 hours.
3. Confirmed no successful logon (4624) from the same IP after the failures.
4. Checked whether other accounts were targeted from the same IP. None were, so this did not match password spraying.
5. Reviewed `DeviceProcessEvents` on the target host for suspicious activity around the same time. Nothing unusual found.

**Finding:** Repeated failed logons against a single test account from one internal IP, with no successful logon and no related endpoint activity. The source matched the machine used to run the lab test.

**Verdict:** Benign true positive. The detection worked as designed, and the activity was the failed logons I generated for testing.

**Action:** Closed the incident as lab-generated activity. In a real environment, a success after the failures, multiple targeted accounts, or an external source IP would have been escalated to Tier 2.


## Limitations

- Static thresholds; tuned for lab volume only.
- DET-002 is string matching and will miss other obfuscation.
- No automated response (playbooks) configured.
