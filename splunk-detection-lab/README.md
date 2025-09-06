# Splunk Detection Lab

> 📝 **Write-up in progress.** This template defines the lab's structure and
> candidate detection logic. Tuning results and screenshots will be added as the
> exercise is completed. No findings are fabricated.

**Tester:** Khaja Syed
**Type:** Lab exercise (isolated, self-owned environment)
**Primary tool:** Splunk
**Framework:** MITRE ATT&CK

---

## 🎯 Objective
Ingest Windows/endpoint logs into Splunk and build detections for common attack
behaviors: brute-force authentication, PowerShell abuse, and persistence.

## 🖥️ Environment
- Splunk (lab instance)
- Log sources: Windows Security / Sysmon / PowerShell operational logs
- **Host-Only networking recommended**

## 🔎 Candidate Detections

> These are starting-point SPL queries for a lab; field names assume Sysmon +
> Windows Security logs and will need tuning to the environment.

### Brute-force authentication (ATT&CK T1110)
```spl
index=wineventlog EventCode=4625
| stats count AS failures, values(Account_Name) AS accounts by src_ip
| where failures >= 10
```

### PowerShell abuse (ATT&CK T1059.001)
```spl
index=wineventlog (EventCode=4104 OR source="*PowerShell/Operational*")
| search ScriptBlockText IN ("*-enc*","*DownloadString*","*IEX*","*FromBase64String*","*-nop*")
| table _time host User ScriptBlockText
```

### Persistence — Run keys / scheduled tasks (ATT&CK T1547.001, T1053.005)
```spl
index=sysmon (EventCode=13 TargetObject="*\\CurrentVersion\\Run*")
    OR (EventCode=1 Image="*schtasks.exe*" CommandLine="*/create*")
| table _time host User Image TargetObject CommandLine
```

## 📝 Tuning Notes & Findings
_To be completed._

## 💡 Lessons Learned
_To be completed._
