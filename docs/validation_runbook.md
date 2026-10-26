# Easy-to-Intermediate Sigma Lab Runbook

## Lab
- Splunk: `http://192.168.110.129:8000` (use Ubuntu Firefox)
- Expected Sysmon index: `sysmon`
- Run fresh tests with time picker set to **Last 15 minutes**.
- First confirm telemetry and field names. Do not assume every event source is enabled.

## 1. Inventory
```spl
index=sysmon
| stats count by EventCode
| sort - count
```

```spl
index=sysmon EventCode=1
| table _time host User Image ParentImage CommandLine
| sort - _time
```

```spl
index=sysmon EventCode=3
| stats count by Image DestinationIp DestinationPort Protocol
| sort - count
```

```spl
index=sysmon (EventCode=12 OR EventCode=13 OR EventCode=14)
| stats count by EventCode
```

```spl
index=sysmon EventCode=10
| stats count by SourceImage TargetImage GrantedAccess
| sort - count

```
Failed logons are Windows Security events, not Sysmon:
```spl
index=* EventCode=4625
| stats count by index host
```
If field names differ, inspect a raw event and adapt.

## Rule 1 — PowerShell process activity
PowerShell:
```powershell
powershell.exe -NoProfile -Command "Write-Output 'SigmaLab-Rule01-PowerShell'"
```
Splunk:
```spl
index=sysmon EventCode=1
| where like(lower(Image), "%powershell.exe") OR like(lower(Image), "%pwsh.exe")
| table _time host User Image ParentImage CommandLine
| sort - _time
```

## Rule 2 — cmd.exe
PowerShell:
```powershell
cmd.exe /c "echo SigmaLab-Rule02-Cmd"
```
Splunk:
```spl
index=sysmon EventCode=1
| where like(lower(Image), "%cmd.exe")
| table _time host User Image ParentImage CommandLine
| sort - _time
```

## Rule 3 — Windows Script Host
Search:
```spl
index=sysmon EventCode=1
| where like(lower(Image), "%wscript.exe") OR like(lower(Image), "%cscript.exe")
| table _time host Image ParentImage CommandLine
| sort - _time
```
Optional benign test, if permitted: create `C:\Temp\SigmaLab03.vbs` with `WScript.Echo "SigmaLab Rule 3"` and run `cscript.exe //nologo C:\Temp\SigmaLab03.vbs`; then delete the file. Do not bypass execution policy.

## Rule 4 — Failed logons
```spl
index=* EventCode=4625
| table _time host Account_Name Logon_Type Status Sub_Status
| sort - _time
```
Requires Windows Security Event ID 4625 ingestion.

## Rule 5 — Office spawning a shell
```spl
index=sysmon EventCode=1
| where (like(lower(ParentImage), "%winword.exe") OR like(lower(ParentImage), "%excel.exe") OR like(lower(ParentImage), "%powerpnt.exe"))
    AND (like(lower(Image), "%powershell.exe") OR like(lower(Image), "%pwsh.exe") OR like(lower(Image), "%cmd.exe"))
| table _time host ParentImage Image CommandLine
| sort - _time
```
Do not create malicious Office macros just to force a match. Existing telemetry only; otherwise not runtime-validated.

## Rule 6 — Certutil
```spl
index=sysmon EventCode=1
| where like(lower(Image), "%certutil.exe")
| table _time host Image CommandLine
| sort - _time
```
Narrow:
```spl
index=sysmon EventCode=1
| where like(lower(Image), "%certutil.exe")
| where like(lower(CommandLine), "% -urlcache %") OR like(lower(CommandLine), "% -decode %") OR like(lower(CommandLine), "% -decodehex %")
| table _time host Image CommandLine
| sort - _time
```
Do not download or decode executable payloads for validation.

## Rule 7 — Scheduled task
PowerShell: create a harmless task and immediately remove it:
```powershell
$taskName = "SigmaLab-Rule07"
schtasks.exe /Create /TN $taskName /SC ONCE /ST 23:59 /TR "cmd.exe /c echo SigmaLab-Rule07" /F
schtasks.exe /Delete /TN $taskName /F
```
If the time is rejected or admin rights are required, don't force it.
Splunk:
```spl
index=sysmon EventCode=1
| where like(lower(Image), "%schtasks.exe")
| where like(lower(CommandLine), "% /create%") OR like(lower(CommandLine), "% /change%")
| table _time host Image ParentImage CommandLine
| sort - _time
```

## Rule 8 — Registry Run key
This temporarily creates then removes a uniquely named current-user Run value:
```powershell
$runKey = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
New-Item -Path $runKey -Force | Out-Null
New-ItemProperty -Path $runKey -Name "SigmaLabRule08" -Value "cmd.exe /c echo SigmaLab-Rule08" -PropertyType String -Force | Out-Null
Remove-ItemProperty -Path $runKey -Name "SigmaLabRule08" -ErrorAction SilentlyContinue
```
Splunk:
```spl
index=sysmon (EventCode=12 OR EventCode=13 OR EventCode=14)
| where like(lower(TargetObject), "%\\software\\microsoft\\windows\\currentversion\\run%")
| table _time host EventCode Image EventType TargetObject Details
| sort - _time
```
Only claim validation if the registry event is ingested and the query returns it.

## Rule 9 — Network connection visibility
```spl
index=sysmon EventCode=3
| table _time host Image DestinationIp DestinationPort Protocol Initiated
| sort - _time
```

## Rule 10 — Process access visibility
```spl
index=sysmon EventCode=10
| table _time host SourceImage TargetImage GrantedAccess CallTrace
| sort - _time
```
Do not run process-injection tools. If Event ID 10 is absent, document it as not runtime-validated.


## Validation labels
- `Validated`: test event observed locally, ingested by Splunk, and returned by query.
- `Telemetry confirmed, detection not triggered`: data exists but condition did not match.
- `Not runtime-validated`: no safe test or suitable event.
- `Data source unavailable`: required telemetry is not collected/indexed.

Sigma YAML is portable starter logic; the SPL queries are lab-specific and must be mapped to actual Splunk fields. Broad visibility rules need tuning before production use.
