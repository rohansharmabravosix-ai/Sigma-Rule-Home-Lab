# Windows Threat Detection Engineering with Sigma, Splunk & Sysmon

## Project Overview

This project focuses on developing 10 easy-to-intermediate Sigma detection rules for Windows security monitoring. Using Sysmon telemetry and Splunk, I investigated endpoint activity, wrote detection logic, tested rules against available events, and documented the limitations encountered during validation.

The goal was to practise the detection engineering workflow from hypothesis development to rule creation, telemetry investigation, evidence collection, and validation reporting.

## Tools & Technologies

- **Sigma** — Platform-independent detection rules
- **Splunk Enterprise** — Log investigation and SPL searches
- **Sysmon** — Windows endpoint telemetry
- **Windows 11** — Test endpoint
- **MITRE ATT&CK** — Adversary behaviour classification

## Detection Coverage

| # | Detection rule | Focus |
|---|---|---|
| 01 | PowerShell Process Activity | PowerShell execution visibility |
| 02 | Windows Command Shell | `cmd.exe` execution |
| 03 | Windows Script Host | `wscript.exe` and `cscript.exe` |
| 04 | Failed Logon Event | Windows Security Event ID 4625 |
| 05 | Office Application Spawning a Shell | Parent-child process relationships |
| 06 | Suspicious Certutil Arguments | Potential file transfer or decoding |
| 07 | Scheduled Task Commands | Potential scheduled task persistence |
| 08 | Registry Run Key Modification | Potential registry-based persistence |
| 09 | Network Connection Visibility | Sysmon network connection events |
| 10 | Process Access Visibility | Sysmon process access events |

These rules are investigative starting points. A matching event does not, by itself, prove malicious activity.

## Methodology

Each detection followed the same general workflow:

1. **Define the hypothesis** — Identify the Windows activity or behaviour to investigate.
2. **Write the Sigma rule** — Define the log source, detection conditions, and relevant MITRE ATT&CK mapping.
3. **Generate benign test activity where appropriate** — Use controlled commands and scripts to produce observable events.
4. **Search telemetry in Splunk** — Use SPL to find relevant Sysmon or Windows events.
5. **Review the results** — Compare event fields with the Sigma detection conditions.
6. **Capture evidence** — Save screenshots of test activity, Splunk results, and rule definitions.
7. **Document limitations** — Record unavailable telemetry, untriggered detections, and rules that could not be runtime-validated.

## Validation Results & Challenges

Not every rule could be fully validated in the available home-lab environment. These limitations were documented rather than treating the existence of a YAML file as proof that a detection works.

### Rule 1 — PowerShell Process Activity
Investigated PowerShell process creation through Sysmon and Splunk. An initial encoded PowerShell test introduced unnecessary troubleshooting, so the approach was simplified to a benign PowerShell command to make process validation more straightforward.

### Rule 2 — Windows Command Shell
Focused on identifying `cmd.exe` process creation in Sysmon telemetry and checking the corresponding event in Splunk.

### Rule 3 — Windows Script Host
The initial search returned no matching events. To generate test telemetry, a benign `.vbs` file was created and executed with `cscript.exe`. The resulting process activity was successfully located, demonstrating the value of generating controlled test events instead of relying solely on existing logs.

### Rule 4 — Failed Logon Event
**Status: Data source unavailable during validation**

The required Windows Security Event ID 4625 telemetry was not available in the current Splunk data sources. The rule was retained, but runtime validation was not completed. Further work would involve enabling and verifying Windows Security event collection.

### Rule 5 — Office Application Spawning a Shell
**Status: Not observed during validation**

The available telemetry did not provide a matching Office-to-shell process relationship. No malicious Office file was created simply to trigger the rule. The limitation was documented, and validation was deferred until suitable telemetry or a controlled test scenario is available.

### Rule 6 — Suspicious Certutil Arguments
Investigated available `certutil.exe` process events and command-line arguments. Validation depends on whether the relevant activity exists in the collected telemetry; suspicious downloads or executable decoding were not required to test the rule.

### Rule 7 — Scheduled Task Commands
Designed to identify scheduled task creation or modification commands. Validation depends on the availability of corresponding process-creation events and relevant command-line arguments.

### Rule 8 — Registry Run Key Modification
Designed to identify changes to registry locations associated with startup persistence. Validation depends on collecting the relevant registry telemetry and confirming that the event fields match the Sigma rule.

### Rule 9 — Network Connection Visibility
Designed to investigate Sysmon network connection events. Validation depends on whether Event ID 3 is enabled, collected, and mapped to the fields used by the rule.

### Rule 10 — Process Access Visibility
**Status: Not runtime-validated**

No matching Sysmon Process Access Event ID 10 was confirmed during validation. The rule was retained as a detection hypothesis, with further testing dependent on suitable process-access telemetry. No process-injection tooling was required to complete the project.

*Note: Rules 2 and 6–9 should be assigned final validation statuses based on the evidence actually captured. A rule definition or a broad search alone does not confirm that its detection conditions work.*

## What I Accomplished

- Developed a collection of 10 Sigma rules covering Windows execution, authentication, persistence, and endpoint visibility.
- Used Sysmon and Splunk to investigate Windows process activity with SPL.
- Generated benign PowerShell and VBScript test activity to verify observable process events.
- Practised mapping detection hypotheses to MITRE ATT&CK techniques.
- Captured supporting evidence for rule definitions and available validation results.
- Identified the impact of missing telemetry and the difference between an untriggered detection and an unavailable data source.
- Established a repeatable workflow for writing, testing, documenting, and evaluating detection rules.


## Future Improvements

- Enable and verify additional Windows Security and Sysmon event sources.
- Validate each rule against representative events and controlled simulations.
- Refine conditions to reduce false positives.
- Convert Sigma rules into Splunk SPL using a compatible conversion workflow.
- Build Splunk alerts and dashboards around validated detections.
- Expand testing to include documented false-positive and negative-test cases.

## Disclaimer

This project was conducted in a controlled home-lab environment for educational and defensive cybersecurity purposes. Validation status reflects the evidence available at the time of testing. The rules are learning exercises and should be reviewed and tested before production use.
