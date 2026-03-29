# Detection Coverage Matrix

This matrix tracks implemented detections across the lab environment, mapped to MITRE ATT&CK techniques, telemetry sources, validation methods, and current coverage gaps. It is intended to show defensive coverage maturity, identify blind spots, and guide future detection engineering efforts.

| Tactic | Technique | Detection | Data Source | Log Source / Sensor | Test Method | Alert Logic | Status | Score | Coverage Area | Gaps / Notes |
|-------|-----------|-----------|-------------|---------------------|-------------|-------------|--------|-------|---------------|--------------|
| Credential Access | T1003.001 | LSASS Access | Sysmon | Splunk | Manual + Atomic | 5m scheduled search | Working | 4 | Credential dumping / memory access | Stable. Good high-signal detection, but may miss indirect or heavily obfuscated dumping techniques. |
| Discovery | T1012 | Registry Query | Sysmon | Splunk | Manual + Atomic | 5m scheduled search | Working | 4 | Host discovery / system configuration awareness | Stable. Can expand with parent process analysis and suspicious registry path tuning. |
| Lateral Movement | T1021.001 | Remote Desktop Protocol Connection in Zeek Conn | Zeek Conn | Sigma | Manual | On ingest / Sigma alerting | Working | 3 | Network connection to RDP service on TCP 3389 | Useful baseline visibility for remote access and lateral movement. May detect legitimate administrative RDP activity and should be tuned to known management sources. |
| Defense Evasion | T1027 | Obfuscated Files or Information | Sysmon | Splunk | Manual + Atomic | 5m scheduled search | Working | 3 | Obfuscated command execution / suspicious scripting | Useful but broad. High opportunity for tuning around encoded PowerShell, unusual command-line length, and script interpreter ancestry. |
| Discovery | T1046 | ICMP Ping | Suricata | Sensor-NSM / Security Onion | Manual | Real-time signature | Working | 3 | Network service / host discovery | Useful baseline discovery coverage, but can be noisy in active or monitored networks. Consider subnet scoping or allowlists. |
| Discovery | T1046 | Nmap SYN Scan | Suricata | Sensor-NSM / Security Onion | Manual | Threshold-based real-time signature | Working | 5 | Port scanning / reconnaissance | Strong signal in the lab. Could tune thresholds by subnet or scanner behavior to reduce false positives in enterprise environments. |
| Defense Evasion / Privilege Escalation | T1055 | Process Injection | Sysmon | Splunk | Manual + Atomic | 5m scheduled search | Working | 4 | In-memory execution / process tampering | Stable. Could be strengthened with Event ID 8, Event ID 10, access masks, and target process risk scoring. |
| Execution | T1059.001 | PowerShell Execution | Sysmon | Splunk | Manual + Atomic | 5m scheduled search | Working | 4 | Script execution | Strong foundational coverage. Needs tuning for encoded commands, hidden windows, suspicious parents, and download cradles. |
| Execution / Command and Control | T1059.001 | PowerShell Web Request | Suricata | Sensor-NSM / Security Onion | Manual | Real-time signature | Working | 4 | Script-based outbound retrieval | Good for detecting web-enabled PowerShell activity. Should be correlated with Sysmon or EDR to improve fidelity. |
| Command and Control | T1071.001 | Suspicious HTTP User-Agent Python Requests | Suricata | Sensor-NSM / Security Onion | Manual | Real-time signature | Testing | 4 | Scripted HTTP traffic / custom tooling | Useful for detecting obvious scripted traffic. May require allowlisting for legitimate Python automation. |
| Command and Control | T1071.001 | Python Requests User-Agent in Zeek HTTP | Zeek HTTP | Sigma | Manual | On ingest / Sigma alerting | Working | 3 | Scripted HTTP activity using python-requests | Good behavioral network detection for scripted web traffic. May also catch benign internal automation and developer tooling. |
| Command and Control / Ingress Tool Transfer | T1105 | Executable Download (.exe) | Suricata | Sensor-NSM / Security Onion | Manual | Real-time signature | Working | 3 | Tool transfer / payload staging | Useful but broad. Requires allowlisting for legitimate software repositories and admin activity. |
| Defense Evasion / Persistence / Ingress Tool Transfer | T1197 | BITS Download Activity | Suricata | Sensor-NSM / Security Onion | Manual | Real-time signature | Working | 3 | Background file transfer / stealthy download behavior | Good supplemental coverage, but BITS has legitimate enterprise use. Best used with endpoint context and destination reputation. |

## Current Coverage Summary

### Covered ATT&CK Techniques
- T1003.001 - LSASS Access
- T1012 - Registry Query
- T1027 - Obfuscated Files or Information
- T1046 - Network Service Discovery
- T1055 - Process Injection
- T1059.001 - PowerShell
- T1071.001 - Web Protocols: HTTP/S
- T1105 - Ingress Tool Transfer
- T1197 - BITS Jobs

### Primary Telemetry Sources
- Sysmon -> Splunk
- Suricata -> Security Onion

### Detection Strengths
- Good foundational coverage across host and network telemetry
- Strong visibility into discovery and scripted execution behavior
- Solid lab validation model using both manual testing and Atomic Red Team-style execution
- Mix of scheduled SIEM analytics and real-time IDS signatures

### Current Gaps
- Limited persistence coverage
- Limited credential access coverage beyond LSASS
- Limited lateral movement coverage
- Limited identity and cloud detection coverage
- Limited correlation across endpoint + network detections
- Some network detections are strong indicators but still require allowlisting/tuning for enterprise realism