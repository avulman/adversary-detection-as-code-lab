# Detection Coverage Matrix

This matrix tracks implemented detections across the lab environment, mapped to MITRE ATT&CK techniques, telemetry sources, validation methods, and current coverage gaps. It is intended to show defensive coverage maturity, identify blind spots, and guide future detection engineering efforts.

| Technique | Tactic | Detection | Data Source | Log Source / Sensor | Alert Logic | Score | Coverage Area | Gaps / Notes |
|-----------|--------|-----------|-------------|---------------------|-------------|--------|-------------------------------|-------------|
| T1003.001 | Credential Access | LSASS Access | Sysmon | Splunk | 5m scheduled search | 4 | Credential dumping / memory access | Stable. Good high-signal detection, but may miss indirect or heavily obfuscated dumping techniques. |
| T1012 | Discovery | Registry Query | Sysmon | Splunk | 5m scheduled search | 4 | Host discovery / system configuration awareness | Stable. Can expand with parent process analysis and suspicious registry path tuning. |
| T1021.001 | Lateral Movement | Remote Desktop Protocol Connection in Zeek Conn | Zeek Conn | Sigma | On ingest / Sigma alerting | 3 | Network connection to RDP service on TCP 3389 | Useful baseline visibility for remote access and lateral movement. May detect legitimate administrative RDP activity and should be tuned to known management sources. |
| T1021.004 | Lateral Movement | SSH Connection in Zeek Conn | Zeek Conn | Sigma | On ingest / Sigma alerting | 3 | Network connection to SSH service on TCP 22 | Good baseline visibility for remote access and lateral movement over SSH. May also detect legitimate administration and automation traffic. |
| T1027 | Defense Evasion | Obfuscated Files or Information | Sysmon | Splunk | 5m scheduled search | 3 | Obfuscated command execution / suspicious scripting | Useful but broad. High opportunity for tuning around encoded PowerShell, unusual command-line length, and script interpreter ancestry. |
| T1046 | Discovery | ICMP Ping | Suricata | Sensor-NSM / Security Onion | Real-time signature | 3 | Network service / host discovery | Useful baseline discovery coverage, but can be noisy in active or monitored networks. Consider subnet scoping or allowlists. |
| T1046 | Discovery | Nmap SYN Scan | Suricata | Sensor-NSM / Security Onion | Threshold-based real-time signature | 5 | Port scanning / reconnaissance | Strong signal in the lab. Could tune thresholds by subnet or scanner behavior to reduce false positives in enterprise environments. |
| T1059.001 | Execution | PowerShell Execution | Sysmon | Splunk | 5m scheduled search | 4 | Script execution | Strong foundational coverage. Needs tuning for encoded commands, hidden windows, suspicious parents, and download cradles. |
| T1059.001 | Execution / Command and Control | PowerShell Web Request | Suricata | Sensor-NSM / Security Onion | Real-time signature | 4 | Script-based outbound retrieval | Good for detecting web-enabled PowerShell activity. Should be correlated with Sysmon or EDR to improve fidelity. |
| T1071.001 | Command and Control | Suspicious HTTP User-Agent Python Requests | Suricata | Sensor-NSM / Security Onion | Real-time signature | 4 | Scripted HTTP traffic / custom tooling | Useful for detecting obvious scripted traffic. May require allowlisting for legitimate Python automation. |
| T1071.001 | Command and Control | Python Requests User-Agent in Zeek HTTP | Zeek HTTP | Sigma | On ingest / Sigma alerting | 3 | Scripted HTTP activity using python-requests | Good behavioral network detection for scripted web traffic. May also catch benign internal automation and developer tooling. |
| T1105 | Command and Control / Ingress Tool Transfer | Executable Download (.exe) | Suricata | Sensor-NSM / Security Onion | Real-time signature | 3 | Tool transfer / payload staging | Useful but broad. Requires allowlisting for legitimate software repositories and admin activity. |
| T1133 | Initial Access | SMB Connection in Zeek Conn | Zeek Conn | Sigma | On ingest / Sigma alerting | 2 | Network connection to SMB service on TCP 445 | Useful baseline visibility into remote service access and file-sharing activity, but potentially noisy in Windows environments without tuning. |

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