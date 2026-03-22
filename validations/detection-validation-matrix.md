| Technique | Detection | Data Source | Log Source | Test Method  | Alert Logic | Status | Score | Notes |
|----------|----------|------------|------------|------------|----------|--------|-------|------|
| T1003.001 | LSASS Access | Sysmon | Splunk | Manual + Atomic | 5m | Working | 4 | Stable
| T1012 | Registry Query | Sysmon | Splunk | Manual + Atomic | 5m | Working | 4 | Stable |
| T1027 | Obfuscated Files or Information | Sysmon | Splunk | Manual + Atomic | 5m | Working | 3 | Lots of potential for additional tuning |
| T1046 | Nmap SYN Scan | Suricata | Attacker VM (nmap) | Working | 5 | Strong signal |
| T1055 | Process Injection | Sysmon | Splunk | Manual + Atomic | 5m | Working | 4 | Stable |
| T1059.001 | PowerShell Execution | Sysmon | Splunk | Manual + Atomic | 5m | Working | 4 | Needs tuning |
