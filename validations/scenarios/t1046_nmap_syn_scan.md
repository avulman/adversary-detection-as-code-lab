# T1046 - Network Service Discovery

## Objective
Detect TCP SYN scanning consistent with Nmap network reconnaissance.

## Telemetry
- Suricata NIDS alert
- Host: Security Onion sensor
- Data Source: Network traffic

## Detection Logic
See `t1046_nmap_syn_scan.rules`

## Why It Matters
Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure devices, including those that may be vulnerable to remote software exploitation. Common methods to acquire this information include port and/or vulnerability scans using tools that are brought onto a system.

## Expected Artifacts
- Suricata alert for repeated SYN packets
- Source IP = attacker VM
- Destination IP = lab subnet target(s)

## Validation
1. From the attacker VM, run `nmap -sS 10.10.10.20`
1. Run `nmap -sS -T4 -p- 10.10.10.20`
2. Verify alert appears in Security Onion
4. Confirm source and destination IPs match the scan activity


## Result
Pass

## Tuning Notes
Thresholding is used to reduce noise from normal single-connection activity. Tune count and seconds based on lab traffic volume.