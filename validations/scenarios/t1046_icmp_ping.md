# T1046 - ICMP Ping Detection

## Objective
Detect ICMP echo requests (ping) used for network discovery.

## Telemetry
- Suricata
- Protocol: ICMP
- Host: Sensor-NSM

## Detection Logic
See `t1046_icmp_ping.rules`

## Why It Matters
Adversaries often use ICMP ping sweeps to identify live hosts on a network prior to further reconnaissance or lateral movement.

## Expected Artifacts
- ICMP traffic
- Type: 8 (Echo Request)
- Source IP: Attacker
- Destination IP: Target host

## Validation
1. Run `ping 10.10.10.20`
2. Run `ping -c 5 10.10.10.20` (Linux) or `ping -n 5 10.10.10.20` (Windows)
3. Verify alert appears in Security Onion Suricata alerts view

## Result
Pass

## Tuning Notes
This detection may generate noise in environments with frequent network monitoring or health checks. Consider restricting to specific subnets or excluding known benign sources if needed.