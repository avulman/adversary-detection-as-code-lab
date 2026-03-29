# T1133 - SMB Connection in Zeek Conn

## Objective
Detect SMB network connections to TCP port 445 captured in Zeek connection logs.

## Telemetry
- Zeek Conn
- Host: SENSOR-NSM
- Data Source: Network traffic
- Platform: Security Onion

## Detection Logic
See `t1133_smb_connection_zeek_conn.yml`

## Why It Matters
Adversaries may leverage external-facing remote services to initially access and/or persist within a network. Remote services such as VPNs, Citrix, and other access mechanisms allow users to connect to internal enterprise network resources from external locations. There are often remote service gateways that manage connections and credential authentication for these services. Services such as Windows Remote Management and VNC can also be used externally.

## Expected Artifacts
- Zeek connection log entry
- `event.dataset: zeek.conn`
- `destination.port: 445`
- `network.transport: tcp`
- Source and destination IPs reflect the client and SMB server involved

## Validation
1. From a Windows or Linux host, initiate an SMB connection to a reachable Windows system.
2. Example from Windows:
   `dir \\10.10.10.20\C$`
3. Example from Linux:
   `smbclient -L //10.10.10.20 -U user`
4. In Security Onion Hunt, search for:
   `event.dataset: zeek.conn AND destination.port: 445`
5. Confirm the connection appears and verify source and destination details.

## Result
Pass

## Tuning Notes
SMB is common in Windows environments, so this rule should be tuned by source host, expected server list, subnet, or asset role to reduce noise.