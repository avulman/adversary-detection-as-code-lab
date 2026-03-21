# T1012 - Query Registry

## Objective
Detect registry enumeration using reg.exe or PowerShell.

## Telemetry
- Sysmon Event ID 1
- Host: WIN-ENDPOINT-01
- Index: sysmon

## Detection Logic
See `t1012_registry_query.spl`

## Why It Matters
Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.

## Expected Artifacts
- Image = reg.exe or powershell.exe
- CommandLine contains query, HKLM, HKCU

## Validation
1. Run `reg query HKLM\Software\Microsoft\Windows\CurrentVersion`
2. Run `powershell -Command "Get-ItemProperty HKLM:\Software"`
3. Run `Invoke-AtomicTest T1012`
4. Search Splunk with the detection query

## Result
Pass

## Tuning Notes
Excluded splunkd.exe as it is the core executable process for Splunk software.