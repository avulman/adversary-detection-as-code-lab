# T1027 - Obfuscated Files or Information

## Objective
Detect obfuscation

## Telemetry
- Sysmon Event ID 1
- Host: WIN-ENDPOINT-01
- Index: sysmon

## Detection Logic
See `t1027_obfuscated_files_or_information.spl`

## Why It Matters
Adversaries may attempt to make an executable or file difficult to discover or analyze by encrypting, encoding, or otherwise obfuscating its contents on the system or in transit. This is common behavior that can be used across different platforms and the network to evade defenses.

## Expected Artifacts
- Obfuscation techniques in command line

## Validation
1. Run `Invoke-AtomicTest T1027.`
2. Run `powershell.exe -EncodedCommand RwBlAHQALQBQAHIAbwBjAGUAcwBzAA==`
3. Run `powershell.exe -Command "IEX ([Text.Encoding]::UNICODE.GetString([Convert]::FromBase64String((gp HKCU:Software\Microsoft\Windows\CurrentVersion Debug).Debug)))"`
4. Search Splunk with the detection query

## Result
Pass

## Tuning Notes
More tuning can be done to catch various types of obfuscation.