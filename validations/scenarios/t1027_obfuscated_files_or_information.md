# T1027 - Obfuscated Files or Information

## Objective
Detect process injection

## Telemetry
- Sysmon Event ID 1
- Host: WIN-ENDPOINT-01
- Index: sysmon

## Detection Logic
See `t1027_obfuscated_files_or_information.spl`

## Why It Matters
Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.

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