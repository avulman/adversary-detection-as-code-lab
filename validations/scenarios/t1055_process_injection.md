# T1055 - Process Injection

## Objective
Detect process injection

## Telemetry
- Sysmon Event ID 8
- Host: WIN-ENDPOINT-01
- Index: sysmon

## Detection Logic
See `t1055_process_injection.spl`

## Why It Matters
Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges. Process injection is a method of executing arbitrary code in the address space of a separate live process. Running code in the context of another process may allow access to the process's memory, system/network resources, and possibly elevated privileges. Execution via process injection may also evade detection from security products since the execution is masked under a legitimate process.

## Expected Artifacts
- Event Code 8 (CreateRemoteThread) indicating that one processes has created a threat in another

## Validation
1. Run `Invoke-AtomicTest T1055
2. Search Splunk with the detection query

## Result
Pass

## Tuning Notes
Lots of tuning to be done. Very generic at the moment.