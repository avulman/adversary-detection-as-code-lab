This detects Windows Registry queries.

Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.

Testing:
```powershell
'Invoke-AtomicTest T1012'
```
Detection Results:
