This detects Windows Registry queries.

Adversaries may interact with the Windows Registry to gather information about the system, configuration, and installed software.

Testing:
```powershell
'Invoke-AtomicTest T1012'
```
Detection Results:
<img width="1903" height="641" alt="image" src="https://github.com/user-attachments/assets/cbe98d9c-6cb8-4f80-891a-ceb0243223be" />
