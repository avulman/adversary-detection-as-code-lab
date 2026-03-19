This is a very simple PowerShell exeuction detection.

Adversaries may abuse PowerShell commands and scripts for execution. PowerShell is a powerful interactive command-line interface and scripting environment included in the Windows operating system. Adversaries can use PowerShell to perform a number of actions, including discovery of information and execution of code. Examples include the Start-Process cmdlet which can be used to run an executable and the Invoke-Command cmdlet which runs a command locally or on a remote computer (though administrator permissions are required to use PowerShell to connect to remote systems).

Testing:
```powershell
'Invoke-AtomicTest T1059.001'

'powershell.exe -ExecutionPolicy Bypass -Command "Write-host testing powershell execution detection"'
```
Detection Results:
<img width="1901" height="544" alt="image" src="https://github.com/user-attachments/assets/4963746e-0536-4f16-a35b-f60d50dee2d3" />
