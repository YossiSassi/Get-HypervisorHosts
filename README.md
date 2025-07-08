# Get-HypervisorHosts 💻
<b> Detects if host(s) are running common Hypervisors (e.g. Hyper-V, VMware, VirtualBox, WSL etc.) to assist hunt for attackers carrying out tasks from VM without logging, AV or EDR monitoring.</b><br>
Looks for Microsoft Hyper-V, VMware Workstation/Player (basic ESXi signals if accessible), VirtualBox, QEMU/KVM (via process signatures), WSL Hyper-V Platform. By default queries localhost. Requires WinRM (port 5985) for remote host(s) query.<br>

<b>As a Red Teamer,</b> one of the techniques used quite often on an organization's Pwn3d box would be to introduce a VM with required tools pre-loaded, to avoid dealing with AV/EDR/Logging etc. this is a common practice (By the way, that's one reason why you might see alerts with names such as 'WIN-D2B1E23QVBC'). Yet what sparked this simple script was this <b><a title="X tweet by fellow colleague Stephan Berger" href="https://x.com/malmoeb/status/1937493450573684743?t=cysH2XBtdSoiZU3ZOWY32A&s=03" target="_blank">X tweet by fellow colleague Stephan Berger</a></b>. I thought it would be beneficial to have such a powershell script handy. of course, not replacing proper hunting platforms and tools that you may have in place, just as is. It uses several indicators, such as files, services etc.<br>

The optional parameter <b>ComputerName</b> defaults to local host. Any number of remote hosts can be queried using WinRM/PSremoting (usual especially in Active Directory domains).<br>
The optional parameter <b>CsvOutputPath</b> may be speficied to export results to a CSV file.<br>
### Example: Get indicators from local host
Import the module/function, and then run it straight forward without any parameters to get locally installed Hypervisors:<br>
```
Import-Module .\Get-HypervisorHosts.ps1;
Get-HypervisorHosts
```
![Sample results](/screenshots/gethypervisorhosts1.png) <br>
### Example: Hunt for hosts running hypervisors in the AD domain
Import the module/function, get computer names (from list, file, directly from AD, etc.) and run the query against multiple hosts, with Verbose enabled (to get query status in real-time). Results exported to a CSV file when done:<br>
```
Import-Module .\Get-HypervisorHosts.ps1;
$Date = (Get-Date).AddDays(-30); $c = Get-ADComputer -Filter {Enabled -eq $true -and LastLogonDate -ge $Date} -Properties LastLogonDate | Select -ExpandProperty Name;
Get-HypervisorHosts -ComputerName $c -CsvOutputPath c:\temp\hypervisorHostsInfo.csv -Verbose
```
![Sample results](/screenshots/gethypervisorhosts2.png) <br>
<b>Comments and improvements are welcome!</b>
