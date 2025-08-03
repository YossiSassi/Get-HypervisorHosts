function Get-HypervisorHosts {
<#
.SYNOPSIS
Get-HypervisorHosts - Detects if host(s) are running common Hypervisors (e.g. Hyper-V, VMware, VirtualBox, WSL etc.) to assist hunt for attackers carrying out tasks from VM without logging, AV or EDR monitoring.

Function: Get-HypervisorHosts
Author: 1nTh35h311 (yossis@protonmail.com, #Yossi_Sassi)

Version: 1.1
v1.1 - Added help + Changed csv output to 'write as we go' rather than wait until done + Added OS version information + Added optional parameter that gets interactively logged-on user(s).
v1.0 - initial script

Required Dependencies: None
Optional Dependencies: Some details may require modules, e.g. Hyper-V modules to get number of VMs

.DESCRIPTION
Get-HypervisorHosts - Detects if host(s) are running common Hypervisors (e.g. Hyper-V, VMware, VirtualBox, WSL etc.) to assist hunt for attackers carrying out tasks from VM without logging, AV or EDR monitoring.
Looks for Microsoft Hyper-V, VMware Workstation/Player (basic ESXi signals if accessible), VirtualBox, QEMU/KVM (via process signatures), WSL Hyper-V Platform.
By default queries localhost. Requires WinRM (port 5985) for remote host(s) query.

.PARAMETER ComputerName
The Active Directory host to query. can specifiy one or many hosts. default is localhost.

.PARAMETER CsvOutputPath
The full path to save the results to a csv file, e.g. c:\temp\hypervisorHostsInfo.csv

.PARAMETER GetLoggedOnUser
When this switch parameter is specified, results include also the currently interactive logged-on user(s).

.EXAMPLE
Get installed hypervisors from the local host:

Import-Module .\Get-HypervisorHosts.ps1;
Get-HypervisorHosts

.EXAMPLE
Get installed hypervisors from several computers using WinRM, including logged-on users, and display progress (verbose):

Import-Module .\Get-Get-HypervisorHosts.ps1;
Get-HypervisorHosts -ComputerName SRV1, SRV2 -GetLoggedOnUser

.EXAMPLE
Get installed hypervisors from all enabled computer accounts in the domain that logged on in the last 30 days (recently active hosts), filter those with WSMAN SPN (winRM potentially enabled). display progress (verbose) and save results to a csv file. then, when done, help in potential hunt/filter by importing the csv and filtering out only the hosts with hypervisor(s) found (filters out connection errors and none-detected), and outputs to both console as well as a grid report:

# Get report
$Date = (Get-Date).AddDays(-30); 
$ComputersFilteredList = Get-ADComputer -Filter {Enabled -eq $true -and LastLogonDate -ge $Date} -Properties ` LastLogonDate, serviceprincipalname | ? serviceprincipalname -like "*wsman*";
Import-Module .\Get-HypervisorHosts.ps1;
Get-HypervisorHosts -ComputerName $ComputersFilteredList.name -CsvOutputPath c:\temp\hypervisorHostsInfo.csv ` -Verbose;

# filter / hunt for anomalies
$hypervisorResults = import-csv .\hypervisorHostsInfo.csv;
"Total hosts scanned: $($hypervisorResults.count)";
$stateToFilter = 'None detected','ERROR';
$hypervisorResults | ? hypervisor -NotIn $stateToFilter | Out-Gridview #or, in console:
$hypervisorResults | ? hypervisor -NotIn $stateToFilter | ft | more

.LINK
yossis@protonmail.com
#>

[cmdletbinding()]
param(
    [string[]]$ComputerName = @('localhost'),
    [string]$CsvOutputPath = $null,
    [switch]$GetLoggedOnUser
)

$hypervisorIndicators = {
        $hostInfo = @();
        
        # Get computername
        $ComputerName = $ENV:COMPUTERNAME;

        # Get OS information
        $OSversionRegKey = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion";
        $OSInfo = "$($OSversionRegKey.ProductName) $($OSversionRegKey.DisplayVersion) ($($OSversionRegKey.CurrentBuild))";

        # Get interactively logged on users
        $GetLoggedOnUserInfo = {
            $LoggedOnUser = (Get-Process -Name explorer -ErrorAction SilentlyContinue -IncludeUserName).username
        }
        <# alternative way (slower + involves WMI which we can avoid)
        $GetLoggedOnUserInfo = {
            $LoggedOnUser = Get-WmiObject -Class Win32_Process -Filter "Name='explorer.exe'" |
              ForEach-Object {
                $owner = $_.GetOwner();
                $LogonDate = [System.Management.ManagementDateTimeConverter]::ToDateTime($_.CreationDate);
                "$($owner.Domain)\$($owner.User) ($LogonDate)"
              } | Select-Object -Unique
        }
        #>

        switch ($Host.Name) {
        # PSRemoting
        "ServerRemoteHost" {
                if ($using:GetLoggedOnUser) {
                    $GetLoggedOnUserInfo | Invoke-Expression
                }
                else
                    {
                    $LoggedOnUser = "n/a"
                }
            }
        # localhost (no $using:)
        "ConsoleHost" {
                if ($GetLoggedOnUser) {
                    $GetLoggedOnUserInfo | Invoke-Expression
                }
                else
                    {
                    $LoggedOnUser = "n/a"
                }
            }
        }

        # Hyper-V
        $hvServices = "vmms", "vmcompute";
        foreach ($svc in $hvServices) {
            try {
                $s = Get-Service -Name $svc -ErrorAction Stop
                if ($s.Status -eq "Running") {
                    $hostInfo += [PSCustomObject]@{
                        Computer = $ComputerName
                        Hypervisor = "Microsoft Hyper-V"
                        Indicator  = $svc
                        Type       = "Service"
                        Status     = "Running"
                        OSInfo     = $OSInfo
                        LoggedOnUser = $LoggedOnUser
                    }
                }
                else
                    {
                    $hostInfo += [PSCustomObject]@{
                        Computer = $ComputerName
                        Hypervisor = "Microsoft Hyper-V"
                        Indicator  = $svc
                        Type       = "Service"
                        Status     = $s.Status
                        OSInfo     = $OSInfo
                        LoggedOnUser = $LoggedOnUser
                    }
                }
            } catch {}
        }

        try {
            # requires Hyper-V module 
            $vms = Get-VM -ErrorAction Stop
            if ($($vms | Measure-Object).Count -gt 0) {
                $hostInfo += [PSCustomObject]@{
                    Computer = $ComputerName
                    Hypervisor = "Microsoft Hyper-V"
                    Indicator  = "Get-VM"
                    Type       = "Defined VMs"
                    Status     = "$($($VMs | Measure-Object).Count) VMs"
                    OSInfo     = $OSInfo
                    LoggedOnUser = $LoggedOnUser
                }
            }
        } catch {}

        # VMware
        $vmwareProcesses = "vmware-authd", "vmware-hostd", "vmware-vmx"
        foreach ($p in $vmwareProcesses) {
            if (Get-Process -Name $p -ErrorAction SilentlyContinue) {
                $hostInfo += [PSCustomObject]@{
                    Computer = $ComputerName
                    Hypervisor = "VMware Workstation/ESXi"
                    Indicator  = $p
                    Type       = "Process"
                    Status     = "Running"
                    OSInfo     = $OSInfo
                    LoggedOnUser = $LoggedOnUser
                }
            }
        }

        # VirtualBox
        $vboxProcesses = "VBoxSVC", "VBoxHeadless";
        foreach ($p in $vboxProcesses) {
            if (Get-Process -Name $p -ErrorAction SilentlyContinue) {
                $hostInfo += [PSCustomObject]@{
                    Computer = $ComputerName
                    Hypervisor = "Oracle VirtualBox"
                    Indicator  = $p
                    Type       = "Process"
                    Status     = "Running"
                    OSInfo     = $OSInfo
                    LoggedOnUser = $LoggedOnUser
                }
            }
        }

        # QEMU/KVM
        $qemuProcesses = "qemu-system", "qemu-ga";
        foreach ($q in $qemuProcesses) {
            if (Get-Process -Name $q -ErrorAction SilentlyContinue) {
                $hostInfo += [PSCustomObject]@{
                    Computer = $ComputerName
                    Hypervisor = "QEMU/KVM"
                    Indicator  = $q
                    Type       = "Process"
                    Status     = "Running"
                    OSInfo     = $OSInfo
                    LoggedOnUser = $LoggedOnUser
                }
            }
        }

        # WSL2 Hypervisor (nested Hyper-V layer)
        try {
            # alternative no.1, sometimes can get stuck -> (Get-WindowsOptionalFeature -Online -FeatureName "*-Linux" -ErrorAction Stop).State -eq 'Enabled'
            # alternative no.2 -> $wslInstalled = (& wsl.exe --status) -match "Default Version|WSL"; if ($wslInstalled) {
            $WSLoutput = & wsl.exe --status 2>&1;
            if ($LASTEXITCODE -eq 0 -and $WSLoutput) {
                $hostInfo += [PSCustomObject]@{
                    Computer = $ComputerName
                    Hypervisor = "WSL"
                    Indicator  = "Windows-Subsystem-for-Linux"
                    Type       = "WSL.exe"
                    Status     = "Installed"
                    OSInfo     = $OSInfo
                    LoggedOnUser = $LoggedOnUser
                }

            }
            } catch {}

            # if no hypervisor found - add a 'None detected' result
            if ($($hostInfo | Measure-Object).count -eq 0) {
                $hostInfo += [PSCustomObject]@{
                    Computer = $ComputerName
                    Hypervisor = "None detected"
                    Indicator  = "-"
                    Type       = "-"
                    Status     = "-"
                    OSInfo     = $OSInfo
                    LoggedOnUser = $LoggedOnUser
                }
        }

        return $hostInfo
    }

# function to ensure port 5985 is open, to shorten wait for TCP timeout (Note: probably safe to set to less than 500ms, depending on the environment)
filter Invoke-PortPing {((New-Object System.Net.Sockets.TcpClient).ConnectAsync($_,5985)).Wait(500)}

$allResults = foreach ($Computer in $ComputerName) {
        try {
            Write-Verbose "Querying $computer...";
            if ($computer -eq 'localhost') {                
                # Check for elevated rights
                $WindowsIdentity = [system.security.principal.windowsidentity]::GetCurrent();
                $Principal = New-Object System.Security.Principal.WindowsPrincipal($WindowsIdentity);
                $AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator;
                if (!$Principal.IsInRole($AdminRole))
                {
	                Write-Warning "Please run as administrator / elevated shell. Quiting.";
	                Break
                }
                $results = & $hypervisorIndicators
            } else {
                if (($computer | Invoke-PortPing) -eq "True") {
                    # host is reachable on port 5895 - check hypervisor hosts indicators via WinRM / PSRemoting
                    $results = Invoke-Command -ComputerName $computer -ScriptBlock $hypervisorIndicators -ErrorAction Stop
                }
                else {throw} # host unreachable on 5985
            }

            $results

        } catch {
            [PSCustomObject]@{
                Computer   = $computer
                Hypervisor = "ERROR"
                Indicator  = "-"
                Type       = "Connection"
                Status     = $(if ($_.Exception.Message -eq "ScriptHalted") {'Port not responding'} else {$_.Exception.Message})
                OSInfo     = "-"
                LoggedOnUser = "-"
            }
        }
        
        # write current computer result to CSV if parameter was specified
        if ($CsvOutputPath) {
            $results | Select Computer, Hypervisor, Indicator, Type, Status, OSInfo, LoggedOnUser | Export-Csv -Path $CsvOutputPath -NoTypeInformation -Encoding UTF8 -Append
        }

        Clear-Variable results, Computer, Hypervisor, Indicator, Type, Status, OSInfo, LoggedOnUser -ErrorAction SilentlyContinue

    }

if ($CsvOutputPath) {
        Write-Host "`nResults saved to $CsvOutputPath" -ForegroundColor Cyan
    }

return $allResults | Select Computer, Hypervisor, Indicator, Type, Status, OSInfo, LoggedOnUser | Format-Table -AutoSize
}