<# 
Get-HypervisorHosts - Detects if host(s) are running common Hypervisors (e.g. Hyper-V, VMware, VirtualBox, WSL etc.) to assist hunt for attackers carrying out tasks from VM without logging, AV or EDR monitoring.
Looks for Microsoft Hyper-V, VMware Workstation/Player (basic ESXi signals if accessible), VirtualBox, QEMU/KVM (via process signatures), WSL Hyper-V Platform.
By default queries localhost. Requires WinRM (port 5985) for remote host(s) query.
Version: 1.0
Comments: 1nTh35h311 (yossis@protonmail.com)
#>
function Get-HypervisorHosts {
[cmdletbinding()]
param(
    [string[]]$ComputerName = @('localhost'),
    [string]$CsvOutputPath = $null
)

# Check for elevated rights
$WindowsIdentity = [system.security.principal.windowsidentity]::GetCurrent();
$Principal = New-Object System.Security.Principal.WindowsPrincipal($WindowsIdentity);
$AdminRole = [System.Security.Principal.WindowsBuiltInRole]::Administrator;
if (!$Principal.IsInRole($AdminRole))
{
	Write-Warning "Please run as administrator / elevated shell. Quiting.";
	Break
}

$hypervisorIndicators = {
        $hostInfo = @();

        # Hyper-V
        $hvServices = "vmms", "vmcompute";
        foreach ($svc in $hvServices) {
            try {
                $s = Get-Service -Name $svc -ErrorAction Stop
                if ($s.Status -eq "Running") {
                    $hostInfo += [PSCustomObject]@{
                        Hypervisor = "Microsoft Hyper-V"
                        Indicator  = $svc
                        Type       = "Service"
                        Status     = "Running"
                    }
                }
                else
                    {
                    $hostInfo += [PSCustomObject]@{
                        Hypervisor = "Microsoft Hyper-V"
                        Indicator  = $svc
                        Type       = "Service"
                        Status     = $s.Status
                    }
                }
            } catch {}
        }

        try {
            # requires Hyper-V module 
            $vms = Get-VM -ErrorAction Stop
            if ($($vms | Measure-Object).Count -gt 0) {
                $hostInfo += [PSCustomObject]@{
                    Hypervisor = "Microsoft Hyper-V"
                    Indicator  = "Get-VM"
                    Type       = "Defined VMs"
                    Status     = "$($($VMs | Measure-Object).Count) VMs"
                }
            }
        } catch {}

        # VMware
        $vmwareProcesses = "vmware-authd", "vmware-hostd", "vmware-vmx"
        foreach ($p in $vmwareProcesses) {
            if (Get-Process -Name $p -ErrorAction SilentlyContinue) {
                $hostInfo += [PSCustomObject]@{
                    Hypervisor = "VMware Workstation/ESXi"
                    Indicator  = $p
                    Type       = "Process"
                    Status     = "Running"
                }
            }
        }

        # VirtualBox
        $vboxProcesses = "VBoxSVC", "VBoxHeadless";
        foreach ($p in $vboxProcesses) {
            if (Get-Process -Name $p -ErrorAction SilentlyContinue) {
                $hostInfo += [PSCustomObject]@{
                    Hypervisor = "Oracle VirtualBox"
                    Indicator  = $p
                    Type       = "Process"
                    Status     = "Running"
                }
            }
        }

        # QEMU/KVM
        $qemuProcesses = "qemu-system", "qemu-ga";
        foreach ($q in $qemuProcesses) {
            if (Get-Process -Name $q -ErrorAction SilentlyContinue) {
                $hostInfo += [PSCustomObject]@{
                    Hypervisor = "QEMU/KVM"
                    Indicator  = $q
                    Type       = "Process"
                    Status     = "Running"
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
                    Hypervisor = "WSL"
                    Indicator  = "Windows-Subsystem-for-Linux"
                    Type       = "WSL.exe"
                    Status     = "Installed"
                }
            }
        } catch {}

        return $hostInfo
    }

# function to ensure port 5985 is open, to shorten wait for TCP timeout (Note: probably safe to set to less than 500ms, depending on the environment)
filter Invoke-PortPing {((New-Object System.Net.Sockets.TcpClient).ConnectAsync($_,5985)).Wait(500)}

$allResults = foreach ($Computer in $ComputerName) {
        try {
            Write-Verbose "Querying $computer...";
            if ($computer -eq 'localhost') {
                $results = & $hypervisorIndicators
            } else {
                if (($computer | Invoke-PortPing) -eq "True") {
                    # host is reachable on port 5895 - check hypervisor hosts indicators via WinRM / PSRemoting
                    $results = Invoke-Command -ComputerName $computer -ScriptBlock $hypervisorIndicators -ErrorAction Stop
                }
                else {throw} # host unreachable on 5985
            }

            if ($($results | Measure-Object).count -eq 0) {
                [PSCustomObject]@{
                    Computer   = $computer
                    Hypervisor = "None detected"
                    Indicator  = "-"
                    Type       = "-"
                    Status     = "-"
                }
            } else {
                $results | ForEach-Object {
                    $_ | Add-Member -NotePropertyName Computer -NotePropertyValue $computer -Force
                    $_
                }
            }
        } catch {
            [PSCustomObject]@{
                Computer   = $computer
                Hypervisor = "ERROR"
                Indicator  = "-"
                Type       = "Connection"
                Status     = $(if ($_.Exception.Message -eq "ScriptHalted") {'Port not responding'} else {$_.Exception.Message})
            }
        }
    }

if ($CsvOutputPath) {
        $allResults | Export-Csv -Path $CsvOutputPath -NoTypeInformation -Encoding UTF8;
        Write-Host "`nSaved to $CsvOutputPath" -ForegroundColor Cyan
    }

    return $allResults | Format-Table -AutoSize
}