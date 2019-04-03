$runningAsAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")

if(-not $runningAsAdmin){
    throw 'Rerun this script as an admin'
}

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch as an elevated process:
    Start-Process powershell.exe "-File", ('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
    exit
}

workflow rename-localsystem {
    param (
        [string]$newname
    )
    
    Rename-Computer -Newname $newname -Force -Passthru
    
    Restart-Computer -Wait
    Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty Name | Set-Content -Path "C:\Scripts$newname.txt"
}

# rename-localsystem -newname W12SUS
