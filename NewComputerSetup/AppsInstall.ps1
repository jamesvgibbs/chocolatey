$runningAsAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")

if(-not $runningAsAdmin){
    throw 'Rerun this script as an admin'
}


#   Description:
# This script will use Windows package manager to bootstrap Chocolatey and
# install a list of packages. Script will also install Sysinternals Utilities
# into your default drive's root directory.

# Requires -RunAsAdministrator

set-executionpolicy unrestricted

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
{
  # Relaunch as an elevated process:
  Start-Process powershell.exe "-File",('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
  exit
}

$ErrorActionPreference = 'silentlycontinue'

$DebloatFolder = "C:\Temp\installer"
If (Test-Path $DebloatFolder) {
    Write-Output "$DebloatFolder exists. Skipping."
}
Else {
    Write-Output "The folder "$DebloatFolder" doesn't exist. This folder will be used for storing logs created after the script runs. Creating now."
    Start-Sleep 1
    New-Item -Path "$DebloatFolder" -ItemType Directory
    Write-Output "The folder $DebloatFolder was successfully created."
}

Start-Transcript -OutputDirectory "$DebloatFolder"

$packages = @(
    "googlechrome"
    "adblockpluschrome"
    "grammarly-chrome"
    # "lastpass"
    # "lastpass-chrome"
    "dashlane"
    #"dashlane-chrome --version 1.0.0"
    "slack"
    "speccy"
    #"windows-10-update-assistant"
    "tsprint"
    #"notepadplusplus.install"
    #"peazip.install"
    #"7zip.install"
    #"autoit"
    #"filezilla"
    #"firefox"
    #"imgburn"
    #"paint.net"
    #"putty"
    #"python"
    #"sysinternals"
    #"vlc"
    #"windirstat"
    #"wireshark"
)

Write-Output "Setting up Chocolatey software package manager"
Get-PackageProvider -Name chocolatey -Force

Write-Output "Setting up Full Chocolatey Install"
Install-Package -Name Chocolatey -Force -ProviderName chocolatey
$chocopath = (Get-Package chocolatey | Where-Object{$_.Name -eq "chocolatey"} | Select-Object @{N="Source";E={((($a=($_.Source -split "\\"))[0..($a.length - 2)]) -join "\"),"Tools\chocolateyInstall" -join "\"}} | Select-Object -ExpandProperty Source)
& $chocopath "upgrade all -y"
choco install chocolatey-core.extension --force

Write-Output "Creating daily task to automatically upgrade Chocolatey packages"
$ScheduledJob = @{
    Name = "Chocolatey Daily Upgrade"
    ScriptBlock = {choco upgrade all -y}
    Trigger = New-JobTrigger -Daily -at 2am
    ScheduledJobOption = New-ScheduledJobOption -RunElevated -MultipleInstancePolicy StopExisting -RequireNetwork
}
Register-ScheduledJob @ScheduledJob

Write-Output "Installing Packages"
$packages | ForEach-Object{choco install $_ --force -y}

Write-Output "Installing Sysinternals Utilities to C:\Sysinternals"
$download_uri = "https://download.sysinternals.com/files/SysinternalsSuite.zip"
$wc = new-object net.webclient
$wc.DownloadFile($download_uri, "/SysinternalsSuite.zip")
Add-Type -AssemblyName "system.io.compression.filesystem"
[io.compression.zipfile]::ExtractToDirectory("/SysinternalsSuite.zip", "/Sysinternals")
Write-Output "Removing zipfile"
Remove-Item "/SysinternalsSuite.zip"

# Write-Output "Installing Google Chrome Extension Dashlane"
# choco install dashlane-chrome --version 1.0.0 -y

# Write-Output "Installing Windows 10 Update Assistance"
# choco install windows-10-update-assistant -y
# Write-Output "Install Zoom"
# choco install zoom -y --checksum "3EF3C210C475B0F51F58D443B8C87994D7CC1459AD9E64D958946F9B2443CDFC"

# Phone
# https://www.zoiper.com/en/voip-softphone/download/zoiper5/for/windows
# Vonage Business


################
$username = "GJITAdmin"
$password =  ConvertTo-SecureString  -AsPlainText "GJ1500" -Force
New-LocalUser "$username" -Password $password -FullName "$username" -Description "Local admin $username"
Add-LocalGroupMember -Group "Administrators" -Member "$username"
################

Stop-Transcript