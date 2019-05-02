# to run this script execute:
#  (new-object Net.WebClient).DownloadString("https://raw.githubusercontent.com/jimgibbs/chocolatey/master/NewComputerSetup/machine-setup.ps1") | iex

$runningAsAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")

if(-not $runningAsAdmin){
    throw 'Rerun this script as an admin'
}

Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
# download the file and run it
###############################################
###                                         ###
###             DEBLOAT WINDOWS             ###
###                                         ###
###############################################
$machineSetupUrl = 'https://raw.githubusercontent.com/jimgibbs/chocolatey/master/NewComputerSetup/Windows10Debloater.ps1'
$expectedFilepath = (join-path $env:TEMP 'machine-setup.ps1')

if(test-path $expectedFilepath -PathType Leaf){
    Remove-Item -Path $expectedFilepath
}

if(-not (Test-Path $expectedFilepath)){
    New-Item -Path ([System.IO.Path]::GetDirectoryName($expectedFilepath)) -ItemType Directory
}

Invoke-WebRequest -Uri $machineSetupUrl -OutFile $expectedFilepath

. $expectedFilepath

# download the file and run it
###############################################
###                                         ###
###             SET BACKGROUD               ###
###                                         ###
###############################################
$machineSetupUrl = 'https://raw.githubusercontent.com/jimgibbs/chocolatey/master/NewComputerSetup/setbackground.ps1'
$expectedFilepath = (join-path $env:TEMP 'SayedHamachineSetup\machine-setup.ps1')

if(test-path $expectedFilepath -PathType Leaf){
    Remove-Item -Path $expectedFilepath
}

if(-not (Test-Path $expectedFilepath)){
    New-Item -Path ([System.IO.Path]::GetDirectoryName($expectedFilepath)) -ItemType Directory
}

Invoke-WebRequest -Uri $machineSetupUrl -OutFile $expectedFilepath

. $expectedFilepath


# download the file and run it
###############################################
###                                         ###
###             INSTALL APPS                ###
###                                         ###
###############################################
$machineSetupUrl = 'https://raw.githubusercontent.com/jimgibbs/chocolatey/master/NewComputerSetup/AppsInstall.ps1'
$expectedFilepath = (join-path $env:TEMP 'SayedHamachineSetup\machine-setup.ps1')

if(test-path $expectedFilepath -PathType Leaf){
    Remove-Item -Path $expectedFilepath
}

if(-not (Test-Path $expectedFilepath)){
    New-Item -Path ([System.IO.Path]::GetDirectoryName($expectedFilepath)) -ItemType Directory
}

Invoke-WebRequest -Uri $machineSetupUrl -OutFile $expectedFilepath

. $expectedFilepath


###############################################
###                                         ###
###             SET TIMEZONE                ###
###                                         ###
###############################################
Set-TimeZone -Name "Eastern Standard Time"


###############################################
###                                         ###
###           RESTART COMPUTER              ###
###                                         ###
###############################################
Restart-Computer 