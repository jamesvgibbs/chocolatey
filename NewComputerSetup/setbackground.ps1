$runningAsAdmin = [bool](([System.Security.Principal.WindowsIdentity]::GetCurrent()).groups -match "S-1-5-32-544")

if(-not $runningAsAdmin){
    throw 'Rerun this script as an admin'
}

If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    # Relaunch as an elevated process:
    Start-Process powershell.exe "-File", ('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs
    exit
}
  
Function DownloadImage {
    $url = "https://github.com/jimgibbs/chocolatey/raw/master/NewComputerSetup/gj-background.jpg"

    Invoke-WebRequest $url -OutFile "C:\Users\Public\Pictures\gj-background.jpg"
}

Function SetWallpaper {
    $path = "C:\Users\Public\Pictures\gj-background.jpg"
    if(-Not (Test-Path $path)){
        DownloadImage
    }

    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\" -name Wallpaper -value $path
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\" -name TileWallpaper -value "0"
    Set-ItemProperty -Path "HKCU:\Control Panel\Desktop\" -name WallpaperStyle -value "10"

    Start-Sleep 5
    RUNDLL32.EXE USER32.DLL,UpdatePerUserSystemParameters 2, True
}

$SetBackground = "C:\Temp\SetBackground"
If (Test-Path $SetBackground) {
    Write-Output "$SetBackground exists. Skipping."
}
Else {
    Write-Output "The folder "$SetBackground" doesn't exist. This folder will be used for storing logs created after the script runs. Creating now."
    Start-Sleep 1
    New-Item -Path "$SetBackground" -ItemType Directory
    Write-Output "The folder $SetBackground was successfully created."
}

Start-Transcript -OutputDirectory "$SetBackground"

Start-Sleep 1
Write-Output "Dowloading Background Image."
DownloadImage
Write-Output "Download Complete."
Start-Sleep 1
Write-Output "Set Background Image."
SetWallpaper
Write-Output "Background Set."
Start-Sleep 1
Stop-Transcript