$ErrorActionPreference = "Stop";

$toolsPath = Split-Path -parent $MyInvocation.MyCommand.Definition

Write-Host $toolsPath

$packageArgs = @{
    $packageName   = $env:ChocolateyPackageName
    fileType       = "exe"
    silentArgs     = "/S"
    file           = "$toolsPath\Zoiper5_Installer_v5.2.25.exe"
    softwareName   = 'Zoiper*'
    validExitCodes = @(0)
};

Install-ChocolateyInstallPackage @packageArgs

$installLocation = Get-AppInstallLocation $packageArgs.softwareName
if (!$installLocation)  {  Write-Warning "Can't find $PackageName install location"; return }

Write-Host "$packageName installed to '$installLocation'"
Install-BinFile -Path "$installLocation\zoiper.exe" -Name 'Zoiper'

Get-ChildItem $toolsPath\*.exe | ForEach-Object { Remove-Item $_ -ea 0; if (Test-Path $_) { Set-Content "$_.ignore" '' } }