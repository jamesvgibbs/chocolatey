# Requires -RunAsAdministrator
set-executionpolicy unrestricted
# Self-elevate the script if required
If (-NOT ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "You didn't run this script as an Administrator. This script will self elevate to run as an Administrator." -ForegroundColor "White"
    Start-Sleep 1
    # Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File", ('"{0}"' -f $MyInvocation.MyCommand.Path) -Verb RunAs 

    $arguments = "&" + $MyInvocation.MyCommand.Definition + ""
    Start-Process "powershell.exe" -Verb RunAs -ArgumentList $arguments

    Break
}
Else {
    #no errors throughout
    $ErrorActionPreference = 'silentlycontinue'

    $DebloatFolder = "C:\Temp\Windows10Debloater"
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

    Write-Output "Add-Type -AssemblyName PresentationCore, PresentationFramework"
    Add-Type -AssemblyName PresentationCore, PresentationFramework

    #This will debloat Windows 10
    #Creates a "drive" to access the HKCR (HKEY_CLASSES_ROOT)
    Write-Output "Creating PSDrive 'HKCR' (HKEY_CLASSES_ROOT). This will be used for the duration of the script as it is necessary for the removal and modification of specific registry keys."
    New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    Start-Sleep 1
    Write-Output "Uninstalling bloatware, please wait."
    DebloatAll
    Write-Output "Bloatware removed."
    Start-Sleep 1
    Write-Output "Removing specific registry keys."
    Remove-Keys
    Write-Output "Leftover bloatware registry keys removed."
    Start-Sleep 1
    Write-Output "Checking to see if any Whitelisted Apps were removed, and if so re-adding them."
    Start-Sleep 1
    FixWhitelistedApps
    Start-Sleep 1
    Write-Output "Disabling Cortana from search, disabling feedback to Microsoft, and disabling scheduled tasks that are considered to be telemetry or unnecessary."
    Protect-Privacy
    Start-Sleep 1
    DisableCortana
    Write-Output "Cortana disabled and removed from search, feedback to Microsoft has been disabled, and scheduled tasks are disabled."
    Start-Sleep 1
    Write-Output "Stopping and disabling Diagnostics Tracking Service"
    DisableDiagTrack
    Write-Output "Diagnostics Tracking Service disabled"
    Start-Sleep 1
    Write-Output "Disabling WAP push service"
    Start-Sleep 1
    DisableWAPPush
    Write-Output "Re-enabling DMWAppushservice if it was disabled"
    CheckDMWService
    Start-Sleep 1
    Stop-EdgePDF
    Write-Output "Edge will no longer take over as the default PDF viewer."
    UninstallOneDrive
    Write-Output "OneDrive is now removed from the computer."
    UnpinStart
    Write-Output "Start Apps unpined."

    Write-Output "Unloading the HKCR drive..."
    Remove-PSDrive HKCR 
    Start-Sleep 1

    If (Test-Path -Path "$env:ProgramData\Chocolatey" !== True) {
        Set-ExecutionPolicy Bypass -Scope Process -Force; Invoke-Expression ((New-Object System.Net.WebClient).DownloadString("https://chocolatey.org/install.ps1"))
    }

    # Browsers + Extensions
    Write-Output "Installing Google Chrome"
    choco install googlechrome -y
    Write-Output "Installing Google Chrome Extension AdBlocker Plus"
    choco install adblockpluschrome -y
    Write-Output "Installing Google Chrome Extension Grammarly"
    choco install grammarly-chrome -y

    # Password Manager
    Write-Output "Installing LastPass"
    choco install lastpass -y
    Write-Output "Installing Google Chrome Extension LastPass"
    choco install lastpass-chrome -y
    Write-Output "Installing Dashlane"
    choco install dashlane -y
    Write-Output "Installing Google Chrome Extension Dashlane"
    choco install dashlane-chrome --version 1.0.0 -y

    # Utilities + other
    Write-Output "Installing Slack"
    choco install slack -y
    Write-Output "Installing Windows 10 Update Assistance"
    choco install windows-10-update-assistant -y
    Write-Output "Installing Speccy"
    choco install speccy -y
    Write-Output "Install Zoom"
    choco install zoom -y --checksum "3EF3C210C475B0F51F58D443B8C87994D7CC1459AD9E64D958946F9B2443CDFC"

    # Phone
    # https://www.zoiper.com/en/voip-softphone/download/zoiper5/for/windows
    # Vonage Business

    Write-Output "Initiating reboot."
    Start-Sleep 2
    Restart-Computer

    Stop-Transcript
}

Function DebloatAll {
    
    [CmdletBinding()]
        
    Param()
    
    #Removes AppxPackages
    #Credit to /u/GavinEke for a modified version of my whitelist code
    [regex]$WhitelistedApps = 'Microsoft.ScreenSketch|Microsoft.Paint3D|Microsoft.WindowsCalculator|Microsoft.WindowsStore|Microsoft.Windows.Photos|CanonicalGroupLimited.UbuntuonWindows|`
    Microsoft.XboxGameCallableUI|Microsoft.XboxGamingOverlay|Microsoft.Xbox.TCUI|Microsoft.XboxGamingOverlay|Microsoft.XboxIdentityProvider|Microsoft.MicrosoftStickyNotes|Microsoft.MSPaint|Microsoft.WindowsCamera|.NET|Framework|`
    Microsoft.HEIFImageExtension|Microsoft.ScreenSketch|Microsoft.StorePurchaseApp|Microsoft.VP9VideoExtensions|Microsoft.WebMediaExtensions|Microsoft.WebpImageExtension|Microsoft.DesktopAppInstaller|WindSynthBerry|MIDIBerry|Slack'
    Get-AppxPackage -AllUsers | Where-Object {$_.Name -NotMatch $WhitelistedApps} | Remove-AppxPackage
    Get-AppxPackage | Where-Object {$_.Name -NotMatch $WhitelistedApps} | Remove-AppxPackage
    Get-AppxProvisionedPackage -Online | Where-Object {$_.PackageName -NotMatch $WhitelistedApps} | Remove-AppxProvisionedPackage -Online
}

Function Remove-Keys {
        
    [CmdletBinding()]
            
    Param()
        
    #These are the registry keys that it will delete.
            
    $Keys = @(
            
        #Remove Background Tasks
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.BackgroundTasks\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        #Windows File
        "HKCR:\Extensions\ContractId\Windows.File\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
            
        #Registry keys to delete if they aren't uninstalled by RemoveAppXPackage/RemoveAppXProvisionedPackage
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\46928bounde.EclipseManager_2.2.4.51_neutral__a5h4egax66k6y"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Launch\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
            
        #Scheduled Tasks to delete
        "HKCR:\Extensions\ContractId\Windows.PreInstalledConfigTask\PackageId\Microsoft.MicrosoftOfficeHub_17.7909.7600.0_x64__8wekyb3d8bbwe"
            
        #Windows Protocol Keys
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.PPIProjection_10.0.15063.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.15063.0.0_neutral_neutral_cw5n1h2txyewy"
        "HKCR:\Extensions\ContractId\Windows.Protocol\PackageId\Microsoft.XboxGameCallableUI_1000.16299.15.0_neutral_neutral_cw5n1h2txyewy"
               
        #Windows Share Target
        "HKCR:\Extensions\ContractId\Windows.ShareTarget\PackageId\ActiproSoftwareLLC.562882FEEB491_2.6.18.18_neutral__24pqs290vpjk0"
    )
        
    #This writes the output of each key it is removing and also removes the keys listed above.
    ForEach ($Key in $Keys) {
        Write-Output "Removing $Key from registry"
        Remove-Item $Key -Recurse
    }
}
            
Function Protect-Privacy {
        
    [CmdletBinding()]
        
    Param()
            
    #Disables Windows Feedback Experience
    Write-Output "Disabling Windows Feedback Experience program"
    $Advertising = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\AdvertisingInfo"
    If (Test-Path $Advertising) {
        Set-ItemProperty $Advertising Enabled -Value 0 
    }
            
    #Stops Cortana from being used as part of your Windows Search Function
    Write-Output "Stopping Cortana from being used as part of your Windows Search Function"
    $Search = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    If (Test-Path $Search) {
        Set-ItemProperty $Search AllowCortana -Value 0 
    }

    #Disables Web Search in Start Menu
    Write-Output "Disabling Bing Search in Start Menu"
    $WebSearch = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\Windows Search"
    Set-ItemProperty "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Search" BingSearchEnabled -Value 0 
    If (!(Test-Path $WebSearch)) {
        New-Item $WebSearch
    }
    Set-ItemProperty $WebSearch DisableWebSearch -Value 1 
            
    #Stops the Windows Feedback Experience from sending anonymous data
    Write-Output "Stopping the Windows Feedback Experience program"
    $Period = "HKCU:\Software\Microsoft\Siuf\Rules"
    If (!(Test-Path $Period)) { 
        New-Item $Period
    }
    Set-ItemProperty $Period PeriodInNanoSeconds -Value 0 

    #Prevents bloatware applications from returning and removes Start Menu suggestions               
    Write-Output "Adding Registry key to prevent bloatware apps from returning"
    $registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\CloudContent"
    $registryOEM = "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\ContentDeliveryManager"
    If (!(Test-Path $registryPath)) { 
        New-Item $registryPath
    }
    Set-ItemProperty $registryPath DisableWindowsConsumerFeatures -Value 1 

    If (!(Test-Path $registryOEM)) {
        New-Item $registryOEM
    }
    Set-ItemProperty $registryOEM  ContentDeliveryAllowed -Value 0 
    Set-ItemProperty $registryOEM  OemPreInstalledAppsEnabled -Value 0 
    Set-ItemProperty $registryOEM  PreInstalledAppsEnabled -Value 0 
    Set-ItemProperty $registryOEM  PreInstalledAppsEverEnabled -Value 0 
    Set-ItemProperty $registryOEM  SilentInstalledAppsEnabled -Value 0 
    Set-ItemProperty $registryOEM  SystemPaneSuggestionsEnabled -Value 0          
    
    #Preping mixed Reality Portal for removal    
    Write-Output "Setting Mixed Reality Portal value to 0 so that you can uninstall it in Settings"
    $Holo = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Holographic"    
    If (Test-Path $Holo) {
        Set-ItemProperty $Holo  FirstRunSucceeded -Value 0 
    }

    #Disables Wi-fi Sense
    Write-Output "Disabling Wi-Fi Sense"
    $WifiSense1 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting"
    $WifiSense2 = "HKLM:\SOFTWARE\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots"
    $WifiSense3 = "HKLM:\SOFTWARE\Microsoft\WcmSvc\wifinetworkmanager\config"
    If (!(Test-Path $WifiSense1)) {
        New-Item $WifiSense1
    }
    Set-ItemProperty $WifiSense1  Value -Value 0 
    If (!(Test-Path $WifiSense2)) {
        New-Item $WifiSense2
    }
    Set-ItemProperty $WifiSense2  Value -Value 0 
    Set-ItemProperty $WifiSense3  AutoConnectAllowedOEM -Value 0 
        
    #Disables live tiles
    Write-Output "Disabling live tiles"
    $Live = "HKCU:\SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\PushNotifications"    
    If (!(Test-Path $Live)) {      
        New-Item $Live
    }
    Set-ItemProperty $Live  NoTileApplicationNotification -Value 1 
        
    #Turns off Data Collection via the AllowTelemtry key by changing it to 0
    Write-Output "Turning off Data Collection"
    $DataCollection1 = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection"
    $DataCollection2 = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\DataCollection"
    $DataCollection3 = "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Policies\DataCollection"    
    If (Test-Path $DataCollection1) {
        Set-ItemProperty $DataCollection1  AllowTelemetry -Value 0 
    }
    If (Test-Path $DataCollection2) {
        Set-ItemProperty $DataCollection2  AllowTelemetry -Value 0 
    }
    If (Test-Path $DataCollection3) {
        Set-ItemProperty $DataCollection3  AllowTelemetry -Value 0 
    }
    
    #Disabling Location Tracking
    Write-Output "Disabling Location Tracking"
    $SensorState = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}"
    $LocationConfig = "HKLM:\SYSTEM\CurrentControlSet\Services\lfsvc\Service\Configuration"
    If (!(Test-Path $SensorState)) {
        New-Item $SensorState
    }
    Set-ItemProperty $SensorState SensorPermissionState -Value 0 
    If (!(Test-Path $LocationConfig)) {
        New-Item $LocationConfig
    }
    Set-ItemProperty $LocationConfig Status -Value 0 
        
    #Disables People icon on Taskbar
    Write-Output "Disabling People icon on Taskbar"
    $People = 'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People'
    If (Test-Path $People) {
        Set-ItemProperty $People -Name PeopleBand -Value 0 -Verbose
    }
        
    #Disables scheduled tasks that are considered unnecessary 
    Write-Output "Disabling scheduled tasks"
    Get-ScheduledTask  XblGameSaveTaskLogon | Disable-ScheduledTask
    Get-ScheduledTask  XblGameSaveTask | Disable-ScheduledTask
    Get-ScheduledTask  Consolidator | Disable-ScheduledTask
    Get-ScheduledTask  UsbCeip | Disable-ScheduledTask
    Get-ScheduledTask  DmClient | Disable-ScheduledTask
    Get-ScheduledTask  DmClientOnScenarioDownload | Disable-ScheduledTask

    Write-Output "Stopping and disabling Diagnostics Tracking Service"
    #Disabling the Diagnostics Tracking Service
    Stop-Service "DiagTrack"
    Set-Service "DiagTrack" -StartupType Disabled

    
    Write-Output "Removing CloudStore from registry if it exists"
    $CloudStore = 'HKCUSoftware\Microsoft\Windows\CurrentVersion\CloudStore'
    If (Test-Path $CloudStore) {
        Stop-Process Explorer.exe -Force
        Remove-Item $CloudStore
        Start-Process Explorer.exe -Wait
    }
}

Function DisableCortana {
    Write-Host "Disabling Cortana"
    $Cortana1 = "HKCU:\SOFTWARE\Microsoft\Personalization\Settings"
    $Cortana2 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization"
    $Cortana3 = "HKCU:\SOFTWARE\Microsoft\InputPersonalization\TrainedDataStore"
    If (!(Test-Path $Cortana1)) {
        New-Item $Cortana1
    }
    Set-ItemProperty $Cortana1 AcceptedPrivacyPolicy -Value 0 
    If (!(Test-Path $Cortana2)) {
        New-Item $Cortana2
    }
    Set-ItemProperty $Cortana2 RestrictImplicitTextCollection -Value 1 
    Set-ItemProperty $Cortana2 RestrictImplicitInkCollection -Value 1 
    If (!(Test-Path $Cortana3)) {
        New-Item $Cortana3
    }
    Set-ItemProperty $Cortana3 HarvestContacts -Value 0
    
}
        
Function Stop-EdgePDF {
    
    #Stops edge from taking over as the default .PDF viewer    
    Write-Output "Stopping Edge from taking over as the default .PDF viewer"
    $NoPDF = "HKCR:\.pdf"
    $NoProgids = "HKCR:\.pdf\OpenWithProgids"
    $NoWithList = "HKCR:\.pdf\OpenWithList" 
    If (!(Get-ItemProperty $NoPDF  NoOpenWith)) {
        New-ItemProperty $NoPDF NoOpenWith 
    }        
    If (!(Get-ItemProperty $NoPDF  NoStaticDefaultVerb)) {
        New-ItemProperty $NoPDF  NoStaticDefaultVerb 
    }        
    If (!(Get-ItemProperty $NoProgids  NoOpenWith)) {
        New-ItemProperty $NoProgids  NoOpenWith 
    }        
    If (!(Get-ItemProperty $NoProgids  NoStaticDefaultVerb)) {
        New-ItemProperty $NoProgids  NoStaticDefaultVerb 
    }        
    If (!(Get-ItemProperty $NoWithList  NoOpenWith)) {
        New-ItemProperty $NoWithList  NoOpenWith
    }        
    If (!(Get-ItemProperty $NoWithList  NoStaticDefaultVerb)) {
        New-ItemProperty $NoWithList  NoStaticDefaultVerb 
    }
            
    #Appends an underscore '_' to the Registry key for Edge
    $Edge = "HKCR:\AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_"
    If (Test-Path $Edge) {
        Set-Item $Edge AppXd4nrz8ff68srnhf9t5a8sbjyar1cr723_ 
    }
}

Function CheckDMWService {

    Param([switch]$Debloat)
  
    If (Get-Service -Name dmwappushservice | Where-Object {$_.StartType -eq "Disabled"}) {
        Set-Service -Name dmwappushservice -StartupType Automatic
    }

    If (Get-Service -Name dmwappushservice | Where-Object {$_.Status -eq "Stopped"}) {
        Start-Service -Name dmwappushservice
    } 
}

Function FixWhitelistedApps {
    
    [CmdletBinding()]
            
    Param()
    
    If (!(Get-AppxPackage -AllUsers | Select-Object Microsoft.Paint3D, Microsoft.WindowsCalculator, Microsoft.WindowsStore, Microsoft.Windows.Photos)) {
    
        #Credit to abulgatz for these 4 lines of code
        Get-AppxPackage -allusers Microsoft.Paint3D | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
        Get-AppxPackage -allusers Microsoft.WindowsCalculator | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
        Get-AppxPackage -allusers Microsoft.WindowsStore | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"}
        Get-AppxPackage -allusers Microsoft.Windows.Photos | ForEach-Object {Add-AppxPackage -DisableDevelopmentMode -Register "$($_.InstallLocation)\AppXManifest.xml"} 
    } 
}

Function UninstallOneDrive {

    Write-Output "Checking for pre-existing files and folders located in the OneDrive folders..."
    Start-Sleep 1
    If (Get-Item -Path "$env:USERPROFILE\OneDrive\*") {
        Write-Output "Files found within the OneDrive folder! Checking to see if a folder named OneDriveBackupFiles exists."
        Start-Sleep 1
              
        If (Get-Item "$env:USERPROFILE\Desktop\OneDriveBackupFiles" -ErrorAction SilentlyContinue) {
            Write-Output "A folder named OneDriveBackupFiles already exists on your desktop. All files from your OneDrive location will be moved to that folder." 
        }
        else {
            If (!(Get-Item "$env:USERPROFILE\Desktop\OneDriveBackupFiles" -ErrorAction SilentlyContinue)) {
                Write-Output "A folder named OneDriveBackupFiles will be created and will be located on your desktop. All files from your OneDrive location will be located in that folder."
                New-item -Path "$env:USERPROFILE\Desktop" -Name "OneDriveBackupFiles"-ItemType Directory -Force
                Write-Output "Successfully created the folder 'OneDriveBackupFiles' on your desktop."
            }
        }
        Start-Sleep 1
        Move-Item -Path "$env:USERPROFILE\OneDrive\*" -Destination "$env:USERPROFILE\Desktop\OneDriveBackupFiles" -Force
        Write-Output "Successfully moved all files/folders from your OneDrive folder to the folder 'OneDriveBackupFiles' on your desktop."
        Start-Sleep 1
        Write-Output "Proceeding with the removal of OneDrive."
        Start-Sleep 1
    }
    Else {
        If (!(Get-Item -Path "$env:USERPROFILE\OneDrive\*")) {
            Write-Output "Either the OneDrive folder does not exist or there are no files to be found in the folder. Proceeding with removal of OneDrive."
            Start-Sleep 1
        }
    }

    Write-Output "Uninstalling OneDrive"
    
    New-PSDrive  HKCR -PSProvider Registry -Root HKEY_CLASSES_ROOT
    $onedrive = "$env:SYSTEMROOT\SysWOW64\OneDriveSetup.exe"
    $ExplorerReg1 = "HKCR:\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    $ExplorerReg2 = "HKCR:\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6}"
    Stop-Process -Name "OneDrive*"
    Start-Sleep 2
    If (!(Test-Path $onedrive)) {
        $onedrive = "$env:SYSTEMROOT\System32\OneDriveSetup.exe"
    }
    Start-Process $onedrive "/uninstall" -NoNewWindow -Wait
    Start-Sleep 2
    Write-Output "Stopping explorer"
    Start-Sleep 1
    .\taskkill.exe /F /IM explorer.exe
    Start-Sleep 3
    Write-Output "Removing leftover files"
    Remove-Item "$env:USERPROFILE\OneDrive" -Force -Recurse
    Remove-Item "$env:LOCALAPPDATA\Microsoft\OneDrive" -Force -Recurse
    Remove-Item "$env:PROGRAMDATA\Microsoft OneDrive" -Force -Recurse
    If (Test-Path "$env:SYSTEMDRIVE\OneDriveTemp") {
        Remove-Item "$env:SYSTEMDRIVE\OneDriveTemp" -Force -Recurse
    }
    Write-Output "Removing OneDrive from windows explorer"
    If (!(Test-Path $ExplorerReg1)) {
        New-Item $ExplorerReg1
    }
    Set-ItemProperty $ExplorerReg1 System.IsPinnedToNameSpaceTree -Value 0 
    If (!(Test-Path $ExplorerReg2)) {
        New-Item $ExplorerReg2
    }
    Set-ItemProperty $ExplorerReg2 System.IsPinnedToNameSpaceTree -Value 0
    Write-Output "Restarting Explorer that was shut down before."
    Start-Process explorer.exe -NoNewWindow
    
    Write-Host "Enabling the Group Policy 'Prevent the usage of OneDrive for File Storage'."
    $OneDriveKey = 'HKLM:Software\Policies\Microsoft\Windows\OneDrive'
    If (!(Test-Path $OneDriveKey)) {
        Mkdir $OneDriveKey 
    }

    $DisableAllOneDrive = 'HKLM:Software\Policies\Microsoft\Windows\OneDrive'
    If (Test-Path $DisableAllOneDrive) {
        New-ItemProperty $DisableAllOneDrive -Name OneDrive -Value DisableFileSyncNGSC -Verbose 
    }
}

Function UnpinStart {
    #Unpins all tiles from the Start Menu
    Write-Output "Unpinning all tiles from the start menu"
    (New-Object -Com Shell.Application).
    NameSpace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}').
    Items() |
        ForEach-Object { $_.Verbs() } |
        Where-Object {$_.Name -match 'Un.*pin from Start'} |
        ForEach-Object {$_.DoIt()}
}
