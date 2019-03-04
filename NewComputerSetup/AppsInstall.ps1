set-executionpolicy unrestricted

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