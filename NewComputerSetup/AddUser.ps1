$username = "Servis"
$password =  ConvertTo-SecureString  -AsPlainText "P4$$w0rd!@#" -Force
New-LocalUser "$username" -Password $password -FullName "$username" -Description "Local admin $username"
Add-LocalGroupMember -Group "Administrators" -Member "$username"