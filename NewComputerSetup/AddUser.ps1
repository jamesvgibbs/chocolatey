$username = "GJITAdmin"
$password =  ConvertTo-SecureString  -AsPlainText "GJ1500" -Force
New-LocalUser "$username" -Password $password -FullName "$username" -Description "Local admin $username"
Add-LocalGroupMember -Group "Administrators" -Member "$username"