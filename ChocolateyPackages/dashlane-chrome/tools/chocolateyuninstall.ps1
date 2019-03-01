$bits = Get-ProcessorBits
$packageName = 'dashlane-chrome'
$extensionID = 'fdjamakpfbbddfjaooikfcpapjohcfmg'

if ($bits -eq 64) {
    Remove-Item "HKLM:\SOFTWARE\Wow6432node\Google\Chrome\Extensions\$extensionID" -Force -ErrorAction SilentlyContinue
   }else{
    Remove-Item "HKLM:\SOFTWARE\Google\Chrome\Extensions\$extensionID" -Force -ErrorAction SilentlyContinue
}