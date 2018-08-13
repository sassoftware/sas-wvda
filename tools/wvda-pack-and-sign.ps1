cd  $PSScriptRoot\..

$verString = (select-string -path .\sas-wvda.ps1 -pattern "myversionnumber" | Select-Object -First 1).tostring().split('=')[1].trim(' ', '"')

$archiveName = "zips\sas-wvda-$verString-windows.zip"

write-host "creating archive $archiveName for version $verString"

if (test-path $archiveName ) {
  Write-Error "Archive for version $verString exists.  Update version in sas-wvda.ps1!"
  exit
}

\\dntsrc\sastools\bin\digisign -microsoft HelperFunctions.psm1 HelperFunctions.psm1
\\dntsrc\sastools\bin\digisign -microsoft sas-wvda.ps1 sas-wvda.ps1

Compress-Archive -Path SAS_Code_Signing_Certs.p7b, HelperFunctions.psm1, LICENSE, README.md, sas-wvda.ps1 -DestinationPath $archiveName
