################################################################################
# Copyright 2018 SAS Institute Inc.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    https://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
################################################################################

<#
.SYNOPSIS
Does preflight checks and / or config for Viya 3.4 on a Windows Host.

.DESCRIPTION
Viya 3.4 deployed on Windows has the following Requirements:
    Supported only on Windows Server (is not supported on Workstation)
    Runs only on Windows Server 2012 R2 or higher
    Runs only on Windows Servers that are joined to a domain (to support kerberos)
    The host computer account must be trusted for Delegation
    The following Service Principals must exist:
        HTTP/fqdn@KRB.REALM
        sascas/fqdn@KRB.REALM
    keytab must contain the HTTP SPN info
    should be able to kinit with the keytab
    LOCAL Security Policy must grant the service account:
        Log on as a service
        Replace Process Level Token
    Validate that the svc account name in cas credentials file matches
    Validate the credentials stored in postgresUser.xml are valid
    Validate the credentials stored in casUser.xml are valid
    Validates the Windows subsystem SharedSection value tuning
    Validates various TCP related tuning has been applied to the system

.PARAMETER KeyTabPath
This is the path to the keytab that contains credentials for the HTTP/<HOSTNAME> principal

.PARAMETER DeployDir
The path to the deployment directory.  This is the path that contains the postgresUser.xml and casUser.xml files
Required when validate is sas or all

.PARAMETER Validate
specifies which class of validations to perform.  Defaults to all.

Valid values:
    host     - validate configuration of the host only can be done without having the SAS deployment tooling
    sas      - validate the credentials for PostgreSQL and the SAS Cloud Analytics Server are valid and
               and that the SAS Cloud Analytics Server credentials match the account that owns the sascas/<HOSTNAME> SPN
    certs    - Add / validate / update that the required SAS public certs are installed in the TrustedPublisher store
    tuning   - validate that SAS recommended tuning has been applied to this host
    keytab   - validate the keytab can be used successfully by kinit
    adconfig - validate the domain entities are correctly convigured
    postgres - validate postgres service account is correctly configured
    all      - perform all validations

.PARAMETER Remediate
Specifies that the script should modify values that are insufficient per SAS recommendations to the recommended value.

.PARAMETER SvcAcctOUName
Default: OU=serviceAccounts
If domain accounts are created specifies the location within the structure of
Active Directory to house the accounts.  The DNs for the realm of the host will
be added to this string.  If the specified location does not exist the default
location for your Active Directory will be used.

.PARAMETER SvcAcctPrefix
Default: 'svc-sas-'
Specifies the account prefix for all default account names created by this script

.PARAMETER SvcAcctSuffix
Default: empty string
Specifies the account name suffix for all default account names created by this script.

.PARAMETER PwLength
Default: 20
If accounts are created with random passwords this is the length of the password.

.PARAMETER PwNumSpecialChars
Default: 8
If accounts are created with random passwords this is the number of special characters in the password.

.PARAMETER PostgresAcct
default: <svcAcctPrefix>postgres
Account name to use for the local postgres account. No prefix or suffix will be added - the name will be as specified. Use this parameter for validation to specify the Postgres account if it already exists and is different from the default.


.PARAMETER PostgresPassword
Password to use for the local postgres account.  If not specified a random password will be generated

.PARAMETER HTTPAcct
Account name to use for the domain account used by the HTTP service.  No prefix or suffix will be added

.PARAMETER HTTPPassword
Password to use for the HTTP service account.  If not specified a random password will be generated

.PARAMETER CASAcct
Account name to use for the CAS domain account.  No prefix or suffix will be added

.PARAMETER CASPassword
Password to use for the CAS service account.  If not specified a random password will be generated

.PARAMETER CreateADEntities
Specifies that the script should attempt to create any AD entities that are not found.
NOTE: REQUIRES that account executing the script have administrative permission to create and modify
      Accounts in Active Directory

.PARAMETER CmdFileOnly
Specifies that the script should not attempt to create Active Directory Entities at execution time.  Instead a script will
be created to perform any remediation.  This can be helpful for situations where the SAS Administrator is a local server
administrator but not a domain administrator.  The script can be provided to a domain admin.  The output of the script
will be a zip file that the domain admin should return to the SAS administrator for subsequent use during deployment of SAS Viya.

.PARAMETER CmdFilePath
Specifies the output path and filename of the command file script.  By default the script will be placed in the current directory.
The default file name is SASViyaADEntitySetup.ps1

.PARAMETER WinBatchDesktopHeapSize
Default: 20480 (This is the maximum value allowed)
Note that setting this value to 20480 will reduce resources available to support interactive processes such as remote desktop sessions
and applications that display a visual GUI executed directly on the server.  This parameter can be used to set a lower value.  Under no
circumstances should this value be set lower than 5120 when running Viya 3.4.  SAS recommends that this value be at least 10240 and this
value may be satisfactory for light to medium usage of SAS Viya 3.4 such as SAS Visual Analytics only.  If running SAS Visual Data Mining
and Machine Learning this value should not be lowered from the default.

.EXAMPLE
sas-wvda c:\path\to\myhost.keytab

Will run all validations and look for casUser.xml and postgresUser.xml in the current directory.

This will validate
 - Stored credentials are valid
 - That SAS recommended OS tuning has been applied
 - That Kerberos Principals have been properly configured
 - That the principal stored for the Cloud Analytics Server matches the principal that owns the sascas/<HOSTNAME> SPN
 - That the keytab contains valid credentials for the HTTP/<hostname> SPN

.EXAMPLE
sas-wvda c:\path\to\myhost.keytab -validate all -deployDir c:\path\to\my\deployment

Same as previous example except will look for casUser.xml and postgresUser.xml in c:\path\to\my\deployment
rather than the current directory

.EXAMPLE
sas-wvda c:\path\to\myhost.keytab -validate HOST

Will validate
 - That SAS recommended OS tuning has been applied
 - That Kerberos Principals have been properly configured
 - That the keytab contains valid credentials for the HTTP/<hostname> SPN

.EXAMPLE
sas-wvda c:\path\to\myhost.keytab -validate SAS -deployDir c:\path\to\my\deployment

Will Validate postgres and SAS Cloud Analytics Server credentials stored in c:\path\to\my\deployment

#>

param(
        [Parameter(
                    Mandatory=$false,
                    Position=0,
                    HelpMessage='Path to keytab')]
        [string]$KeyTabPath,
        [string]$DeployDir = '.',
        [string]$Validate = 'all',
        [switch]$Remediate,
        [string]$SvcAcctOUName = 'OU=serviceAccounts',
        [ValidateLength(0,8)]
        [AllowEmptyString()]
        [string]$SvcAcctPrefix = 'svc-sas-',
        [string]$SvcAcctSuffix = '',
        [int]$PwLength = 20,
        [int]$PwNumSpecialChars = 8,
        [string]$PostgresAcct,
        [string]$PostgresPassword,
        [string]$HTTPAcct,
        [string]$HTTPPassword,
        [string]$CASAcct,
        [string]$CASPassword,
        [switch]$CreateADEntities,
        [switch]$CreateKeytab,
        [switch]$CmdFileOnly,
        [string]$CmdFilePath,
        [ValidateRange(768,20480)]
        [int]$WinBatchDesktopHeapSize = 20480,
        [switch]$CheckRemoteVersion
)

Set-StrictMode -Version 5.1
#Requires -RunAsAdministrator
#Requires -Version 5.1

$myVersionNumber = "1.1.05"
$remoteVerCheckURL = "https://raw.githubusercontent.com/sassoftware/sas-wvda/master/sas-wvda.ps1"
$remoteVerDownloadURL = "https://github.com/sassoftware/sas-wvda"

$validateRequestValid = $false
switch ($validate.ToLower()) {
    'all'      { $validateRequestValid = $true }
    'sas'      { $validateRequestValid = $true }
    'certs'    { $validateRequestValid = $true }
    'tuning'   { $validateRequestValid = $true }
    'keytab'   { $validateRequestValid = $true }
    'adconfig' { $validateRequestValid = $true }
    'postgres' { $validateRequestValid = $true }
    'host'     { $validateRequestValid = $true }
}

if(-not $validateRequestValid) {
    Write-SASUserMessage -severity "error" -message "The requested validation operation ($validate) is not recognized.  Valid values are`n       all, sas, certs, tuning, keytab, adconfig, postgres, host"
    exit 1
}

if ( $PSBoundParameters.containskey('Verbose')) {
    $script:inVerboseMode = $true
} else {
    $script:inVerboseMode = $false
}

[int]$script:installStatusOK = 0
[int]$script:installStatusWarning = 1
[int]$script:installStatusError = 2
[int]$script:installStatusFatal = 3
[int]$script:installStatus = $installStatusOK
$script:recommendedBatchDesktopHeapSize = 20480
$script:RequestedBatchDesktopHeapSize = $WinBatchDesktopHeapSize
$script:restartRequired = $false
$script:minDotNetRelease = 393295

$script:cmdFileContent = ''
$script:casCred = $null
$script:pgCred = $null
$myHostName = $env:COMPUTERNAME

if ([string]::IsNullOrEmpty($HTTPAcct)) {
    $HTTPsvcAcctName = $svcAcctPrefix + $myHostName + "-HTTP" + $svcAcctSuffix
} else {
    $HTTPsvcAcctName = $HTTPAcct
}
if ([string]::IsNullOrEmpty($CASAcct)) {
    $CASsvcAcctName = $svcAcctPrefix + $myHostName + "-CAS" + $svcAcctSuffix
} else {
    $CASsvcAcctName = $CASAcct
}
if ([string]::IsNullOrEmpty($PostgresAcct)) {
    $postgresAcctName = $svcAcctPrefix + "postgres" + $svcAcctSuffix
} else {
    $postgresAcctName = $PostgresAcct
}

[string]$script:ctPass = ''
[string]$READMEtxt = ''

# ------------------ Begin Function Declarations ------------------
function Write-SASUserMessage {
    param(
        [Parameter(Mandatory=$true,
                    Position=0)]
        [string]$severity,
        [Parameter(Mandatory=$true,
                    Position=1)]
        [string]$message,
        [switch]$noLabel
    )
    # Uses severities of Info, Alert, Warning, and Error to format output
    $fieldSep = $message.IndexOf(" -f ")
    if(($fieldSep -gt 0) -and ($message -like '*{*}*')) {
        $s = $message.Substring(0,$fieldSep)
        $f = $message.Substring($fieldSep, ($message.Length - $fieldSep))
        $msg = $s + $f
    } else {
        $msg = '"' + $message + '"'
    }

    switch ($severity.ToUpper()) {
        "INFO" {
            if(-not $noLabel) { Write-Host -noNewLine "INFO: " -ForegroundColor Green }
            $cmd = 'Write-Host(' + $msg + ') -ForegroundColor Green'
            Invoke-Expression $cmd
            Break
        }
        "ALERT" {
            Write-Host -noNewLine "NOTE: " -ForegroundColor Yellow
            $cmd = 'Write-Host(' + $msg + ') -ForegroundColor Yellow'
            Invoke-Expression $cmd
            Break
        }
        "WARNING" {
            $cmd = 'Write-Warning(' + $msg + ') '
            Invoke-Expression $cmd
            Break
        }
        "DEBUG" {
            $cmd = 'Write-Debug(' + $msg + ') '
            Invoke-Expression $cmd
            Break
        }
        "ERROR" {
            if(-not $noLabel) { Write-Host -noNewLine "ERROR: " -ForegroundColor Red }
            $cmd = 'Write-Host(' + $msg + ') -ForegroundColor Red'
            Invoke-Expression $cmd
            Break
        }
        default {
            Write-Host "ERROR: call to Write-SASUserMessage with invalid severity!`nSeverity: $severity Message Text:`n$message" -ForegroundColor Red
        }
    }
}

function Set-SASInstallStatus {
    param(
        [Parameter(Mandatory=$true,
                    Position=0)]
        [int]$targetStatus
    )
    if ($installStatus -lt $targetStatus) {
        $installStatus = $targetStatus
    }
}

function Get-AdminToolInstallStatus {
    Import-Module $PSScriptRoot\HelperFunctions.psm1
    Import-Module ServerManager
    Import-Module Microsoft.PowerShell.LocalAccounts
    $ADModuleStatus = Get-WindowsFeature RSAT-AD-Powershell
    $ADAdminStatus = Get-WindowsFeature RSAT-AD-AdminCenter

    if ($ADModuleStatus.Installed -and $ADAdminStatus.Installed) {
        Write-Debug "Required Administrative features are installed"
    } else {
        If (-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
            [Security.Principal.WindowsBuiltInRole] "Administrator")) {

            Write-SASUserMessage -severity "error" -message "Required Administrative features are not installed!"
            Write-SASUserMessage -severity "error" -message "This script must be executed as an Administrator!"
            Write-SASUserMessage -severity "error" -message "Install server features RSAT-AD-Powershell and RSAT-AD-AdminCenter and run this tool as an administrator!"

            Exit 1
        } else {
            do {
                write-host "Required Administrative features are not installed.  Install RSAT-AD-Powershell and RSAT-AD-AdminCenter? Y/N"
                $installFeatures = Read-Host
            } until ("Y","N" -ccontains $installFeatures.toUpper())
            if ($installFeatures.toUpper() -eq "Y") {
                Add-WindowsFeature RSAT-AD-PowerShell,RSAT-AD-AdminCenter
            } else {
                Write-SASUserMessage -severity "alert" -message "Required Administrative features will not be installed.  Errors will Occur."
            }
        }
    }

    Import-Module ActiveDirectory
}

function Set-wvdaVariables {
<#
    host     - validate configuration of the host only can be done without having the SAS deployment tooling
    sas      - validate the credentials for PostgreSQL and the SAS Cloud Analytics Server are valid and
               and that the SAS Cloud Analytics Server credentials match the account that owns the sascas/<HOSTNAME> SPN
    certs    - validate certs
    tuning   - validate that SAS recommended tuning has been applied to this host
    keytab   - validate the keytab can be used successfully by kinit
    adconfig - validate the domain entities are correctly convigured
    postgres - validate postgres service account is correctly configured
    all      - perform all validations
#>

    # Have seen some timeouts on our first call wrap this in a loop to retry up to 5 times
    $local:iterCount = 0
    $local:success = $false
    Do {
        try {
            $local:iterCount++
            $script:compInfo = Get-ADComputer -identity $myHostName -Properties *
            $sep = $script:compInfo.CanonicalName.IndexOf('/')
            $compDomainName = $script:compInfo.CanonicalName.Substring(0,$sep)
            $script:krb5Realm = $compDomainName.toUpper()
            $script:domainInfo = Get-ADDomain -Identity $compDomainName
            $script:NetBIOSDomain = $script:domainInfo.NetBIOSName
            $local:success = $true
        } catch {
            Write-SASUserMessage -severity "alert" -message "Failed to obtain Active Directory data due to`n      $_.`n      Will attempt up to 5 times..."
        }
    } until (($local:iterCount -eq 5) -or $local:success)

    if ($local:success) {
        Write-SASUserMessage -severity "debug" -message "Active Directory query returned successfully."
    } else {
        Write-SASUserMessage -severity "error" -message "Mutiple attempts to query Active Directory have failed.  Can not continue.  Contact your Active Directory administrator for assistance."
        exit 1
    }

    if ($script:inVerboseMode) {
        Write-SASUserMessage -severity "info" -message "KRB5 Realm: $script:krb5Realm"
        $msg = "Computer Attributes: "
        $o = Get-ADComputer -identity $myHostName -Properties * | Format-List | Out-String
        foreach ($l in $o) { $msg += "`n      $l" }
        Write-SASUserMessage -severity "info" -message "$msg"
        $msg = "Domain Attributes:"
        $o = Get-ADDomain -Identity $compDomainName | Format-List | Out-String
        foreach ($l in $o) { $msg += "`n      $l" }
        Write-SASUserMessage -severity "info" -message "$msg"
    }

    if (($validate -eq "host") -or ($validate -eq "all")) {
        $script:valHost = $true
    } else {
        $script:valHost = $false
    }
    if (($validate -eq "sas") -or ($validate -eq "all")) {
        $script:valSAS = $true
    } else {
        $script:valSAS = $false
    }
    if (($validate -eq "tuning") -or ($validate -eq "host") -or ($validate -eq "all")) {
        $script:valTuning = $true
    } else {
        $script:valTuning = $false
    }
    if (($validate -eq "keytab") -or ($validate -eq "host") -or ($validate -eq "adconfig") -or ($validate -eq "all")) {
        $script:valKeytab = $true
    } else {
        $script:valKeytab = $false
    }
    if (($validate -eq "postgres") -or ($validate -eq "host") -or ($validate -eq "all")) {
        $script:valPostgres = $true
    } else {
        $script:valPostgres = $false
    }
    if (($validate -eq "adconfig") -or ($validate -eq "keytab") -or ($validate -eq "host") -or ($validate -eq "all")) {
        $script:valADConfig = $true
    } else {
        $script:valADConfig = $false
    }
    if (($validate -eq "certs") -or ($validate -eq "sas") -or ($validate -eq "host") -or ($validate -eq "all")) {
        $script:valCerts = $true
    } else {
        $script:valCerts = $false
    }
}

function Validate-Java {
    $script:javaIsValid = $false
    # Validate JAVA_HOME is defined
    if(Test-Path env:JAVA_HOME) {
        #JAVA_HOME is defined
        if(Test-Path $env:JAVA_HOME) {
            #The path in JAVA_HOME exists
            if(Test-Path "$env:JAVA_HOME\bin\java.exe") {
                #the executable appears to be there so let's see what it tells us
                $javaInfo = cmd /c  "`"$env:java_home\bin\java.exe`" -version 1>&2" 2>&1 | %{ "$_" }
                if((($javaInfo[0] -match "java version") -and ($javaInfo[0] -match "1.8")) -or ($javaInfo[0] -match "jdk version") -and ($javaInfo[0] -match "1.8")) {
                    Write-SASUserMessage -severity "info" -message "JAVA_HOME ($env:JAVA_HOME) points to an installation of Java 8: OK"
                    foreach($l in $javaInfo) {
                        if($l -match "64-bit") {
                            $script:javaIsValid = $true
                            break
                        }
                    }
                    if($script:javaIsValid) {
                        Write-SASUserMessage -severity "info" -message "64-bit version of Java 8 found in JAVA_HOME: OK"
                    } else {
                        Write-SASUserMessage -severity "Warning" -message "The version of java pointed to by JAVA_HOME ($env:JAVA_HOME) is not 64-bit.  SAS Viya requires 64-bit Java 8."
                    }
                } else {
                    Write-SASUserMessage -severity "warning" -message "JAVA_HOME ($env:JAVA_HOME) does not point to an installation of Java 8.  Found $javaInfo[0]"
                }
            } else {
                Write-SASUserMessage -severity "warning" -message "The path contained in JAVA_HOME ($env:JAVA_HOME) is valid but does not contain JAVA_HOME\bin\java.exe!"
            }
        } else {
            Write-SASUserMessage -severity "error" -message "The path defined in JAVA_HOME ($env:JAVA_HOME) does not exist!"
        }
    } else {
        #JAVA_HOME is not defined
        Write-SASUserMessage -severity "warning" -message "JAVA_HOME is not set!"
    }
}

function Validate-dotNETVersion {
    # for more specifics re: .NET Framework version numbers see:
    # https://docs.microsoft.com/en-us/dotnet/framework/migration-guide/how-to-determine-which-versions-are-installed
    $dotNETRegKey = 'Software\Microsoft\NET Framework Setup\NDP\v4\Full'

    $script:myPath = 'HKLM' + ':' + $dotNETRegKey
    $private:updateNeeded = $false
    $private:addRegEnt = $false
    try {
        $currValue = Get-ItemProperty -Path $myPath | select 'Release'
        [int64]$release = $currValue.Release
        if($release -lt $script:minDotNetRelease) { $private:updateNeeded = $true }
    } catch {
        $private:updateNeeded = $true
    }

    if($private:updateNeeded) {
        Write-SASUserMessage -severity "warning" -message "SAS Viya requires that the version of .NET Framework installed be 4.6 or later (Release $script:minDotNetRelease).
         The current Release number is $release.  The installer for .NET Framework 4.6 can be obtained from
         https://support.microsoft.com/en-us/kb/3045557."
    } else {
        Write-SASUserMessage -severity "info" -message "The version of the .NET Framework is 4.6 or higher"
    }
}

function Init-wvdaInfo {
    $wvdaInfo  = @{}

}

function Set-RestartRequired {
    if($script:restartRequired -eq $false) {
        $script:restartRequired = $true
    }
}


function Set-SecurePassword {
    param(
        [string]$inputPass
    )

    $script:ctPass = ""

    if ([string]::IsNullOrEmpty($inputPass)) {
        Add-Type -AssemblyName System.Web
        $script:ctPass = [System.Web.Security.Membership]::GeneratePassword($pwLength, $pwNumSpecialChars)
        # Do NOT allow any dollar signs to be in the generated passwords
        $script:ctPass = $script:ctPass.Replace('$','*')
    } else {
        $script:ctPass = $inputPass
    }
    $SSPass = ConvertTo-SecureString $ctPass -AsPlainText -Force
    $SSPass
}

function Validate-SASSigningCerts {

    $scriptsInstalled = $false

    $thumbprints_lmtp = get-childitem -Path Cert:\LocalMachine\TrustedPublisher
    $certpath = Join-Path -Path "$PSScriptRoot" -ChildPath "SAS_Code_Signing_Certs.p7b"
    $data = [System.IO.File]::ReadAllBytes($certpath)
    [reflection.assembly]::LoadWithPartialName("System.Security") | Out-Null
    $cms = New-Object System.Security.Cryptography.Pkcs.SignedCms
    $cms.Decode($data)
    $thumbprints_p7b = $cms.Certificates
    $differences = $thumbprints_p7b | Where { $thumbprints_lmtp -notcontains $_ }
    if ( -not ($differences -eq $null)) {
        if ($Remediate) {
            #cmd /c  "`"$env:java_home\bin\java.exe`" -version 1>&2" 2>&1 | %{ "$_" }
            $certUtilOutput = cmd /c "`"certutil.exe`" -addstore TrustedPublisher $PSScriptRoot\SAS_Code_Signing_Certs.p7b " 2>&1
            if ($lastExitCode -eq 0) {
                $msg = "SAS Public Cert update: OK`n      CERTUTIL output:"
                foreach($l in $certUtilOutput) { $msg += "`n      $l" }
                Write-SASUserMessage -severity "info" -message $msg.Replace('"', '`"')
            } else {
                $msg = "SAS Public Cert update: FAILED`n       CERTUTIL output:"
                foreach($l in $certUtilOutput) { $msg += "`n       $l" }
                Write-SASUserMessage -severity "warning" -message $msg.Replace('"', '`"')
            }
        } else {
            Write-SASUserMessage -severity "warning" "SAS Public Certs are not installed!"
        }
    } else {
       Write-SASUserMessage -severity "info" -message "SAS public code signing certs are installed: OK"
    }
}

function validate-cppRuntimePreReqs {

    $found2013RunTime = $false
    $found2015RunTime = $false

    $cppRuntimeRegLocation = "HKLM:\SOFTWARE\Classes\Installer\Dependencies"
    $cppRegLocationExists = Test-Path -Path $cppRuntimeRegLocation

    if ($cppRegLocationExists) {
        $cppRuntimeCandidates = Get-ChildItem -Path $cppRuntimeRegLocation
        foreach($item in $cppRuntimeCandidates) {
            try {
                $ps = get-itemproperty -path Registry::$item
                $dn = $ps.DisplayName
            } catch {
                continue
            }
            if ($dn -like "Microsoft Visual C++ 2013 Redistributable (x64)*") {
                $found2013RunTime = $true
                Write-SASUserMessage -severity "info" -message "$dn is installed: OK"
            }
            if ($dn -like "Microsoft Visual C++ 2015 Redistributable (x64)*") {
                $found2015RunTime = $true
                Write-SASUserMessage -severity "info" -message "$dn is installed: OK"
            }
            # The 2017 Redistributable covers 2015 as well.  While it may look odd to search for 2017 and set found2015 to true
            # This is by design and matches expectations of the behavior / functionality of 2017 and 2015.
            if ($dn -like "Microsoft Visual C++ 2017 Redistributable (x64)*") {
                $found2015RunTime = $true
                Write-SASUserMessage -severity "info" -message "$dn is installed: OK"
            }
        }
    }

    if (-not $found2013RunTime) {
        Write-SASUserMessage -severity "warning" -message "The 64-bit Microsoft Visual C++ 2013 Redistributable Package must be installed on this host prior to installing SAS Viya.`n         Download and execute the appropriate vcredist_x64.exe from`n         https://support.microsoft.com/en-us/help/3179560/update-for-visual-c-2013-and-visual-c-redistributable-package."
    }
    if (-not $found2015RunTime) {
        Write-SASUserMessage -severity "warning" -message "The 64-bit Microsoft Visual C++ 2015 Redistributable Package must be installed on this host prior to installing SAS Viya.`n         Download and execute vc_redist.x64.exe`n         from https://www.microsoft.com/en-us/download/details.aspx?id=48145`n         Installing the 64-bit Microsoft Visual C++ 2017 Redistributable Package will also satisfy this requirement.`n         The 2017 package can be obtained from https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads"
    }
}

function Validate-ExecutionEnvironment {

    # Are we running in a 64-bit environment?
    if (($env:PROCESSOR_ARCHITECTURE -eq "x86") -or ($env:ProgramFiles -eq ${env:ProgramFiles(x86)})) {
        Write-SASUserMessage -severity "error" -message "SAS Viya is only supported on 64-bit platforms.  To install SAS Viya you must use a 64-bit command session"
        exit 1
    } else {
        Write-SASUserMessage -severity "info"  -message "Running in a 64-bit environment: OK"
    }

    # Are we running the PowerShell 5.1 or higher?
    $psMajor = [int]$PSVersionTable.PSVersion.Major
    $psMinor = [int]$PSVersionTable.PSVersion.Minor
    if ((($psMajor -ge 5) -and ($psMinor -ge 1)) -or ($psMajor -gt 5) ) {
        Write-SASUserMessage -severity "info" -message "Running PowerShell 5.1 or higher: OK"
    } else {
        Write-SASUserMessage -severity "error" -message "PowerShell 5.1 or greater is required to run SAS Viya 3.4.`nUpdate can be obtained from https://www.microsoft.com/en-us/download/details.aspx?id=54616."
        exit
    }

    # Are we a Domain Admin?
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
    $script:runningWithDomainAdminPrivs = $WindowsPrincipal.IsInRole("Domain Admins")

    if($runningWithDomainAdminPrivs) {
        Write-SASUserMessage -severity "info" -message "Currently running as a Domain Admin..."
    } else {
        if ($createADEntities -and -not $cmdFileOnly) {
            Write-SASUserMessage -severity "warning" -message "The current account is not a Domain Admin yet -createADEntities has been specified.`n         Will not attempt to modify domain entities.  A script will be created instead."
            $script:cmdFileOnly = $true
            if (-not $createKeyTab) {
                Write-SASUserMessage -severity "warning" -message "-createADEntities has been specified while setting cmdFileOnly yet -createKeytab is not specified`n         Setting -createKeyTab option to ensure a keytab is generated and provided."
                $script:createKeyTab = $true
            }
        }
    }

    # Will need various bits of info about the computer system so let's grab as much as we can here:
    # Reference info online at https://msdn.microsoft.com/en-us/library/aa394239%28v=vs.85%29.aspx
    $osInfo = Get-WmiObject -Class Win32_OperatingSystem

    # Viya 3.4 does not support workstations - only servers so ensure we are running on a Server.
    # ProductType values translate as follows:
    # 1 - Workstation OS
    # 2 - Domain Controller
    # 3 - Server
    if ($osInfo.ProductType -eq 1) {
        Write-SASUserMessage -severity "error" -message "Running on a Windows Workstation.  SAS Viya 3.4 for Windows must run on a server."
        exit 1
    } else {
        Write-SASUserMessage -severity  "info" -message "Running on Windows Server: OK"
    }

    # For Kerberos we can not be on a standalone / workgroup server.  Must be part of a Domain
    # PartOfDomain (boolean Property)
    if (-not (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
        Write-SASUserMessage -severity "error" -message "This server is not part of a domain!  The server must be joined to a domain to host SAS Viya."
        exit 1
    } else {
        Write-SASUserMessage -severity "info" -message "Server is part of a domain: OK"
    }

    # For Viya 3.4 supported versions of Windows Server are Windows 2012 R2 and higher
    # see https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx for more information
    $verInfo = $osInfo.Version.Split(".")
    if (([int]$verInfo[0] -lt 6) -or (([int]$verInfo[0] -eq 6) -and ([int]$verInfo[1] -lt 3))) {
        Write-SASUserMessage -severity "error" -message '"SAS Viya 3.4 supports Windows Server 2012 R2 and Higher.`n       Running on {0} is not supported!" -f $osInfo.Caption.ToString()'
        exit 1
    } else {
        # Running on a supported version
        Write-SASUserMessage -severity "info" -message '"Running on {0}: OK" -f $osInfo.Caption.ToString()'
    }

}

function Validate-SAS {

    # Can we find postgresUser.xml
    $postgresUserCredExists = Test-Path $DeployDir\postgresUser.xml
    if (-not $postgresUserCredExists) {
        Write-SASUserMessage -severity "warning" -message "Cannot locate postgresUser.xml file in $DeployDir!`n       Use encryptPostgresUser.bat to store credentials!`n       This must be corrected before running the SAS Viya deployment!"
    } else {
        $script:pgCred = Import-Clixml $DeployDir\postgresUser.xml
        try {
                Start-Process -Credential $script:pgCred -FilePath ping -WindowStyle Hidden
                Write-SASUserMessage -severity "info" -message "Validate Postgres User Credentials: OK"
        } catch {
            Write-SASUserMessage -severity "warning" -message "$_"
            Write-SASUserMessage -severity "warning" -message "Postgres user Credentials are not valid for logon!`n       This must be corrected before running the SAS Viya deployment!"
        }
    }

    # Can we find casUser.xml
    $casUserCredExists = Test-Path $DeployDir\casUser.xml
    if (-not $casUserCredExists) {
        Write-SASUserMessage -severity "warning" -message "Cannot locate casUser.xml file in $DeployDir!`n       Use encryptCasUser.bat to store credentials!`n       This must be corrected before running the SAS Viya deployment!"
    } else {
        $script:casCred = Import-Clixml $DeployDir\casUser.xml
        try {
                Start-Process -Credential $script:casCred -FilePath ping -WindowStyle Hidden
                Write-SASUserMessage -severity "info" -message "Validate CAS User Credentials: OK"
        } catch {
            Write-SASUserMessage -severity "warning" -message "$_"
            Write-SASUserMessage -severity "warning" -message "CAS user Credentials are not valid for logon!`n       This must be corrected before running the SAS Viya deployment!"
        }
    }

}

function Write-krb5Ini {

    "[libdefaults]`n" > $PSScriptRoot\krb5.ini
    "default_realm = $script:krb5Realm `n`n" >> .\krb5.ini

}

function Validate-Keytab {

    if ([string]::IsNullOrEmpty($keyTabPath)) {
        Write-SASUserMessage -severity "Warning" -message "Keytab Path not specified.  Keytab can not be validated."
        $keyTabExists = $false
    } else {
        $keyTabExists = Test-Path $keyTabPath
    }
    If ($keyTabExists -eq $False) {
        Write-SASUserMessage -severity "warning" -message "Keytab not found at $keyTabPath - Keytab will not be validated."
    } else {
        if ($script:HTTPUser -eq $null) {
            Write-SASUserMessage -severity "warning" -message "The HTTP SPN could not be found therefore the keytab can not be validated."
        } else {
            if (Test-Path env:JAVA_HOME) {
                $klistOutput = & "$env:JAVA_HOME\bin\klist.exe" -k -t $keyTabPath 2>&1
                if( $script:inVerboseMode) {
                    $msg = "Keytab content:"
                    foreach($l in $klistOutput) { $msg += "`n      $l" }
                    Write-SASUserMessage -severity "info" -message $msg
                }
                $klistOutput = $klistOutput | Select-String -Pattern HTTP/$myHostName | Select-Object -First 1
                if ($klistOutput -eq $null) {
                    Write-SASUserMessage -severity "warning" -message "Could not locate HTTP principal for this host in keytab!"
                } else {
                    $keytabPrinc = $klistOutput.ToString().split()[3]
                    $keytabPrincRealm = $keytabPrinc.split("@")[1]
                    if (-not ($keytabPrincRealm -eq $script:krb5Realm)) {
                        Write-SASUserMessage -severity "warning" -message '"Realm of keytab principal ({0}) does not match expected realm of ({1})!" -f $keytabPrincRealm, $script:krb5Realm'
                    }
                    if( $script:inVerboseMode) { Write-SASUserMessage -severity "info" -message "Will kinit using principal $keytabPrinc" }
                    Write-krb5Ini
                    if( $script:inVerboseMode) {
                        $krb5DebugString = "-Dsun.security.krb5.debug=true"
                    } else {
                        $krb5DebugString = "-Dsun.security.krb5.debug=false"
                    }
                    $env:_JAVA_OPTIONS = "$krb5DebugString -Djava.security.krb5.conf=$PSScriptRoot\krb5.ini"
                    $kinitOutput = & "$env:JAVA_HOME\bin\kinit.exe" -f -k -t $keyTabPath $keytabPrinc 2>&1
                    if ($lastExitCode -eq 0) {
                        $msg = "KINIT using keytab: OK`n      KINIT output:"
                        foreach($l in $kinitOutput) { $msg += "`n      $l" }
                        Write-SASUserMessage -severity "info" -message $msg
                    } else {
                        if ( (-not ($script:HTTPUser -eq $null)) -and ($script:HTTPUser -ne $keytabPrinc)) {
                            $msg = '"The HTTP User Principal Name ({0}) does not match the `n         HTTP Service Principal Name ({1}).`
             This means that the keytab can not be successfully validated by this tool.`
             If Integrated Windows Authentication is not successful once your SAS Viya deployment is complete`
             and Kerberos is configured via Environment Manager your keytab may be invalid." -f $script:HTTPUser.UserPrincipalName.tostring(),$keytabPrinc'
                            Write-SASUserMessage -severity "warning" -message $msg
                        } else {
                            $msg = "KINIT using $keyTabPath failed with output:"
                            foreach($l in $kinitOutput) { $msg += "`n         $l" }
                            Write-SASUserMessage -severity "warning" -message $msg
                        }
                    }
                    $env:_JAVA_OPTIONS = ""
                }
            } else {
                Write-SASUserMessage -severity "warning" -message "JAVA_HOME environment variable is not set.  Keytab not validated!"
            }
        }
    }

}

function Validate-SASTuning {

    # Validate the SharedSection tuning:
    $script:myPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems"
    $script:myKey = "Windows"
    $private:updateNeeded = $false
    $private:newWinSSParms = ""
    $WinSSParms = Get-ItemProperty -Path $myPath | select $myKey
    $WinSSParms = $WinSSparms.Windows.ToString().split()
    foreach ($parm in $WinSSParms) {
        $KVPair = $parm.split("=")
        if ($KVPair[0] -eq "SharedSection") {
            $Values = $KVPair[1].split(",")
            $curBatchDesktopHeapSize = [int]$Values[2]
            if ($remediate) {
                if($recommendedBatchDesktopHeapSize -ne $RequestedBatchDesktopHeapSize) {
                    #input validation covers the default setting to the max so here we only need to
                    #do sanity checks - not bounds checks - and determine if we are going to force the
                    #specific value passed in.
                    if($RequestedBatchDesktopHeapSize -lt $curBatchDesktopHeapSize) {
                        do {
                            Write-SASUserMessage -severity "alert" -message "The requested value for BatchDesktopHeapSize($RequestedBatchDesktopHeapSize) < current Value($curBatchDesktopHeapSize)!`n      Force Update to lower value? Y/N"
                            $forceUpdate = Read-Host
                        } until ("Y","N" -ccontains $forceUpdate.toUpper())
                        if ($forceUpdate.toUpper() -eq "Y") {
                            $updateNeeded = $true
                        } else {
                            Write-SASUserMessage -severity "alert" -message "BatchDesktopHeapSize will not be updated."
                        }
                    } else {
                        $updateNeeded = $true
                    }
                } elseif($curBatchDesktopHeapSize -lt $requestedBatchDesktopHeapSize) {
                    $updateNeeded = $true
                }
                $replStr = "," + $curBatchDesktopHeapSize + "$"
                $KVPair[1] = $KVPair[1] -replace $replStr, ",$RequestedbatchDesktopHeapSize"
                $parm = $KVPair[0] + "=" + $kvPair[1]
            } else { #We are not going to change anything so just issue the right message
                if($curBatchDesktopHeapSize -lt $requestedBatchDesktopHeapSize) {
                    $msg = '"SharedSection Tuning does not match requested value!`n         The third parameter of the Windows Subsystem Shared Section triplet must be at least {0}!`n'
                    $msg += '         The current Value is {1}.  To Remediate run script with the -remediate switch or open regedit,`n'
                    $msg += '         find HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\SubSystems\Windows and change`n'
                    $msg += '         SharedSection={2},{3},{4} to read SharedSection={2},{3},{5}" -f $RequestedbatchDesktopHeapSize,$curBatchDesktopHeapSize,$values[0],$values[1],$curBatchDesktopHeapSize,$RequestedbatchDesktopHeapSize'
                    Write-SASUserMessage -severity "warning" -message $msg
                } else {
                    Write-SASUserMessage -severity "info" -message '"Windows subsystem SharedSection tuning(SharedSection={0},{1},{2}) meets minimum: OK" -f $values[0],$values[1],$curBatchDesktopHeapSize'
                }
            }
        }
        $newWinSSParms = $newWinSSParms + " " + $parm
    }
    if ($updateNeeded) {
        Write-Debug "Updating`n $WinSSParms `nto:`n $newWinSSParms"
        Set-ItemProperty -Path "$myPath" -Name "$mykey" -Value "$newWinSSParms"
        Set-RestartRequired
        $updateNeeded = $false
        Write-SASUserMessage -severity "alert" -message '"Updated Windows subsystem SharedSection tuning from SharedSection={0},{1},{2} to SharedSection={0},{1},{3}" -f $values[0],$values[1],$curBatchDesktopHeapSize,$RequestedbatchDesktopHeapSize'
    } elseif($remediate) {
        Write-SASUserMessage -severity "info" -message '"Windows subsystem SharedSection tuning(SharedSection={0},{1},{2}) meets minimum: OK" -f $values[0],$values[1],$curBatchDesktopHeapSize'
    }

    $validations  = @(
        @{  Hive  = "HKLM";
            Path  = "\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
            Key   = "TcpTimedWaitDelay";
            Oper  = "-eq";
            Value = 30;
         },
        @{  Hive  = "HKLM";
            Path  = "\SYSTEM\CurrentControlSet\Control\PriorityControl";
            # see https://technet.microsoft.com/library/Cc976120 for info
            Key   = "Win32PrioritySeparation";
            Oper  = "-eq";
            Value = 36;
         }
    )


    foreach ($item in $validations) {

        $script:myPath = $item.Hive + ":" + $item.Path
        $script:myKey = $item.Key
        $private:updateNeeded = $false
        $private:addRegEnt = $false
        try {
            $currValue = Get-ItemProperty -Path $myPath | select $myKey
            $currValue = $currValue.$myKey
        } catch {
            Write-Debug "could not get value for $myPath $myKey."
        }
        if ([string]::IsNullOrEmpty($currValue)) {
            if ($remediate) {
                $addRegEnt = $true
                $updateNeeded = $true
            } else {
                Write-SASUserMessage -severity "warning" -message '"{0} value is not set!  SAS recommends this value be set to {1}" -f $myKey, $item.Value'
            }
        } else {
          if ($item.Oper -eq "-eq") {
            if ($currValue -eq $item.Value) {
                Write-SASUserMessage -severity "info" -message  '"{0} is set to {1} : OK" -f $myKey, $currValue'
            } else {
                if ( -not $remediate  ) {
                    Write-SASUserMessage -severity "warning" -message '"{0} is set to {1}.  SAS recommends this value be set to {2}." -f $myKey, $currValue, $item.Value'
                } else {
                    $updateNeeded = $true
                }
            }
          } elseIf ($item.oper -eq "-ge") {
            if ($currValue -lt $item.Value) {
                if (-not $remediate) {
                    Write-SASUserMessage -severity "warning" -message '"{0} is set to {1}.  SAS recommends the value be at least {2}." -f $myKey, $currValue, $item.Value'
                } else {
                    $updateNeeded = $true
                }
            } else {
                Write-SASUserMessage -severity "info" -message '"{0} is set to at least {1}: OK" -f $myKey, $item.Value'
            }
          } else {
            Write-SASUserMessage -severity "error" -message "Unsupported operator: $item.oper"
          }
        }
        if ($updateNeeded -and $remediate) {
            if ($addRegEnt) {
                Write-SASUserMessage -severity "alert" -message  '"Adding {0}\{1} with value: {2}" -f $myPath, $mykey, $item.Value.tostring()'
                New-ItemProperty -Path $myPath -Name $myKey -Value $item.Value.ToInt32($null) -PropertyType DWORD  | Out-Null
            } else {
                Write-SASUserMessage -severity "alert" -message  '"Updating {0} from: {1} to: {2}" -f $mykey, $currValue, $item.Value.tostring()'
                Set-ItemProperty -Path "$myPath" -Name "$mykey" -Value $item.Value.ToInt32($null)
            }
            Set-RestartRequired
        }
    }

    $ephemeralPortError = $false
    # validate ephemeral port start
    $myVal = Get-NetTCPSetting | select DynamicPortRangeStartPort
    $portStart = 0
    foreach ($p in $myVal) {
        if (-not [string]::IsNullOrEmpty($p.DynamicPortRangeStartPort)) {
            if ($p.DynamicPortRangeStartPort -gt $portStart) {
                $portStart = $p.DynamicPortRangeStartPort
            }
        }
    }
    if ($portStart -gt 32768) {
        Write-Debug ("ERROR: TCP ephemeral port range start value ({0}) > 32768!" -f $portStart)
        $ephemeralPortError = $true
    } else {
        Write-SASUserMessage -severity "info" -message  '"TCP ephemeral port range start value ({0}) 32768 or less: OK" -f $portStart'
    }

    # validate ephemeral port quantity
    $myVal = Get-NetTCPSetting | select DynamicPortRangeNumberOfPorts
    $portQty = 0
    foreach ($p in $myVal) {
        if (-not [string]::IsNullOrEmpty($p.DynamicPortRangeNumberOfPorts)) {
            if ($p.DynamicPortRangeNumberOfPorts -gt $portQty) {
                $portQty = $p.DynamicPortRangeNumberOfPorts
            }
        }
    }
    if ($portQty -lt 32767) {
        Write-Debug ("ERROR: TCP ephemeral port quantity ({0}) < 32767!" -f $portQty)
        $ephemeralPortError = $true
    } else {
        Write-SASUserMessage -severity "info" -message  '"TCP ephemeral port quantity ({0}) 32767 or greater: OK" -f $portQty'
    }
    if ($ephemeralPortError) {
        if ($remediate) {
            $cmdList = @()
            $cmdList += 'netsh int ipv4 set dynamicport tcp start=32768 num=32767'
            $cmdList += 'netsh int ipv4 set dynamicport udp start=32768 num=32767'
            $cmdList += 'netsh int ipv6 set dynamicport tcp start=32768 num=32767'
            $cmdList += 'netsh int ipv6 set dynamicport udp start=32768 num=32767'
            # Execute the change
            $cmdBlock = ""
            foreach ($cmd in $cmdList) {
                $cmdBlock = $cmdBlock + $cmd + "`n"
            }
            Write-Debug "Invoking command:`n     $cmdBlock"
            $errorActionPreference = "SilentlyContinue"
            Invoke-Expression $cmdBlock
            Write-SASUserMessage -severity "alert" -message "Updated IPv4 and IPv6 dynamic Port range for tcp and udp."
            $errorActionPreference = "Continue"
            Set-RestartRequired
        } else {
            Write-SASUserMessage -severity "warning" -message '"Dynamic Port start range and / or quantity do not meet SAS recommendations!`n         TCP ephemeral port quantity ({0}) < 32767!`n         TCP ephemeral port range start value ({1}) > 32768!" -f $portQty, $portStart'
        }
    }
}

function Validate-Postgres {

    # Validate the local Postgres Account exists and is configured correctly
    if(-not ($script:pgCred -eq $null)) {
        $postgresAcctName = $script:pgCred.UserName.toString()
        $fieldSep = $postgresAcctName.IndexOf("\")
        if ($fieldSep -gt 0) {
            $fieldSep += 1
            $postgresAcctName = $postgresAcctName.Substring($fieldSep, ($postgresAcctName.Length - $fieldSep))
        }
    }
    if ($postgresAcctName.length -gt 20) {
        $postgresAcctName = $postgresAcctName.substring(0, 20)
        Write-SASUserMessage -severity "alert" -message '"Postgres service account name exceeds 20 chars truncating AccountName to {0}" -f $postgresAcctName'
    }
    $errorActionPreference = "SilentlyContinue"
    $pgAcct = Get-LocalUser -Name $postgresAcctName
    $errorActionPreference = "Continue"

    if($pgAcct -eq $null) {
        if($remediate) {
            # Account not found so we need to create it and set everything up correctly
            $PostgresSSPass = Set-SecurePassword -inputPass $PostgresPassword

            $errorActionPreference = "SilentlyContinue"
            $pgAcct = $null
            $pgAcct = New-LocalUser -Description "SAS Viya Postgres svc acct" -Name $postgresAcctName -Password $PostgresSSPass -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword
            $errorActionPreference = "Continue"
            if($pgAcct -eq $null){
                $e=$error[0]
                Write-SASUserMessage -severity "error" -message "Exception Message: $($e.toString())"
            } else {
                $pgAcctFullName = "$myHostName\$postgresAcctName"
                if($?) {
                    Write-SASUserMessage -severity "alert" -message '"The Postgres Service Account ({0}) was successfully created with password: {1} " -f $pgAcctFullName, $ctPass'
                    Add-LocalGroupMember -Group "Users" -Member $pgAcctFullName
                    if($?) {
                        Write-SASUserMessage -severity "alert" -message "Added $pgAcctFullName to the Users group"
                    } else {
                        Write-SASUserMessage -severity "alert" -message "Attempt to Add $pgAcctFullName to the Users group FAILED!"
                    }
                    Grant-UserRight -Account $pgAcctFullName -Right seServiceLogonRight
                    if($?) {
                        Write-SASUserMessage -severity "alert" -message "Granted $pgAcctFullName the seServiceLogonRight right"
                    } else {
                        Write-SASUserMessage -severity "error" -message "Attempt to grant $pgAcctFullName the seServiceLogonRight right failed!"
                    }
                }
            }
        } else {
            Write-SASUserMessage -severity "warning" -message "The Postgres service account was not found"
        }
    } elseif (($pgAcct.GetType()).Name -eq "LocalUser") {
        Write-SASUserMessage -severity "info" -message "The postgres service account exists: OK"
        $errorActionPreference = "SilentlyContinue"
        $isLocalUser = Get-LocalGroupMember -Group "Users" -Member $postgresAcctName
        $errorActionPreference = "Continue"
        if ($isLocalUser -eq $null) {
            if($remediate) {
                Add-LocalGroupMember -Group "Users" -Member $postgresAcctName
                if($?) {
                    Write-SASUserMessage -severity "alert" -message "Added $myHostName\$postgresAcctName to the Users group"
                } else {
                    Write-SASUserMessage -severity "alert" -message "Attempt to Add $myHostName\$postgresAcctName to the Users group FAILED!"
                }
            } else {
                Write-SASUserMessage -severity "warning" -message "The postgres service account is not a member of the local Users group!"
            }
        } else {
            Write-SASUserMessage -severity "info" -message "The postgres service account is a member of the local Users group: OK"
        }
        $acctRights = Get-UserRightsGrantedToAccount -Account $postgresAcctName
        $hasPrivSvcLogon = $false
        if(-not($acctRights -eq $null)) {
            foreach($right in $acctRights.Right) {
                if ($right -eq "seServiceLogonRight") {
                    $hasPrivSvcLogon = $true
                    break
                }
            }
        }
        if ($hasPrivSvcLogon -eq $false) {
            if($remediate) {
                Grant-UserRight -Account $postgresAcctName -Right seServiceLogonRight
                if($?) {
                    Write-SASUserMessage -severity "alert" -message "Granted $postgresAcctName the seServiceLogonRight right"
                } else {
                    Write-SASUserMessage -severity "error" -message "Attempt to grant $postgresAcctName the seServiceLogonRight right failed!"
                }
            } else {
                Write-SASUserMessage -severity "warning" -message "$postgresAcctName does not have Log on as a Service right"
            }
        } else {
            Write-SASUserMessage -severity "info" -message "$postgresAcctName has Log on as a Service right: OK"
        }
    } else {
        Write-SASUserMessage -severity "warning" -message "The postgres service account does not exist!"
    }
}

function Validate-ADConfig {

    # Obtain FQDN and other computer account attributes
    $comp = Get-ADComputer -Identity $myHostName -Properties TrustedForDelegation,TrustedToAuthForDelegation
    $compTrustedForDelegation = [System.Convert]::ToBoolean($comp.TrustedForDelegation)
    $compFQDN = $comp.DNSHostName.ToString().ToLower()
    $compLDAPRoot = (($comp.distinguishedName.split(",") | ? {$_ -like "DC=*"}) -join ",")
    $svcAcctOUName = $svcAcctOUName + "," + $compLDAPRoot
    $script:casSPN = "sascas/$compFQDN"
    $httpSPN = "HTTP/$compFQDN"
    $krbRealm = $script:krb5realm

    # If -cmdFileOnly are specified initialize the command file
    if ($cmdFileOnly) {

        # if $cmdFilePath is not specified then use default name in current directory
        if ([string]::IsNullOrEmpty($script:cmdFilePath)) {
            $script:cmdFilePath = "SASViyaADEntitySetup.ps1"
        }
        # Now we need to put some comments at the top of the file to help AD Admins understand what is going on
        $script:cmdFileContent = @'
<#
.SYNOPSIS
Helper Script for SAS Viya 3.4 Active Directory entity creation

.DESCRIPTION
SAS Viya 3.4 running on Windows requires certain entities be configured in Active Directory and that those entities
have required attributes configured properly for Integrated Windows Authentication and credential delegation.  This
script was produced to enable seperation of responsibilities between the SAS Administration and Active Directory
Administration.

This script has been produced with suggested values based upon the host intended to run the SAS Viya services.  The name
of the service account can change but all service principal names must remain the same.  All capabilities configured
for the accounts are required.

SAS Viya 3.4 for Windows currently supports only single host deployments.

SAS Viya 3.4 requires two Service Principal Names:
    HTTP/hostname.fqdn@REALM
    sascas/hostname.fqdn@REALM

Future releases of SAS Viya for Windows may support multi-host deployments.  Due to this SAS recommends that each
service principal name be associated with a distinct account.  Until multi-host deployments are supported the SPNs
can both be associated with a single account.  This script will follow the recommendation and create an account for
each SPN.

NOTE THAT THIS SCRIPT HAS BEEN VALIDATED TO WORK ON POWERSHELL 5.1 OR HIGHER.
#>

#Requires -RunAsAdministrator

# Edit the following variable to ensure that accounts are created in the proper location within your Active Directory structure

'@
        $script:cmdFileContent = $script:cmdFileContent + '$svcAcctOUName = "OU=serviceAccounts,' + $compLDAPRoot + '"' + "`n"
        $script:cmdFileContent = $script:cmdFileContent + '$compFQDN = "' + $compFQDN + '"' + "`n"
        $script:cmdFileContent = $script:cmdFileContent + '$krbRealm = "' + $script:krb5realm + '"' + "`n"
        $script:cmdFileContent = $script:cmdFileContent + '$NetBIOSDomain = "' + $script:NetBIOSDomain + '"' + "`n"
        $script:cmdFileContent = $script:cmdFileContent + "# Edit the following variables to set the service account name if the suggestions do not meet your standards`n"
        $script:cmdFileContent = $script:cmdFileContent + '$svcAcctPrefix = "' + $svcAcctPrefix + '"' + "`n"
        $script:cmdFileContent = $script:cmdFileContent + '$svcAcctSuffix = "' + $svcAcctSuffix + '"' + "`n"
        $script:cmdFileContent = $script:cmdFileContent + '$myHostName = "' + $myHostName + '"' + "`n`n"

        $script:cmdFileContent = $script:cmdFileContent + '# if the following variables are not defined then the accounts created will be created according to the pattern $svcAcctPrefix + $myHostName + "-<SVC>" + $svcAcctSuffix' + "`n"
        $script:cmdFileContent = $script:cmdFileContent + '# for the host where SAS will be deployed.  For example if the host is mycoviya with the default value for $svcAcctPrefix and empty $svcAccount Suffix the account name for' + "`n"
        $script:cmdFileContent = $script:cmdFileContent + "# the HTTP account would be svc-sas-mycoviya-HTTP.  If you wish to specify account names which match your organization's standards simply uncomment and define the`n"
        $script:cmdFileContent = $script:cmdFileContent + '# account names below' + "`n"
        $script:cmdFileContent = $script:cmdFileContent + '#$HTTPsvcAcctName = ""' + "`n"
        $script:cmdFileContent = $script:cmdFileContent + '#$CASsvcAcctName = ""' + "`n`n"

        $script:cmdFileContent = $script:cmdFileContent + "# The following two fields govern how passwords are generated for accounts created by this script.  You may change the values`n"
        $script:cmdFileContent = $script:cmdFileContent + "# to better reflect your security requirements.  Valid Values are between 1 and 128`n"
        $script:cmdFileContent = $script:cmdFileContent + "# See https://msdn.microsoft.com/en-us/library/system.web.security.membership.generatepassword(v=vs.110).aspx for more info`n"
        $script:cmdFileContent = $script:cmdFileContent + '$pwLength = '+ $PwLength.ToString() + "`n"
        $script:cmdFileContent = $script:cmdFileContent + '$pwNumSpecialChars = ' + $PwNumSpecialChars.ToString() + "`n"
        $script:cmdFileContent = $script:cmdFileContent + @'

# If these variables are not defined then random passwords will be generated below based upon the length and number of special chars specified above.
# The assumption is that values entered below are clear-text passwords.  Secure strings will be generated below.
#$CASPassword=""
#$HTTPPassword=""

$READMEtxt = @()
# You may send notes to the Viya Admin by editing and adding lines following pattern here:
# $READMEtxt += "Notes from your domain admin:"
# $READMEtxt += "  --  None  -- "

# ------------------ Make no changes below this line!! ------------------
# ------------------ Make no changes below this line!! ------------------
# ------------------ Make no changes below this line!! ------------------
# ------------------ Make no changes below this line!! ------------------
'@
        $script:cmdFileContent = $script:cmdFileContent + "`n"
        $script:cmdFileContent = $script:cmdFileContent + "# Make no changes below this line!!`n`n"
        $script:cmdFileContent = $script:cmdFileContent + '$casSPN = "sascas/' + $compFQDN + '"' + "`n"
        $script:cmdFileContent = $script:cmdFileContent + '$httpSPN = "HTTP/' + $compFQDN + '"' +"`n`n"
        $script:cmdFileContent = $script:cmdFileContent + @'
$READMEtxt += "Actions Completed by domain admin helper script: `n"

$script:ctPass=""

# ------------------ Begin Function Declarations ------------------
function Write-SASUserMessage {
    param(
        [Parameter(Mandatory=$true,
                    Position=0)]
        [string]$severity,
        [Parameter(Mandatory=$true,
                    Position=1)]
        [string]$message,
        [switch]$noLabel
    )
    # Uses severities of Info, Alert, Warning, and Error to format output
    $fieldSep = $message.IndexOf(" -f ")
    if ($fieldSep -gt 0) {
        $s = $message.Substring(0,$fieldSep)
        $f = $message.Substring($fieldSep, ($message.Length - $fieldSep))
        $msg = $s + $f
    } else {
        $msg = '"' + $message + '"'
    }

    switch ($severity.ToUpper()) {
        "INFO" {
            if(-not $noLabel) { Write-Host -noNewLine "INFO: " -ForegroundColor Green }
            $cmd = 'Write-Host(' + $msg + ') -ForegroundColor Green'
            Invoke-Expression $cmd
            Break
        }
        "ALERT" {
            Write-Host -noNewLine "NOTE: " -ForegroundColor Yellow
            $cmd = 'Write-Host(' + $msg + ') -ForegroundColor Yellow'
            Invoke-Expression $cmd
            Break
        }
        "WARNING" {
            $cmd = 'Write-Warning(' + $msg + ') '
            Invoke-Expression $cmd
            Break
        }
        "ERROR" {
            if(-not $noLabel) { Write-Host -noNewLine "ERROR: " -ForegroundColor Red }
            $cmd = 'Write-Host(' + $msg + ') -ForegroundColor Red'
            Invoke-Expression $cmd
            Break
        }
        default {
            Write-Host "ERROR: call to Write-SASUserMessage with invalid severity!`nSeverity: $severity Message Text:`n$message" -ForegroundColor Red
        }
    }
}

function Set-SecurePassword {
    param(
        [string]$inputPass
    )

    $script:ctPass = ""

    if ([string]::IsNullOrEmpty($inputPass)) {
        Add-Type -AssemblyName System.Web
        $script:ctPass = [System.Web.Security.Membership]::GeneratePassword($pwLength, $pwNumSpecialChars)
    } else {
        $script:ctPass = $inputPass
    }
    $SSPass = ConvertTo-SecureString $ctPass -AsPlainText -Force
    $SSPass
}
# ------------------  End Function Declarations  ------------------

'@
    }

    # Validate this computer is trusted for delegation
    if ($compTrustedForDelegation -eq $True) {
        Write-SASUserMessage -severity "info" -message  "Host Account for $myHostName trusted for delegation: OK"
    } else {
        if ($createADEntities) {
            $cmd = "Set-ADcomputer -Identity $myHostName -TrustedForDelegation " + '$true'
            if ($cmdFileOnly) {
                # Append content to command file
                $script:cmdFileContent = $script:cmdFileContent + "# The AD Computer account for $myHostName is not trusted for delegation`n# SAS Viya requires that the computer account be trusted for delegaation.`n"
                $script:cmdFileContent = $script:cmdFileContent + $cmd + " `n"
                $script:cmdFileContent = $script:cmdFileContent + 'if($?) {' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + '    $msg = "The server host account was successfully marked TrustedForDelegation." ' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + '    $READMEtxt += $msg' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + '    Write-SASUserMessage -severity "info" -message $msg' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + '} else {' + "`n"
                $script:cmdFileContent = $script:cmdFileContent + '    $msg = "The server host account was Not successfully marked TrustedForDelegation."' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + '    $READMEtxt += $msg' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + '    Write-SASUserMessage -severity "error" -message $msg' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + '}' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + "`n`n"
            } elseif ($runningWithDomainAdminPrivs) {
                # Execute the change
                Invoke-Expression $cmd
            }
        } else {
            Write-SASUserMessage -severity "warning" -message  "Host Account for $myHostName is not trusted for delegation!"
        }
    }

    # Does the sascas/FQDN SPN exist in AD?
    $results = Get-ADUser -properties ServicePrincipalNames,DistinguishedName,TrustedForDelegation,ObjectCategory -Filter {ServicePrincipalName -like '*'} | where-object { $PSItem.ServicePrincipalNames -contains $casSPN}
    # if we didn't find the SPN in Active Directory
    if ($results -eq $null) {
        if ($createADentities) {
            # If the CAS service account exists already use it:
            $errorActionPreference = "SilentlyContinue"
            $casAcct = $null
            $casAcct = Get-ADUser -Identity $CASsvcAcctName
            $errorActionPreference = "Continue"
            if ($casAcct -eq $null) {
                # Account doesn't exist so create it
                # see https://msdn.microsoft.com/en-us/library/system.web.security.membership.generatepassword.aspx for more details
                $cmdList = @()
                $cmdList += '$CASssPass = Set-SecurePassword -inputPass $CASPassword'
                $cmdList += 'if ($CASsvcAcctName -eq $null) { $CASsvcAcctName = $svcAcctPrefix + $myHostName + "-CAS" + $svcAcctSuffix }'
                $cmdList += 'if ($CASsvcAcctName.length -gt 20) {'
                $cmdList += '    $CASsamName = $CASsvcAcctName.substring(0, 20)'
                $cmdList += '    $msg = "CAS service account name exceeds 20 chars truncating sAMAccountName to {0}" -f $CASsamName'
                $cmdList += '    Write-SASUserMessage -severity "alert" -message $msg'
                $cmdList += '} else {'
                $cmdList += '    $CASsamName = $CASsvcAcctName'
                $cmdList += '}'
                $cmdList += ''
                $cmdList += '$casAcctCreateSuccess = $false'
                $cmdList += ''
                $cmdList += '$script:targetOUExists = $false'
                $cmdList += 'try {'
                $cmdList += '    $doesOUExist = Get-ADOrganizationalUnit -Identity "$svcAcctOUName"'
                $cmdList += '    $script:targetOUExists = $true'
                $cmdList += '} catch {'
                $cmdList += '    Write-SASUserMessage -severity "warning" -message "Requested target container $svcAcctOUName does not exist.`nWill use default instead."'
                $cmdList += '}'
                $cmdList += 'if ($script:targetOUExists) {'
                $cmdList += '    try {'
                $cmdList += '        $casAcct = New-ADUser -SamAccountName $CASsamName -DisplayName $CASsvcAcctName -Name $CASsvcAcctName -AccountPassword $CASssPass -OtherAttributes @{ServicePrincipalName = "$casSPN"} -TrustedForDelegation $true -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true -Path $svcAcctOUName'
                $cmdList += '        $casAcctCreateSuccess = $true'
                $cmdList += '    } catch {'
                $cmdList += '        $e=$error[0]'
                $cmdList += '        Write-SASUserMessage -severity "error" -message "Exception Message: $($e.toString())" '
                $cmdList += '    }'
                $cmdList += '} else {'
                $cmdList += '    try {'
                $cmdList += '        $casAcct = New-ADUser -SamAccountName $CASsamName -DisplayName $CASsvcAcctName -Name $CASsvcAcctName -AccountPassword $CASssPass -OtherAttributes @{ServicePrincipalName = "$casSPN"} -TrustedForDelegation $true -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true'
                $cmdList += '        $casAcctCreateSuccess = $true'
                $cmdList += '    } catch {'
                $cmdList += '        $e=$error[0]'
                $cmdList += '        Write-SASUserMessage -severity "error" -message "Exception Message: $($e.toString())" '
                $cmdList += '    }'
                $cmdList += '}'
                $cmdList += ''
                $cmdList += 'if($casAcctCreateSuccess) {'
                $cmdList += '    $CASdomainUserName = "$NetBIOSDomain\$CASsamName"'
                $cmdList += '    $msg = "The CAS Service Account ($CASdomainUserName) was successfully created with password: $ctPass"'
                $cmdList += '    $READMEtxt += $msg'
                $cmdList += '    Write-SASUserMessage -severity "alert" -message $msg'
                $cmdList += '} else {'
                $cmdList += '    $msg = "CAS Service Account creation failed!" '
                $cmdList += '    $READMEtxt += $msg'
                $cmdList += '    Write-SASUserMessage -severity "error" -message $msg'
                $cmdList += '}'
                if ($cmdFileOnly) {
                    # Append content to command file
                    $script:cmdFileContent = $script:cmdFileContent + "# The AD service account $CASsvcAcctName does not exist`n# SAS Viya requires that the service account exist and be properly configured.`n"
                    foreach ($cmd in $cmdList) {
                        $script:cmdFileContent = $script:cmdFileContent + $cmd + "`n"
                    }
                    $script:cmdFileContent = $script:cmdFileContent +"`n"
                } elseif ($runningWithDomainAdminPrivs) {
                    # Execute the change
                    $cmdBlock = ""
                    foreach ($cmd in $cmdList) {
                        $cmdBlock = $cmdBlock + $cmd + "`n"
                    }
                    Write-Debug "Invoking command:`n     $cmdBlock"
                    Invoke-Expression $cmdBlock
                }
            } else {
                #Account exists but does not have required SPN
                #$cmd = '$adu = Get-ADUser -Filter ' + "'" + 'Name -eq "' + $CASsvcAcctName + '"' + "'" + ' -SearchBase "' + $svcAcctOUName + '" -Properties ServicePrincipalName ' +"`n"
                $cmd = 'Set-ADUser -Identity "' + $CASsvcAcctName + '" -Add @{ServicePrincipalName = "' + $casSPN + '"} -TrustedForDelegation $true'
                if ($cmdFileOnly) {
                    # Append content to command file
                    $script:cmdFileContent = $script:cmdFileContent + "# The AD service account $CASsvcAcctName exists but does not have the correct SPN`n# SAS Viya requires that the service account exist and be properly configured.`n"
                    $script:cmdFileContent = $script:cmdFileContent + $cmd + "`n"
                } elseif ($runningWithDomainAdminPrivs) {
                    # Execute the change
                    Invoke-Expression $cmd
                }
            }
        } else {
            Write-SASUserMessage -severity "warning" -message "SPN sascas/$compFQDN is not defined!"
        }
    } elseif (($results.GetType()).Name -eq "ADUser") {
        # This is where finding 1 logic starts...
        Write-SASUserMessage -severity "info" -message "sascas/$compFQDN is defined: OK"
        # Get the NetBIOSName for the domain the user is in:
        $UserNetBIOSDomain = (Get-ADDomain (($results.distinguishedName.split(",") | ? {$_ -like "DC=*"}) -join ",")).NetBIOSName
        Write-SASUserMessage -severity "info" -message '"sascas SPN Account Name = {0}\{1}" -f $UserNetBIOSDomain, $results.sAMAccountName.ToString()'
        $script:domainUserName = $UserNetBIOSDomain+"\"+$results.sAMAccountName.ToString()

        if ($valSAS) {
            #Is the account the same as the account entered in the casUser.xml file?
            if((-not($domainUserName -eq $null)) -and (-not($script:casCred -eq $null))) {
                if ($domainUserName -ne $script:casCred.UserName.ToString()) {
                    #check if we are using the netbios domain and casUser.xml is using the KRB domain / forest name and do they match
                    $fieldSep = $script:casCred.UserName.ToString().IndexOf("\")
                    if ($fieldSep -gt 0) {
                        $casCredDomain  = $script:casCred.UserName.ToString().Substring(0,$fieldSep)
                        $casCredAccount = $script:casCred.UserName.ToString().Substring(($fieldSep + 1), ($script:casCred.UserName.ToString().Length - ($fieldSep +1)))
                        $ccu = get-aduser -Identity $casCredAccount
                        $ccuDomain = ($ccu.distinguishedName.split(",") | ? {$_ -like "DC=*"}) -join ","
                        $resDomain = ($results.distinguishedName.split(",") | ? {$_ -like "DC=*"}) -join ","
                        if(($casCredAccount -eq $results.sAMAccountName.ToString()) -and ($resDomain -eq $ccuDomain)) {
                            Write-SASUserMessage -severity "info" -message "Stored CAS Username matches SPN User: OK"
                        } else {
                            Write-SASUserMessage -severity "warning" -message "The stored CAS credentials are not for the account that owns the sascas/$compFQDN Service Principal Name"
                        }
                    } else {
                        Write-SASUserMessage -severity "warning" -message "The stored CAS credentials are not for the account that owns the sascas/$compFQDN Service Principal Name"
                    }
                } else {
                    Write-SASUserMessage -severity "info" -message "Stored CAS Username matches SPN User: OK"
                }
            }
        }

        #Is this account trusted for delegation?
        $acct = $results.name.ToString()
        if ([System.Convert]::ToBoolean($results.TrustedForDelegation)) {
            Write-SASUserMessage -severity "info" -message "$script:domainUserName is trusted for delegation: OK"
        } else {
            if ($remediate) {
                $cmd = "Set-ADuser -Identity $acct -TrustedForDelegation " + '$true'
                if ($cmdFileOnly) {
                    # Append content to command file
                    $script:cmdFileContent = $script:cmdFileContent + "# The SAS Viya service account ($script:domainUserName) is not trusted for delegation`n# SAS Viya requires that the service account be trusted for delegaation.`n"
                    $script:cmdFileContent = $script:cmdFileContent + $cmd + "`n`n"
                } elseif ($runningWithDomainAdminPrivs) {
                    # Execute the change
                    Invoke-Expression $cmd
                }
            } else {
                Write-SASUserMessage -severity "warning" -message "$script:domainUserName is not trusted for delegation!"
            }
        }

        $acctRights = Get-UserRightsGrantedToAccount -Account $domainUserName

        # Does this account have SeAssignPrimaryTokenPrivilege (aka "Replace a Process level token")
        $hasPrivReplaceToken = $false
        if(-not($acctRights -eq $null)) {
            foreach($right in $acctRights.Right) {
                if ($right -eq "SeAssignPrimaryTokenPrivilege") {
                    $hasPrivReplaceToken = $true
                    break
                }
            }
        }
        if ($hasPrivReplaceToken -eq $false) {
            if ($remediate) {
                Grant-UserRight -Account $domainUserName -Right SeAssignPrimaryTokenPrivilege
                if($?) {
                    Write-SASUserMessage -severity "alert" -message "Granted $domainUserName the SeAssignPrimaryTokenPrivilege Right"
                } else {
                    Write-SASUserMessage -severity "error" -message "Attempt to grant $domainUserName the SeAssignPrimaryTokenPrivilege Right failed!"
                }
            } else {
                Write-SASUserMessage -severity "warning" -message "$acct does not have the Replace Process Level Token right"
            }
        } else {
            Write-SASUserMessage -severity "info" -message "$acct has Replace Process Level Token: OK"
        }

        # Does this account have SeServiceLogonRight (aka "log on as a service")
        $hasPrivSvcLogon = $false
        if(-not($acctRights -eq $null)) {
            foreach($right in $acctRights.Right) {
                if ($right -eq "seServiceLogonRight") {
                    $hasPrivSvcLogon = $true
                    break
                }
            }
        }
        if ($hasPrivSvcLogon -eq $false) {
            if($remediate) {
                Grant-UserRight -Account $domainUserName -Right seServiceLogonRight
                if($?) {
                    Write-SASUserMessage -severity "alert" -message "Granted $domainUserName the seServiceLogonRight right"
                } else {
                    Write-SASUserMessage -severity "error" -message "Attempt to grant $domainUserName the seServiceLogonRight right failed!"
                }
            } else {
                Write-SASUserMessage -severity "warning" -message "$acct does not have Log on as a Service right"
            }
        } else {
            Write-SASUserMessage -severity "info" -message "$acct has Log on as a Service right: OK"
        }

        # Is this account a member of local Administrators group
        $errorActionPreference = "SilentlyContinue"
        $isLocalAdmin = Get-LocalGroupMember -Member $domainUserName -Group "Administrators"
        $errorActionPreference = "Continue"
        if ($isLocalAdmin -eq $null) {
            if($remediate) {
                Add-LocalGroupMember -Group "Administrators" -Member $domainUserName
                if($?) {
                    Write-SASUserMessage -severity "alert" -message "Added $domainUserName to the local Administrators group"
                } else {
                    Write-SASUserMessage -severity "error" -message "Attempt to add $domainUserName to the local Administrators group failed!"
                }
            } else {
                Write-SASUserMessage -severity "warning" -message "$domainUserName is not a member of the local Administrators group"
            }
        } Else {
            Write-SASUserMessage -severity "info" -message "$domainUserName is a member of the local Administrators group: OK"
        }

    } else {
        # if results was not null and it was not of type ADUser then we must have found more than 1 result
        Write-SASUserMessage -severity "error" -message "SPN sascas/$compFQDN is defined on multiple hosts!"
        foreach($result in $results)
        {
            Write-host "Object Name = " $result.name -backgroundcolor "yellow" -foregroundcolor "black"
            Write-host "DN      =      "  $result.distinguishedName
            Write-host "Object Cat. = "  $result.objectCategory
        }
    }


    # Does the HTTP/FQDN SPN exist in AD?
    $script:HTTPdomainUserName = ""
    $httpSPN="HTTP/$compFQDN"
    $results = Get-ADUser -properties ServicePrincipalNames,DistinguishedName,TrustedForDelegation,ObjectCategory -Filter {ServicePrincipalName -like '*'} | where-object { $PSItem.ServicePrincipalNames -contains $httpSPN}
    $script:HTTPUser = $results
    if($results -ne $null) {
        $UserNetBIOSDomain = (Get-ADDomain (($results.distinguishedName.split(",") | ? {$_ -like "DC=*"}) -join ",")).NetBIOSName
    }

    if ($results -eq $null) {
        # If our SPN is was not found in Active Directory
        if ($createADEntities) {
            # If the HTTP service account exists already use it:
            $errorActionPreference = "SilentlyContinue"
            $httpAcct = $null
            $httpAcct = Get-ADUser -Identity $HTTPsvcAcctName
            $errorActionPreference = "Continue"
            if ($httpAcct -eq $null) {
                # Account doesn't exist so create it
                # see https://msdn.microsoft.com/en-us/library/system.web.security.membership.generatepassword.aspx for more details
                $cmdList = @()
                $cmdList += '$HTTPssPass = Set-SecurePassword -inputPass $HTTPPassword'
                $cmdList += 'if ($HTTPsvcAcctName -eq $null) { $HTTPsvcAcctName = $svcAcctPrefix + $myHostName + "-HTTP" + $svcAcctSuffix }'
                $cmdList += '$httpUPN = $HTTPsvcAcctName + "@" + $KRB5REALM'
                $cmdList += 'if ($HTTPsvcAcctName.length -gt 20) {'
                $cmdList += '    $script:HTTPsamName = $HTTPsvcAcctName.substring(0, 20)'
                $cmdList += '    $msg = "HTTP service account name exceeds 20 chars truncating sAMAccountName to {0}" -f $HTTPsamName'
                $cmdList += '    Write-SASUserMessage -severity "alert" -message $msg'
                $cmdList += '} else {'
                $cmdList += '    $HTTPsamName = $HTTPsvcAcctName'
                $cmdList += '}'

                $cmdList += '$script:targetOUExists = $false'
                $cmdList += 'try {'
                $cmdList += '    $doesOUExist = Get-ADOrganizationalUnit -Identity "$svcAcctOUName"'
                $cmdList += '    $script:targetOUExists = $true'
                $cmdList += '} catch {'
                $cmdList += '    Write-SASUserMessage -severity "warning" -message "Requested target container $svcAcctOUName does not exist.`nWill use default instead."'
                $cmdList += '}'
                $cmdList += '$httpAcctCreateSuccess = $false'

                $cmdList += 'if ($script:targetOUExists) {'
                $cmdList += '    try {'
                $cmdList += '        $httpAcct = New-ADUser -UserPrincipalName $httpUPN -SamAccountName $HTTPsamName -DisplayName $HTTPSvcAcctName -Name $HTTPsvcAcctName -AccountPassword $HTTPssPass -OtherAttributes @{ServicePrincipalName = "$httpSPN"} -TrustedForDelegation $true -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true -Path $svcAcctOUName'
                $cmdList += '        $httpAcctCreateSuccess = $true'
                $cmdList += '    } catch {'
                $cmdList += '        $e=$error[0]'
                $cmdList += '        Write-SASUserMessage -severity "error" -message "Exception Message: $($e.toString())" '
                $cmdList += '    }'
                $cmdList += '} else {'
                $cmdList += '    try {'
                $cmdList += '        $httpAcct = New-ADUser -UserPrincipalName $httpUPN -SamAccountName $HTTPsamName -DisplayName $HTTPSvcAcctName -Name $HTTPsvcAcctName -AccountPassword $HTTPssPass -OtherAttributes @{ServicePrincipalName = "$httpSPN"} -TrustedForDelegation $true -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true'
                $cmdList += '        $httpAcctCreateSuccess = $true'
                $cmdList += '    } catch {'
                $cmdList += '        $e=$error[0]'
                $cmdList += '        Write-SASUserMessage -severity "error" -message "Exception Message: $($e.toString())" '
                $cmdList += '    }'
                $cmdList += '}'

                $cmdList += 'if($httpAcctCreateSuccess) {'
                $cmdList += '    $HTTPdomainUserName = "$NetBIOSDomain\$HTTPsamName"'
                $cmdList += '    $msg = "The HTTP service account ($HTTPDomainUserName) was created successfully."'
                $cmdList += '    $READMEtxt += $msg'
                $cmdList += '    Write-SASUserMessage -severity "info" -message $msg'
                $cmdList += '    Write-SASUserMessage -severity "info" -message "sleeping for 5 seconds to allow replication." '
                $cmdList += '    Start-Sleep -s 5'
                $cmdList += '    $script:HTTPUser = get-aduser -identity $HTTPsamName'
                $cmdList += '} else {'
                $cmdList += '    $msg = "HTTP Service Account creation failed!"'
                $cmdList += '    $READMEtxt += $msg'
                $cmdList += '    Write-SASUserMessage -severity "error" -message $msg'
                $cmdList += '}'

                if ($cmdFileOnly) {
                    # Append content to command file
                    $script:cmdFileContent = $script:cmdFileContent + "# The AD service account $HTTPsvcAcctName does not exist`n# SAS Viya requires that the service account exist and be properly configured.`n"
                    foreach ($cmd in $cmdList) {
                        $script:cmdFileContent = $script:cmdFileContent + $cmd + "`n"
                    }
                    $script:cmdFileContent = $script:cmdFileContent +"`n"
                } elseif ($runningWithDomainAdminPrivs) {
                    # Execute the change
                    $cmdBlock = ""
                    foreach ($cmd in $cmdList) {
                        $cmdBlock = $cmdBlock + $cmd + "`n"
                    }
                    Write-Debug "Invoking command:`n     $cmdBlock"
                    Invoke-Expression $cmdBlock
                }
            } else {
                #Account exists but does not have required SPN
                $cmd = "Get-ADUser -Filter 'Name -eq " + $HTTPsvcAcctName + "' -SearchBase '" + $svcAcctOUName + "' -Properties ServicePrincipalName | % {Set-ADUser $_ -Add @{ServicePrincipalName = '" + $httpSPN + "'} -TrustedForDelegation " + '$true' + " }"
                if ($cmdFileOnly) {
                    # Append content to command file
                    $script:cmdFileContent = $script:cmdFileContent + "# The AD service account $HTTPsvcAcctName exists but does not have the correct SPN`n# SAS Viya requires that the service account exist and be properly configured.`n"
                    $script:cmdFileContent = $script:cmdFileContent + $cmd + "`n"
                } elseif ($runningWithDomainAdminPrivs) {
                    # Execute the change
                    Invoke-Expression $cmd
                }
            }
        } else {
            Write-SASUserMessage -severity "warning" -message "SPN HTTP/$compFQDN is not defined!"
            if($createKeyTab) {
                $createKeyTab = $false
                Write-SASUserMessage -severity "warning" -message "-createKeyTab specified but the HTTP SPN is not defined.  Setting createKeyTab = False"
            }
        }


    } elseif (($results.GetType()).Name -eq "ADUser") {
        # if we found 1 and only 1 account with this SPN
        Write-SASUserMessage -severity "info" -message "HTTP/$compFQDN is defined: OK"
        Write-SASUserMessage -severity "info" -message '"HTTP SPN Account Name = {0}\{1}" -f $UserNetBIOSDomain, $results.sAMAccountName.ToString()'
        $HTTPsamName = $results.sAMAccountName.ToString()
        $acct = $results.Name.ToString()
        $HTTPdomainUserName = $UserNetBIOSDomain+"\"+$results.sAMAccountName.ToString()

    } else {
        Write-SASUserMessage -severity "error" -message "SPN HTTP/$compFQDN is defined on multiple hosts!"
        foreach($result in $results)
        {
            Write-host "Object Name = " $result.name -backgroundcolor "yellow" -foregroundcolor "black"
            Write-host "DN      =      "  $result.distinguishedName
            Write-host "Object Cat. = "  $result.objectCategory
        }
        if($createKeyTab) {
            $createKeyTab = $false
            Write-SASUserMessage -severity "warning" -message "-createKeyTab specified but the HTTP SPN is defined multiple times.  Setting createKeyTab = False"
        }
    }

    if ($createKeyTab) {
        $ktcmdOut = ""
        $cmdList = @()
        $cmdList += 'if ($keyTabPath -eq $null) { $keyTabPath = "http-' + $myHostName + '.keytab" }'
        $cmdList += '# If creating a keytab alone we need to pass in the existing HTTPdomainUserName thus next few lines'
        $cmdList += 'if($HTTPdomainUserName -eq $null) { $HTTPdomainUserName = "' + $HTTPdomainUserName + '" }'
        $cmdList += 'if($HTTPPassword -eq $null) {'
        $cmdList += '    $ktcmd = "ktpass /out " + $keyTabPath + " /mapuser " + $HTTPsamName + " /princ " + $httpSPN + "@" + $krbRealm + " /crypto all /pass +randpass /ptype KRB5_NT_PRINCIPAL /kvno 0 /mapop add"'
        $cmdList += '} else {'
        $cmdList += '    $ktcmd = "ktpass /out " + $keyTabPath + " /mapuser " + $HTTPsamName + " /princ " + $httpSPN + "@" + $krbRealm + " /crypto all /pass """ + $HTTPPassword + """ /ptype KRB5_NT_PRINCIPAL /kvno 0 /mapop add +setpass +setupn"'
        $cmdList += '}'
        $cmdList += '$errorActionPreference = "SilentlyContinue"'
        $cmdList += '$ktcmdOut = Invoke-Expression $ktcmd'
        $cmdList += '$errorActionPreference = "Continue"'
        $cmdList += 'if($LASTEXITCODE -eq 0) {'
        $cmdList += '    $msg = "The HTTP keytab ($keyTabPath) was successfully created." '
        $cmdList += '    foreach($l in $ktcmdOut) {'
        $cmdList += '        $msg += "`n      $l"'
        $cmdList += '    }'
        $cmdList += '    $READMEtxt += $msg' + " `n"
        $cmdList += '    Write-SASUserMessage -severity "alert" -message $msg'
        $cmdList += '} else {'
        $cmdList += '    $msg = "The HTTP keytab creation FAILED." '
        $cmdList += '    foreach($l in $ktcmdOut) {'
        $cmdList += '        $msg += "`n      $l"'
        $cmdList += '    }'
        $cmdList += '    $READMEtxt += $msg' + " `n"
        $cmdList += '    Write-SASUserMessage -severity "error" -message "The creation of the HTTP keytab failed!"'
        $cmdList += '}'
        if ($cmdFileOnly) {
            # Append content to command file
            $script:cmdFileContent = $script:cmdFileContent + "# Generate a keytab for the HTTP/ SPN.  +randpass is used.`n# SAS Viya requires that the HTTP SPN have a properly configured keytab.`n# Provide this keytab to the SAS Viya Administrator.`n"
            foreach ($cmd in $cmdList) {
                $script:cmdFileContent = $script:cmdFileContent + $cmd + "`n"
            }
            $script:cmdFileContent = $script:cmdFileContent +"`n"
            $script:cmdFileContent = $script:cmdFileContent + '$errorActionPreference = "SilentlyContinue"' + " `n"
            $script:cmdFileContent = $script:cmdFileContent + 'Invoke-Expression $ktcmd' + " `n"
            $script:cmdFileContent = $script:cmdFileContent + '$errorActionPreference = "Continue"' + " `n"

        } elseif ($runningWithDomainAdminPrivs) {
            # Execute the change
            $cmdBlock = ""
            foreach ($cmd in $cmdList) {
                $cmdBlock = $cmdBlock + $cmd + "`n"
            }
            Write-Debug "Invoking command:`n     $cmdBlock"
            try {
                Invoke-Expression $cmdBlock
            } catch {
                Write-SASUserMessage -severity "warning" -message "Could not create keytab.  Error returned: $_"
            }
        }
    }
}
# ------------------  End Function Declarations  ------------------

# ------------------ Begin Main Logic ------------------

Write-Host ""
Write-SASUserMessage -severity "Info" -message "sas-wvda version $myVersionNumber `n"
Write-SASUserMessage -severity "Info" -message "Executing on host: $env:computername"

if ($CheckRemoteVersion) {
    $remoteScriptVer = ((Invoke-WebRequest -Uri "$remoteVerCheckURL").Content.split([Environment]::NewLine) | Select-String 'myVersionNumber =')[0].ToString().Split('=')[1].Replace('"','').Replace(' ','')
    if ($remoteScriptVer -gt $myVersionNumber) {
        Write-SASUserMessage -severity "alert" -message "There is a newer version of this tool available at $remoteVerDownloadURL.`n      The remote version number is: $remoteScriptVer"
    } else {
        Write-SASUserMessage -severity "info" -message "There are no updates available."
    }
}

Validate-Java
Get-AdminToolInstallStatus
Validate-dotNETVersion
Validate-ExecutionEnvironment
Validate-cppRuntimePreReqs
Set-wvdaVariables

switch ($true) {
    $valSAS      { Validate-SAS }
    $valADConfig { Validate-ADConfig }
    $valKeytab   { Validate-Keytab }
    $valPostgres { Validate-Postgres }
    $valTuning   { Validate-SASTuning }
    $valCerts    { Validate-SASSigningCerts }
}


if ($cmdFileOnly) {
    # Write content of the command file
        $script:cmdFileContent = $script:cmdFileContent + @'

$READMElines = ""
foreach ($line in $READMEtxt) {
    $READMElines = $READMElines + $line + " `n"
}
$READMElines > ViyaAdminREADME.txt

Compress-Archive -Path ViyaAdminREADME.txt, $keyTabPath -DestinationPath ViyaAdminInfo.zip -Force

rm ViyaAdminREADME.txt
rm $keyTabPath

Write-SASUserMessage -severity "alert" -message  "Administrative information and artifacts required by the SAS Administrator have been placed in ViyaAdminInfo.zip `
      Securely transmit the zip file the SAS Viya Administrator.  Time is of the essence as the deployment of SAS Viya can not continue `
      until the SAS Administrator has these artifacts."
'@
    $script:cmdFileContent > $cmdFilePath
    Write-Host "Provide $cmdFilePath to your Active Directory administrator.  When the script has successfully completed you will be provided:`n - The name and password of the CAS account`n - A keytab for the HTTP service principal`nYou must have all of these artifacts prior to deployment of SAS Viya 3.4." -foregroundcolor "Yellow"
}

if($script:restartRequired) {
    Write-SASUserMessage -severity "alert" -message "System settings have been updated which require a restart to become effective`n      This system must be restarted prior to installing SAS Viya!"
}
