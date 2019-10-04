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

#---------------------- define logging formatter function -------------
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
            if(-not $noLabel) { Write-Host -noNewLine $I18nStrings.INFO_LABEL -ForegroundColor Green }
            $cmd = "Write-Host(@'`n{0}`n'@) -ForegroundColor Green" -f $msg
            Invoke-Expression $cmd
            Break
        }
        "ALERT" {
            if(-not $noLabel) { Write-Host -noNewLine $I18nStrings.ALERT_LABEL -ForegroundColor Yellow }
            $cmd = "Write-Host(@'`n{0}`n'@) -ForegroundColor Yellow" -f $msg
            Invoke-Expression $cmd
            Break
        }
        "WARNING" {
            $cmd = "Write-Warning(@'`n{0}`n'@)" -f $msg
            Invoke-Expression $cmd
            Break
        }
        "DEBUG" {
            $cmd = "Write-Debug(@'`n{0}`n'@)" -f $msg
            Invoke-Expression $cmd
            Break
        }
        "ERROR" {
            if(-not $noLabel) { Write-Host -noNewLine $I18nStrings.ERROR_LABEL -ForegroundColor Red }
            $cmd = "Write-Host(@'`n{0}`n'@) -ForegroundColor Red" -f $msg
            Invoke-Expression $cmd
            Break
        }
        default {
            Write-Host ($I18nStrings.ERROR_LABEL + ($I18nStrings.USERMESSAGE_DEFAULT -f $severity, $message)) -ForegroundColor Red
        }
    }
}
#-----------------End define logging formatter function -----------------------


# This string variable contains function that are used both in this script and possibly in a script generated by this script.
# But I only want to maintain one copy of each.
# Use Invoke-Expression to load these functions into current context.
$commonFunctions = @'
function Set-SecurePassword {
    param(
        [string]$inputPass
    )

    $script:ctPass = ""

    if (!$inputPass) {
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

function FindFreeSamAccountName {
    param(
        [string] $longAccountName
    )
    if ($longAccountName.length -le 20) {
        $longAccountName
        return
    }
    # Here we are dealing with truncated SamAccountName. We need to munge in Administrator's script to avoid name allocation race conditions.
    # EG: sas machine administrator runs "sas-wvda -remediate -cmdfileonly -createADEntities" on multiple hosts,
    # and then gives all zip files to AD admin at the same time.
    $local:i = [Uint64]0
    $shortName = $longAccountName.substring(0, 20) <# first check simple truncation #>
    $local:tu=$null;
    $local:mungeString="0123456789ABCDEFGHIJKLMNOPQRSTUV"
    do {
        $local:tu = Get-ADUser -Filter ('sAMAccountName -like "*{0}*"' -f $shortName)
        if ($local:tu -eq $null) { break } <# If AD did not find the short name, then it is ok to use             #>
        $ts=""                             <# Else build a base32 encoded representation of current index $i      #>
        if ($i -eq 36){
        $i2=$i                             <# base32 because it avoids symbols that confuse AD, but is very dense #>
        }
        for ($i2=$i; $i2 -ge $local:mungeString.Length; $i2/=$local:mungeString.Length) {
            $mod=$i2%$local:mungeString.Length;
            $ts=$local:mungeString[$mod]+$ts;
            $i2-=$mod
        }
        $ts=$local:mungeString[$i2]+$ts
        $shortName = $shortName.substring(0,20-$ts.length)+$ts <# truncate further, then append the index #>
        $i++
    } while ($local:tu) <# While this short name is found in AD #>
    $shortName
}
'@
Invoke-Expression $commonFunctions

#Import Localized Strings, with partial localization merged with defaults
$I18nStrings = Import-LocalizedData -ErrorAction SilentlyContinue -FileName sas-wvda-l10n.psd1
if ($I18nStrings -eq $null) {
    Write-SASUserMessage -severity "error" -noLabel -message "Unable to locate '$PsUICulture' language-specific message file. Cannot continue."
    exit 1
} else {
    $defaultStrings = Import-LocalizedData -UICulture "en-US" -ErrorAction SilentlyContinue -FileName sas-wvda-l10n.psd1
    if ($defaultStrings -eq $null) {
        Write-SASUserMessage -severity "error" -noLabel -message "Unable to locate default English-language message file. Cannot continue."
        exit 1
    } else {
        #At this point, we know that both $I18nStrings and $defaultStrings are non-null.
        try {
            $defaultStrings.keys | where { !($I18nStrings.ContainsKey($_)) } | %{ $I18nStrings.add($_,$defaultStrings[$_]) }
        } catch {
            Write-SASUserMessage -severity "error" -noLabel -message "Error populating '$PsUICulture' language-specific message file. Cannot continue."
            exit 1
        }
        if ( ($I18nStrings.GetType().name -ne "Hashtable") -or ($I18nStrings.count -lt $defaultStrings.count) ) {
            Write-SASUserMessage -severity "error" -noLabel -message "Invalid '$PsUICulture' language-specific message file. Cannot continue."
            exit 1
        } else {
            #Not sure if we'll keep this "informational" message.
            #Write-SASUserMessage -severity "info" -message "Message file ok. Continuing..."
        }
    }
}


$myVersionNumber = "1.1.09"
$remoteVerCheckURL = "https://raw.githubusercontent.com/sassoftware/sas-wvda/master/sas-wvda.ps1"
$remoteVerDownloadURL = "https://github.com/sassoftware/sas-wvda"

$validateRequestList='all','sas','certs','tuning','keytab','adconfig','postgres','host'
if (-not $validateRequestList.Contains($validate.ToLower())) {
    Write-SASUserMessage -severity "error" -message ($I18nStrings.BAD_VALIDATION_OPTION -f $validate)
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
[int]$script:winVersion = 0

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
        Write-Debug $I18nStrings.ADMIN_FEATURES_PRESENT
    } else {
        If (-not([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(`
            [Security.Principal.WindowsBuiltInRole] "Administrator")) {

            Write-SASUserMessage -severity "error" -message $I18nStrings.ADMIN_FEATURES_MISSING
            Exit 1
        } else {
            do {
                Write-Host ($I18nStrings.ADMIN_FEATURES_REMEDIA_YN -f ${I18nStrings}.Y,${I18nStrings}.N)
                $installFeatures = Read-Host
            } until ($I18nStrings.Y,$I18nStrings.N -ccontains $installFeatures.toUpper())
            if ($installFeatures.toUpper() -eq $I18nStrings.Y) {
                Add-WindowsFeature RSAT-AD-PowerShell,RSAT-AD-AdminCenter
            } else {
                Write-SASUserMessage -severity "alert" -message $I18nStrings.ADMIN_FEATURES_REMEDIA_R
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
            Write-SASUserMessage -severity "alert" -message ($I18nStrings.SET_WVDA_VARIABLES_RETRY -f $_)
        }
    } until (($local:iterCount -eq 5) -or $local:success)

    if ($local:success) {
        Write-SASUserMessage -severity "debug" -message $I18nStrings.SET_WVDA_VARIABLES_QUERY_SUC
    } else {
        Write-SASUserMessage -severity "error" -message $I18nStrings.SET_WVDA_VARIABLES_QUERY_FAIL
        exit 1
    }

    if ($script:inVerboseMode) {
        Write-SASUserMessage -severity "info" -message ($I18nStrings.KRB5_REALM -f $script:krb5Realm)
        $msg = $I18nStrings.COMPUTER_ATTRIBUTES
        $o = Get-ADComputer -identity $myHostName -Properties * | Format-List | Out-String
        foreach ($l in $o) { $msg += "`n      $l" }
        Write-SASUserMessage -severity "info" -message "$msg"
        $msg = $I18nStrings.DOMAIN_ATTRIBUTES
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

function Check-CredentialsGuard {
    #messages shown to user are for 3.4 and earlier versions of Viya.
    if ($script:winVersion -le 6) { <# Windows Credential Guard does not exist on Windows Server 2012 and earlier. #>
        Write-SASUserMessage -severity "Info" -message $I18nStrings.CG_NOT_PRESENT
        return
    }
    try {
        $DevGuard = Get-CimInstance –ClassName Win32_DeviceGuard –Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
    } catch {
       Write-SASUserMessage -severity "Info" -message $I18nStrings.CG_NOT_PRESENT
       return
    }

    if ($DevGuard.SecurityServicesConfigured -contains 1) {
        if ($Remediate) {
            $RegistryKeyPath = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
            Set-ItemProperty -Path $RegistryKeyPath -Name "RequirePlatformSecurityFeatures" -Value 0
            Set-ItemProperty -Path $RegistryKeyPath -Name "EnableVirtualizationBasedSecurity" -Value 0
            Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LsaCfgFlags" -Value 0
            $DevGuard = Get-CimInstance –ClassName Win32_DeviceGuard -Namespace root\Microsoft\Windows\DeviceGuard -ErrorAction Stop
            if ($DevGuard.SecurityServicesConfigured -contains 0) {
                Write-SASUserMessage -severity "Info" -message $I18nStrings.CG_CHANGED_OK
            } else {
                Write-SASUserMessage -severity "Warning" -message $I18nStrings.CG_CHANGED_FAIL
            }
        } else {
            Write-SASUserMessage -severity "Warning" -message $I18nStrings.CG_CONFIGURED
        }
        if ($DevGuard.SecurityServicesRunning -contains 1) {
            $sev="Warning"
            if ($Remediate){
                $sev="Info"
                $script:restartRequired=$true
            }
            Write-SASUserMessage -severity $sev -message $I18nStrings.CG_RUNNING
        } else {
            Write-SASUserMessage -severity "Info" -message $I18nStrings.CG_NOT_RUNNING
        }
    } else {
       Write-SASUserMessage -severity "Info" -message $I18nStrings.CG_NOT_CONFIGURED
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
                    Write-SASUserMessage -severity "info" -message ($I18nStrings.JAVA_INSTALL_OK -f $env:JAVA_HOME)
                    foreach($l in $javaInfo) {
                        if($l -match "64-bit") {
                            $script:javaIsValid = $true
                            break
                        }
                    }
                    if($script:javaIsValid) {
                        Write-SASUserMessage -severity "info" -message $I18nStrings.JAVA_64_OK
                    } else {
                        Write-SASUserMessage -severity "Warning" -message ($I18nStrings.JAVA_64_BAD -f $env:JAVA_HOME)
                    }
                } else {
                    Write-SASUserMessage -severity "warning" -message ($I18nStrings.JAVA_INSTALL_BAD -f $env:JAVA_HOME,$javaInfo[0] )
                }
            } else {
                Write-SASUserMessage -severity "warning" -message ($I18nStrings.JAVA_NO_EXE -f $env:JAVA_HOME)
            }
        } else {
            Write-SASUserMessage -severity "error" -message ($I18nStrings.JAVA_PATH_BAD -f $env:JAVA_HOME)
        }
    } else {
        #JAVA_HOME is not defined
        Write-SASUserMessage -severity "warning" -message $I18nStrings.JAVA_NO_HOME
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
        Write-SASUserMessage -severity "warning" -message ($I18nStrings.DOTNET_BAD_VERSION -f $script:minDotNetRelease,$release,"https://support.microsoft.com/en-us/kb/3045557")
    } else {
        Write-SASUserMessage -severity "info" -message $I18nStrings.DOTNET_GOOD_VERSION
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
            $certUtilOutput = cmd /c "`"certutil.exe`" -addstore TrustedPublisher $PSScriptRoot\SAS_Code_Signing_Certs.p7b " 2>&1
            if ($lastExitCode -eq 0) {
                $msg = $I18nStrings.PUBLIC_CERT_UPDATE_OK -f "CERTUTIL"
                foreach($l in $certUtilOutput) { $msg += "`n      $l" }
                Write-SASUserMessage -severity "info" -message $msg.Replace('"', '`"')
            } else {
                $msg = $I18nStrings.PUBLIC_CERT_UPDATE_FAILED -f "CERTUTIL"
                foreach($l in $certUtilOutput) { $msg += "`n       $l" }
                Write-SASUserMessage -severity "warning" -message $msg.Replace('"', '`"')
            }
        } else {
            Write-SASUserMessage -severity "warning" $I18nStrings.PUBLIC_CERT_NOT_INSTALLED
        }
    } else {
       Write-SASUserMessage -severity "info" -message $I18nStrings.PUBLIC_CERT_INSTALLED
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
                Write-SASUserMessage -severity "info" -message ($I18nStrings.VC_RUNTIME_INSTALLED -f $dn)
            }
            if ($dn -like "Microsoft Visual C++ 2015 Redistributable (x64)*") {
                $found2015RunTime = $true
                Write-SASUserMessage -severity "info" -message ($I18nStrings.VC_RUNTIME_INSTALLED -f $dn)
            }
            # The 2017 Redistributable covers 2015 as well.  While it may look odd to search for 2017 and set found2015 to true
            # This is by design and matches expectations of the behavior / functionality of 2017 and 2015.
            if ($dn -like "Microsoft Visual C++ 2017 Redistributable (x64)*") {
                $found2015RunTime = $true
                Write-SASUserMessage -severity "info" -message ($I18nStrings.VC_RUNTIME_INSTALLED -f $dn)
            }
        }
    }

    if (-not $found2013RunTime) {
        Write-SASUserMessage -severity "warning" -message $I18nStrings.VC_RUNTIME_NEED_2013
    }
    if (-not $found2015RunTime) {
        Write-SASUserMessage -severity "warning" -message $I18nStrings.VC_RUNTIME_NEED_2015
    }
}

function Validate-ExecutionEnvironment {

    # Are we running in a 64-bit environment?
    if (($env:PROCESSOR_ARCHITECTURE -eq "x86") -or ($env:ProgramFiles -eq ${env:ProgramFiles(x86)})) {
        Write-SASUserMessage -severity "error" -message $I18nStrings.NEED_64BIT
        exit 1
    } else {
        Write-SASUserMessage -severity "info"  -message $I18nStrings.OK_64BIT
    }

    # Are we running the PowerShell 5.1 or higher?
    $psMajor = [int]$PSVersionTable.PSVersion.Major
    $psMinor = [int]$PSVersionTable.PSVersion.Minor
    if ((($psMajor -ge 5) -and ($psMinor -ge 1)) -or ($psMajor -gt 5) ) {
        Write-SASUserMessage -severity "info" -message $I18nStrings.PS_VER_OK
    } else {
        Write-SASUserMessage -severity "error" -message $I18nStrings.PS_VER_BAD
        exit 1
    }

    # Are we a Domain user (vs. local machine user)?
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement
    $UserPrincipal = [System.DirectoryServices.AccountManagement.UserPrincipal]::Current
    if($UserPrincipal.ContextType -eq "Machine") {
        Write-SASUserMessage -severity "error" -message $I18nStrings.MUST_BE_DOMAIN
        exit 1
    }


    # Are we a Domain Admin?
    $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    $WindowsPrincipal = New-Object System.Security.Principal.WindowsPrincipal($CurrentUser)
    $script:runningWithDomainAdminPrivs = $WindowsPrincipal.IsInRole("Domain Admins")

    if($runningWithDomainAdminPrivs) {
        Write-SASUserMessage -severity "info" -message $I18nStrings.CURRENTLY_DOMAIN_ADMIN
    } else {
        if ($createADEntities -and -not $cmdFileOnly) {
            Write-SASUserMessage -severity "warning" -message $I18nStrings.NOT_DA_CREATE_SCRIPT
            $script:cmdFileOnly = $true
            if (-not $createKeyTab) {
                Write-SASUserMessage -severity "warning" -message $I18nStrings.NOT_DA_NO_CREATE_KT
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
        Write-SASUserMessage -severity "error" -message $I18nStrings.NEED_SERVER
        exit 1
    } else {
        Write-SASUserMessage -severity  "info" -message $I18nStrings.GOOD_SERVER
    }

    # For Kerberos we can not be on a standalone / workgroup server.  Must be part of a Domain
    # PartOfDomain (boolean Property)
    if (-not (Get-WmiObject -Class Win32_ComputerSystem).PartOfDomain) {
        Write-SASUserMessage -severity "error" -message $I18nStrings.SERVER_DOMAIN_BAD
        exit 1
    } else {
        Write-SASUserMessage -severity "info" -message $I18nStrings.SERVER_DOMAIN_OK
    }

    # For Viya 3.4 supported versions of Windows Server are Windows 2012 R2 and higher
    # see https://msdn.microsoft.com/en-us/library/windows/desktop/ms724832(v=vs.85).aspx for more information
    $verInfo = $osInfo.Version.Split(".")
    if (([int]$verInfo[0] -lt 6) -or (([int]$verInfo[0] -eq 6) -and ([int]$verInfo[1] -lt 3))) {
        Write-SASUserMessage -severity "error" -message ($I18nStrings.WIN_VER_BAD -f $osInfo.Caption.ToString())
        exit 1
    } else {
        # Running on a supported version
        Write-SASUserMessage -severity "info" -message ($I18nStrings.WIN_VER_OK -f $osInfo.Caption.ToString())
        $script:winVersion = [int]$verInfo[0]
    }

}

function Validate-SAS {

    # Can we find postgresUser.xml
    $postgresUserCredExists = Test-Path $DeployDir\postgresUser.xml
    if (-not $postgresUserCredExists) {
        Write-SASUserMessage -severity "warning" -message ($I18nStrings.POSTGRES_NO_FILE -f $DeployDir)
    } else {
        $script:pgCred = Import-Clixml $DeployDir\postgresUser.xml
        try {
                Start-Process -Credential $script:pgCred -FilePath ping -WindowStyle Hidden
                Write-SASUserMessage -severity "info" -message $I18nStrings.POSTGRES_FILE_CONTENT_OK
        } catch {
            Write-SASUserMessage -severity "warning" -message "$_"
            Write-SASUserMessage -severity "warning" -message $I18nStrings.POSTGRES_FILE_CONTENT_FAIL
        }
    }

    # Can we find casUser.xml
    $casUserCredExists = Test-Path $DeployDir\casUser.xml
    if (-not $casUserCredExists) {
        Write-SASUserMessage -severity "warning" -message ($I18nStrings.CAS_NO_FILE -f $DeployDir)
    } else {
        $script:casCred = Import-Clixml $DeployDir\casUser.xml
        try {
                Start-Process -Credential $script:casCred -FilePath ping -WindowStyle Hidden
                Write-SASUserMessage -severity "info" -message $I18nStrings.CAS_FILE_CONTENT_OK
        } catch {
            Write-SASUserMessage -severity "warning" -message "$_"
            Write-SASUserMessage -severity "warning" -message $I18nStrings.CAS_FILE_CONTENT_FAIL
        }
    }

}

function Write-krb5Ini {

    "[libdefaults]`n" > $PSScriptRoot\krb5.ini
    "default_realm = $script:krb5Realm `n`n" >> .\krb5.ini

}

function Validate-Keytab {

    if ([string]::IsNullOrEmpty($keyTabPath)) {
        Write-SASUserMessage -severity "Warning" -message $I18nStrings.KEYTAB_NO_PATH
        $keyTabExists = $false
    } else {
        $keyTabExists = Test-Path $keyTabPath
    }
    If ($keyTabExists -eq $False) {
        Write-SASUserMessage -severity "warning" -message ($I18nStrings.KEYTAB_NO_FILE -f $keyTabPath)
    } else {
        if ($script:HTTPUser -eq $null) {
            Write-SASUserMessage -severity "warning" -message $I18nStrings.KEYTAB_NO_HTTP_SPN
        } else {
            if (Test-Path env:JAVA_HOME) {
                $klistOutput = & "$env:JAVA_HOME\bin\klist.exe" -k -t $keyTabPath 2>&1
                if( $script:inVerboseMode) {
                    $msg = $I18nStrings.KEYTAB_CONTENT
                    foreach($l in $klistOutput) { $msg += "`n      $l" }
                    Write-SASUserMessage -severity "info" -message $msg
                }
                $klistOutput = $klistOutput | Select-String -Pattern HTTP/$myHostName | Select-Object -First 1
                if ($klistOutput -eq $null) {
                    Write-SASUserMessage -severity "warning" -message $I18nStrings.KEYTAB_HTTP_NO_PRINCIPAL
                } else {
                    $keytabPrinc = $klistOutput.ToString().split()[3]
                    $keytabPrincRealm = $keytabPrinc.split("@")[1]
                    if (-not ($keytabPrincRealm -eq $script:krb5Realm)) {
                        Write-SASUserMessage -severity "warning" -message ($I18nStrings.KEYTAB_NO_MATCH -f $keytabPrincRealm, $script:krb5Realm)
                    }
                    if( $script:inVerboseMode) { Write-SASUserMessage -severity "info" -message ($I18nStrings.KEYTAB_WILL_KINIT -f $keytabPrinc) }
                    Write-krb5Ini
                    if( $script:inVerboseMode) {
                        $krb5DebugString = "-Dsun.security.krb5.debug=true"
                    } else {
                        $krb5DebugString = "-Dsun.security.krb5.debug=false"
                    }
                    $env:_JAVA_OPTIONS = "$krb5DebugString -Djava.security.krb5.conf=$PSScriptRoot\krb5.ini"
                    $kinitOutput = & "$env:JAVA_HOME\bin\kinit.exe" -f -k -t $keyTabPath $keytabPrinc 2>&1
                    if ($lastExitCode -eq 0) {
                        $msg = $I18nStrings.KEYTAB_KINIT_OK -f "KINIT"
                        foreach($l in $kinitOutput) { $msg += "`n      $l" }
                        Write-SASUserMessage -severity "info" -message $msg
                    } else {
                        if ( (-not ($script:HTTPUser -eq $null)) -and ($script:HTTPUser -ne $keytabPrinc)) {
                            $msg = $I18nStrings.KEYTAB_VERIFY_FAILED -f $script:HTTPUser.UserPrincipalName.tostring(),$keytabPrinc
                            Write-SASUserMessage -severity "warning" -message $msg
                        } else {
                            $msg = $I18nStrings.KEYTAB_KINIT_FAIL -f "KINIT",$keyTabPath
                            foreach($l in $kinitOutput) { $msg += "`n         $l" }
                            Write-SASUserMessage -severity "warning" -message $msg
                        }
                    }
                    $env:_JAVA_OPTIONS = ""
                }
            } else {
                Write-SASUserMessage -severity "warning" -message $I18nStrings.KEYTAB_NO_JAVA
            }
        }
    }

}

function Validate-WSearch{
    $local:severity='info'
    $startType=$null
    $status=$null
    $displayName=$null

    $oldError=$error.Clone()
    $error.Clear()
    $local:service = Get-Service -Name 'WSearch' -ErrorAction SilentlyContinue
    if (-not $?) {
        $startType="Disabled"
        $status="uninstalled"
        $displayName="Wsearch"
    } else {
        if ($Remediate){
            if ($local:service.Status -eq 'Running') {
                $output=@()
                $local:service | Stop-Service -ErrorAction SilentlyContinue -ErrorVariable +output -Force
                if (!$?) {
                    $local:msg=$I18nStrings.WSEARCH_STOP_FAIL+$output
                    Write-SASUserMessage -severity 'warning' -message $local:msg
                }
            }
            if ($local:service.StartType -ne 'Disabled' ) {
                $output=@()
                $local:service | Set-Service -ErrorAction SilentlyContinue -ErrorVariable +output -StartupType Disabled
                if (!$? ){
                    $local:msg=$I18nStrings.WSEARCH_DISABLE_FAIL+$output
                    Write-SASUserMessage -severity 'warning' -message $local:msg
                }
            }
            $local:service = Get-Service -Name 'WSearch' -ErrorAction SilentlyContinue
        }
        $startType=$local:service.StartType
        $status=$local:service.Status
        $displayName=$local:service.DisplayName
    }
    if ($startType -ne "Disabled" -or $status -eq "Running"){
        $local:severity='warning'
    }
    Write-SASUserMessage -severity $local:severity -message ( $I18nStrings.WSEARCH_STATUS -f $status, $startType,$displayName )
    if ($local:severity -eq "warning") {
        Write-SASUserMessage -severity "warning" -message $I18nStrings.WSEARCH_SKIP
    }
    $error.Clear()
    $null=$oldError|%{$error.Add($_)}
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
                            Write-SASUserMessage -severity "alert" -message ($I18nStrings.TUNING_HEAPSIZE_YN -f $RequestedBatchDesktopHeapSize, $curBatchDesktopHeapSize, ${I18nStrings}.Y,${I18nStrings}.N)
                            $forceUpdate = Read-Host
                        } until (${I18nStrings}.Y,${I18nStrings}.N -ccontains $forceUpdate.toUpper())
                        if ($forceUpdate.toUpper() -eq ${I18nStrings}.Y) {
                            $updateNeeded = $true
                        } else {
                            Write-SASUserMessage -severity "alert" -message $I18nStrings.TUNING_HEAPSIZE_SKIP
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
                    $fullPath="$script:myPath\$script:myKey"
                    $msg = $I18nStrings.TUNING_USER_WORK -f $RequestedbatchDesktopHeapSize,$curBatchDesktopHeapSize,$values[0],$values[1],$curBatchDesktopHeapSize,$fullPath
                    Write-SASUserMessage -severity "warning" -message $msg
                } else {
                    Write-SASUserMessage -severity "info" -message ($I18nStrings.TUNING_SHAREDSECTION_OK -f $values[0],$values[1],$curBatchDesktopHeapSize)
                }
            }
        }
        $newWinSSParms = $newWinSSParms + " " + $parm
    }
    if ($updateNeeded) {
        Write-Debug ($I18nStrings.TUNING_DO_UPDATE -f $WinSSParms,$newWinSSParms)
        Set-ItemProperty -Path "$myPath" -Name "$mykey" -Value "$newWinSSParms"
        Set-RestartRequired
        $updateNeeded = $false
        Write-SASUserMessage -severity "alert" -message ($I18nStrings.TUNING_DONE_UPDATE -f $values[0],$values[1],$curBatchDesktopHeapSize,$RequestedbatchDesktopHeapSize)
    } elseif($remediate) {
        Write-SASUserMessage -severity "info" -message ($I18nStrings.TUNING_SKIP_UPDATE -f $values[0],$values[1],$curBatchDesktopHeapSize)
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
            Write-SASUserMessage -severity "debug" -message ($I18nStrings.TUNING_VALIDATION_GET_FAIL -f $myPath,$myKey)
        }
        if ([string]::IsNullOrEmpty($currValue)) {
            if ($remediate) {
                $addRegEnt = $true
                $updateNeeded = $true
            } else {
                Write-SASUserMessage -severity "warning" -message ($I18nStrings.TUNING_VALIDATION_RECOMMEND_SET -f $myKey, $item.Value)
            }
        } else {
          if ($item.Oper -eq "-eq") {
            if ($currValue -eq $item.Value) {
                Write-SASUserMessage -severity "info" -message  ($I18nStrings.TUNING_VALIDATION_RECOMMEND_EQ_OK -f $myKey, $currValue)
            } else {
                if ( -not $remediate  ) {
                    Write-SASUserMessage -severity "warning" -message ($I18nStrings.TUNING_VALIDATION_RECOMMEND_EQ -f $myKey, $currValue, $item.Value)
                } else {
                    $updateNeeded = $true
                }
            }
          } elseIf ($item.oper -eq "-ge") {
            if ($currValue -lt $item.Value) {
                if (-not $remediate) {
                    Write-SASUserMessage -severity "warning" -message ($I18nStrings.TUNING_VALIDATION_RECOMMEND_GE -f $myKey, $currValue, $item.Value)
                } else {
                    $updateNeeded = $true
                }
            } else {
                Write-SASUserMessage -severity "info" -message ($I18nStrings.TUNING_VALIDATION_RECOMMEND_GE_OK -f $myKey, $item.Value)
            }
          } else {
            Write-SASUserMessage -severity "error" -message ($I18nStrings.TUNING_VALIDATION_BAD_OPERATOR -f $item.oper)
          }
        }
        if ($updateNeeded -and $remediate) {
            if ($addRegEnt) {
                Write-SASUserMessage -severity "alert" -message  ($I18nStrings.TUNING_VALIDATION_ADD -f $myPath, $mykey, $item.Value.tostring())
                New-ItemProperty -Path $myPath -Name $myKey -Value $item.Value.ToInt32($null) -PropertyType DWORD  | Out-Null
            } else {
                Write-SASUserMessage -severity "alert" -message  ($I18nStrings.TUNING_VALIDATION_UPDATE -f $mykey, $currValue, $item.Value.tostring())
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
        Write-SASUserMessage -severity "debug" -message ($I18nStrings.TUNING_PORT_START_BAD -f $portStart)
        $ephemeralPortError = $true
    } else {
        Write-SASUserMessage -severity "info" -message  ($I18nStrings.TUNING_PORT_START_OK -f $portStart)
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
        Write-SASUserMessage -severity "debug" -message ($I18nStrings.TUNING_PORT_QTY_BAD -f $portQty)
        $ephemeralPortError = $true
    } else {
        Write-SASUserMessage -severity "info" -message  ($I18nStrings.TUNING_PORT_QTY_OK -f $portQty)
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
            Write-SASUserMessage -severity "debug" -message ($I18nStrings.INVOKING_COMMAND -f $cmdBlock)
            $errorActionPreference = "SilentlyContinue"
            Invoke-Expression $cmdBlock
            Write-SASUserMessage -severity "alert" -message $I18nStrings.TUNING_PORT_DONE
            $errorActionPreference = "Continue"
            Set-RestartRequired
        } else {
            Write-SASUserMessage -severity "warning" -message ($I18nStrings.TUNING_PORT_SKIP -f $portQty, $portStart)
        }
    }
}

function Validate-Postgres {
    $pgDomainNetBIOSName=""
    # Validate the Postgres Account exists and is configured correctly
    if(-not ($script:pgCred -eq $null)) {
        $postgresAcctName = $script:pgCred.UserName.toString()
    }
    $fieldSep = $postgresAcctName.IndexOf("\")
    if ($fieldSep -gt 0) {
        $pgDomainNetBIOSName = $postgresAcctName.Substring(0,$fieldSep)
        $fieldSep += 1
        $postgresAcctName = $postgresAcctName.Substring($fieldSep, ($postgresAcctName.Length - $fieldSep))
        if ($pgDomainNetBIOSName -eq $myHostName) {
            $pgDomainNetBIOSName=""
        }
    }
    if ($postgresAcctName.length -gt 20) {
        $postgresAcctName = $postgresAcctName.substring(0, 20)
        Write-SASUserMessage -severity "alert" -message ($I18nStrings.POSTGRES_NAME_LONG -f $postgresAcctName)
    }
    $errorActionPreference = "SilentlyContinue"
    if ($pgDomainNetBIOSName) {
        $pgAcct = Get-ADUser -Filter ('sAMAccountName -like "*{0}*"' -f $postgresAcctName)
        if (!$pgAcct) {
            $pgAcct = Get-LocalUser -Name $postgresAcctName
            if ($pgAcct) {
                $pgDomainNetBIOSName=""
            }
        } elseif (($pgAcct.GetType()).Name -eq "ADUser") {
            $pgDomainNetBIOSName=(($pgAcct.DistinguishedName -split "," | ?{$_ -like "DC=*"} | %{$_ -replace "DC=",""})[0])
            $postgresAcctName = "$pgDomainNetBIOSName\$postgresAcctName"
        }
    } else {
        $pgAcct = Get-LocalUser -Name $postgresAcctName
        if (!$pgAcct) {
            $pgAcct = Get-ADUser -Filter ('sAMAccountName -like "*{0}*"' -f $postgresAcctName)
            if ($pgAcct -and ($pgAcct.GetType()).Name -eq "ADUser") {
                $pgDomainNetBIOSName=(($pgAcct.DistinguishedName -split "," | ?{$_ -like "DC=*"} | %{$_ -replace "DC=",""})[0])
                $postgresAcctName = "$pgDomainNetBIOSName\$postgresAcctName"
            }
        }
    }
    $errorActionPreference = "Continue"

    if($pgAcct -eq $null) {
        if($remediate) {
            # Account not found so we need to create it and set everything up correctly
            $PostgresSSPass = Set-SecurePassword -inputPass $PostgresPassword

            $errorActionPreference = "SilentlyContinue"
            $pgAcct = New-LocalUser -Description "SAS Viya Postgres svc acct" -Name $postgresAcctName -Password $PostgresSSPass -PasswordNeverExpires -AccountNeverExpires -UserMayNotChangePassword
            $errorActionPreference = "Continue"
            if($pgAcct -eq $null){
                $e=$error[0]
                Write-SASUserMessage -severity "error" -message "Exception Message: $($e.toString())"
                return # if $pgAcct is still $null, we can just leave this function.
            }
            # Setup of the account will continue in the next if block.
        } else {
            Write-SASUserMessage -severity "warning" -message $I18nStrings.POSTGRES_ACCT_SKIP
            return #if $pgAcct is still null, we can just leave this function.
        }
    }

    #At this point $pgAcct will not be $null, because of return statments above.
    if ($pgAcct.GetType().Name -eq "Object[]") {
        Write-SASUserMessage -severity "error" -message $I18nStrings.POSTGRES_MANY_ACCT
    } elseif (!($pgAcct.GetType().Name -eq "LocalUser") -and !($pgAcct.GetType().Name -eq "ADUser")) {
        Write-SASUserMessage -severity "warning" -message $I18nStrings.POSTGRES_NO_ACCT
    } else {
        Write-SASUserMessage -severity "info" -message $I18nStrings.POSTGRES_ACCT_FOUND
        # get localized name for local "Users" group from well-known SID.
        $groupName=(Get-LocalGroup -SID "S-1-5-32-545").Name
        $errorActionPreference = "SilentlyContinue"
        $isLocalMember = Get-LocalGroupMember -Name $groupName -Member $postgresAcctName
        $errorActionPreference = "Continue"
        if ($isLocalMember -eq $null) {
            if($remediate) {
                Add-LocalGroupMember -Group $groupName -Member $postgresAcctName
                if($?) {
                    Write-SASUserMessage -severity "alert" -message ($I18nStrings.GROUP_SUC -f $postgresAcctName,$groupName)
                } else {
                    Write-SASUserMessage -severity "alert" -message ($I18nStrings.GROUP_FAIL -f $postgresAcctName,$groupName)
                }
            } else {
                Write-SASUserMessage -severity "warning" -message ($I18nStrings.GROUP_SKIP -f $postgresAcctName,$groupName)
            }
        } else {
            Write-SASUserMessage -severity "info" -message ($I18nStrings.GROUP_OK -f $postgresAcctName,$groupName)
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
                    Write-SASUserMessage -severity "alert" -message ($I18nStrings.RIGHT_SUC -f $postgresAcctName,"seServiceLogonRight")
                } else {
                    Write-SASUserMessage -severity "error" -message ($I18nStrings.RIGHT_FAIL -f $postgresAcctName,"seServiceLogonRight")
                }
            } else {
                Write-SASUserMessage -severity "warning" -message ($I18nStrings.RIGHT_SKIP -f $postgresAcctName,"Log on as a Service")
            }
        } else {
            Write-SASUserMessage -severity "info" -message ($I18nStrings.RIGHT_OK -f $postgresAcctName,"Log on as a Service")
        }
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
        $script:cmdFileContent = @"
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

# Edit the following variables to ensure that accounts are created in the proper location within your Active Directory structure

`$svcAcctOUName = "OU=serviceAccounts,$compLDAPRoot"
`$compFQDN = "$compFQDN"
`$krbRealm = "$script:krb5realm"
`$NetBIOSDomain = "$script:NetBIOSDomain"
# Edit the following variables to set the service account name if the suggestions do not meet your standards
`$svcAcctPrefix = "$svcAcctPrefix"
`$svcAcctSuffix = "$svcAcctSuffix"
`$myHostName = "$myHostName"

# if the following variables are not defined then the accounts created will be created according to the pattern `$svcAcctPrefix + `$myHostName + "-<SVC>" + `$svcAcctSuffix
# for the host where SAS will be deployed.  For example if the host is mycoviya with the default value for `$svcAcctPrefix and empty `$svcAccount Suffix the account name for
# the HTTP account would be svc-sas-mycoviya-HTTP.  If you wish to specify account names which match your organization's standards simply uncomment and define the
# account names below
#`$HTTPsvcAcctName = ""
#`$CASsvcAcctName = ""

# The following two fields govern how passwords are generated for accounts created by this script.  You may change the values
# to better reflect your security requirements.  Valid Values are between 1 and 128
# See https://msdn.microsoft.com/en-us/library/system.web.security.membership.generatepassword(v=vs.110).aspx for more info
`$pwLength = $($PwLength.ToString())
`$pwNumSpecialChars = $($PwNumSpecialChars.ToString())

# If these variables are not defined then random passwords will be generated below based upon the length and number of special chars specified above.
# The assumption is that values entered below are clear-text passwords.  Secure strings will be generated below.
#`$CASPassword=""
#`$HTTPPassword=""

`$READMEtxt = @()
# You may send notes to the Viya Admin by editing and adding lines following pattern here:
# `$READMEtxt += "Notes from your domain admin:"
# `$READMEtxt += "  --  None  -- "

# ------------------ Make no changes below this line!! ------------------
# ------------------ Make no changes below this line!! ------------------
# ------------------ Make no changes below this line!! ------------------
# ------------------ Make no changes below this line!! ------------------

# Make no changes below this line!!


`$casSPN = "sascas/$compFQDN"
`$httpSPN = "HTTP/$compFQDN"


`$READMEtxt += "Actions Completed by domain admin helper script:"

`$script:ctPass=""

# ------------------ Begin Function Declarations ------------------
function Write-SASUserMessage {
    param(
        [Parameter(Mandatory=`$true,
                    Position=0)]
        [string]`$severity,
        [Parameter(Mandatory=`$true,
                    Position=1)]
        [string]`$message,
        [switch]`$noLabel
    )
    # Uses severities of Info, Alert, Warning, and Error to format output
    `$fieldSep = `$message.IndexOf(" -f ")
    if (`$fieldSep -gt 0) {
        `$s = `$message.Substring(0,`$fieldSep)
        `$f = `$message.Substring(`$fieldSep, (`$message.Length - `$fieldSep))
        `$msg = `$s + `$f
    } else {
        `$msg = '"' + `$message + '"'
    }

    switch (`$severity.ToUpper()) {
        "INFO" {
            if(-not `$noLabel) { Write-Host -noNewLine "${I18nStrings.INFO_LABEL}" -ForegroundColor Green }
            `$cmd = "Write-Host(@'``n" + `$msg + "``n'@) -ForegroundColor Green"
            Invoke-Expression `$cmd
            Break
        }
        "ALERT" {
            if(-not `$noLabel) { Write-Host -noNewLine "${I18nStrings.ALERT_LABEL}" -ForegroundColor Yellow }
            `$cmd = "Write-Host(@'``n" + `$msg + "``n'@) -ForegroundColor Yellow"
            Invoke-Expression `$cmd
            Break
        }
        "WARNING" {
            `$cmd = "Write-Warning(@'``n' + `$msg + '``n'@)"
            Invoke-Expression `$cmd
            Break
        }
        "DEBUG" {
            `$cmd = "Write-Debug(@'``n" + `$msg + "``n'@)"
            Invoke-Expression `$cmd
            Break
        }
        "ERROR" {
            if(-not `$noLabel) { Write-Host -noNewLine "${I18nStrings.ERROR_LABEL}" -ForegroundColor Red }
            `$cmd = "Write-Host(@'``n" + `$msg + "``n'@) -ForegroundColor Red"
            Invoke-Expression `$cmd
            Break
        }
        default {
            Write-Host ("$(${I18nStrings.ERROR_LABEL}+${I18nStrings.USERMESSAGE_DEFAULT})" -f `$severity,`$message)' -ForegroundColor Red
        }
    }
}

$commonFunctions
# ------------------  End Function Declarations  ------------------

"@
    }

    # Validate this computer is trusted for delegation
    if ($compTrustedForDelegation -eq $True) {
        Write-SASUserMessage -severity "info" -message  ($I18nStrings.AD_HOST_TRUST_OK -f $myHostName)
    } else {
        if ($createADEntities) {
            $cmd = "Set-ADcomputer -Identity $myHostName -TrustedForDelegation " + '$true'
            if ($cmdFileOnly) {
                # Append content to command file
                $script:cmdFileContent = $script:cmdFileContent + "# The AD Computer account for $myHostName is not trusted for delegation`n# SAS Viya requires that the computer account be trusted for delegaation.`n"
                $script:cmdFileContent = $script:cmdFileContent + $cmd + " `n"
                $script:cmdFileContent = $script:cmdFileContent + 'if($?) {' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + '    $msg = "'+$I18nStrings.AD_HOST_TRUST_SUC+'" ' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + '    $READMEtxt += $msg' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + '    Write-SASUserMessage -severity "info" -message $msg' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + '} else {' + "`n"
                $script:cmdFileContent = $script:cmdFileContent + '    $msg = "'+$I18nStrings.AD_HOST_TRUST_FAIL+'"' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + '    $READMEtxt += $msg' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + '    Write-SASUserMessage -severity "error" -message $msg' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + '}' + " `n"
                $script:cmdFileContent = $script:cmdFileContent + "`n`n"
            } elseif ($runningWithDomainAdminPrivs) {
                # Execute the change
                Invoke-Expression $cmd
                if ($?) {
                    Write-SASUserMessage -severity "info" -message $I18nStrings.AD_HOST_TRUST_SUC
                } else {
                    Write-SASUserMessage -severity "error" -message $I18nStrings.AD_HOST_TRUST_FAIL
                }
            } else {
                Write-SASUserMessage -severity "warning" -message ($I18nStrings.AD_HOST_TRUST_SKIP -f $myHostName)
            }
        } else {
            Write-SASUserMessage -severity "warning" -message  ($I18nStrings.AD_HOST_TRUST_SKIP -f $myHostName)
        }
    }

    # Does the sascas/FQDN SPN exist in AD?
    $CASdomainUserName = ""
    $CASsamName=""
    $results = Get-ADUser -properties ServicePrincipalNames,DistinguishedName,TrustedForDelegation,ObjectCategory -Filter {ServicePrincipalName -like '*'} | where-object { $PSItem.ServicePrincipalNames -contains $casSPN}
    # if we didn't find the SPN in Active Directory
    if ($results -eq $null) {
        if ($createADentities) {
            # If the CAS service account exists already use it:
            $errorActionPreference = "SilentlyContinue"
            $casAcct = $null
            $casAcct = Get-ADUser -Filter ('Name -like "*{0}*"' -f $CASsvcAcctName)
            $errorActionPreference = "Continue"
            if ($casAcct -eq $null) {
                # Account doesn't exist so create it
                # see https://msdn.microsoft.com/en-us/library/system.web.security.membership.generatepassword.aspx for more details
                $cmdList = @()
                $cmdList += '$CASssPass = Set-SecurePassword -inputPass $CASPassword'
                $cmdList += 'if (!$CASPassword) {'
                $cmdList += '    $CASPassword = $ctPass'
                $cmdList += '}'
                $cmdList += 'if ($CASsvcAcctName -eq $null) { $CASsvcAcctName = $svcAcctPrefix + $myHostName + "-CAS" + $svcAcctSuffix }'
                $cmdList += '$CASsamName = FindFreeSamAccountName $CASsvcAcctName'
                $cmdList += ''
                $cmdList += '$casAcctCreateSuccess = $false'
                $cmdList += ''
                $cmdList += '$script:targetOUExists = $false'
                $cmdList += 'try {'
                $cmdList += '    $doesOUExist = Get-ADOrganizationalUnit -Identity "$svcAcctOUName"'
                $cmdList += '    $script:targetOUExists = $true'
                $cmdList += '} catch {'
                $cmdList += "    Write-SASUserMessage -severity `"warning`" -message (`"$($I18nStrings.AD_NO_CONTAINER)`" -f `$svcAcctOUName)"
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
                $cmdList += "    `$msg = `"$($I18nStrings.ACCT_SUC)`" -f `"CAS`",`$CASdomainUserName,`$CASPassword"
                $cmdList += '    $READMEtxt += $msg'
                $cmdList += '    Write-SASUserMessage -severity "info" -message $msg'
                $cmdList += '} else {'
                $cmdList += "    `$msg = `"$($I18nStrings.ACCT_FAIL)`" -f `"CAS`""
                $cmdList += '    $READMEtxt += $msg'
                $cmdList += '    Write-SASUserMessage -severity "error" -message $msg'
                $cmdList += '}'
                $cmdBlock = $cmdList -join "`n"
                if ($cmdFileOnly) {
                    # Append content to command file
                    if ($CASPassword) { # If the User gave us a password, ensure the data gets passed on to the Admin script.
                        $script:cmdFileContent=$script:cmdFileContent -replace '#\$CASPassword=""',('$CASPassword="{0}"' -f $CASPassword)
                    }
                    $script:cmdFileContent = $script:cmdFileContent + "# The AD service account $CASsvcAcctName does not exist`n# SAS Viya requires that the service account exist and be properly configured.`n"
                    $script:cmdFileContent = $script:cmdFileContent + $cmdBlock + "`n"
                } elseif ($runningWithDomainAdminPrivs) {
                    # Execute the change
                    Write-SASUserMessage -severity "debug" -message ($I18nStrings.INVOKING_COMMAND -f $cmdBlock)
                    Invoke-Expression $cmdBlock
                }
            } else {
                #Account exists but does not have required SPN
                #$cmd = "`$adu = Get-ADUser -Filter 'Name -eq `"$CASsvcAcctName`"' -SearchBase '$svcAcctOUName' -Properties ServicePrincipalName `n"
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
            Write-SASUserMessage -severity "warning" -message ($I18nStrings.AD_SPN_SKIP -f "sascas",$compFQDN)
        }
    } elseif (($results.GetType()).Name -eq "ADUser") {
        # This is where finding 1 logic starts...
        Write-SASUserMessage -severity "info" -message ($I18nStrings.AD_SPN -f "sascas",$compFqdn)
        # Get the NetBIOSName for the domain the user is in:
        $UserNetBIOSDomain = (Get-ADDomain (($results.distinguishedName.split(",") | ? {$_ -like "DC=*"}) -join ",")).NetBIOSName
        Write-SASUserMessage -severity "info" -message ($I18nStrings.AD_SPN_NAME -f $UserNetBIOSDomain, $results.sAMAccountName.ToString(),"sascas")
        $CASdomainUserName = $UserNetBIOSDomain+"\"+$results.sAMAccountName.ToString()

        if ($valSAS) {
            #Is the account the same as the account entered in the casUser.xml file?
            if((-not($CASdomainUserName -eq $null)) -and (-not($script:casCred -eq $null))) {
                if ($CASdomainUserName -ne $script:casCred.UserName.ToString()) {
                    #check if we are using the netbios domain and casUser.xml is using the KRB domain / forest name and do they match
                    $fieldSep = $script:casCred.UserName.ToString().IndexOf("\")
                    if ($fieldSep -gt 0) {
                        $casCredDomain  = $script:casCred.UserName.ToString().Substring(0,$fieldSep)
                        $casCredAccount = $script:casCred.UserName.ToString().Substring(($fieldSep + 1), ($script:casCred.UserName.ToString().Length - ($fieldSep +1)))
                        $ccu = get-aduser -Filter ('Name -like "*{0}*"' -f $casCredAccount)
                        $ccuDomain = ($ccu.distinguishedName.split(",") | ? {$_ -like "DC=*"}) -join ","
                        $resDomain = ($results.distinguishedName.split(",") | ? {$_ -like "DC=*"}) -join ","
                        if(($casCredAccount -eq $results.sAMAccountName.ToString()) -and ($resDomain -eq $ccuDomain)) {
                            Write-SASUserMessage -severity "info" -message $I18nStrings.AD_CAS_SPN_OK
                        } else {
                            Write-SASUserMessage -severity "warning" -message ($I18nStrings.AD_CAS_SPN_FAIL -f $compFQDN)
                        }
                    } else {
                        Write-SASUserMessage -severity "warning" -message ($I18nStrings.AD_CAS_SPN_FAIL -f $compFQDN)
                    }
                } else {
                    Write-SASUserMessage -severity "info" -message $I18nStrings.AD_CAS_SPN_OK
                }
            }
        }

        #Is this account trusted for delegation?
        $acct = $results.name.ToString()
        if ([System.Convert]::ToBoolean($results.TrustedForDelegation)) {
            Write-SASUserMessage -severity "info" -message ($I18nStrings.AD_CAS_ACCT_TRUST_OK -f $CASdomainUserName)
        } else {
            if ($remediate) {
                $cmd = "Set-ADuser -Identity $acct -TrustedForDelegation " + '$true'
                if ($cmdFileOnly) {
                    # Append content to command file
                    $script:cmdFileContent = $script:cmdFileContent + "# The SAS Viya service account ($CASdomainUserName) is not trusted for delegation`n# SAS Viya requires that the service account be trusted for delegaation.`n"
                    $script:cmdFileContent = $script:cmdFileContent + $cmd + "`n`n"
                } elseif ($runningWithDomainAdminPrivs) {
                    # Execute the change
                    Invoke-Expression $cmd
                }
            } else {
                Write-SASUserMessage -severity "warning" -message ($I18nStrings.AD_CAS_ACCT_TRUST_SKIP -f $CASdomainUserName)
            }
        }

        $acctRights = Get-UserRightsGrantedToAccount -Account $CASdomainUserName

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
                Grant-UserRight -Account $CASdomainUserName -Right SeAssignPrimaryTokenPrivilege
                if($?) {
                    Write-SASUserMessage -severity "alert" -message ($I18nStrings.RIGHT_SUC -f $CASdomainUserName,"SeAssignPrimaryTokenPrivilege")
                } else {
                    Write-SASUserMessage -severity "error" -message ($I18nStrings.RIGHT_FAIL -f $CASdomainUserName,"SeAssignPrimaryTokenPrivilege")
                }
            } else {
                Write-SASUserMessage -severity "warning" -message ($I18nStrings.RIGHT_SKIP -f $acct,"Replace Process Level Token")
            }
        } else {
            Write-SASUserMessage -severity "info" -message ($I18nStrings.RIGHT_OK -f $acct,"Replace Process Level Token")
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
                Grant-UserRight -Account $CASdomainUserName -Right seServiceLogonRight
                if($?) {
                    Write-SASUserMessage -severity "alert" -message ($I18nStrings.RIGHT_SUC -f $CASdomainUserName,"seServiceLogonRight")
                } else {
                    Write-SASUserMessage -severity "error" -message ($I18nStrings.RIGHT_FAIL -f $CASdomainUserName,"seServiceLogonRight")
                }
            } else {
                Write-SASUserMessage -severity "warning" -message ($I18nStrings.RIGHT_SKIP -f $acct,"Log on as a Service")
            }
        } else {
            Write-SASUserMessage -severity "info" -message ($I18nStrings.RIGHT_OK -f $acct,"Log on as a Service")
        }
        # get localized name for local "Administrators" group from wll-known SID.
        $groupName=(Get-LocalGroup -SID "S-1-5-32-544").Name

        # Is this account a member of local Administrators group
        $errorActionPreference = "SilentlyContinue"
        $oldErrors=$error.Clone();
        $error.Clear()
        $isLocalAdmin = Get-LocalGroupMember -Member $CASdomainUserName -Group $groupName
        $findError = $null
        if ($error[0] -ne $null) {
            # PrincipalNotFound is thrown when the user is not present. so that is not an "error"
            if ($error[0].FullyQualifiedErrorId -notmatch "PrincipalNotFound,Microsoft.PowerShell.Commands.GetLocalGroupMemberCommand") {
                $FindError = $error[0]
            }
            $error.Clear()
        }
        if ($isLocalAdmin -eq $null) {
            if($remediate) {
                Add-LocalGroupMember -Group $groupName -Member $CASdomainUserName
                $rc=$?
                if ($error[0].FullyQualifiedErrorId -eq "MemberExists,Microsoft.PowerShell.Commands.AddLocalGroupMemberCommand") {
                    Write-SASUserMessage -severity "info" -message ($I18nStrings.GROUP_OK -f $CASdomainUserName,$groupName)
                } elseif($rc) {
                    Write-SASUserMessage -severity "alert" -message ($I18nStrings.GROUP_SUC -f $CASdomainUserName,$groupName)
                } else {
                    Write-SASUserMessage -severity "error" -message ($I18nStrings.GROUP_FAIL -f $CASdomainUserName,$groupName)
                }
                $error.Clear()
            } elseif(!$findError) {
                Write-SASUserMessage -severity "warning" -message ($I18nStrings.GROUP_SKIP -f $CASdomainUserName,$groupName)
            } else {
                Write-SASUserMessage -severity "warning" -message (($I18nStrings.GROUP_SEARCH_FAIL -f $CASdomainUserName,$groupName)+ "`nGet-LocalGroupMember : $findError")
            }
        } else {
            Write-SASUserMessage -severity "info" -message ($I18nStrings.GROUP_OK -f $CASdomainUserName,$groupName)
        }
        $errorActionPreference = "Continue"
        $null = $oldErrors | %{$error.Add($_)}

    } else {
        # if results was not null and it was not of type ADUser then we must have found more than 1 result
        Write-SASUserMessage -severity "error" -message ($I18nStrings.AD_SPN_MANY -f "sascas",$compFQDN)
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
            $script:HTTPUser = Get-ADUser -Filter ('Name -like "*{0}*"' -f $HTTPsvcAcctName)
            $errorActionPreference = "Continue"
            if ($script:HTTPUser -eq $null) {
                # Account doesn't exist so create it
                # see https://msdn.microsoft.com/en-us/library/system.web.security.membership.generatepassword.aspx for more details
                $cmdList = @()
                $cmdList += '$HTTPssPass = Set-SecurePassword -inputPass $HTTPPassword'
                $cmdList += 'if (!$HTTPPassword) {'
                $cmdList += '    $HTTPPassword=$ctPass'
                $cmdList += '}'
                $cmdList += 'if (!$HTTPsvcAcctName) { $HTTPsvcAcctName = ' + $HTTPsvcAcctName + ' }'
                $cmdList += '$httpUPN = $HTTPsvcAcctName + "@" + $KRB5REALM'
                $cmdList += '$HTTPsamName = FindFreeSamAccountName $HTTPsvcAcctName'

                $cmdList += '$script:targetOUExists = $false'
                $cmdList += 'try {'
                $cmdList += '    $doesOUExist = Get-ADOrganizationalUnit -Identity "$svcAcctOUName"'
                $cmdList += '    $script:targetOUExists = $true'
                $cmdList += '} catch {'
                $cmdList += '    Write-SASUserMessage -severity "warning" -message ("' + $I18nStrings.AD_NO_CONTAINER + '" -f $svcAcctOUName)'
                $cmdList += '}'
                $cmdList += '$httpAcctCreateSuccess = $false'

                $cmdList += 'if ($script:targetOUExists) {'
                $cmdList += '    try {'
                $cmdList += '        $script:HTTPUser = New-ADUser -UserPrincipalName $httpUPN -SamAccountName $HTTPsamName -DisplayName $HTTPSvcAcctName -Name $HTTPsvcAcctName -AccountPassword $HTTPssPass -OtherAttributes @{ServicePrincipalName = "$httpSPN"} -TrustedForDelegation $true -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true -Path $svcAcctOUName'
                $cmdList += '        $httpAcctCreateSuccess = $true'
                $cmdList += '    } catch {'
                $cmdList += '        $e=$error[0]'
                $cmdList += '        Write-SASUserMessage -severity "error" -message "Exception Message: $($e.toString())" '
                $cmdList += '    }'
                $cmdList += '} else {'
                $cmdList += '    try {'
                $cmdList += '        $script:HTTPUser = New-ADUser -UserPrincipalName $httpUPN -SamAccountName $HTTPsamName -DisplayName $HTTPSvcAcctName -Name $HTTPsvcAcctName -AccountPassword $HTTPssPass -OtherAttributes @{ServicePrincipalName = "$httpSPN"} -TrustedForDelegation $true -PasswordNeverExpires $true -CannotChangePassword $true -Enabled $true'
                $cmdList += '        $httpAcctCreateSuccess = $true'
                $cmdList += '    } catch {'
                $cmdList += '        $e=$error[0]'
                $cmdList += '        Write-SASUserMessage -severity "error" -message "Exception Message: $($e.toString())" '
                $cmdList += '    }'
                $cmdList += '}'

                $cmdList += 'if($httpAcctCreateSuccess) {'
                $cmdList += '    $HTTPdomainUserName = "$NetBIOSDomain\$HTTPsamName"'
                $cmdList += '    $msg = "' + $I18nStrings.ACCT_SUC + '" -f "HTTP",$HTTPDomainUserName,$HTTPPassword'
                $cmdList += '    $READMEtxt += $msg'
                $cmdList += '    Write-SASUserMessage -severity "info" -message $msg'
                $cmdList += '    Write-SASUserMessage -severity "info" -message "sleeping for 5 seconds to allow replication." '
                $cmdList += '    Start-Sleep -s 5'
                $cmdList += '    $script:HTTPUser = get-aduser -identity $HTTPsamName'
                $cmdList += '} else {'
                $cmdList += '    $msg = "' + $I18nStrings.ACCT_FAIL + '" -f "HTTP"'
                $cmdList += '    $READMEtxt += $msg'
                $cmdList += '    Write-SASUserMessage -severity "error" -message $msg'
                $cmdList += '}'
                $cmdBlock = $cmdList -join "`n"
    
                if ($cmdFileOnly) {
                    if ($HTTPPassword) { # If the User gave us a password, ensure the data gets passed on to the Admin script.
                        $script:cmdFileContent=$script:cmdFileContent -replace '#\$HTTPPassword=""',('$HTTPPassword="{0}"' -f $HTTPPassword)
                    }
                    $script:cmdFileContent = $script:cmdFileContent + "# The AD service account $HTTPsvcAcctName does not exist`n# SAS Viya requires that the service account exist and be properly configured.`n"
                    $script:cmdFileContent = $script:cmdFileContent + $cmdBlock + "`n"
                } elseif ($runningWithDomainAdminPrivs) {
                    # Execute the change
                    Write-Debug ($I18nStrings.INVOKING_COMMAND -f $cmdBlock)
                    Invoke-Expression $cmdBlock
                    $UserNetBIOSDomain = (Get-ADDomain (($script:HTTPUser.distinguishedName.split(",") | ? {$_ -like "DC=*"}) -join ",")).NetBIOSName
                    if (!$HTTPsamName) {$HTTPsamName=$script:HTTPUser.sAMAccountName.ToString()}
                    $HTTPdomainUserName = $UserNetBIOSDomain+"\"+$HTTPsamName
                }
            } else {
                #Account exists but does not have required SPN
                $cmd = "Set-ADUser -Identity " + $svcAcctName + " -Add @{ServicePrincipalName = '" + $httpSPN + "'} -TrustedForDelegation `$true }"
                $UserNetBIOSDomain = (Get-ADDomain (($script:HTTPUser.distinguishedName.split(",") | ? {$_ -like "DC=*"}) -join ",")).NetBIOSName
                $HTTPsamName=$HTTPUser.sAmAccountName.ToString()
                $HTTPdomainUserName = $UserNetBIOSDomain+"\"+$HTTPsamName
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
            Write-SASUserMessage -severity "warning" -message ($I18nStrings.AD_SPN_SKIP -f "HTTP",$compFQDN)
            if($createKeyTab) {
                $createKeyTab = $false
                Write-SASUserMessage -severity "warning" -message $I18nStrings.AD_HTTP_KT_SKIP
            }
        }


    } elseif (($results.GetType()).Name -eq "ADUser") {
        # if we found 1 and only 1 account with this SPN
        Write-SASUserMessage -severity "info" -message ($I18nStrings.AD_SPN -f "HTTP",$compFQDN)
        Write-SASUserMessage -severity "info" -message ($I18nStrings.AD_SPN_NAME -f $UserNetBIOSDomain, $results.sAMAccountName.ToString(),"HTTP")
        $HTTPsamName = $results.sAMAccountName.ToString()
        $acct = $results.Name.ToString()
        $HTTPdomainUserName = $UserNetBIOSDomain+"\"+$results.sAMAccountName.ToString()

    } else {
        Write-SASUserMessage -severity "error" -message $I18nStrings.AD_SPN_MANY -f "HTTP",$compFQDN
        foreach($result in $results)
        {
            Write-host "Object Name = " $result.name -BackgroundColor Yellow -ForegroundColor Black
            Write-host "DN      =      "  $result.distinguishedName
            Write-host "Object Cat. = "  $result.objectCategory
        }
        if($createKeyTab) {
            $createKeyTab = $false
            Write-SASUserMessage -severity "warning" -message $I18nStrings.AD_HTTP_KT_SKIP_MANY
        }
    }

    if ($createKeyTab) {
        $ktcmdOut = ""
        $cmdList = @()
        $cmdList += 'if ( -not $keyTabPath ) { $keyTabPath = "http-' + $myHostName + '.keytab" }'
        $cmdList += '# If creating a keytab alone we need to pass in the existing HTTPdomainUserName thus next few lines'
        $cmdList += 'if(-not $HTTPdomainUserName) { $HTTPdomainUserName = "' + $HTTPdomainUserName + '" }'
        $cmdList += 'if (-not $HTTPPassword) { $HTTPPassword = "' + $HTTPPassword + '" }'
        $cmdList += 'if(-not $HTTPPassword) {'
        $cmdList += '    $ktcmd = "ktpass /out " + $keyTabPath + " /mapuser " + $HTTPdomainUserName + " /princ " + $httpSPN + "@" + $krbRealm + " /crypto all +rndpass /ptype KRB5_NT_PRINCIPAL /kvno 0 /mapop add "'
        $cmdList += '} else {'
        $cmdList += '    $ktcmd = "ktpass /out " + $keyTabPath + " /mapuser " + $HTTPdomainUserName + " /princ " + $httpSPN + "@" + $krbRealm + " /crypto all /pass """ + $HTTPPassword + """ /ptype KRB5_NT_PRINCIPAL /kvno 0 /mapop add +setpass +setupn "'
        $cmdList += '}'
        $cmdList += 'try {'
        $cmdList += '    $ktcmdOut = cmd /c "$ktcmd 1>&2" 2>&1 | %{ "$_" }'
        $cmdList += '    if($LASTEXITCODE -eq 0) {'
        $cmdList += '        $msg = "' + $I18nStrings.AD_HTTP_KT_SUC + '" -f $keyTabPath'
        $cmdList += '        if ($VerbosePreference -eq [System.Management.Automation.ActionPreference]::Continue) {'
        $cmdList += '            $ktcmdOut -join "`n"'
        $cmdList += '        }'
        $cmdList += '        $READMEtxt += $msg' + " `n"
        $cmdList += '        Write-SASUserMessage -severity "alert" -message $msg'
        $cmdList += '    } else {'
        $cmdList += '        $msg = "' + $I18nStrings.AD_HTTP_KT_FAIL1 + '" -f $ktcmd'
        $cmdList += '        foreach($l in $ktcmdOut) {'
        $cmdList += '            $msg += "`n      $l"'
        $cmdList += '        }'
        $cmdList += '        $READMEtxt += $msg' + " `n"
        $cmdList += '        Write-SASUserMessage -severity "error" -message ("' + $I18nStrings.AD_HTTP_KT_FAIL2 + '" -f $msg)'
        $cmdList += '    }'
        $cmdList += '} catch {'
        $cmdList += '    $e=$error[0]'
        $cmdList += '    Write-SASUserMessage -severity "error" -message "ktpass command is: $ktcmd" '
        $cmdList += '    Write-SASUserMessage -severity "error" -message "Exception Message: $($e.toString())" '
        $cmdList += '}'
        $cmdBlock = $cmdList -join "`n"

        if ($cmdFileOnly) {
            if ($HTTPPassword) { # If the User gave us a password, ensure the data gets passed on to the Admin script.
                $script:cmdFileContent=$script:cmdFileContent -replace '#\$HTTPPassword=""',('$HTTPPassword="{0}"' -f $HTTPPassword)
            }
            # Append content to command file
            $script:cmdFileContent = $script:cmdFileContent + "# Generate a keytab for the HTTP/ SPN.  +rndpass is used.`n# SAS Viya requires that the HTTP SPN have a properly configured keytab.`n# Provide this keytab to the SAS Viya Administrator.`n"
            $script:cmdFileContent = $script:cmdFileContent + $cmdBlock + "`n"
        } elseif ($runningWithDomainAdminPrivs) {
            # Execute the change
            Write-SASUserMessage -severity "debug" -message  ($I18nStrings.INVOKING_COMMAND -f $cmdBlock)
            try {
                Invoke-Expression $cmdBlock
            } catch {
                Write-SASUserMessage -severity "warning" -message ($I18nStrings.AD_HTTP_KT_ERRMSG -f $_)
            }
        }
    }
}
# ------------------  End Function Declarations  ------------------

# ------------------ Begin Main Logic ------------------

Write-Host ""
Write-SASUserMessage -severity "Info" -message ($I18nStrings.VERSION -f $myVersionNumber)
Write-SASUserMessage -severity "Info" -message ($I18nStrings.HOST -f $env:computername)

if ($CheckRemoteVersion) {
    $remoteScriptVer = ((Invoke-WebRequest -Uri "$remoteVerCheckURL").Content.split([Environment]::NewLine) | Select-String 'myVersionNumber =')[0].ToString().Split('=')[1].Replace('"','').Replace(' ','')
    if ($remoteScriptVer -gt $myVersionNumber) {
        Write-SASUserMessage -severity "alert" -message ($I18nStrings.NEWER -f $remoteVerDownloadURL,$remoteScriptVer)
    } else {
        Write-SASUserMessage -severity "info" -message $I18nStrings.NEWEST
    }
}

Validate-Java
Validate-ExecutionEnvironment
Get-AdminToolInstallStatus
Validate-dotNETVersion
Validate-cppRuntimePreReqs
Validate-WSearch
Set-wvdaVariables
Check-CredentialsGuard

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

$READMElines = $READMEtxt -join "`n"
$READMElines > ViyaAdminREADME.txt

Compress-Archive -Path ViyaAdminREADME.txt, $keyTabPath -DestinationPath ViyaAdminInfo.zip -Force

rm ViyaAdminREADME.txt
rm $keyTabPath

Write-SASUserMessage -severity "alert" -message "{0}"
'@ -f $I18nStrings.ADMIN_INSTRUCTIONS
    $script:cmdFileContent > $cmdFilePath
    Write-SASUserMessage -severity "alert" -noLabel -message ($I18nStrings.ACTION_REQUIRED -f $cmdFilePath)
}

if($script:restartRequired) {
    Write-SASUserMessage -severity "alert" -message $I18nStrings.RESTART_REQUIRED
}
