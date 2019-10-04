ConvertFrom-StringData @"
Y = Y
N = N
BAD_VALIDATION_OPTION = The requested validation operation ({0}) is not recognized.  Valid values are\n       all, sas, certs, tuning, keytab, adconfig, postgres, host
INFO_LABEL = INFO: 
ALERT_LABEL = NOTE: 
ERROR_LABEL = ERROR: 
USERMESSAGE_DEFAULT = ERROR: call to Write-SASUserMessage with invalid severity!\nSeverity: {0} Message Text:\n{1}

ADMIN_FEATURES_PRESENT = Required Administrative features are installed
ADMIN_FEATURES_MISSING = Required Administrative features are not installed!\nThis script must be executed as an Administrator!\nInstall server features RSAT-AD-Powershell and RSAT-AD-AdminCenter and run this tool as an administrator!
ADMIN_FEATURES_REMEDIA_YN = Required Administrative features are not installed.  Install RSAT-AD-Powershell and RSAT-AD-AdminCenter? {0}/{1}
ADMIN_FEATURES_REMEDIA_R = Required Administrative features will not be installed.  Errors will occur.

SET_WVDA_VARIABLES_RETRY = Failed to obtain Active Directory data due to\n      {0}.\n      Will attempt up to 5 times...
SET_WVDA_VARIABLES_QUERY_SUC = Active Directory query returned successfully.
SET_WVDA_VARIABLES_QUERY_FAIL = Mutiple attempts to query Active Directory have failed.  Can not continue.  Contact your Active Directory administrator for assistance.
KRB5_REALM = KRB5 Realm: {0}

JAVA_INSTALL_OK = JAVA_HOME ({0}) points to an installation of Java 8: OK
JAVA_64_OK = 64-bit version of Java 8 found in JAVA_HOME: OK
JAVA_64_BAD = The version of java pointed to by JAVA_HOME ({0}) is not 64-bit.  SAS Viya requires 64-bit Java 8.
JAVA_INSTALL_BAD = JAVA_HOME ({0}) does not point to an installation of Java 8.  Found {1}
JAVA_NO_EXE = The path contained in JAVA_HOME ({0}) is valid but does not contain JAVA_HOME\\bin\\java.exe!
JAVA_PATH_BAD = The path defined in JAVA_HOME ({0}) does not exist!
JAVA_NO_HOME = JAVA_HOME is not set!

CG_NOT_PRESENT = Windows Defender Credential Guard not available on this system.
CG_CHANGED_OK = Windows Defender Credential Guard status changed to not configured
CG_CHANGED_FAIL = Windows Defender Credential Guard failed to change configuration settings. Please ensure there are no Group Policy rules enabling this feature on this system.
CG_CONFIGURED = Windows Defender Credential Guard configured
CG_RUNNING = Windows Defender Credential Guard running - This must be disabled for Viya3.4 and prior to work.
CG_NOT_RUNNING = Windows Defender Credential Guard is not running
CG_NOT_CONFIGURED = Windows Defender Credential Guard is not configured
COMPUTER_ATTRIBUTES = Computer Attributes: 
DOMAIN_ATTRIBUTES = Domain Attributes:

DOTNET_BAD_VERSION =  SAS Viya requires that the version of .NET Framework installed be 4.6 or later (Release {0}).\n         The current Release number is {1}.  The installer for .NET Framework 4.6 can be obtained from\n         {2}.
DOTNET_GOOD_VERSION = The version of the .NET Framework is 4.6 or higher

PUBLIC_CERT_UPDATE_OK = SAS Public Cert update: OK\n      {0} output:
PUBLIC_CERT_UPDATE_FAILED = SAS Public Cert update: FAILED\n      {0} output:
PUBLIC_CERT_NOT_INSTALLED = SAS Public Certs are not installed!
PUBLIC_CERT_INSTALLED = SAS public code signing certs are installed: OK

VC_RUNTIME_INSTALLED = {0} is installed: OK
VC_RUNTIME_NEED_2013 = The 64-bit Microsoft Visual C++ 2013 Redistributable Package must be installed on this host prior to installing SAS Viya.\n         Download and execute the appropriate vcredist_x64.exe from\n         https://support.microsoft.com/en-us/help/3179560/update-for-visual-c-2013-and-visual-c-redistributable-package.
VC_RUNTIME_NEED_2015 = The 64-bit Microsoft Visual C++ 2015 Redistributable Package must be installed on this host prior to installing SAS Viya.\n         Download and execute vc_redist.x64.exe\n         from https://www.microsoft.com/en-us/download/details.aspx?id = 48145\n         Installing the 64-bit Microsoft Visual C++ 2017 Redistributable Package will also satisfy this requirement.\n         The 2017 package can be obtained from https://support.microsoft.com/en-us/help/2977003/the-latest-supported-visual-c-downloads

OK_64BIT = Running in a 64-bit environment: OK
NEED_64BIT = SAS Viya is only supported on 64-bit platforms.  To install SAS Viya you must use a 64-bit command session

PS_VER_OK = Running PowerShell 5.1 or higher: OK
PS_VER_BAD = PowerShell 5.1 or greater is required to run SAS Viya 3.4.\nUpdate can be obtained from https://www.microsoft.com/en-us/download/details.aspx?id = 54616.

MUST_BE_DOMAIN = You must be logged in with domain credentials to execute this script.  You are currently running under local machine credentials!
CURRENTLY_DOMAIN_ADMIN = Currently running as a Domain Admin...
NOT_DA_CREATE_SCRIPT = The current account is not a Domain Admin yet -createADEntities has been specified.\n         Will not attempt to modify domain entities.  A script will be created instead.
NOT_DA_NO_CREATE_KT = -createADEntities has been specified while setting cmdFileOnly yet -createKeytab is not specified\n         Setting -createKeyTab option to ensure a keytab is generated and provided.

NEED_SERVER = Running on a Windows Workstation.  SAS Viya 3.4 for Windows must run on a server.
GOOD_SERVER = Running on Windows Server: OK
SERVER_DOMAIN_OK = Server is part of a domain: OK
SERVER_DOMAIN_BAD = This server is not part of a domain!  The server must be joined to a domain to host SAS Viya.
WIN_VER_BAD = SAS Viya 3.4 supports Windows Server 2012 R2 and Higher.\n       Running on {0} is not supported!
WIN_VER_OK = Running on {0}: OK

POSTGRES_NO_FILE = Cannot locate postgresUser.xml file in {0}!\n       Use encryptPostgresUser.bat to store credentials!\n       This must be corrected before running the SAS Viya deployment!
POSTGRES_FILE_CONTENT_OK = Validate Postgres User Credentials: OK
POSTGRES_FILE_CONTENT_FAIL = Postgres user Credentials are not valid for logon!\n       This must be corrected before running the SAS Viya deployment!
CAS_NO_FILE = Cannot locate casUser.xml file in {0}!\n       Use encryptCasUser.bat to store credentials!\n       This must be corrected before running the SAS Viya deployment!
CAS_FILE_CONTENT_OK = Validate CAS User Credentials: OK
CAS_FILE_CONTENT_FAIL = CAS user Credentials are not valid for logon!\n       This must be corrected before running the SAS Viya deployment!


KEYTAB_NO_PATH = Keytab Path not specified.  Keytab can not be validated.
KEYTAB_NO_FILE = Keytab not found at {0} - Keytab will not be validated.
KEYTAB_NO_HTTP_SPN = The HTTP SPN could not be found therefore the keytab can not be validated.
KEYTAB_CONTENT = Keytab content:
KEYTAB_HTTP_NO_PRINCIPAL = Could not locate HTTP principal for this host in keytab!
KEYTAB_NO_MATCH = Realm of keytab principal ({0}) does not match expected realm of ({1})!
KEYTAB_WILL_KINIT = Will kinit using principal {0}
KEYTAB_KINIT_OK = {0} using keytab: OK\n      _0_ output:
KEYTAB_KINIT_FAIL = {0} using {1} failed with output:
KEYTAB_VERIFY_FAILED = The HTTP User Principal Name ({0}) does not match the \n         HTTP Service Principal Name ({1}).\n             This means that the keytab can not be successfully validated by this tool.\n             If Integrated Windows Authentication is not successful once your SAS Viya deployment is complete\n             and Kerberos is configured via Environment Manager your keytab may be invalid.
KEYTAB_NO_JAVA = JAVA_HOME environment variable is not set.  Keytab not validated!

WSEARCH_STOP_FAIL = Failed to stop Windows search service. output:\n
WSEARCH_DISABLE_FAIL = Failed to disable Windows search service. output:\n
WSEARCH_STATUS = {2} service is: {0}, and has start type: {1}
WSEARCH_SKIP = Windows search service has been detected as 'Running' or set to start automatically. Please stop this service, and disable automatic startup.

TUNING_HEAPSIZE_YN = The requested value for BatchDesktopHeapSize({0}) < current Value({1})!\n      Force Update to lower value? {2}/{3}
TUNING_HEAPSIZE_SKIP = BatchDesktopHeapSize will not be updated.
TUNING_USER_WORK = SharedSection Tuning does not match requested value!\n         The third parameter of the Windows Subsystem Shared Section triplet must be at least {0}!\n         The current Value is {1}.  To Remediate run script with the -remediate switch or open regedit,\n         find {5} and change\n         SharedSection = {2},{3},{4} to read SharedSection = {2},{3},{0}
TUNING_SHAREDSECTION_OK = Windows subsystem SharedSection tuning(SharedSection = {0},{1},{2}) meets minimum: OK
TUNING_DO_UPDATE = Updating\n {0} \nto:\n {1}
TUNING_DONE_UPDATE = Updated Windows subsystem SharedSection tuning from SharedSection = {0},{1},{2} to SharedSection = {0},{1},{3}
TUNING_SKIP_UPDATE = Windows subsystem SharedSection tuning(SharedSection = {0},{1},{2}) meets minimum: OK
TUNING_VALIDATION_GET_FAIL = could not get value for {0} {1}.
TUNING_VALIDATION_RECOMMEND_SET = {0} value is not set!  SAS recommends this value be set to {1}
TUNING_VALIDATION_RECOMMEND_EQ = {0} is set to {1}.  SAS recommends this value be set to {2}.
TUNING_VALIDATION_RECOMMEND_EQ_OK = {0} is set to {1} : OK
TUNING_VALIDATION_RECOMMEND_GE = {0} is set to {1}.  SAS recommends the value be at least {2}.
TUNING_VALIDATION_RECOMMEND_GE_OK = {0} is set to at least {1}: OK
TUNING_VALIDATION_BAD_OPERATOR = Unsupported operator: {0}
TUNING_VALIDATION_ADD = Adding {0}\\{1} with value: {2}
TUNING_VALIDATION_UPDATE = Updating {0} from: {1} to: {2}
TUNING_PORT_START_BAD = ERROR: TCP ephemeral port range start value ({0}) > 32768!
TUNING_PORT_START_OK = TCP ephemeral port range start value ({0}) 32768 or less: OK
TUNING_PORT_QTY_BAD = ERROR: TCP ephemeral port quantity ({0}) < 32767!
TUNING_PORT_QTY_OK = TCP ephemeral port quantity ({0}) 32767 or greater: OK
INVOKING_COMMAND = Invoking command:\n     {0}
TUNING_PORT_DONE = Updated IPv4 and IPv6 dynamic Port range for tcp and udp.
TUNING_PORT_SKIP = Dynamic Port start range and / or quantity do not meet SAS recommendations!\n         TCP ephemeral port quantity ({0}) < 32767!\n         TCP ephemeral port range start value ({1}) > 32768!

POSTGRES_NAME_LONG = Postgres service account name exceeds 20 chars truncating AccountName to {0}
ACCT_SUC = The {0} Service Account ({1}) was successfully created with password: {2}
ACCT_FAIL = {0} Service Account creation failed!
POSTGRES_ACCT_SKIP = The Postgres service account was not found
POSTGRES_ACCT_FOUND = The postgres service account exists: OK
POSTGRES_MANY_ACCT = Active directory returned multiple responses for the postgres service account."
POSTGRES_NO_ACCT = The postgres service account does not exist!
RIGHT_SUC = Granted {0} the {1} right
RIGHT_FAIL = Attempt to grant {0} the {1} right failed!
RIGHT_SKIP = {0} does not have the {1} right
RIGHT_OK = {0} has {1}: OK
GROUP_SUC = Added {0} to the local `"{1}`" group
GROUP_FAIL = Attempt to add {0} to the local `"{1}`" group failed!
GROUP_SKIP = {0} is not a member of the local `"{1}`" group
GROUP_OK = {0} is a member of the local `"{1}`" group: OK
GROUP_SEARCH_FAIL = Encountered error while searching local `"{1}`" group. Cannot verify {0} is a member. This could be because of an orphaned Security Identifier (SID) in the local {1} group.

AD_HOST_TRUST_OK = Host Account for {0} trusted for delegation: OK
AD_HOST_TRUST_SUC = The server host account was successfully marked TrustedForDelegation.
AD_HOST_TRUST_FAIL = The server host account was Not successfully marked TrustedForDelegation.
AD_HOST_TRUST_SKIP = Host Account for {0} is not trusted for delegation!
AD_NO_CONTAINER = Requested target container {0} does not exist.\nWill use default instead.
AD_SPN_SKIP = SPN {0}/{1} is not defined!
AD_SPN = {0}/{1} is defined: OK
AD_SPN_NAME = {2} SPN Account Name  =  {0}\\{1}
AD_CAS_SPN_OK = Stored CAS Username matches SPN User: OK
AD_CAS_SPN_FAIL = The stored CAS credentials are not for the account that owns the sascas/{0} Service Principal Name
AD_CAS_ACCT_TRUST_OK = {0} is trusted for delegation: OK
AD_CAS_ACCT_TRUST_SKIP = {0} is not trusted for delegation!
AD_SPN_MANY = SPN {0}/{1} is defined on multiple hosts!
AD_HTTP_KT_SKIP = -createKeyTab specified but the HTTP SPN is not defined.  Setting createKeyTab  =  False
AD_HTTP_KT_SKIP_MANY = -createKeyTab specified but the HTTP SPN is defined multiple times.  Setting createKeyTab  =  False
AD_HTTP_KT_SUC = The HTTP keytab ({0}) was successfully created.
AD_HTTP_KT_FAIL1 = The HTTP keytab creation FAILED.  Command executed: {0}
AD_HTTP_KT_FAIL2 = The creation of the HTTP keytab failed!\n{0}
AD_HTTP_KT_ERRMSG = Could not create keytab.  Error returned: {0}

VERSION = sas-wvda version {0}
HOST = Executing on host: {0}
NEWER = There is a newer version of this tool available at {0}.\n      The remote version number is: {1}
NEWEST = There are no updates available.
ADMIN_INSTRUCTIONS = Administrative information and artifacts required by the SAS Administrator have been placed in ViyaAdminInfo.zip \n      Securely transmit the zip file the SAS Viya Administrator.  Time is of the essence as the deployment of SAS Viya can not continue \n      until the SAS Administrator has these artifacts.
ACTION_REQUIRED = Provide {0} to your Active Directory administrator.  When the script has successfully completed you will be provided:\n - The name and password of the CAS account\n - A keytab for the HTTP service principal\nYou must have all of these artifacts prior to deployment of SAS Viya 3.4.
RESTART_REQUIRED = System settings have been updated which require a restart to become effective\n      This system must be restarted prior to installing SAS Viya!
"@
