<#
Obtained from https://github.com/Microsoft/BaselineManagement/blob/master/src/DSCResources/HelperFunctions.psm1

    MIT License

    Copyright (c) Microsoft Corporation. All rights reserved.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE

VERSION   DATE          AUTHOR
1.0       2015-03-10    Tony Pombo
    - Initial Release

1.1       2015-03-11    Tony Pombo
    - Added enum Rights, and configured functions to use it
    - Fixed a couple typos in the help

1.2       2015-11-13    Tony Pombo
    - Fixed exception in LsaWrapper.EnumerateAccountsWithUserRight when SID cannot be resolved
    - Added Grant-TokenPrivilege
    - Added Revoke-TokenPrivilege

1.3       2016-10-29    Tony Pombo
    - Minor changes to support Nano server
    - SIDs can now be specified for all account parameters
    - Script is now digitally signed

#> # Revision History

#Requires -Version 3.0
Set-StrictMode -Version 2.0

Add-Type -TypeDefinition @'
using System;
namespace PS_LSA
{
    using System.ComponentModel;
    using System.Runtime.InteropServices;
    using System.Security;
    using System.Security.Principal;
    using LSA_HANDLE = IntPtr;

    public enum Rights
    {
        SeTrustedCredManAccessPrivilege,      // Access Credential Manager as a trusted caller
        SeNetworkLogonRight,                  // Access this computer from the network
        SeTcbPrivilege,                       // Act as part of the operating system
        SeMachineAccountPrivilege,            // Add workstations to domain
        SeIncreaseQuotaPrivilege,             // Adjust memory quotas for a process
        SeInteractiveLogonRight,              // Allow log on locally
        SeRemoteInteractiveLogonRight,        // Allow log on through Remote Desktop Services
        SeBackupPrivilege,                    // Back up files and directories
        SeChangeNotifyPrivilege,              // Bypass traverse checking
        SeSystemtimePrivilege,                // Change the system time
        SeTimeZonePrivilege,                  // Change the time zone
        SeCreatePagefilePrivilege,            // Create a pagefile
        SeCreateTokenPrivilege,               // Create a token object
        SeCreateGlobalPrivilege,              // Create global objects
        SeCreatePermanentPrivilege,           // Create permanent shared objects
        SeCreateSymbolicLinkPrivilege,        // Create symbolic links
        SeDebugPrivilege,                     // Debug programs
        SeDenyNetworkLogonRight,              // Deny access this computer from the network
        SeDenyBatchLogonRight,                // Deny log on as a batch job
        SeDenyServiceLogonRight,              // Deny log on as a service
        SeDenyInteractiveLogonRight,          // Deny log on locally
        SeDenyRemoteInteractiveLogonRight,    // Deny log on through Remote Desktop Services
        SeEnableDelegationPrivilege,          // Enable computer and user accounts to be trusted for delegation
        SeRemoteShutdownPrivilege,            // Force shutdown from a remote system
        SeAuditPrivilege,                     // Generate security audits
        SeImpersonatePrivilege,               // Impersonate a client after authentication
        SeIncreaseWorkingSetPrivilege,        // Increase a process working set
        SeIncreaseBasePriorityPrivilege,      // Increase scheduling priority
        SeLoadDriverPrivilege,                // Load and unload device drivers
        SeLockMemoryPrivilege,                // Lock pages in memory
        SeBatchLogonRight,                    // Log on as a batch job
        SeServiceLogonRight,                  // Log on as a service
        SeSecurityPrivilege,                  // Manage auditing and security log
        SeRelabelPrivilege,                   // Modify an object label
        SeSystemEnvironmentPrivilege,         // Modify firmware environment values
        SeManageVolumePrivilege,              // Perform volume maintenance tasks
        SeProfileSingleProcessPrivilege,      // Profile single process
        SeSystemProfilePrivilege,             // Profile system performance
        SeUnsolicitedInputPrivilege,          // "Read unsolicited input from a terminal device"
        SeUndockPrivilege,                    // Remove computer from docking station
        SeAssignPrimaryTokenPrivilege,        // Replace a process level token
        SeRestorePrivilege,                   // Restore files and directories
        SeShutdownPrivilege,                  // Shut down the system
        SeSyncAgentPrivilege,                 // Synchronize directory service data
        SeTakeOwnershipPrivilege              // Take ownership of files or other objects
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_OBJECT_ATTRIBUTES
    {
        internal int Length;
        internal IntPtr RootDirectory;
        internal IntPtr ObjectName;
        internal int Attributes;
        internal IntPtr SecurityDescriptor;
        internal IntPtr SecurityQualityOfService;
    }

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    struct LSA_UNICODE_STRING
    {
        internal ushort Length;
        internal ushort MaximumLength;
        [MarshalAs(UnmanagedType.LPWStr)]
        internal string Buffer;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct LSA_ENUMERATION_INFORMATION
    {
        internal IntPtr PSid;
    }

    internal sealed class Win32Sec
    {
        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaOpenPolicy(
            LSA_UNICODE_STRING[] SystemName,
            ref LSA_OBJECT_ATTRIBUTES ObjectAttributes,
            int AccessMask,
            out IntPtr PolicyHandle
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaAddAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaRemoveAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            bool AllRights,
            LSA_UNICODE_STRING[] UserRights,
            int CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaEnumerateAccountRights(
            LSA_HANDLE PolicyHandle,
            IntPtr pSID,
            out IntPtr /*LSA_UNICODE_STRING[]*/ UserRights,
            out ulong CountOfRights
        );

        [DllImport("advapi32", CharSet = CharSet.Unicode, SetLastError = true)]
        internal static extern uint LsaEnumerateAccountsWithUserRight(
            LSA_HANDLE PolicyHandle,
            LSA_UNICODE_STRING[] UserRights,
            out IntPtr EnumerationBuffer,
            out ulong CountReturned
        );

        [DllImport("advapi32")]
        internal static extern int LsaNtStatusToWinError(int NTSTATUS);

        [DllImport("advapi32")]
        internal static extern int LsaClose(IntPtr PolicyHandle);

        [DllImport("advapi32")]
        internal static extern int LsaFreeMemory(IntPtr Buffer);
    }

    internal sealed class Sid : IDisposable
    {
        public IntPtr pSid = IntPtr.Zero;
        public SecurityIdentifier sid = null;

        public Sid(string account)
        {
            try { sid = new SecurityIdentifier(account); }
            catch { sid = (SecurityIdentifier)(new NTAccount(account)).Translate(typeof(SecurityIdentifier)); }
            Byte[] buffer = new Byte[sid.BinaryLength];
            sid.GetBinaryForm(buffer, 0);

            pSid = Marshal.AllocHGlobal(sid.BinaryLength);
            Marshal.Copy(buffer, 0, pSid, sid.BinaryLength);
        }

        public void Dispose()
        {
            if (pSid != IntPtr.Zero)
            {
                Marshal.FreeHGlobal(pSid);
                pSid = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~Sid() { Dispose(); }
    }

    public sealed class LsaWrapper : IDisposable
    {
        enum Access : int
        {
            POLICY_READ = 0x20006,
            POLICY_ALL_ACCESS = 0x00F0FFF,
            POLICY_EXECUTE = 0X20801,
            POLICY_WRITE = 0X207F8
        }
        const uint STATUS_ACCESS_DENIED = 0xc0000022;
        const uint STATUS_INSUFFICIENT_RESOURCES = 0xc000009a;
        const uint STATUS_NO_MEMORY = 0xc0000017;
        const uint STATUS_OBJECT_NAME_NOT_FOUND = 0xc0000034;
        const uint STATUS_NO_MORE_ENTRIES = 0x8000001a;

        IntPtr lsaHandle;

        public LsaWrapper() : this(null) { } // local system if systemName is null
        public LsaWrapper(string systemName)
        {
            LSA_OBJECT_ATTRIBUTES lsaAttr;
            lsaAttr.RootDirectory = IntPtr.Zero;
            lsaAttr.ObjectName = IntPtr.Zero;
            lsaAttr.Attributes = 0;
            lsaAttr.SecurityDescriptor = IntPtr.Zero;
            lsaAttr.SecurityQualityOfService = IntPtr.Zero;
            lsaAttr.Length = Marshal.SizeOf(typeof(LSA_OBJECT_ATTRIBUTES));
            lsaHandle = IntPtr.Zero;
            LSA_UNICODE_STRING[] system = null;
            if (systemName != null)
            {
                system = new LSA_UNICODE_STRING[1];
                system[0] = InitLsaString(systemName);
            }

            uint ret = Win32Sec.LsaOpenPolicy(system, ref lsaAttr, (int)Access.POLICY_ALL_ACCESS, out lsaHandle);
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void AddPrivilege(string account, Rights privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());
                ret = Win32Sec.LsaAddAccountRights(lsaHandle, sid.pSid, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void RemovePrivilege(string account, Rights privilege)
        {
            uint ret = 0;
            using (Sid sid = new Sid(account))
            {
                LSA_UNICODE_STRING[] privileges = new LSA_UNICODE_STRING[1];
                privileges[0] = InitLsaString(privilege.ToString());
                ret = Win32Sec.LsaRemoveAccountRights(lsaHandle, sid.pSid, false, privileges, 1);
            }
            if (ret == 0) return;
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public Rights[] EnumerateAccountPrivileges(string account)
        {
            uint ret = 0;
            ulong count = 0;
            IntPtr privileges = IntPtr.Zero;
            Rights[] rights = null;

            using (Sid sid = new Sid(account))
            {
                ret = Win32Sec.LsaEnumerateAccountRights(lsaHandle, sid.pSid, out privileges, out count);
            }
            if (ret == 0)
            {
                rights = new Rights[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_UNICODE_STRING str = (LSA_UNICODE_STRING)Marshal.PtrToStructure(
                        IntPtr.Add(privileges, i * Marshal.SizeOf(typeof(LSA_UNICODE_STRING))),
                        typeof(LSA_UNICODE_STRING));
                    rights[i] = (Rights)Enum.Parse(typeof(Rights), str.Buffer);
                }
                Win32Sec.LsaFreeMemory(privileges);
                return rights;
            }
            if (ret == STATUS_OBJECT_NAME_NOT_FOUND) return null;  // No privileges assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public string[] EnumerateAccountsWithUserRight(Rights privilege)
        {
            uint ret = 0;
            ulong count = 0;
            LSA_UNICODE_STRING[] rights = new LSA_UNICODE_STRING[1];
            rights[0] = InitLsaString(privilege.ToString());
            IntPtr buffer = IntPtr.Zero;
            string[] accounts = null;

            ret = Win32Sec.LsaEnumerateAccountsWithUserRight(lsaHandle, rights, out buffer, out count);
            if (ret == 0)
            {
                accounts = new string[count];
                for (int i = 0; i < (int)count; i++)
                {
                    LSA_ENUMERATION_INFORMATION LsaInfo = (LSA_ENUMERATION_INFORMATION)Marshal.PtrToStructure(
                        IntPtr.Add(buffer, i * Marshal.SizeOf(typeof(LSA_ENUMERATION_INFORMATION))),
                        typeof(LSA_ENUMERATION_INFORMATION));

                    try {
                        accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).Translate(typeof(NTAccount)).ToString();
                    } catch (System.Security.Principal.IdentityNotMappedException) {
                        accounts[i] = (new SecurityIdentifier(LsaInfo.PSid)).ToString();
                    }
                }
                Win32Sec.LsaFreeMemory(buffer);
                return accounts;
            }
            if (ret == STATUS_NO_MORE_ENTRIES) return null;  // No accounts assigned
            if (ret == STATUS_ACCESS_DENIED) throw new UnauthorizedAccessException();
            if ((ret == STATUS_INSUFFICIENT_RESOURCES) || (ret == STATUS_NO_MEMORY)) throw new OutOfMemoryException();
            throw new Win32Exception(Win32Sec.LsaNtStatusToWinError((int)ret));
        }

        public void Dispose()
        {
            if (lsaHandle != IntPtr.Zero)
            {
                Win32Sec.LsaClose(lsaHandle);
                lsaHandle = IntPtr.Zero;
            }
            GC.SuppressFinalize(this);
        }
        ~LsaWrapper() { Dispose(); }

        // helper functions:
        static LSA_UNICODE_STRING InitLsaString(string s)
        {
            // Unicode strings max. 32KB
            if (s.Length > 0x7ffe) throw new ArgumentException("String too long");
            LSA_UNICODE_STRING lus = new LSA_UNICODE_STRING();
            lus.Buffer = s;
            lus.Length = (ushort)(s.Length * sizeof(char));
            lus.MaximumLength = (ushort)(lus.Length + sizeof(char));
            return lus;
        }
    }

    public sealed class TokenManipulator
    {
        [StructLayout(LayoutKind.Sequential, Pack = 1)]
        internal struct TokPriv1Luid
        {
            public int Count;
            public long Luid;
            public int Attr;
        }

        internal const int SE_PRIVILEGE_DISABLED = 0x00000000;
        internal const int SE_PRIVILEGE_ENABLED = 0x00000002;
        internal const int TOKEN_QUERY = 0x00000008;
        internal const int TOKEN_ADJUST_PRIVILEGES = 0x00000020;

        internal sealed class Win32Token
        {
            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool AdjustTokenPrivileges(
                IntPtr htok,
                bool disall,
                ref TokPriv1Luid newst,
                int len,
                IntPtr prev,
                IntPtr relen
            );

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern IntPtr GetCurrentProcess();

            [DllImport("advapi32.dll", ExactSpelling = true, SetLastError = true)]
            internal static extern bool OpenProcessToken(
                IntPtr h,
                int acc,
                ref IntPtr phtok
            );

            [DllImport("advapi32.dll", SetLastError = true)]
            internal static extern bool LookupPrivilegeValue(
                string host,
                string name,
                ref long pluid
            );

            [DllImport("kernel32.dll", ExactSpelling = true)]
            internal static extern bool CloseHandle(
                IntPtr phtok
            );
        }

        public static void AddPrivilege(Rights privilege)
        {
            bool retVal;
            int lasterror;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_ENABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            lasterror = Marshal.GetLastWin32Error();
            if (lasterror != 0) throw new Win32Exception();
        }

        public static void RemovePrivilege(Rights privilege)
        {
            bool retVal;
            int lasterror;
            TokPriv1Luid tp;
            IntPtr hproc = Win32Token.GetCurrentProcess();
            IntPtr htok = IntPtr.Zero;
            retVal = Win32Token.OpenProcessToken(hproc, TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, ref htok);
            tp.Count = 1;
            tp.Luid = 0;
            tp.Attr = SE_PRIVILEGE_DISABLED;
            retVal = Win32Token.LookupPrivilegeValue(null, privilege.ToString(), ref tp.Luid);
            retVal = Win32Token.AdjustTokenPrivileges(htok, false, ref tp, Marshal.SizeOf(tp), IntPtr.Zero, IntPtr.Zero);
            Win32Token.CloseHandle(htok);
            lasterror = Marshal.GetLastWin32Error();
            if (lasterror != 0) throw new Win32Exception();
        }
    }
}
'@ # This type (PS_LSA) is used by Grant-UserRight, Revoke-UserRight, Get-UserRightsGrantedToAccount, Get-AccountsWithUserRight, Grant-TokenPriviledge, Revoke-TokenPrivilege

function Grant-UserRight {
 <#
  .SYNOPSIS
    Assigns user rights to accounts
  .DESCRIPTION
    Assigns one or more user rights (privileges) to one or more accounts. If you specify privileges already granted to the account, they are ignored.
  .PARAMETER Account
    Logon name of the account. More than one account can be listed. If the account is not found on the computer, the default domain is searched. To specify a domain, you may use either "DOMAIN\username" or "username@domain.dns" formats. SIDs may be also be specified.
  .PARAMETER Right
    Name of the right to grant. More than one right may be listed.

    Possible values:
      SeTrustedCredManAccessPrivilege      Access Credential Manager as a trusted caller
      SeNetworkLogonRight                  Access this computer from the network
      SeTcbPrivilege                       Act as part of the operating system
      SeMachineAccountPrivilege            Add workstations to domain
      SeIncreaseQuotaPrivilege             Adjust memory quotas for a process
      SeInteractiveLogonRight              Allow log on locally
      SeRemoteInteractiveLogonRight        Allow log on through Remote Desktop Services
      SeBackupPrivilege                    Back up files and directories
      SeChangeNotifyPrivilege              Bypass traverse checking
      SeSystemtimePrivilege                Change the system time
      SeTimeZonePrivilege                  Change the time zone
      SeCreatePagefilePrivilege            Create a pagefile
      SeCreateTokenPrivilege               Create a token object
      SeCreateGlobalPrivilege              Create global objects
      SeCreatePermanentPrivilege           Create permanent shared objects
      SeCreateSymbolicLinkPrivilege        Create symbolic links
      SeDebugPrivilege                     Debug programs
      SeDenyNetworkLogonRight              Deny access this computer from the network
      SeDenyBatchLogonRight                Deny log on as a batch job
      SeDenyServiceLogonRight              Deny log on as a service
      SeDenyInteractiveLogonRight          Deny log on locally
      SeDenyRemoteInteractiveLogonRight    Deny log on through Remote Desktop Services
      SeEnableDelegationPrivilege          Enable computer and user accounts to be trusted for delegation
      SeRemoteShutdownPrivilege            Force shutdown from a remote system
      SeAuditPrivilege                     Generate security audits
      SeImpersonatePrivilege               Impersonate a client after authentication
      SeIncreaseWorkingSetPrivilege        Increase a process working set
      SeIncreaseBasePriorityPrivilege      Increase scheduling priority
      SeLoadDriverPrivilege                Load and unload device drivers
      SeLockMemoryPrivilege                Lock pages in memory
      SeBatchLogonRight                    Log on as a batch job
      SeServiceLogonRight                  Log on as a service
      SeSecurityPrivilege                  Manage auditing and security log
      SeRelabelPrivilege                   Modify an object label
      SeSystemEnvironmentPrivilege         Modify firmware environment values
      SeManageVolumePrivilege              Perform volume maintenance tasks
      SeProfileSingleProcessPrivilege      Profile single process
      SeSystemProfilePrivilege             Profile system performance
      SeUnsolicitedInputPrivilege          "Read unsolicited input from a terminal device"
      SeUndockPrivilege                    Remove computer from docking station
      SeAssignPrimaryTokenPrivilege        Replace a process level token
      SeRestorePrivilege                   Restore files and directories
      SeShutdownPrivilege                  Shut down the system
      SeSyncAgentPrivilege                 Synchronize directory service data
      SeTakeOwnershipPrivilege             Take ownership of files or other objects
  .PARAMETER Computer
    Specifies the name of the computer on which to run this cmdlet. If the input for this parameter is omitted, then the cmdlet runs on the local computer.
  .EXAMPLE
    Grant-UserRight "bilbo.baggins" SeServiceLogonRight

    Grants bilbo.baggins the "Logon as a service" right on the local computer.
  .EXAMPLE
    Grant-UserRight -Account "Edward","Karen" -Right SeServiceLogonRight,SeCreateTokenPrivilege -Computer TESTPC

    Grants both Edward and Karen, "Logon as a service" and "Create a token object" rights on the TESTPC system.
  .INPUTS
    String Account
    PS_LSA.Rights Right
    String Computer
  .OUTPUTS
    None
  .LINK
    http://msdn.microsoft.com/en-us/library/ms721786.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('User','Username')][String[]] $Account,
        [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('Privilege')] [PS_LSA.Rights[]] $Right,
        [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] $Computer
    )
    process {
        $lsa = New-Object PS_LSA.LsaWrapper($Computer)
        foreach ($Acct in $Account) {
            foreach ($Priv in $Right) {
                if ($PSCmdlet.ShouldProcess("Adding Privilege ($priv) for Account ($acct)"))
                {
                    $lsa.AddPrivilege($Acct,$Priv)
                }
            }
        }
    }
} # Assigns user rights to accounts

function Revoke-UserRight {
 <#
  .SYNOPSIS
    Removes user rights from accounts
  .DESCRIPTION
    Removes one or more user rights (privileges) from one or more accounts. If you specify privileges not held by the account, they are ignored.
  .PARAMETER Account
    Logon name of the account. More than one account can be listed. If the account is not found on the computer, the default domain is searched. To specify a domain, you may use either "DOMAIN\username" or "username@domain.dns" formats. SIDs may be also be specified.
  .PARAMETER Right
    Name of the right to revoke. More than one right may be listed.

    Possible values:
      SeTrustedCredManAccessPrivilege      Access Credential Manager as a trusted caller
      SeNetworkLogonRight                  Access this computer from the network
      SeTcbPrivilege                       Act as part of the operating system
      SeMachineAccountPrivilege            Add workstations to domain
      SeIncreaseQuotaPrivilege             Adjust memory quotas for a process
      SeInteractiveLogonRight              Allow log on locally
      SeRemoteInteractiveLogonRight        Allow log on through Remote Desktop Services
      SeBackupPrivilege                    Back up files and directories
      SeChangeNotifyPrivilege              Bypass traverse checking
      SeSystemtimePrivilege                Change the system time
      SeTimeZonePrivilege                  Change the time zone
      SeCreatePagefilePrivilege            Create a pagefile
      SeCreateTokenPrivilege               Create a token object
      SeCreateGlobalPrivilege              Create global objects
      SeCreatePermanentPrivilege           Create permanent shared objects
      SeCreateSymbolicLinkPrivilege        Create symbolic links
      SeDebugPrivilege                     Debug programs
      SeDenyNetworkLogonRight              Deny access this computer from the network
      SeDenyBatchLogonRight                Deny log on as a batch job
      SeDenyServiceLogonRight              Deny log on as a service
      SeDenyInteractiveLogonRight          Deny log on locally
      SeDenyRemoteInteractiveLogonRight    Deny log on through Remote Desktop Services
      SeEnableDelegationPrivilege          Enable computer and user accounts to be trusted for delegation
      SeRemoteShutdownPrivilege            Force shutdown from a remote system
      SeAuditPrivilege                     Generate security audits
      SeImpersonatePrivilege               Impersonate a client after authentication
      SeIncreaseWorkingSetPrivilege        Increase a process working set
      SeIncreaseBasePriorityPrivilege      Increase scheduling priority
      SeLoadDriverPrivilege                Load and unload device drivers
      SeLockMemoryPrivilege                Lock pages in memory
      SeBatchLogonRight                    Log on as a batch job
      SeServiceLogonRight                  Log on as a service
      SeSecurityPrivilege                  Manage auditing and security log
      SeRelabelPrivilege                   Modify an object label
      SeSystemEnvironmentPrivilege         Modify firmware environment values
      SeManageVolumePrivilege              Perform volume maintenance tasks
      SeProfileSingleProcessPrivilege      Profile single process
      SeSystemProfilePrivilege             Profile system performance
      SeUnsolicitedInputPrivilege          "Read unsolicited input from a terminal device"
      SeUndockPrivilege                    Remove computer from docking station
      SeAssignPrimaryTokenPrivilege        Replace a process level token
      SeRestorePrivilege                   Restore files and directories
      SeShutdownPrivilege                  Shut down the system
      SeSyncAgentPrivilege                 Synchronize directory service data
      SeTakeOwnershipPrivilege             Take ownership of files or other objects
  .PARAMETER Computer
    Specifies the name of the computer on which to run this cmdlet. If the input for this parameter is omitted, then the cmdlet runs on the local computer.
  .EXAMPLE
    Revoke-UserRight "bilbo.baggins" SeServiceLogonRight

    Removes the "Logon as a service" right from bilbo.baggins on the local computer.
  .EXAMPLE
    Revoke-UserRight "S-1-5-21-3108507890-3520248245-2556081279-1001" SeServiceLogonRight

    Removes the "Logon as a service" right from the specified SID on the local computer.
  .EXAMPLE
    Revoke-UserRight -Account "Edward","Karen" -Right SeServiceLogonRight,SeCreateTokenPrivilege -Computer TESTPC

    Removes the "Logon as a service" and "Create a token object" rights from both Edward and Karen on the TESTPC system.
  .INPUTS
    String Account
    PS_LSA.Rights Right
    String Computer
  .OUTPUTS
    None
  .LINK
    http://msdn.microsoft.com/en-us/library/ms721809.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('User','Username')][String[]] $Account,
        [Parameter(Position=1, Mandatory=$true, ValueFromPipelineByPropertyName=$true)]
        [Alias('Privilege')] [PS_LSA.Rights[]] $Right,
        [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] $Computer
    )
    process {
        $lsa = New-Object PS_LSA.LsaWrapper($Computer)
        foreach ($Acct in $Account) {
            foreach ($Priv in $Right) {

                if ($PSCmdlet.ShouldProcess("Revoking Privilege ($priv) for Account ($acct)"))
                {
                    $lsa.RemovePrivilege($Acct,$Priv)
                }
            }
        }
    }
} # Removes user rights from accounts

function Get-UserRightsGrantedToAccount {
 <#
  .SYNOPSIS
    Gets all user rights granted to an account
  .DESCRIPTION
    Retrieves a list of all the user rights (privileges) granted to one or more accounts. The rights retrieved are those granted directly to the user account, and does not include those rights obtained as part of membership to a group.
  .PARAMETER Account
    Logon name of the account. More than one account can be listed. If the account is not found on the computer, the default domain is searched. To specify a domain, you may use either "DOMAIN\username" or "username@domain.dns" formats. SIDs may be also be specified.
  .PARAMETER Computer
    Specifies the name of the computer on which to run this cmdlet. If the input for this parameter is omitted, then the cmdlet runs on the local computer.
  .EXAMPLE
    Get-UserRightsGrantedToAccount "bilbo.baggins"

    Returns a list of all user rights granted to bilbo.baggins on the local computer.
  .EXAMPLE
    Get-UserRightsGrantedToAccount -Account "Edward","Karen" -Computer TESTPC

    Returns a list of user rights granted to Edward, and a list of user rights granted to Karen, on the TESTPC system.
  .INPUTS
    String Account
    String Computer
  .OUTPUTS
    String Account
    PS_LSA.Rights Right
  .LINK
    http://msdn.microsoft.com/en-us/library/ms721790.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('User','Username')][String[]] $Account,
        [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] $Computer
    )
    process {
        $lsa = New-Object PS_LSA.LsaWrapper($Computer)
        foreach ($Acct in $Account) {
        $rights = $lsa.EnumerateAccountPrivileges($Acct)
        foreach ($right in $rights) {
            $output = @{'Account'=$Acct; 'Right'=$right; }
            Write-Output (New-Object -Typename PSObject -Prop $output)
        }
    }
  }
} # Gets all user rights granted to an account

function Get-AccountsWithUserRight {
 <#
  .SYNOPSIS
    Gets all accounts that are assigned a specified privilege
  .DESCRIPTION
    Retrieves a list of all accounts that hold a specified right (privilege). The accounts returned are those that hold the specified privilege directly through the user account, not as part of membership to a group.
  .PARAMETER Right
    Name of the right to query. More than one right may be listed.

    Possible values:
      SeTrustedCredManAccessPrivilege      Access Credential Manager as a trusted caller
      SeNetworkLogonRight                  Access this computer from the network
      SeTcbPrivilege                       Act as part of the operating system
      SeMachineAccountPrivilege            Add workstations to domain
      SeIncreaseQuotaPrivilege             Adjust memory quotas for a process
      SeInteractiveLogonRight              Allow log on locally
      SeRemoteInteractiveLogonRight        Allow log on through Remote Desktop Services
      SeBackupPrivilege                    Back up files and directories
      SeChangeNotifyPrivilege              Bypass traverse checking
      SeSystemtimePrivilege                Change the system time
      SeTimeZonePrivilege                  Change the time zone
      SeCreatePagefilePrivilege            Create a pagefile
      SeCreateTokenPrivilege               Create a token object
      SeCreateGlobalPrivilege              Create global objects
      SeCreatePermanentPrivilege           Create permanent shared objects
      SeCreateSymbolicLinkPrivilege        Create symbolic links
      SeDebugPrivilege                     Debug programs
      SeDenyNetworkLogonRight              Deny access this computer from the network
      SeDenyBatchLogonRight                Deny log on as a batch job
      SeDenyServiceLogonRight              Deny log on as a service
      SeDenyInteractiveLogonRight          Deny log on locally
      SeDenyRemoteInteractiveLogonRight    Deny log on through Remote Desktop Services
      SeEnableDelegationPrivilege          Enable computer and user accounts to be trusted for delegation
      SeRemoteShutdownPrivilege            Force shutdown from a remote system
      SeAuditPrivilege                     Generate security audits
      SeImpersonatePrivilege               Impersonate a client after authentication
      SeIncreaseWorkingSetPrivilege        Increase a process working set
      SeIncreaseBasePriorityPrivilege      Increase scheduling priority
      SeLoadDriverPrivilege                Load and unload device drivers
      SeLockMemoryPrivilege                Lock pages in memory
      SeBatchLogonRight                    Log on as a batch job
      SeServiceLogonRight                  Log on as a service
      SeSecurityPrivilege                  Manage auditing and security log
      SeRelabelPrivilege                   Modify an object label
      SeSystemEnvironmentPrivilege         Modify firmware environment values
      SeManageVolumePrivilege              Perform volume maintenance tasks
      SeProfileSingleProcessPrivilege      Profile single process
      SeSystemProfilePrivilege             Profile system performance
      SeUnsolicitedInputPrivilege          "Read unsolicited input from a terminal device"
      SeUndockPrivilege                    Remove computer from docking station
      SeAssignPrimaryTokenPrivilege        Replace a process level token
      SeRestorePrivilege                   Restore files and directories
      SeShutdownPrivilege                  Shut down the system
      SeSyncAgentPrivilege                 Synchronize directory service data
      SeTakeOwnershipPrivilege             Take ownership of files or other objects
  .PARAMETER Computer
    Specifies the name of the computer on which to run this cmdlet. If the input for this parameter is omitted, then the cmdlet runs on the local computer.
  .EXAMPLE
    Get-AccountsWithUserRight SeServiceLogonRight

    Returns a list of all accounts that hold the "Log on as a service" right.
  .EXAMPLE
    Get-AccountsWithUserRight -Right SeServiceLogonRight,SeDebugPrivilege -Computer TESTPC

    Returns a list of accounts that hold the "Log on as a service" right, and a list of accounts that hold the "Debug programs" right, on the TESTPC system.
  .INPUTS
    PS_LSA.Rights Right
    String Computer
  .OUTPUTS
    String Account
    String Right
  .LINK
    http://msdn.microsoft.com/en-us/library/ms721792.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding()]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('Privilege')] [PS_LSA.Rights[]] $Right,
        [Parameter(ValueFromPipelineByPropertyName=$true, HelpMessage="Computer name")]
        [Alias('System','ComputerName','Host')][String] $Computer
    )
    process {
        $lsa = New-Object PS_LSA.LsaWrapper($Computer)
        foreach ($Priv in $Right) {
            $output = @{'Account'=$lsa.EnumerateAccountsWithUserRight($Priv); 'Right'=$Priv; }
            Write-Output (New-Object –Typename PSObject –Prop $output)
        }
    }
} # Gets all accounts that are assigned a specified privilege

function Grant-TokenPrivilege {
 <#
  .SYNOPSIS
    Enables privileges in the current process token.
  .DESCRIPTION
    Enables one or more privileges for the current process token. If a privilege cannot be enabled, an exception is thrown.
  .PARAMETER Privilege
    Name of the privilege to enable. More than one privilege may be listed.

    Possible values:
      SeTrustedCredManAccessPrivilege      Access Credential Manager as a trusted caller
      SeNetworkLogonRight                  Access this computer from the network
      SeTcbPrivilege                       Act as part of the operating system
      SeMachineAccountPrivilege            Add workstations to domain
      SeIncreaseQuotaPrivilege             Adjust memory quotas for a process
      SeInteractiveLogonRight              Allow log on locally
      SeRemoteInteractiveLogonRight        Allow log on through Remote Desktop Services
      SeBackupPrivilege                    Back up files and directories
      SeChangeNotifyPrivilege              Bypass traverse checking
      SeSystemtimePrivilege                Change the system time
      SeTimeZonePrivilege                  Change the time zone
      SeCreatePagefilePrivilege            Create a pagefile
      SeCreateTokenPrivilege               Create a token object
      SeCreateGlobalPrivilege              Create global objects
      SeCreatePermanentPrivilege           Create permanent shared objects
      SeCreateSymbolicLinkPrivilege        Create symbolic links
      SeDebugPrivilege                     Debug programs
      SeDenyNetworkLogonRight              Deny access this computer from the network
      SeDenyBatchLogonRight                Deny log on as a batch job
      SeDenyServiceLogonRight              Deny log on as a service
      SeDenyInteractiveLogonRight          Deny log on locally
      SeDenyRemoteInteractiveLogonRight    Deny log on through Remote Desktop Services
      SeEnableDelegationPrivilege          Enable computer and user accounts to be trusted for delegation
      SeRemoteShutdownPrivilege            Force shutdown from a remote system
      SeAuditPrivilege                     Generate security audits
      SeImpersonatePrivilege               Impersonate a client after authentication
      SeIncreaseWorkingSetPrivilege        Increase a process working set
      SeIncreaseBasePriorityPrivilege      Increase scheduling priority
      SeLoadDriverPrivilege                Load and unload device drivers
      SeLockMemoryPrivilege                Lock pages in memory
      SeBatchLogonRight                    Log on as a batch job
      SeServiceLogonRight                  Log on as a service
      SeSecurityPrivilege                  Manage auditing and security log
      SeRelabelPrivilege                   Modify an object label
      SeSystemEnvironmentPrivilege         Modify firmware environment values
      SeManageVolumePrivilege              Perform volume maintenance tasks
      SeProfileSingleProcessPrivilege      Profile single process
      SeSystemProfilePrivilege             Profile system performance
      SeUnsolicitedInputPrivilege          "Read unsolicited input from a terminal device"
      SeUndockPrivilege                    Remove computer from docking station
      SeAssignPrimaryTokenPrivilege        Replace a process level token
      SeRestorePrivilege                   Restore files and directories
      SeShutdownPrivilege                  Shut down the system
      SeSyncAgentPrivilege                 Synchronize directory service data
      SeTakeOwnershipPrivilege             Take ownership of files or other objects
  .EXAMPLE
    Grant-TokenPrivilege SeIncreaseWorkingSetPrivilege

    Enables the "Increase a process working set" privilege for the current process.
  .INPUTS
    PS_LSA.Rights Right
  .OUTPUTS
    None
  .LINK
    http://msdn.microsoft.com/en-us/library/aa375202.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('Right')] [PS_LSA.Rights[]] $Privilege
    )
    process {
        foreach ($Priv in $Privilege)
        {
            if ($PSCmdlet.ShouldProcess("Granting Token Privilege for $priv"))
            {
                try { [PS_LSA.TokenManipulator]::AddPrivilege($Priv) }
                catch [System.ComponentModel.Win32Exception] {
                    throw New-Object System.ComponentModel.Win32Exception("$($_.Exception.Message) ($Priv)", $_.Exception)
                }
            }
        }
    }
} # Enables privileges in the current process token

function Revoke-TokenPrivilege {
 <#
  .SYNOPSIS
    Disables privileges in the current process token.
  .DESCRIPTION
    Disables one or more privileges for the current process token. If a privilege cannot be disabled, an exception is thrown.
  .PARAMETER Privilege
    Name of the privilege to disable. More than one privilege may be listed.

    Possible values:
      SeTrustedCredManAccessPrivilege      Access Credential Manager as a trusted caller
      SeNetworkLogonRight                  Access this computer from the network
      SeTcbPrivilege                       Act as part of the operating system
      SeMachineAccountPrivilege            Add workstations to domain
      SeIncreaseQuotaPrivilege             Adjust memory quotas for a process
      SeInteractiveLogonRight              Allow log on locally
      SeRemoteInteractiveLogonRight        Allow log on through Remote Desktop Services
      SeBackupPrivilege                    Back up files and directories
      SeChangeNotifyPrivilege              Bypass traverse checking
      SeSystemtimePrivilege                Change the system time
      SeTimeZonePrivilege                  Change the time zone
      SeCreatePagefilePrivilege            Create a pagefile
      SeCreateTokenPrivilege               Create a token object
      SeCreateGlobalPrivilege              Create global objects
      SeCreatePermanentPrivilege           Create permanent shared objects
      SeCreateSymbolicLinkPrivilege        Create symbolic links
      SeDebugPrivilege                     Debug programs
      SeDenyNetworkLogonRight              Deny access this computer from the network
      SeDenyBatchLogonRight                Deny log on as a batch job
      SeDenyServiceLogonRight              Deny log on as a service
      SeDenyInteractiveLogonRight          Deny log on locally
      SeDenyRemoteInteractiveLogonRight    Deny log on through Remote Desktop Services
      SeEnableDelegationPrivilege          Enable computer and user accounts to be trusted for delegation
      SeRemoteShutdownPrivilege            Force shutdown from a remote system
      SeAuditPrivilege                     Generate security audits
      SeImpersonatePrivilege               Impersonate a client after authentication
      SeIncreaseWorkingSetPrivilege        Increase a process working set
      SeIncreaseBasePriorityPrivilege      Increase scheduling priority
      SeLoadDriverPrivilege                Load and unload device drivers
      SeLockMemoryPrivilege                Lock pages in memory
      SeBatchLogonRight                    Log on as a batch job
      SeServiceLogonRight                  Log on as a service
      SeSecurityPrivilege                  Manage auditing and security log
      SeRelabelPrivilege                   Modify an object label
      SeSystemEnvironmentPrivilege         Modify firmware environment values
      SeManageVolumePrivilege              Perform volume maintenance tasks
      SeProfileSingleProcessPrivilege      Profile single process
      SeSystemProfilePrivilege             Profile system performance
      SeUnsolicitedInputPrivilege          "Read unsolicited input from a terminal device"
      SeUndockPrivilege                    Remove computer from docking station
      SeAssignPrimaryTokenPrivilege        Replace a process level token
      SeRestorePrivilege                   Restore files and directories
      SeShutdownPrivilege                  Shut down the system
      SeSyncAgentPrivilege                 Synchronize directory service data
      SeTakeOwnershipPrivilege             Take ownership of files or other objects
  .EXAMPLE
    Revoke-TokenPrivilege SeIncreaseWorkingSetPrivilege

    Disables the "Increase a process working set" privilege for the current process.
  .INPUTS
    PS_LSA.Rights Right
  .OUTPUTS
    None
  .LINK
    http://msdn.microsoft.com/en-us/library/aa375202.aspx
    http://msdn.microsoft.com/en-us/library/bb530716.aspx
 #>
    [CmdletBinding(SupportsShouldProcess=$true)]
    param (
        [Parameter(Position=0, Mandatory=$true, ValueFromPipelineByPropertyName=$true, ValueFromPipeline=$true)]
        [Alias('Right')] [PS_LSA.Rights[]] $Privilege
    )
    process {
        foreach ($Priv in $Privilege)
        {
            if ($PSCmdlet.ShouldProcess("Revoking Token Privilege for $priv"))
            {
                try { [PS_LSA.TokenManipulator]::RemovePrivilege($Priv) }
                catch [System.ComponentModel.Win32Exception] {
                    throw New-Object System.ComponentModel.Win32Exception("$($_.Exception.Message) ($Priv)", $_.Exception)
                }
            }
        }
    }
} # Disables privileges in the current process token

Export-ModuleMember -Function Grant-UserRight, Revoke-UserRight
Export-ModuleMember -Function Get-UserRightsGrantedToAccount, Get-AccountsWithUserRight
Export-ModuleMember -Function Grant-TokenPrivilege, Revoke-TokenPrivilege

# SIG # Begin signature block
# MIIZ8gYJKoZIhvcNAQcCoIIZ4zCCGd8CAQExCzAJBgUrDgMCGgUAMGkGCisGAQQB
# gjcCAQSgWzBZMDQGCisGAQQBgjcCAR4wJgIDAQAABBAfzDtgWUsITrck0sYpfvNR
# AgEAAgEAAgEAAgEAAgEAMCEwCQYFKw4DAhoFAAQUNsk5YIXEcETZmRVAZbdJlGdI
# JiugghS9MIIE1zCCA7+gAwIBAgIQDnUoc2vE3IsGoNzV3Yd2EzANBgkqhkiG9w0B
# AQsFADB/MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRp
# b24xHzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxMDAuBgNVBAMTJ1N5
# bWFudGVjIENsYXNzIDMgU0hBMjU2IENvZGUgU2lnbmluZyBDQTAeFw0xNzA4MzEw
# MDAwMDBaFw0yMDA4MzAyMzU5NTlaMG8xCzAJBgNVBAYTAlVTMRcwFQYDVQQIDA5O
# b3J0aCBDYXJvbGluYTENMAsGA1UEBwwEQ2FyeTEbMBkGA1UECgwSU0FTIEluc3Rp
# dHV0ZSBJbmMuMRswGQYDVQQDDBJTQVMgSW5zdGl0dXRlIEluYy4wggEiMA0GCSqG
# SIb3DQEBAQUAA4IBDwAwggEKAoIBAQC9A5t+AYDjWLngma+s/+jJpuH01urcSFEY
# ErMdUEy5P9nsO6VleyE25glSfIWwkSC+FkhpI4UfnlMiHrKS/KkfRy1Di+XWCSO2
# IVGUZ62+yhTwqJQ42jOIGCZ2VZbsLOYyvH7tEcnVtEwFigEzwIP/bxfyaJIg6UP0
# gRNI5bNNCwh3XOWHzMZNBHdIMxl8X/aYppnd4z9wVNz3af638YmSTribVmv9sD3j
# RsJyLzial+GsvbumsPgoYaD9YA4CFIx6S29nPitqe4RqTBE7gtvBneYOeyf3tWxj
# VivykjZThwgMou3jTwEgv31j9OEF3EAZa1pYA7tc6OaWUYMhBDLXAgMBAAGjggFd
# MIIBWTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIHgDArBgNVHR8EJDAiMCCgHqAc
# hhpodHRwOi8vc3Yuc3ltY2IuY29tL3N2LmNybDBhBgNVHSAEWjBYMFYGBmeBDAEE
# ATBMMCMGCCsGAQUFBwIBFhdodHRwczovL2Quc3ltY2IuY29tL2NwczAlBggrBgEF
# BQcCAjAZDBdodHRwczovL2Quc3ltY2IuY29tL3JwYTATBgNVHSUEDDAKBggrBgEF
# BQcDAzBXBggrBgEFBQcBAQRLMEkwHwYIKwYBBQUHMAGGE2h0dHA6Ly9zdi5zeW1j
# ZC5jb20wJgYIKwYBBQUHMAKGGmh0dHA6Ly9zdi5zeW1jYi5jb20vc3YuY3J0MB8G
# A1UdIwQYMBaAFJY7U/B5M5evfYPvLivMyreGHnJmMB0GA1UdDgQWBBRSAEiSNnbL
# 2dKH//yOmEshx6gclzANBgkqhkiG9w0BAQsFAAOCAQEAdJCQzplXSFzX58JQiEyc
# bK8VNLb6dpZRV30/Yx8PzMVszqhQe5skk/ypg4c28Z0CZa2c/SPljjiZs+KwCOB+
# zOG5mhspN2q38Fh6/hR6fBtGbhYeX0o7NqiuNWMVG0V/yggUQX5VnMtD6+F9wFHc
# AEPyVkBdpmmLIB5lr8VIXt9d2ZZ3EPe7FFKU/wKds+iFEBcL9LdmGXezLlAAe6Ab
# Qej/SEJs6HGBVYHGaRecnyJ9xg2qiqqFRZu00nI5Y5Oh10SBl7K3yCcM1KEsbY0X
# IgATXUYzCplN56DplQUvY2EyJ+rB20qoiGC745lX8xdeNAk+OlTzDGxZpL9aB+0t
# yzCCBQAwggPooAMCAQICAQcwDQYJKoZIhvcNAQELBQAwgY8xCzAJBgNVBAYTAlVT
# MRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpTY290dHNkYWxlMSUwIwYDVQQK
# ExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJbmMuMTIwMAYDVQQDEylTdGFyZmll
# bGQgUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgLSBHMjAeFw0xMTA1MDMwNzAw
# MDBaFw0zMTA1MDMwNzAwMDBaMIHGMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJp
# em9uYTETMBEGA1UEBxMKU2NvdHRzZGFsZTElMCMGA1UEChMcU3RhcmZpZWxkIFRl
# Y2hub2xvZ2llcywgSW5jLjEzMDEGA1UECxMqaHR0cDovL2NlcnRzLnN0YXJmaWVs
# ZHRlY2guY29tL3JlcG9zaXRvcnkvMTQwMgYDVQQDEytTdGFyZmllbGQgU2VjdXJl
# IENlcnRpZmljYXRlIEF1dGhvcml0eSAtIEcyMIIBIjANBgkqhkiG9w0BAQEFAAOC
# AQ8AMIIBCgKCAQEA5ZBmS+z5RnGpIIO+6Wy/SslIaYF1Tm0k9ssXE/iwcVmEemsr
# haQ0tRbly8zpQXAspC7W+jJ94ajelBCsMcHA2Gr/WSerdtb8C3RruKeuP8RU9LQx
# RN2TVoykTF6bicskg5viV3232BIfyYVt9NGA8VCbh67UCxAF+ye6KG0X6Q7WTbk5
# VQb/CiQFfi/GHXJs1IspjFd92tnrZhrTT6fff1LEMMWlyQ4CxVO/dzhoBiTDZsg3
# fjAeRXEjNf+Q2Cqdjeewkk08fyoKk9zNFkZl92CEi3ZLkSdzFJLg6u6PFuqNDj52
# F799iYCAREPnLeBDCXXaNuit24k69V0SjiMEgwIDAQABo4IBLDCCASgwDwYDVR0T
# AQH/BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwHQYDVR0OBBYEFCVFgWhQJjg9Oy0s
# vs1q2bY9s2ZjMB8GA1UdIwQYMBaAFHwMMh+n2TB/xH1oo2Kooc6rB1snMDoGCCsG
# AQUFBwEBBC4wLDAqBggrBgEFBQcwAYYeaHR0cDovL29jc3Auc3RhcmZpZWxkdGVj
# aC5jb20vMDsGA1UdHwQ0MDIwMKAuoCyGKmh0dHA6Ly9jcmwuc3RhcmZpZWxkdGVj
# aC5jb20vc2Zyb290LWcyLmNybDBMBgNVHSAERTBDMEEGBFUdIAAwOTA3BggrBgEF
# BQcCARYraHR0cHM6Ly9jZXJ0cy5zdGFyZmllbGR0ZWNoLmNvbS9yZXBvc2l0b3J5
# LzANBgkqhkiG9w0BAQsFAAOCAQEAVmXK/vM/CqiTixjH3kNpEzQgvk5feKhrnNtq
# TUHbwRPs3DEAIl73AJ4M4DRlNPmxOk5IyBKBiFxbPghTevcaZN+4UGHMU1FAKUvC
# 9K46X+TKrSbMTmFD5f1XpjdwzkMrsJTDkunhX6oQSbdp5ODQH2SkK80fb6D4hCQY
# znk9qZG/VBgTiZlUEQ1VxSYLeU9aHG75Y9sUgKQHq/qypbmI3ZH+ZTuko3m+iU3h
# 0LD0yBcMCpYUfAm3bOHC2FXUGKCqQWlwJKO57+la3D7rlErwt95fDnb6+/tpA0VA
# UO5yDKQShoHNE9FOxDzKTg3SJvEAt7SmouFueoH9MKx6H8dZezCCBVkwggRBoAMC
# AQICED141/l2SWCyYX308B7KhiowDQYJKoZIhvcNAQELBQAwgcoxCzAJBgNVBAYT
# AlVTMRcwFQYDVQQKEw5WZXJpU2lnbiwgSW5jLjEfMB0GA1UECxMWVmVyaVNpZ24g
# VHJ1c3QgTmV0d29yazE6MDgGA1UECxMxKGMpIDIwMDYgVmVyaVNpZ24sIEluYy4g
# LSBGb3IgYXV0aG9yaXplZCB1c2Ugb25seTFFMEMGA1UEAxM8VmVyaVNpZ24gQ2xh
# c3MgMyBQdWJsaWMgUHJpbWFyeSBDZXJ0aWZpY2F0aW9uIEF1dGhvcml0eSAtIEc1
# MB4XDTEzMTIxMDAwMDAwMFoXDTIzMTIwOTIzNTk1OVowfzELMAkGA1UEBhMCVVMx
# HTAbBgNVBAoTFFN5bWFudGVjIENvcnBvcmF0aW9uMR8wHQYDVQQLExZTeW1hbnRl
# YyBUcnVzdCBOZXR3b3JrMTAwLgYDVQQDEydTeW1hbnRlYyBDbGFzcyAzIFNIQTI1
# NiBDb2RlIFNpZ25pbmcgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIB
# AQCXgx4AFq8ssdIIxNdok1FgHnH24ke021hNI2JqtL9aG1H3ow0Yd2i72DarLyFQ
# 2p7z518nTgvCl8gJcJOp2lwNTqQNkaC07BTOkXJULs6j20TpUhs/QTzKSuSqwOg5
# q1PMIdDMz3+b5sLMWGqCFe49Ns8cxZcHJI7xe74xLT1u3LWZQp9LYZVfHHDuF33b
# i+VhiXjHaBuvEXgamK7EVUdT2bMy1qEORkDFl5KK0VOnmVuFNVfT6pNiYSAKxzB3
# JBFNYoO2untogjHuZcrf+dWNsjXcjCtvanJcYISc8gyUXsBWUgBIzNP4pX3eL9cT
# 5DiohNVGuBOGwhud6lo43ZvbAgMBAAGjggGDMIIBfzAvBggrBgEFBQcBAQQjMCEw
# HwYIKwYBBQUHMAGGE2h0dHA6Ly9zMi5zeW1jYi5jb20wEgYDVR0TAQH/BAgwBgEB
# /wIBADBsBgNVHSAEZTBjMGEGC2CGSAGG+EUBBxcDMFIwJgYIKwYBBQUHAgEWGmh0
# dHA6Ly93d3cuc3ltYXV0aC5jb20vY3BzMCgGCCsGAQUFBwICMBwaGmh0dHA6Ly93
# d3cuc3ltYXV0aC5jb20vcnBhMDAGA1UdHwQpMCcwJaAjoCGGH2h0dHA6Ly9zMS5z
# eW1jYi5jb20vcGNhMy1nNS5jcmwwHQYDVR0lBBYwFAYIKwYBBQUHAwIGCCsGAQUF
# BwMDMA4GA1UdDwEB/wQEAwIBBjApBgNVHREEIjAgpB4wHDEaMBgGA1UEAxMRU3lt
# YW50ZWNQS0ktMS01NjcwHQYDVR0OBBYEFJY7U/B5M5evfYPvLivMyreGHnJmMB8G
# A1UdIwQYMBaAFH/TZafC3ey78DAJ80M5+gKvMzEzMA0GCSqGSIb3DQEBCwUAA4IB
# AQAThRoeaak396C9pK9+HWFT/p2MXgymdR54FyPd/ewaA1U5+3GVx2Vap44w0kRa
# Ydtwb9ohBcIuc7pJ8dGT/l3JzV4D4ImeP3Qe1/c4i6nWz7s1LzNYqJJW0chNO4Lm
# eYQW/CiwsUfzHaI+7ofZpn+kVqU/rYQuKd58vKiqoz0EAeq6k6IOUCIpF0yH5DoR
# X9akJYmbBWsvtMkBTCd7C6wZBSKgYBU/2sn7TUyP+3Jnd/0nlMe6NQ6ISf6N/Siv
# ShK9DbOXBd5EDBX6NisD3MFQAfGhEV0U5eK9J0tUviuEXg+mw3QFCu+Xw4kisR93
# 873NQ9TxTKk/tYuEr2Ty0BQhMIIFfTCCBGWgAwIBAgIJAO+VwvSA4xuTMA0GCSqG
# SIb3DQEBCwUAMIHGMQswCQYDVQQGEwJVUzEQMA4GA1UECBMHQXJpem9uYTETMBEG
# A1UEBxMKU2NvdHRzZGFsZTElMCMGA1UEChMcU3RhcmZpZWxkIFRlY2hub2xvZ2ll
# cywgSW5jLjEzMDEGA1UECxMqaHR0cDovL2NlcnRzLnN0YXJmaWVsZHRlY2guY29t
# L3JlcG9zaXRvcnkvMTQwMgYDVQQDEytTdGFyZmllbGQgU2VjdXJlIENlcnRpZmlj
# YXRlIEF1dGhvcml0eSAtIEcyMB4XDTE3MTExNDA3MDAwMFoXDTIyMTExNDA3MDAw
# MFowgYcxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQHEwpT
# Y290dHNkYWxlMSQwIgYDVQQKExtTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBMTEMx
# KzApBgNVBAMTIlN0YXJmaWVsZCBUaW1lc3RhbXAgQXV0aG9yaXR5IC0gRzIwggEi
# MA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDm730Ku3SPyEahtiafyThSMSvG
# VFw6JhBrYkQYOcH10SjiERRWLn3DD51isWZDIrkxmTdy/zEt2m0qf2odGk7KRPeO
# 7OMlEbeGS4Cc11H7OvxG6VSADFbYTkrgGREeDgFxPA8WzeaJYFVwJq7kcoFSGN79
# 7hHOoYsd/GkD/iqnEjNfYRUcKdaH9b/Yzjwjte6uba5IeplsNx0eXWU+zy7bff21
# Qb1HQ0P0VTuYCbviRJknhKOZKSGuNhQ9CFDzMQbcbsbyx3+ov/iMaIGp7NHNlk/4
# hR1rFFmMwPRT/m123J8xGpoYBPPMOHyk15bF/1laR3kAr3fhbj0OQoUOUFIBAgMB
# AAGjggGpMIIBpTAMBgNVHRMBAf8EAjAAMA4GA1UdDwEB/wQEAwIGwDAWBgNVHSUB
# Af8EDDAKBggrBgEFBQcDCDAdBgNVHQ4EFgQUnc8cgP4K1qL8WBg+p9NUQO7WFGEw
# HwYDVR0jBBgwFoAUJUWBaFAmOD07LSy+zWrZtj2zZmMwgYQGCCsGAQUFBwEBBHgw
# djAqBggrBgEFBQcwAYYeaHR0cDovL29jc3Auc3RhcmZpZWxkdGVjaC5jb20vMEgG
# CCsGAQUFBzAChjxodHRwOi8vY3JsLnN0YXJmaWVsZHRlY2guY29tL3JlcG9zaXRv
# cnkvc2ZfaXNzdWluZ19jYS1nMi5jcnQwVAYDVR0fBE0wSzBJoEegRYZDaHR0cDov
# L2NybC5zdGFyZmllbGR0ZWNoLmNvbS9yZXBvc2l0b3J5L21hc3RlcnN0YXJmaWVs
# ZDJpc3N1aW5nLmNybDBQBgNVHSAESTBHMEUGC2CGSAGG/W4BBxcCMDYwNAYIKwYB
# BQUHAgEWKGh0dHA6Ly9jcmwuc3RhcmZpZWxkdGVjaC5jb20vcmVwb3NpdG9yeS8w
# DQYJKoZIhvcNAQELBQADggEBAFJGgfPKVmOa5BUYGkgzgZUHAPDVCxA0oDWH0E5+
# lQB0DlDHgv5G6O4Ju2dqL9TAJfhRAS0i+PaXwLOWbz/yxZc9jpCNDbVWIRIZdxzX
# vR7dOSvRPgWFxW1Msip51ys9TQV2ybVAyA+CjVwuNOALYWrT2ZhQBEp47lbsLRag
# 4VwYpydVkbfKa4Egad+0V0SHQrWxwnMaj/7PT+b8WilhTxTRXNWlxRlQ+9wla5Sq
# wn5PwafeJwv6eGS6nKC00cRPDQ6WDCo46VhOjkmv50J+o93p9LM2hkFuoRMrR5O3
# D8Zcg1jbab4rTDT+f+Wn5eYn9PwbYB7e4WMjRafylm5E3HoxggSfMIIEmwIBATCB
# kzB/MQswCQYDVQQGEwJVUzEdMBsGA1UEChMUU3ltYW50ZWMgQ29ycG9yYXRpb24x
# HzAdBgNVBAsTFlN5bWFudGVjIFRydXN0IE5ldHdvcmsxMDAuBgNVBAMTJ1N5bWFu
# dGVjIENsYXNzIDMgU0hBMjU2IENvZGUgU2lnbmluZyBDQQIQDnUoc2vE3IsGoNzV
# 3Yd2EzAJBgUrDgMCGgUAoHAwEAYKKwYBBAGCNwIBDDECMAAwGQYJKoZIhvcNAQkD
# MQwGCisGAQQBgjcCAQQwHAYKKwYBBAGCNwIBCzEOMAwGCisGAQQBgjcCARUwIwYJ
# KoZIhvcNAQkEMRYEFEovgTwvq5k2advI2jSpbOAGdMqlMA0GCSqGSIb3DQEBAQUA
# BIIBALamEp+IjE490AJnq/Vab283xhmfQr9N584RkLfe1v7YC1solZ5+AfLuvAIZ
# VRtPcVVq5O6T+P6+wgDBtekPkcmrI10xlZuteG+DkzENgOnjEEzuU1/KlfAffKOs
# oZBPF5vvNDsY+XfH/Ld4bz+F+CSymGyjRMOW6t9Glrj1AnH0UNVNPcsxGOVEYaOD
# PM3A7BbKa2lACl1vgewx/3XuGxD8ckLR48b+oYMZ2FouQn9oRIykYD+zqIIJglrj
# 7DQtw+DCux8IWuAUyt4zcNdYZMywf/qiAEmeJTfmB73aU623VHqagnODQZF+GGGj
# Ld4XEEbHtXHVHPPAzKBomDm2xsqhggJuMIICagYJKoZIhvcNAQkGMYICWzCCAlcC
# AQEwgdQwgcYxCzAJBgNVBAYTAlVTMRAwDgYDVQQIEwdBcml6b25hMRMwEQYDVQQH
# EwpTY290dHNkYWxlMSUwIwYDVQQKExxTdGFyZmllbGQgVGVjaG5vbG9naWVzLCBJ
# bmMuMTMwMQYDVQQLEypodHRwOi8vY2VydHMuc3RhcmZpZWxkdGVjaC5jb20vcmVw
# b3NpdG9yeS8xNDAyBgNVBAMTK1N0YXJmaWVsZCBTZWN1cmUgQ2VydGlmaWNhdGUg
# QXV0aG9yaXR5IC0gRzICCQDvlcL0gOMbkzAJBgUrDgMCGgUAoF0wGAYJKoZIhvcN
# AQkDMQsGCSqGSIb3DQEHATAcBgkqhkiG9w0BCQUxDxcNMTgwODEyMTcwNjQ4WjAj
# BgkqhkiG9w0BCQQxFgQUpEdtDK9ltE4kWX4tASZwrRjdMLQwDQYJKoZIhvcNAQEB
# BQAEggEAz/SaOCsEqlKl2YU75sf8pa6jojX9smrpo+DzHSKl3hJZZcwI4PapjvMf
# v7usLTqDh2am6OjcjLPvN8/uIgh1Z8aYSOoVkimFIMsmEZiByRVJkBXjgG+bqfN2
# zg2roDjCH+kobP8W239BvA4434tZqXcbkBhclS4Ec6Wv0ccTG1cvf1PvAcCBRp5B
# 1z0lOn+eir4/yXAwhJkFwN+ybzZ+2TyRrZQZ1gFuoJQH3x9cebS8Kt6gF56fEJn7
# 5GS4SQI9tUIoFA8CNmJUwlHjXxuY2O8pO6H8nxL6R0PdEodwKtO+BllMbfDTVE//
# bKDC3GbRcb8wijMtLEj+cxNWwTpsjw==
# SIG # End signature block
