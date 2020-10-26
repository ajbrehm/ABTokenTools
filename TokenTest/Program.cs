//MIT License
//
//Copyright(c) 2020 Andrew J. Brehm
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this softwareand associated documentation files(the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions :
//
//The above copyright noticeand this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.



using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Security.Principal;

namespace TokenTest
{
    class Program
    {
        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa379626%28v=vs.85%29.aspx
        enum TOKEN_INFORMATION_CLASS
        {
            TokenUser = 1,
            TokenGroups,
            TokenPrivileges,
            TokenOwner,
            TokenPrimaryGroup,
            TokenDefaultDacl,
            TokenSource,
            TokenType,
            TokenImpersonationLevel,
            TokenStatistics,
            TokenRestrictedSids,
            TokenSessionId,
            TokenGroupsAndPrivileges,
            TokenSessionReference,
            TokenSandBoxInert,
            TokenAuditPolicy,
            TokenOrigin,
            TokenElevationType,
            TokenLinkedToken,
            TokenElevation,
            TokenHasRestrictions,
            TokenAccessInformation,
            TokenVirtualizationAllowed,
            TokenVirtualizationEnabled,
            TokenIntegrityLevel,
            TokenUIAccess,
            TokenMandatoryPolicy,
            TokenLogonSid,
            TokenIsAppContainer,
            TokenCapabilities,
            TokenAppContainerSid,
            TokenAppContainerNumber,
            TokenUserClaimAttributes,
            TokenDeviceClaimAttributes,
            TokenRestrictedUserClaimAttributes,
            TokenRestrictedDeviceClaimAttributes,
            TokenDeviceGroups,
            TokenRestrictedDeviceGroups,
            TokenSecurityAttributes,
            TokenIsRestricted,
            MaxTokenInfoClass
        }

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa446671(v=vs.85).aspx
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool GetTokenInformation(
            IntPtr TokenHandle,
            TOKEN_INFORMATION_CLASS TokenInformationClass,
            IntPtr TokenInformation,
            int TokenInformationLength,
            out int ReturnLength
            );

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa379176%28v=vs.85%29.aspx
        [DllImport("advapi32.dll", SetLastError = true)]
        static extern bool LookupPrivilegeName(
            string lpSystemName,
            IntPtr lpluid,
            StringBuilder lpName,
            ref int cchName
            );

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa379261(v=vs.85).aspx
        public struct LUID
        {
            public Int32 LowPart;
            public Int32 HighPart;
        }

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa379263(v=vs.85).aspx
        [StructLayout(LayoutKind.Sequential)]
        public struct LUID_AND_ATTRIBUTES
        {
            public LUID Luid;
            public Int32 Attributes;
        }

        //https://msdn.microsoft.com/en-us/library/windows/desktop/aa379630%28v=vs.85%29.aspx
        //http://pinvoke.net/default.aspx/Structures/TOKEN_PRIVILEGES.html
        [StructLayout(LayoutKind.Sequential)]
        public struct TOKEN_PRIVILEGES
        {
            public Int32 PrivilegeCount;
            [MarshalAs(UnmanagedType.ByValArray, SizeConst = 1000)]
            public LUID_AND_ATTRIBUTES[] Privileges;
        }

        static void Main(string[] args)
        {
            // get token
            IntPtr pToken = WindowsIdentity.GetCurrent().Token;
            if (Environment.GetCommandLineArgs().Length > 1) {
                string sUserPrincipalName = Environment.GetCommandLineArgs()[1];
                try {
                    WindowsIdentity identity = new WindowsIdentity(sUserPrincipalName);
                    pToken = identity.Token;
                } catch (Exception ex) {
                    Console.WriteLine(ex.Message);
                    Environment.Exit(1);
                }//try
            }//if

            // get length of TokenInformation TokenPrivileges
            int TokenInformationLength = 0;
            GetTokenInformation(
                WindowsIdentity.GetCurrent().Token,
                TOKEN_INFORMATION_CLASS.TokenPrivileges,
                IntPtr.Zero, // don't have TokenInformation pointer yet
                TokenInformationLength,
                out TokenInformationLength
                );

            // get TokenInformation pointer
            IntPtr TokenInformation = Marshal.AllocHGlobal(TokenInformationLength); // alloc, must free

            // get TokenInformation
            GetTokenInformation(
                pToken,
                TOKEN_INFORMATION_CLASS.TokenPrivileges,
                TokenInformation,
                TokenInformationLength,
                out TokenInformationLength
                );

            // get TokenPrivileges
            TOKEN_PRIVILEGES TokenPrivileges = (TOKEN_PRIVILEGES)Marshal.PtrToStructure(
                TokenInformation,
                typeof(TOKEN_PRIVILEGES)
                );

            // count TokenPrivileges
            int privileges = TokenPrivileges.PrivilegeCount;
            Console.WriteLine(privileges.ToString());

            // for every privilege in TokenPrivileges get privilege name
            for (int privilege = 0; privilege < privileges; privilege++) {
                LUID_AND_ATTRIBUTES LuidAndAttributes = TokenPrivileges.Privileges[privilege];
                LUID Luid = LuidAndAttributes.Luid;
                int luidattributes = LuidAndAttributes.Attributes;
                StringBuilder sbldPrivilegeName = new StringBuilder();
                int privilegenamelength = 0; // length for privilege name string
                int luidsize = Marshal.SizeOf(Luid);
                IntPtr LuidPointer = Marshal.AllocHGlobal(luidsize); // alloc, must free
                Marshal.StructureToPtr(Luid, LuidPointer, true);
                // get length for privilege name string
                LookupPrivilegeName(null, LuidPointer, null, ref privilegenamelength);
                // get privilege name string
                sbldPrivilegeName.EnsureCapacity(privilegenamelength + 1);
                LookupPrivilegeName(null, LuidPointer, sbldPrivilegeName, ref privilegenamelength);
                string sPrivilegeName = sbldPrivilegeName.ToString();
                Console.WriteLine("{0} {1}",luidattributes, sPrivilegeName);
                Marshal.FreeHGlobal(LuidPointer);
            }//for

            // the end
            Marshal.FreeHGlobal(TokenInformation);
            Console.ReadKey();
        }
    }//class
}//namespace
