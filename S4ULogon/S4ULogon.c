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


#define SECURITY_WIN32

#include <Windows.h>
#include <securitybaseapi.h>
#include <processthreadsapi.h>
#include <NTSecAPI.h>
#include <security.h>
#include <wchar.h>

DWORD error;
LPWSTR* aCommandLine;
int args = 0;
DWORD ok;

void ConfigureCommandLine()
{
	LPWSTR szCommandLine = GetCommandLineW();
	aCommandLine = CommandLineToArgvW(szCommandLine, &args);
}

int main()
{
	ConfigureCommandLine();
	
	HANDLE hToken = GetCurrentProcessToken();

	if (2 <= args) {
		
		LPWSTR sUserName = aCommandLine[1];
		LPWSTR sDomainName = L"";
		if (args > 2) {
			sDomainName = aCommandLine[2];
		}//if

		HANDLE hLsaConnection;
		ok = LsaConnectUntrusted(&hLsaConnection);

		//NTSTATUS LsaLogonUser(
		//	HANDLE              LsaHandle,
		//	PLSA_STRING         OriginName,
		//	SECURITY_LOGON_TYPE LogonType,
		//	ULONG               AuthenticationPackage,
		//	PVOID               AuthenticationInformation,
		//	ULONG               AuthenticationInformationLength,
		//	PTOKEN_GROUPS       LocalGroups,
		//	PTOKEN_SOURCE       SourceContext,
		//	PVOID * ProfileBuffer,
		//	PULONG              ProfileBufferLength,
		//	PLUID               LogonId,
		//	PHANDLE             Token,
		//	PQUOTA_LIMITS       Quotas,
		//	PNTSTATUS           SubStatus
		//);

		// prepare an origin
		LSA_STRING lsaOrigin;
		lsaOrigin.Buffer = _strdup("TEST");
		lsaOrigin.Length = 4;
		lsaOrigin.MaximumLength = 4;
		
		// prepare authentication package
		ULONG authenticationpackageid = 0;
		LSA_STRING lsaAuthenticationPackage;
		lsaAuthenticationPackage.Buffer = MSV1_0_PACKAGE_NAME;
		lsaAuthenticationPackage.Length = (USHORT)strlen(lsaAuthenticationPackage.Buffer);
		lsaAuthenticationPackage.MaximumLength = lsaAuthenticationPackage.Length;
		ok = LsaLookupAuthenticationPackage(hLsaConnection, &lsaAuthenticationPackage, &authenticationpackageid);

		wprintf(L"%d\n",ok);

		// prepare authentication info
		USHORT cchUserName = (USHORT)wcslen(sUserName);
		USHORT cbUserName = cchUserName * sizeof(WCHAR);
		USHORT cchDomainName = (USHORT)wcslen(sDomainName);
		USHORT cbDomainName = cchDomainName * sizeof(WCHAR);
		ULONG cbAuthenticationInfo = sizeof(MSV1_0_S4U_LOGON) + cbUserName + cbDomainName;
		LPBYTE pAuthenticationInfoBuffer = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, cbAuthenticationInfo);
		if (!pAuthenticationInfoBuffer) { return 1; }
		MSV1_0_S4U_LOGON* pAuthenticationInfo = (MSV1_0_S4U_LOGON*)pAuthenticationInfoBuffer;
		pAuthenticationInfo->MessageType = MsV1_0S4ULogon;
		size_t offset = sizeof(MSV1_0_S4U_LOGON);
		UNICODE_STRING unisUserName;
		unisUserName.Length = cbUserName;
		unisUserName.MaximumLength = cbUserName;
		unisUserName.Buffer = (PWSTR)(pAuthenticationInfoBuffer + offset);
		memcpy(unisUserName.Buffer, sUserName, cbUserName);
		pAuthenticationInfo->UserPrincipalName = unisUserName;
		offset += cbUserName;
		UNICODE_STRING unisDomainName;
		unisDomainName.Length = cbDomainName;
		unisDomainName.MaximumLength = cbDomainName;
		unisDomainName.Buffer = (PWSTR)(pAuthenticationInfoBuffer + offset);
		memcpy(unisDomainName.Buffer, sDomainName, cbDomainName);
		pAuthenticationInfo->DomainName = unisDomainName;
		LPWSTR pTest = (LPWSTR)(pAuthenticationInfoBuffer + sizeof(MSV1_0_S4U_LOGON));

		// prepare a token source
		TOKEN_SOURCE source;
		ok = strcpy_s(source.SourceName, 8, "Test");
		ok = AllocateLocallyUniqueId(&source.SourceIdentifier);
		
		// other parameters
		PTOKEN_GROUPS pTokenGroups = NULL;
		PVOID pProfile = NULL;
		ULONG cbProfile = 0;
		LUID logonid;
		ok = AllocateLocallyUniqueId(&logonid);
		QUOTA_LIMITS quota;
		NTSTATUS substatus = 0;

		// call
		ok = LsaLogonUser(hLsaConnection, &lsaOrigin, Batch, authenticationpackageid, pAuthenticationInfo, cbAuthenticationInfo, pTokenGroups, &source, &pProfile, &cbProfile, &logonid, &hToken, &quota, &substatus);
		wprintf(L"%d\n", ok);
		error = LsaNtStatusToWinError(ok);
		wprintf(L"%d\n", error);

		// free
		HeapFree(GetProcessHeap(), 0, pAuthenticationInfoBuffer);


	}//if

	DWORD tilength = 0;
	ok = GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &tilength);
	PTOKEN_PRIVILEGES pti = (PTOKEN_PRIVILEGES)GlobalAlloc(0, tilength);
	if (!pti) { return 1; }
	ok = GetTokenInformation(hToken, TokenPrivileges, pti, tilength, &tilength);

	DWORD count = pti->PrivilegeCount;

	wprintf(L"Privilege count: %d\n", count);
	
	for (DWORD i = 0; i < count; i++) {

		LUID_AND_ATTRIBUTES luidaa = pti->Privileges[i];
		LUID luid = luidaa.Luid;
		DWORD cchName = 0;
		ok = LookupPrivilegeNameW(NULL, &luid, NULL, &cchName);
		size_t cbName = cchName * sizeof(WCHAR) + sizeof(WCHAR);
		LPWSTR sName = (LPWSTR)GlobalAlloc(0, cbName);
		ok = LookupPrivilegeNameW(NULL, &luid, sName, &cchName);
		wprintf(L"%s\n", sName);
		GlobalFree(sName);

	}//for

	GlobalFree(pti);
}