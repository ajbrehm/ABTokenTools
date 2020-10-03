#include <Windows.h>
#include <securitybaseapi.h>
#include <processthreadsapi.h>
#include <NTSecAPI.h>
#include <security.h>

HANDLE hOut;
DWORD error;
LPWSTR* aCommandLine;
int args = 0;
BOOL ok;

void Write(LPCWSTR sz)
{
	if (NULL == hOut) {
		hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	}//if
	DWORD length = lstrlenW(sz);
	DWORD written = 0;
	WriteConsoleW(hOut, sz, length, &written, NULL);
}

void WriteLine(LPCWSTR sz)
{
	Write(sz);
	Write(L"\n");
}

void WriteDW(DWORD dw)
{
	size_t cch = 20;
	size_t cb = cch * sizeof(WCHAR);
	LPWSTR sz = (LPWSTR)GlobalAlloc(0, cb);
	if (NULL == sz) { return; }
	_ultow_s(dw, sz, cch, 10);
	WriteLine(sz);
}

void ConfigureCommandLine()
{
	LPWSTR szCommandLine = GetCommandLineW();
	aCommandLine = CommandLineToArgvW(szCommandLine, &args);
}

int main()
{
	ConfigureCommandLine();
	
	HANDLE hToken = GetCurrentProcessToken();

	if (2 == args) {

		LPWSTR sUserName = aCommandLine[1];
		
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
		lsaOrigin.Buffer = L"TokenTest";
		lsaOrigin.Length = wcslen(lsaOrigin.Buffer) * sizeof(WCHAR) + sizeof(WCHAR);

		// prepare authentication package
		ULONG authenticationpackage = 0;
		LSA_STRING lsaAuthenticationPackage;
		lsaAuthenticationPackage.Buffer = NEGOSSP_NAME_W;
		lsaAuthenticationPackage.Length = (USHORT)wcslen(lsaAuthenticationPackage.Buffer);
		lsaAuthenticationPackage.MaximumLength = lsaAuthenticationPackage.MaximumLength;
		ok = LsaLookupAuthenticationPackage(hLsaConnection, &lsaAuthenticationPackage, &authenticationpackage);
		
		// prepare authentication info
		ULONG cchUserName = wcslen(sUserName);
		ULONG cbUserName = cchUserName * sizeof(WCHAR) + sizeof(WCHAR);
		ULONG cbAuthenticationInfo = sizeof(MSV1_0_S4U_LOGON) + cbUserName;
		UNICODE_STRING unisUserName;
		unisUserName.Buffer = sUserName;
		unisUserName.Length = cbUserName;
		MSV1_0_S4U_LOGON logon;
		logon.Flags = MSV1_0_S4U_LOGON_FLAG_CHECK_LOGONHOURS;
		logon.MessageType = MsV1_0S4ULogon;
		logon.UserPrincipalName = unisUserName;

		// prepare a token source
		TOKEN_SOURCE source;
		

	}//if

	DWORD tilength = 0;
	ok = GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &tilength);
	PTOKEN_PRIVILEGES pti = (PTOKEN_PRIVILEGES)GlobalAlloc(0, tilength);
	if (!pti) { return 1; }
	ok = GetTokenInformation(hToken, TokenPrivileges, pti, tilength, &tilength);

	DWORD count = pti->PrivilegeCount;

	Write(L"Privilege count: ");
	WriteDW(count);
	WriteLine(L"");
	
	for (DWORD i = 0; i < count; i++) {

		LUID_AND_ATTRIBUTES luidaa = pti->Privileges[i];
		LUID luid = luidaa.Luid;
		DWORD cchName = 0;
		ok = LookupPrivilegeNameW(NULL, &luid, NULL, &cchName);
		size_t cbName = cchName * sizeof(WCHAR) + sizeof(WCHAR);
		LPWSTR sName = (LPWSTR)GlobalAlloc(0, cbName);
		ok = LookupPrivilegeNameW(NULL, &luid, sName, &cchName);
		WriteLine(sName);
		GlobalFree(sName);

	}//for

	GlobalFree(pti);
}