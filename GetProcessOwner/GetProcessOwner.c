#include <Windows.h>
#include <wchar.h>
#define ERRORSIZE 40

HANDLE hOut;
BOOL result;
DWORD error;
BOOL debug = FALSE;

void Write(LPCWSTR sz)
{
	if (NULL == hOut) {
		hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	}//if
	
	DWORD length = (DWORD)wcslen(sz);
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
	size_t buffersize = 20 * sizeof(WCHAR);
	LPWSTR sz = GlobalAlloc(0, buffersize);
	_ultow_s(dw, sz, buffersize, 10);
	WriteLine(sz);
}

void Error(LPCWSTR szFunctionName)
{
	if (debug) {
		error = GetLastError();
		if (0 != error) {
			WCHAR szError[ERRORSIZE];
			_ultow_s(error, szError, sizeof(szError) / sizeof(WCHAR), 10);
			Write(szFunctionName);
			Write(L" error ");
			WriteLine(szError);
			error = 0;
		}//if
	}//if
}

int main()
{
	// prepare reading command line arguments
	LPWSTR szCommandLine = GetCommandLineW();
	int count = 0;
	LPWSTR* aCommandLine = CommandLineToArgvW(szCommandLine, &count);
	LPWSTR szPID = aCommandLine[1];

	// szPID contains a process id string, if not, make the process id 1000 just for fun
	if (NULL == szPID) { szPID = L"1000"; }

	// read the process id into a DWORD
	DWORD pid = (DWORD)_wtol(szPID);

	// a pointer to the resulting sid
	PSID pSID = NULL;

	// attack the process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	Error(L"OpenProcess");

	// get the process token, this might not work because access denied
	HANDLE hToken = NULL;
	result = OpenProcessToken(hProcess, TOKEN_ALL_ACCESS, &hToken);
	Error(L"OpenProcessToken");

	// if this worked do something, otherwise do something else
	PTOKEN_OWNER pTokenOwner = NULL; // we need this to free it later in case it was used
	if (result) {

		// read the process token for size
		DWORD tokeninformationlength = 0;
		result = GetTokenInformation(hToken, TokenOwner, NULL, tokeninformationlength, &tokeninformationlength);
		Error(L"GetTokenInformation");

		// get privileges for process token
		tokeninformationlength = 0;
		GetTokenInformation(hToken, TokenPrivileges, NULL, tokeninformationlength, &tokeninformationlength);
		PTOKEN_INFORMATION_CLASS pTokenInformation = GlobalAlloc(0, tokeninformationlength);
		GetTokenInformation(hToken, TokenPrivileges, pTokenInformation, tokeninformationlength, &tokeninformationlength);
		PTOKEN_PRIVILEGES pTokenPrivileges = (PTOKEN_PRIVILEGES)pTokenInformation;
		int privileges = pTokenPrivileges->PrivilegeCount;
		Write(L"Number of process privileges: ");
		WriteDW(privileges);
		for (int privilege = 0; privilege < privileges; privilege++)
		{
			LUID_AND_ATTRIBUTES laa = pTokenPrivileges->Privileges[privilege];
			LUID luid = laa.Luid;
			int attributes = laa.Attributes;
			int privilegenamelength = 0;
			LookupPrivilegeNameW(NULL, &luid, NULL, &privilegenamelength);
			LPWSTR szPrivilegeName = GlobalAlloc(0, privilegenamelength * sizeof(WCHAR));
			LookupPrivilegeNameW(NULL, &luid, szPrivilegeName, &privilegenamelength);
			WriteLine(szPrivilegeName);
			GlobalFree(szPrivilegeName);
		}//for

		// get the token owner sid
		pTokenOwner = (PTOKEN_OWNER)GlobalAlloc(GPTR, tokeninformationlength); // alloc must free
		result = GetTokenInformation(hToken, TokenOwner, pTokenOwner, tokeninformationlength, &tokeninformationlength);
		Error(L"GetTokenInformation1");
		if (NULL == pTokenOwner) { return 1; }
		pSID = pTokenOwner->Owner;

	} else {

		// get the security descriptor for the process, first the size
		SECURITY_INFORMATION sirequested = OWNER_SECURITY_INFORMATION;
		DWORD sdlength = 0;
		result = GetUserObjectSecurity(hProcess, &sirequested, NULL, sdlength, &sdlength);
		Error(L"GetUserObjectSecurity");
		
		// then the security descriptor itself, which is a security descriptor, not a sid
		PSECURITY_DESCRIPTOR psd = GlobalAlloc(0, sdlength);
		result = GetUserObjectSecurity(hProcess, &sirequested, psd, sdlength, &sdlength);
		Error(L"GetUserObjectSecurity1");
		BOOL tfDefaulted = FALSE;

		// get the owner sid of the security descriptor, which is a sid, not a security descriptor
		if (0 != psd) { result = GetSecurityDescriptorOwner(psd, &pSID, &tfDefaulted); }
		Error(L"GetSecurityDescriptorOwner");
		GlobalFree(psd);

	}//if

	// if neither of the two ways got us a sid, we leave angrily
	if (NULL == pSID) {
		return 1; 
	}//if

	// get the user name for the sid acquired above
	DWORD cchName = 0;
	DWORD cchDomainName = 0;
	PSID_NAME_USE use = 0;
	result = LookupAccountSidW(NULL, pSID, NULL, &cchName, NULL, &cchDomainName, &use);
	Error(L"LookupAccountSidW");
	LPWSTR szName = (LPWSTR)GlobalAlloc(0, cchName * sizeof(WCHAR)); // alloc must free
	LPWSTR szDomainName = (LPWSTR)GlobalAlloc(0, cchDomainName * sizeof(WCHAR)); //alloc must free
	result = LookupAccountSidW(NULL, pSID, szName, &cchName, szDomainName, &cchDomainName, &use);
	Error(L"LookupAccountSidW1");

	// output the user name
	Write(L"Process owner name: ");
	WriteLine(szName);

	// clean up
	GlobalFree(szDomainName);
	GlobalFree(szName);
	if (NULL != pTokenOwner) { GlobalFree(pTokenOwner); }

	return 0;
}