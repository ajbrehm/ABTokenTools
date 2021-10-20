#include <Windows.h>
#include <wchar.h>

BOOL debug = 1;
BOOL ok;
DWORD error;


void Error(LPCWSTR szFunctionName)
{
	if (debug) {
		error = GetLastError();
		wprintf(L"%s: %d\n", szFunctionName, error);
		error = 0;
	}//if
}

void shout(LPCWSTR szShout)
{
	wprintf(L"%s\n", szShout);
}

void EnablePrivilege(LPWSTR sPrivilegeName)
{
	HANDLE hCurrentProcessToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hCurrentProcessToken);
	TOKEN_PRIVILEGES privs;
	LUID luid;
	ok = LookupPrivilegeValue(NULL, sPrivilegeName, &luid);
	Error(L"LookupPrivilegeValue");
	privs.PrivilegeCount = 1;
	privs.Privileges[0].Luid = luid;
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	ok = AdjustTokenPrivileges(hCurrentProcessToken, FALSE, &privs, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	Error(L"AdjustTokenPrivileges");
}

int main()
{
	// prepare reading command line arguments
	LPWSTR szCommandLine = GetCommandLineW();
	int count = 0;
	LPWSTR* aCommandLine = CommandLineToArgvW(szCommandLine, &count);
	if (2 > count) {
		shout(L"EnablePrivilege sPrivilegeName");
		return 0;
	}//if

	LPWSTR sPrivilegeName = aCommandLine[1];
	
	EnablePrivilege(sPrivilegeName);
	system("cmd");

	return 0;
}