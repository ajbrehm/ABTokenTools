#include <Windows.h>
#include <wchar.h>
#include <WtsApi32.h>
#include <sysinfoapi.h>

BOOL debug = TRUE;
BOOL ok = TRUE;
DWORD error = 0;
LSTATUS status = 0;

void Error(LPCWSTR sz)
{
	if (!debug) { return; }
	if (!ok || status) { error = GetLastError(); }
	fwprintf(stderr, L"%s\tOK: [%d]\tSTATUS: [%d], Error: [%d]\n", sz, ok, status, error);
	error = 0;
	status = 0;
	ok = TRUE;
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
	// read command line
	LPWSTR sCmdLine = GetCommandLineW();
	int args = 0;
	LPWSTR* aCmdLine = CommandLineToArgvW(sCmdLine, &args);
	if (args < 2) {
		wprintf(L"ReplaceToken pid");
		exit(0);
	}//if
	LPWSTR szPID = aCmdLine[1];
	DWORD pid = (DWORD)_wtol(szPID);

	// enable debug privilege
	EnablePrivilege(L"SeDebugPrivilege");

	HANDLE hCurrentProcess = GetCurrentProcess();
	HANDLE hCurrentProcessToken = NULL;
	ok = OpenProcessToken(hCurrentProcess, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &hCurrentProcessToken);
	Error(L"OpenProcessToken");

	HANDLE hNewTargetProcessToken = NULL;
	ok = DuplicateToken(hCurrentProcessToken, SecurityImpersonation, &hNewTargetProcessToken);
	Error(L"DuplicateToken");

	HANDLE hTargetProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	Error(L"OpenProcess");

	

	CloseHandle(hTargetProcess);
	CloseHandle(hCurrentProcess);

}