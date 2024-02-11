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
	HANDLE hBenoitToken = NULL;
	ok = LogonUserW(L"benoit", L".", L"Password1", LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hBenoitToken);
	Error(L"LogonUser");

	//HANDLE hBenoitThreadToken = NULL;
	//ok = DuplicateTokenEx(hBenoitToken, TOKEN_ALL_ACCESS, NULL, SecurityImpersonation, TokenImpersonation, &hBenoitThreadToken);
	//Error(L"DuplicateTokenEx");

	//ok = SetThreadToken(NULL, hBenoitThreadToken);
	//Error(L"SetThreadToken");

	//HANDLE hFile = CreateFileW(L"ReplaceTokenTestFile.txt", FILE_GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	//Error(L"CreateFile");

	//DWORD written = 0;
	//ok = WriteFile(hFile, "Hello", 6, &written, NULL);
	//Error(L"WriteFile");

	//CloseHandle(hFile);
	//Error(L"CloseHandle");


	PROCESS_INFORMATION pi;
	STARTUPINFOW si;
	ZeroMemory(&si, sizeof(STARTUPINFOW));
	si.cb = sizeof(STARTUPINFOW);
	si.lpDesktop = L"Winsta0\\default";
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	DWORD dwCreationFlags = 0;
	//dwCreationFlags += CREATE_NEW_CONSOLE;
	//dwCreationFlags += CREATE_NO_WINDOW;

	ok = CreateProcessAsUserW(hBenoitToken, L"C:\\Windows\\System32\\cmd.exe", L"", NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &si, &pi);
	Error(L"CreateProcessAsUser");

	if (pi.hThread) { CloseHandle(pi.hThread); }
	if (pi.hProcess) { CloseHandle(pi.hProcess); }
	
	system("exit");


}