#include <Windows.h>
#include <securitybaseapi.h>
#include <processthreadsapi.h>

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
		size_t cbName = (cchName + 1) * sizeof(WCHAR);
		LPWSTR sName = (LPWSTR)GlobalAlloc(0, cbName);
		ok = LookupPrivilegeNameW(NULL, &luid, sName, &cchName);
		WriteLine(sName);
		GlobalFree(sName);

	}//for

	GlobalFree(pti);
}