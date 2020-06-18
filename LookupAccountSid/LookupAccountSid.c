#include <Windows.h>
#include <sddl.h>

HANDLE hOut;
HANDLE hHeap;

int Write(LPWSTR sz)
{
	if (NULL == hOut) {
		hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	}//if
	DWORD length = (DWORD)wcslen(sz);
	DWORD written = 0;
	WriteConsoleW(hOut, sz, length, &written, NULL);
	return written;
}

int WriteLine(LPWSTR sz)
{
	DWORD written = 0;
	written += Write(sz);
	written += Write(L"\n");
	return written;

}

int main()
{
	hHeap = GetProcessHeap();
	LPWSTR szCommandLine = GetCommandLineW();
	int count = 0;
	LPWSTR* aCommandLine = CommandLineToArgvW(szCommandLine, &count);
	LPWSTR szSid = aCommandLine[1];
	PSID pSid = HeapAlloc(hHeap, 0, SECURITY_MAX_SID_SIZE);
	ConvertStringSidToSidW(szSid, &pSid);
	DWORD cchAccountName = 0;
	DWORD cchDomainName = 0;
	SID_NAME_USE use = 0;
	LookupAccountSidW(NULL, pSid, NULL, &cchAccountName, NULL, &cchDomainName, &use);
	LPWSTR szAccountName = HeapAlloc(hHeap, 0, cchAccountName * sizeof(WCHAR));
	LPWSTR szDomainName = HeapAlloc(hHeap, 0, cchDomainName * sizeof(WCHAR));
	LookupAccountSidW(NULL, pSid, szAccountName, &cchAccountName, szDomainName, &cchDomainName, &use);
	WriteLine(szAccountName);
	HeapFree(hHeap, 0, pSid);
	pSid = NULL;
	HeapFree(hHeap, 0, szAccountName);
	szAccountName = NULL;
	HeapFree(hHeap, 0, szDomainName);
	szDomainName = NULL;
	return 0;
}