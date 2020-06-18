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
	LPWSTR *aCommandLine = CommandLineToArgvW(szCommandLine, &count);
	LPWSTR szAccountName = aCommandLine[1];
	DWORD cbSid = 0;
	DWORD cchDomainName = 0;
	SID_NAME_USE use = 0;
	LookupAccountNameW(NULL, szAccountName, NULL, &cbSid, NULL, &cchDomainName, &use);
	LPWSTR szDomainName = HeapAlloc(hHeap, 0, cchDomainName * sizeof(WCHAR));
	PSID pSid = HeapAlloc(hHeap, 0, cbSid);
	LookupAccountNameW(NULL, szAccountName, pSid, &cbSid, szDomainName, &cchDomainName, &use);
	LPWSTR szSid = L"SID was not translated";
	if (NULL != pSid) { ConvertSidToStringSidW(pSid, &szSid); }
	WriteLine(szSid);
	LocalFree(szSid);
	szSid = NULL;
	HeapFree(hHeap, 0, szDomainName);
	szDomainName = NULL;
	HeapFree(hHeap, 0, pSid);
	pSid = NULL;
	return 0;
}


