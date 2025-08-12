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

#include <Windows.h>
#include <sddl.h>
#include <wchar.h>

HANDLE hHeap;
LPWSTR sDomainAccountName = NULL;
int error = 0;

int LookupAccountSidAndStore(LPWSTR sSid)
{
	PSID pSid = HeapAlloc(hHeap, 0, SECURITY_MAX_SID_SIZE);
	ConvertStringSidToSidW(sSid, &pSid);
	DWORD cchAccountName = 0;
	DWORD cchDomainName = 0;
	SID_NAME_USE use = 0;
	LookupAccountSidW(NULL, pSid, NULL, &cchAccountName, NULL, &cchDomainName, &use);
	LPWSTR sAccountName = HeapAlloc(hHeap, 0, cchAccountName * sizeof(WCHAR));
	if (NULL == sAccountName) { return 8; }
	LPWSTR sDomainName = HeapAlloc(hHeap, 0, cchDomainName * sizeof(WCHAR));
	if (NULL == sDomainName) { return 8; }
	LookupAccountSidW(NULL, pSid, sAccountName, &cchAccountName, sDomainName, &cchDomainName, &use);
	DWORD cchDomainAccountName = cchAccountName + sizeof(L"\\") + cchAccountName + sizeof(L"\0");
	sDomainAccountName = (LPWSTR)HeapAlloc(hHeap, 0, cchDomainAccountName * sizeof(WCHAR));
	if (NULL == sDomainAccountName) { return 8; }
	wcscpy_s(sDomainAccountName,cchDomainAccountName,sDomainName);
	wcscat_s(sDomainAccountName, cchDomainAccountName, L"\\");
	wcscat_s(sDomainAccountName, cchDomainAccountName, sAccountName);
	HeapFree(hHeap, 0, pSid);
	pSid = NULL;
	HeapFree(hHeap, 0, sAccountName);
	sAccountName = NULL;
	HeapFree(hHeap, 0, sDomainName);
	sDomainName = NULL;
	return 0;
}

int main()
{
	hHeap = GetProcessHeap();
	LPWSTR sCommandLine = GetCommandLineW();
	int count = 0;
	LPWSTR* aCommandLine = CommandLineToArgvW(sCommandLine, &count);
	LPWSTR sSid = aCommandLine[1];
	error = LookupAccountSidAndStore(sSid);
	wprintf(L"%s\n",sDomainAccountName);
	HeapFree(hHeap, 0, sDomainAccountName);
	return error;
}