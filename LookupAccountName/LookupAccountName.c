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
	wprintf(L"%s\n",szSid);
	LocalFree(szSid);
	szSid = NULL;
	HeapFree(hHeap, 0, szDomainName);
	szDomainName = NULL;
	HeapFree(hHeap, 0, pSid);
	pSid = NULL;
	return 0;
}


