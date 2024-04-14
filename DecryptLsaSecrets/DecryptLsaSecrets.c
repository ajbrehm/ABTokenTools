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



#define SECURITY_WIN32
#include <Windows.h>
#include <security.h>
#include <wchar.h>
#include <NTSecAPI.h>
#define ERRORSIZE 40
#define SECRETSIZE 100

BOOL debug = FALSE;
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
	LPWSTR szPID = aCommandLine[1];
	LPWSTR szServiceName = aCommandLine[2];

	// read the process id into a DWORD
	DWORD pid = (DWORD)_wtol(szPID);

	// enable debug privilege
	EnablePrivilege(L"SeDebugPrivilege");

	// get the process handle
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	Error(L"OpenProcess");

	// get the process token, this might not work because access denied
	HANDLE hProcessToken = NULL;
	ok = OpenProcessToken(hProcess, TOKEN_IMPERSONATE|TOKEN_DUPLICATE, &hProcessToken);
	Error(L"OpenProcessToken");

	// duplicate token to read it
	HANDLE hDuplicateToken = NULL;
	ok = DuplicateToken(hProcessToken, SecurityImpersonation, &hDuplicateToken);
	Error(L"DuplicateToken");

	// set new thread token
	ok = SetThreadToken(NULL, hDuplicateToken);
	Error(L"SetThreadToken");

	// prepare LsaOpenPolicy
	LSA_OBJECT_ATTRIBUTES loa;
	loa.Length = 0;
	loa.RootDirectory = NULL;
	loa.Attributes = 0;
	loa.SecurityDescriptor = NULL;
	loa.SecurityQualityOfService = NULL;
	ZeroMemory(&loa, sizeof(loa));

	LSA_UNICODE_STRING lusLocalSystem;
	lusLocalSystem.Buffer = NULL;
	lusLocalSystem.Length = 0;
	lusLocalSystem.MaximumLength = 0;

	LSA_UNICODE_STRING lusSecretLocation;
	lusSecretLocation.Buffer = aCommandLine[2];
	lusSecretLocation.Length = wcslen(lusSecretLocation.Buffer) * sizeof(WCHAR);
	lusSecretLocation.MaximumLength = lusSecretLocation.Length;

	// LsaOpenPolicy
	LSA_HANDLE hPolicy = NULL;
	LsaOpenPolicy(&lusLocalSystem, &loa, POLICY_ALL_ACCESS, &hPolicy);
	Error(L"LsaOpenPolicy");
		
	// retrieve secret
	PLSA_UNICODE_STRING plusSecret = NULL;
	ok = LsaRetrievePrivateData(hPolicy, &lusSecretLocation, &plusSecret);
	Error(L"LsaRetrievePrivateData");
	
	// output
	wprintf(L"%s\n", plusSecret->Buffer);
	
	// frees
	LsaFreeMemory(plusSecret);
	LsaClose(hPolicy);
}
