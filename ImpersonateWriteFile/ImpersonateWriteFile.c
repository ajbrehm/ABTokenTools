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
#include <lmcons.h>

#define ERRORSIZE 40
#define LINELENGTH 255

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
	int cCommandLine = 0;
	LPWSTR* aCommandLine = CommandLineToArgvW(szCommandLine, &cCommandLine);

	if (cCommandLine < 3) {
		wprintf(L"ImpersonateWriteFile pid pathFile [sContent]\n");
		wprintf(L"Type or paste lines of text. Start a line with a dot to exit.");
		exit(0);
	}//if

	LPWSTR szPID = aCommandLine[1];
	LPWSTR pathFileName = aCommandLine[2];

	// get user name
	LPWSTR sUserName = (LPWSTR)malloc((UNLEN + 1) * sizeof(WCHAR));
	DWORD cchUserName = UNLEN + 1;
	ok = GetUserNameW(sUserName, &cchUserName);
	Error(L"GetUserNameW");
	wprintf(L"Now running as [%s].\n", sUserName);

	// read the process id into a DWORD
	DWORD pid = (DWORD)_wtol(szPID);

	// enable impersonate privilege
	EnablePrivilege(L"SeImpersonatePrivilege");

	// get the process handle
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	Error(L"OpenProcess");

	// get the process token, this might not work because access denied
	HANDLE hProcessToken = NULL;
	//ok = OpenProcessToken(hProcess, TOKEN_IMPERSONATE | TOKEN_DUPLICATE, &hProcessToken);
	ok = OpenProcessToken(hProcess, TOKEN_DUPLICATE, &hProcessToken);
	Error(L"OpenProcessToken");

	// duplicate token to read it
	HANDLE hDuplicateToken = NULL;
	ok = DuplicateToken(hProcessToken, SecurityImpersonation, &hDuplicateToken);
	Error(L"DuplicateToken");

	// set new thread token
	ok = SetThreadToken(NULL, hDuplicateToken);
	Error(L"SetThreadToken");

	// get user name
	cchUserName = UNLEN + 1;
	ok = GetUserNameW(sUserName, &cchUserName);
	Error(L"GetUserNameW");
	wprintf(L"Now running as [%s].\n", sUserName);

	// open file
	HANDLE hFile = CreateFileW(pathFileName, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
	Error(L"CreateFile");
	
	// write file
	DWORD written = 0;
	if (4 == cCommandLine) {
		WriteFile(hFile, aCommandLine[3], wcslen(aCommandLine[3]) * sizeof(WCHAR), &written, NULL);
	} else {
		LPWSTR sBuffer;
		BOOL tfContinue = TRUE;
		do {
			sBuffer = (LPWSTR)malloc(LINELENGTH * sizeof(WCHAR));
			if (sBuffer != NULL) {
				ok = wscanf_s(L"%s", sBuffer, LINELENGTH);
				if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, sBuffer, -1, L".", 1, NULL, NULL, 0)) {
					tfContinue = FALSE;
				} else {
					WriteFile(hFile, sBuffer, wcslen(sBuffer) * sizeof(WCHAR), &written, NULL);
					wprintf(L"[%d] bytes written.\n", written);
					WriteFile(hFile, L"\n", wcslen(L"\n") * sizeof(WCHAR), &written, NULL);
					wprintf(L"[%d] bytes written.\n", written);
				}//if
			}//if
		} while (tfContinue);
	}//if
	Error(L"WriteFile");

	// close file
	CloseHandle(hFile);
	Error(L"CloseHandle");

	// revert
	RevertToSelf();
	Error(L"RevertToSelf");

	// get user name
	cchUserName = UNLEN + 1;
	ok = GetUserNameW(sUserName, &cchUserName);
	Error(L"GetUserNameW");
	wprintf(L"Now running as [%s].\n", sUserName);

}
