//MIT License
//
//Copyright(c) 2022 Andrew J. Brehm
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

BOOL debug = 1;
BOOL ok;
DWORD error;

void Debug(LPWSTR s)
{
	if (debug) {
		wprintf(L"%s\n", s);
	}//if
}

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

void Help()
{
	LPWSTR sHelp = L"Usage: RunToken pid pathImage [sArguments]";
	wprintf(L"%s\n", sHelp);
	exit(0);
}

int main()
{
	// prepare reading command line arguments
	LPWSTR szCommandLine = GetCommandLineW();
	int count = 0;
	LPWSTR* aCommandLine = CommandLineToArgvW(szCommandLine, &count);
	if (count < 2) {
		Help();
	}//if
	LPWSTR szPID = aCommandLine[1];
	Debug(szPID);
	LPWSTR pathImage = NULL;
	if (count > 2) {
		pathImage = aCommandLine[2];
		Debug(pathImage);
	}//if
	LPWSTR sArguments = NULL;
	if (count > 3) {
		sArguments = aCommandLine[3];
		Debug(sArguments);
	}//if

	// read the process id into a DWORD
	DWORD pid = (DWORD)_wtol(szPID);

	// enable debug privilege
	EnablePrivilege(L"SeDebugPrivilege");

	// get the process handle
	HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, pid);
	Error(L"OpenProcess");

	// get the process token, this might not work because access denied
	HANDLE hProcessToken = NULL;
	ok = OpenProcessToken(hProcess, TOKEN_IMPERSONATE | TOKEN_DUPLICATE | TOKEN_ASSIGN_PRIMARY | TOKEN_READ, &hProcessToken);
	Error(L"OpenProcessToken");

	// duplicate token to read it
	HANDLE hDuplicateToken = NULL;
	ok = DuplicateTokenEx(hProcessToken, TOKEN_ASSIGN_PRIMARY | TOKEN_DUPLICATE | TOKEN_QUERY | TOKEN_ADJUST_DEFAULT | TOKEN_ADJUST_SESSIONID, NULL, SecurityImpersonation, TokenPrimary, &hDuplicateToken);
	Error(L"DuplicateTokenEx");

	// start new process
	if (pathImage) {
		wprintf(L"Trying to start process from image [%s]...\n", pathImage);
		STARTUPINFOW si;
		PROCESS_INFORMATION pi;
		si.cb = sizeof(STARTUPINFOW);
		ZeroMemory(&si, si.cb);
		ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		DWORD dwCreationFlags = 0;
		dwCreationFlags += CREATE_NEW_CONSOLE;
		ok = CreateProcessWithTokenW(hDuplicateToken, 0, pathImage, sArguments, dwCreationFlags, NULL, NULL, &si, &pi);
		Error(L"CreateProcessWithTokenW");
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}//if

	// close
	CloseHandle(hDuplicateToken);

}
