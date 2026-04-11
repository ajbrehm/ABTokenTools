#include <Windows.h>
#include <wchar.h>

BOOL debug = TRUE;
BOOL ok = TRUE;
DWORD error = 0;
LSTATUS status = 0;

void Error(LPCWSTR sz)
{
	if (!debug) { return; }
	if (!ok || status) { error = GetLastError(); }
	fwprintf(stderr, L"%s\tOK: [%d]\tSTATUS: [%d], Error: [%d]\n", sz, ok, status, error);
	if (error) {
		exit(error);
	}//if
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
	privs.PrivilegeCount = 1;
	privs.Privileges[0].Luid = luid;
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	ok = AdjustTokenPrivileges(hCurrentProcessToken, FALSE, &privs, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
}

int main()
{
	LPWSTR sCmdLine = GetCommandLineW();
	int args = 0;
	LPWSTR* aCmdLine = CommandLineToArgvW(sCmdLine, &args);

	if (args < 3) {
		wprintf(L"RunInSession iSessionId pathImage iJobLimit\n");
		wprintf(L"iJobLimit should be set to 1 to avoid shell code. And the entire thing should be a scheduled task running as LocalSystem.\n");
		exit(0);
	}//if

	int iSessionId = _wtoi(aCmdLine[1]);
	LPWSTR pathImage = aCmdLine[2];
	int iJobLimit = 0;
	if (args > 3) {
		iJobLimit = _wtoi(aCmdLine[3]);
	}//if
	if (debug) { wprintf(L"Image [%s] in session with id [%d] and job limit [%d].\n", pathImage, iSessionId, iJobLimit); }

	HANDLE hToken;
	ok = OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken);
	Error(L"OpenProcessToken");
	HANDLE hModifiedToken;

	TOKEN_PRIVILEGES privs;
	LUID luid;
	ok = LookupPrivilegeValue(NULL, L"SeTcbPrivilege", &luid);
	privs.PrivilegeCount = 1;
	privs.Privileges[0].Luid = luid;
	ok = CreateRestrictedToken(hToken, 0, 0, NULL, privs.PrivilegeCount, privs.Privileges, 0, NULL, &hModifiedToken);
	Error(L"CreateRestrictedToken");
	EnablePrivilege(L"SeTcbPrivilege");
	ok = SetTokenInformation(hModifiedToken, TokenSessionId, &iSessionId, sizeof(DWORD));
	Error(L"SetTokenInformation");

	STARTUPINFO si = { .cb = sizeof(si) };
	PROCESS_INFORMATION pi;
	EnablePrivilege(L"SeAssignPrimaryTokenPrivilege");
	ok = CreateProcessAsUserW(hModifiedToken, pathImage, NULL, NULL, NULL, FALSE, CREATE_NEW_CONSOLE | CREATE_SUSPENDED, NULL, NULL, &si, &pi);
	Error(L"CreateProcessAsUserW");

	// get the process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
	Error(L"OpenProcess");

	// create a job object for the process
	HANDLE hJob = CreateJobObjectW(NULL, L"RunInSessionJob");
	JOBOBJECT_BASIC_LIMIT_INFORMATION basiclimit;
	wprintf(L"Setting job process limit to [%d].\n", iJobLimit);
	basiclimit.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
	basiclimit.ActiveProcessLimit = iJobLimit;
	ok = SetInformationJobObject(hJob, JobObjectBasicLimitInformation, &basiclimit, sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION));
	Error(L"SetInformationJobObject");

	// add process to job
	ok = AssignProcessToJobObject(hJob, hProcess);
	Error(L"AssignProcessToJobObject");

	// unsuspend main thread if it has been suspended
	if (pi.hThread) {
		ResumeThread(pi.hThread);
	}//if

	// clean up
	CloseHandle(hProcess);
	CloseHandle(hJob);

	CloseHandle(pi.hProcess);
	CloseHandle(hModifiedToken);
	CloseHandle(hToken);
}