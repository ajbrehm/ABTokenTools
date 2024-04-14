#include <Windows.h>
#include <wchar.h>
#include <WtsApi32.h>
#include <sysinfoapi.h>

BOOL debug = FALSE;
BOOL ok = TRUE;
DWORD error = 0;
LSTATUS status = 0;

// modify these
LPWSTR sUserName = L"user";
LPWSTR sPassword = L"password";
// stop modifying here

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
	LPWSTR szCommandLine = GetCommandLineW();
	if (debug) { wprintf(L"%s\n",szCommandLine); }
	int count = 0;
	LPWSTR* aCommandLine = CommandLineToArgvW(szCommandLine, &count);

	if (count < 3) {
		wprintf(L"ReplaceToken logonmethod pathImage [sArguments]\n");
		wprintf(L"logonmethod can be 1 (CreateProcessAsUser()) or 2 (CreateProcessWithLogon()).\n");
		wprintf(L"You need SeAssignPrimaryTokenPrivilege to use logon method 1.\n");
		wprintf(L"You need the Secondary Logon service to use logon method 2.\n");
		wprintf(L"Note that you have to compile this tool with a user name and password for the user to be used.\n");
		wprintf(L"ReplaceToken creates a process with a job process limit of 1!.\n");
		exit(0);
	}//if
	
	LPWSTR sLogonType = aCommandLine[1];
	int logontype = _wtoi(sLogonType);

	LPWSTR pathImage = aCommandLine[2];

	LPWSTR sArguments = L"";

	if (count > 2) {
		int offset = wcslen(aCommandLine[0]) + 2 + 1 + wcslen(aCommandLine[1]) + 1 + wcslen(aCommandLine[2]) + 1; // plus two quotes plus space plus space plus space
		sArguments = szCommandLine + offset;
		if (debug) { wprintf(L"%s\n", sArguments); }
	}//if

	PROCESS_INFORMATION pi;
	
	STARTUPINFOW si;
	ZeroMemory(&si, sizeof(STARTUPINFOW));
	si.cb = sizeof(STARTUPINFOW);
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	DWORD dwCreationFlags = 0;
	dwCreationFlags += CREATE_SUSPENDED;

	if (1 == logontype) {

		EnablePrivilege(L"SeAssignPrimaryTokenPrivilege");

		HANDLE hUserToken = NULL;
		ok = LogonUserW(sUserName, L".", sPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_DEFAULT, &hUserToken);
		Error(L"LogonUser");

		ok = CreateProcessAsUserW(hUserToken, pathImage, sArguments, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &si, &pi);
		Error(L"CreateProcessAsUser");

	}//

	if (2 == logontype) {

		ok = CreateProcessWithLogonW(sUserName, L".", sPassword, 0, pathImage, sArguments, dwCreationFlags, NULL, NULL, &si, &pi);
		Error(L"CreateProcessWithLogonW");
		
	}//if

	if (pi.hProcess) {
		// get the process
		//HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pi.dwProcessId);
		//Error(L"OpenProcess");

		// create a job object for the process
		HANDLE hJob = CreateJobObjectW(NULL, L"");
		JOBOBJECT_BASIC_LIMIT_INFORMATION basiclimit;
		basiclimit.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
		basiclimit.ActiveProcessLimit = 1;
		ok = SetInformationJobObject(hJob, JobObjectBasicLimitInformation, &basiclimit, sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION));
		Error(L"SetInformationJobObject");

		// add process to job
		ok = AssignProcessToJobObject(hJob, pi.hProcess);
		Error(L"AssignProcessToJobObject");

		// unsuspend main thread if it has been suspended
		if (pi.hThread) {
			ResumeThread(pi.hThread);
		}//if

		// clean up
		CloseHandle(hJob);
	}//if

	if (pi.hThread) { CloseHandle(pi.hThread); }
	if (pi.hProcess) { CloseHandle(pi.hProcess); }


}