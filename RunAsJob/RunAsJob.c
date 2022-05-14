#include <Windows.h>
#include <wchar.h>

BOOL debug = TRUE;
BOOL ok = TRUE;
LSTATUS status = 0;

void error(LPCWSTR sz)
{
	if (!debug) { return; }
	fwprintf(stderr, sz);
	if ((0 == status) || (!ok)) {
		fwprintf(stderr, L"\tOK\n");
	} else {
		fwprintf(stderr, L"\t%d\n", status);
	}//if
	status = 0;
	ok = TRUE;
}

int main()
{
	LPWSTR sHelp = L"Usage: CreateJob /image pathImage [/processlimit n]\n";

	// read command line
	LPWSTR sCmdLine = GetCommandLineW();
	int args = 0;
	LPWSTR* aCmdLine = CommandLineToArgvW(sCmdLine, &args);
	if (args < 2) {
		wprintf(sHelp);
		return 0;
	}//if

	if (0 == args % 2) {
		wprintf(sHelp);
		return 0;
	}//if

	if (debug) {
		for (int i = 0; i < args; i++) {
			wprintf(L"%d [%s]\n", i, aCmdLine[i]);
		}//for
	}//if

	// get arguments
	LPWSTR pathImage = L"";
	DWORD processlimit = 0;
	for (int i = 1; i < args; i=i+2) {
		if (CSTR_EQUAL == CompareStringEx(NULL, 0, aCmdLine[i], -1, L"/IMAGE", 6, NULL, NULL, NULL)) {
			pathImage = aCmdLine[i + 1];
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, 0, aCmdLine[i], -1, L"/PROCESSLIMIT", 13, NULL, NULL, NULL)) {
			processlimit = _wtoi(aCmdLine[i + 1]);
		}//if
	}//for
	
	if (0 == lstrlenW(pathImage)) {
		wprintf(sHelp);
		return 0;
	}//if

	// start process
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	si.cb = sizeof(STARTUPINFO);
	ZeroMemory(&si, si.cb);
	ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
	DWORD dwCreationFlags = 0;
	dwCreationFlags += CREATE_NEW_CONSOLE + CREATE_BREAKAWAY_FROM_JOB;
	ok = CreateProcess(pathImage, NULL, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &si, &pi);
	error(L"CreateProcess");
	CloseHandle(pi.hProcess);
	CloseHandle(pi.hThread);

	// get pid
	DWORD pid = pi.dwProcessId;

	// 

	// create a job object for the process
	HANDLE hJob = CreateJobObjectW(NULL, L"RunAsJob");
	JOBOBJECT_BASIC_LIMIT_INFORMATION basiclimit;
	basiclimit.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
	basiclimit.ActiveProcessLimit = processlimit;
	ok = SetInformationJobObject(hJob, JobObjectBasicLimitInformation, &basiclimit, sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION));
	error(L"SetInformationJobObject");

	// add process to job
	ok = AssignProcessToJobObject(hJob, pi.hProcess);
	error(L"AssignProcessToJobObject");

	// clean up

	if (debug) {
		LPWSTR sInput = GlobalAlloc(0, 0);
		wscanf_s(&sInput);
	}//if

}