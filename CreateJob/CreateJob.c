#include <Windows.h>
#include <wchar.h>

BOOL debug = TRUE;
BOOL ok = TRUE;
LSTATUS status = 0;

void Error(LPCWSTR sz)
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
	// read command line
	LPWSTR sCmdLine = GetCommandLineW();
	int args = 0;
	LPWSTR* aCmdLine = CommandLineToArgvW(sCmdLine, &args);
	if (args < 3) {
		wprintf(L"Usage: CreateJob limit pid\n");
		return 0;
	}//if

	if (debug) {
		for (int i = 0; i < args; i++) {
			wprintf(L"%d [%s]\n", i, aCmdLine[i]);
		}//for
	}//if

	// get process limit
	DWORD processes = wcstoul(aCmdLine[1], NULL, 10);
	if (debug) { wprintf(L"processes [%d]\n", processes); }

	// get pid
	DWORD pid = wcstoul(aCmdLine[2], NULL, 10);
	if (debug) { wprintf(L"pid [%d]\n", pid); }

	// get the process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	Error(L"OpenProcess");
	
	// create a job object for the process
	HANDLE hJob = CreateJobObjectW(NULL, L"CreateJob");
	JOBOBJECT_BASIC_LIMIT_INFORMATION basiclimit;
	basiclimit.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
	basiclimit.ActiveProcessLimit = processes;
	ok = SetInformationJobObject(hJob, JobObjectBasicLimitInformation, &basiclimit, sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION));
	Error(L"SetInformationJobObject");

	// add process to job
	ok = AssignProcessToJobObject(hJob, hProcess);
	Error(L"AssignProcessToJobObject");

	// clean up
	CloseHandle(hProcess);
	CloseHandle(hJob);

}