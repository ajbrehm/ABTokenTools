#include <Windows.h>
#include <wchar.h>
#include <WtsApi32.h>

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

void help()
{
	LPWSTR sHelp = L"Usage: RunAsJob [/pid pid] [/image pathImage] [/processlimit processlimit] [/sessionid sessionid] [/domain sDomain] [/user sUser] [/password sPassword] [/args ...]\n";
	wprintf(sHelp);
	exit(0);
}

int main()
{
	// read command line
	LPWSTR sCmdLine = GetCommandLineW();
	int args = 0;
	LPWSTR* aCmdLine = CommandLineToArgvW(sCmdLine, &args);
	if (args < 2) {
		help();
	}//if

	if (debug) {
		for (int i = 0; i < args; i++) {
			wprintf(L"%d [%s]\n", i, aCmdLine[i]);
		}//for
	}//if

	// get arguments
	BOOL tfPid = FALSE;
	DWORD pid = -1;
	BOOL tfImage = FALSE;
	LPWSTR pathImage = L"";
	DWORD processlimit = 0;
	DWORD argsstart = 0;
	ULONG sessionid = 65536;
	LPWSTR sDomain = L"";
	LPWSTR sUser = L"";
	LPWSTR sPassword = L"";
	DWORD cDomainUserPassword = 0;
	for (int i = 1; i < args; i=i+2) {
		if (CSTR_EQUAL == CompareStringEx(NULL, 0, aCmdLine[i], -1, L"/pid", 4, NULL, NULL, 0)) {
			if (i + 1 == args) { help(); }
			pid = _wtoi(aCmdLine[i + 1]);
			tfPid = TRUE;
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, 0, aCmdLine[i], -1, L"/image", 6, NULL, NULL, 0)) {
			if (i + 1 == args) { help(); }
			pathImage = aCmdLine[i + 1];
			tfImage = TRUE;
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, 0, aCmdLine[i], -1, L"/processlimit", 13, NULL, NULL, 0)) {
			if (i + 1 == args) { help(); }
			processlimit = _wtoi(aCmdLine[i + 1]);
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, 0, aCmdLine[i], -1, L"/sessionid", 10, NULL, NULL, 0)) {
			if (i + 1 == args) { help(); }
			sessionid = _wtoi(aCmdLine[i + 1]);
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, 0, aCmdLine[i], -1, L"/domain", 7, NULL, NULL, 0)) {
			if (i + 1 == args) { help(); }
			sDomain = aCmdLine[i + 1];
			cDomainUserPassword++;
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, 0, aCmdLine[i], -1, L"/user", 5, NULL, NULL, 0)) {
			if (i + 1 == args) { help(); }
			sUser = aCmdLine[i + 1];
			cDomainUserPassword++;
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, 0, aCmdLine[i], -1, L"/password", 9, NULL, NULL, 0)) {
			if (i + 1 == args) { help(); }
			sPassword = aCmdLine[i + 1];
			cDomainUserPassword++;
		}//if
	}//for

	// check for missing image or pid
	if ((tfPid && tfImage) || (!tfPid && !tfImage)) {
		wprintf(L"pathImage or pid are mandatory.\n");
		return 0;
	}//if

	// find args for client program
	LPWSTR sNewCmdLine = wcsstr(sCmdLine, L"/args");
	if (NULL == sNewCmdLine) { sNewCmdLine = L""; }
	size_t length = wcslen(L"/args");
	sNewCmdLine += length + 1;

	// start process
	if (tfImage) {

		STARTUPINFO si;
		PROCESS_INFORMATION pi;
		si.cb = sizeof(STARTUPINFO);
		ZeroMemory(&si, si.cb);
		ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		DWORD dwCreationFlags = 0;
		//dwCreationFlags += CREATE_NEW_CONSOLE + CREATE_BREAKAWAY_FROM_JOB;
		dwCreationFlags += CREATE_NEW_CONSOLE;

		if (sessionid != 65536) {
			HANDLE hToken;
			ok = WTSQueryUserToken(sessionid, &hToken);
			error(L"WTSQueryUserToken");
			CreateProcessAsUserW(hToken, pathImage, sNewCmdLine, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &si, &pi);
			error(L"CreateProcessAsUserW");
		} else {
			if (3 == cDomainUserPassword) {
				ok = CreateProcessWithLogonW(sUser, sDomain, sPassword, 0, pathImage, sNewCmdLine, dwCreationFlags, NULL, NULL, &si, &pi);
				error(L"CreateProcessWithLogonW");
			} else {
				ok = CreateProcessW(pathImage, sNewCmdLine, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &si, &pi);
				error(L"CreateProcessW");
			}//if
		}//if
		pid = pi.dwProcessId;
		CloseHandle(pi.hProcess);
		CloseHandle(pi.hThread);
	}//if

	// get the process
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	error(L"OpenProcess");

	// create a job object for the process
	HANDLE hJob = CreateJobObjectW(NULL, L"RunAsJob");
	JOBOBJECT_BASIC_LIMIT_INFORMATION basiclimit;
	basiclimit.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
	basiclimit.ActiveProcessLimit = processlimit;
	ok = SetInformationJobObject(hJob, JobObjectBasicLimitInformation, &basiclimit, sizeof(JOBOBJECT_BASIC_LIMIT_INFORMATION));
	error(L"SetInformationJobObject");

	// add process to job
	ok = AssignProcessToJobObject(hJob, hProcess);
	error(L"AssignProcessToJobObject");

	// clean up
	CloseHandle(hProcess);
	CloseHandle(hJob);
	

}