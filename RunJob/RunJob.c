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

#include <Windows.h>
#include <wchar.h>
#include <WtsApi32.h>
#include <sysinfoapi.h>
#include <UserEnv.h>
#include <accctrl.h>
#include <aclapi.h>
#include <sddl.h>
#define PASSWORDBUFFERSIZE 512

BOOL debug = TRUE;
BOOL ok = TRUE;
DWORD error = 0;
LSTATUS status = 0;
LPWSTR sddl = NULL; // can always use this
DWORD size = 0; // same

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

void SetWindowStationSecurity(PSID pSid)
{
	HWINSTA hWindowStation = GetProcessWindowStation();
	SECURITY_INFORMATION secinfo = DACL_SECURITY_INFORMATION;
	size = 0;
	ok = GetUserObjectSecurity(hWindowStation, &secinfo, NULL, 0, &size);
	Error(L"GetUserObjectSecurity");
	PSECURITY_DESCRIPTOR pSD = HeapAlloc(GetProcessHeap(), 0, size);
	if (!pSD) { exit(1); }
	ok = GetUserObjectSecurity(hWindowStation, &secinfo, pSD, size, &size);
	Error(L"GetUserObjectSecurity");

	PACL pDACL = NULL;
	BOOL tfDAclPresent = FALSE;
	BOOL tfDaclDefaulted = FALSE;
	ok = GetSecurityDescriptorDacl(pSD, &tfDAclPresent, &pDACL, &tfDaclDefaulted);
	Error(L"GetSecurityDescriptorDacl");

	if (debug) {
		sddl = NULL;
		ok = ConvertSecurityDescriptorToStringSecurityDescriptor(pSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, NULL);
		Error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
		wprintf(L"sddl before: [%s]\n", sddl);
	}//if

	EXPLICIT_ACCESS access;
	ZeroMemory(&access, sizeof(EXPLICIT_ACCESS));
	access.grfAccessMode = SET_ACCESS;
	access.grfAccessPermissions = WINSTA_ALL_ACCESS | READ_CONTROL;
	access.grfInheritance = NO_INHERITANCE;
	access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
	access.Trustee.TrusteeType = TRUSTEE_IS_USER;
	access.Trustee.ptstrName = pSid;

	PACL pNewDACL;
	status = SetEntriesInAcl(1, &access, pDACL, &pNewDACL);
	Error(L"SetEntriesInAcl");

	PSECURITY_DESCRIPTOR pNewSD = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), 0, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (!pNewSD) { exit(1); }
	ok = InitializeSecurityDescriptor(pNewSD, SECURITY_DESCRIPTOR_REVISION);
	Error(L"InitializeSezurityDescriptor");

	ok = SetSecurityDescriptorDacl(pNewSD, TRUE, pNewDACL, TRUE);
	Error(L"SetSecurityDescriptorDacl");

	ok = SetUserObjectSecurity(hWindowStation, &secinfo, pNewSD);
	Error(L"SetUserObjectSecurity");

	ok = GetUserObjectSecurity(hWindowStation, &secinfo, NULL, 0, &size);
	Error(L"GetUserObjectSecurity");
	PSECURITY_DESCRIPTOR pUltimateSD = HeapAlloc(GetProcessHeap(), 0, size);
	if (!pSD) { exit(1); }
	ok = GetUserObjectSecurity(hWindowStation, &secinfo, pSD, size, &size);
	Error(L"GetUserObjectSecurity");

	if (debug) {
		sddl = NULL;
		ok = ConvertSecurityDescriptorToStringSecurityDescriptor(pSD, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, NULL);
		Error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
		wprintf(L"sddl after: [%s]\n", sddl);
	}//if

	HeapFree(GetProcessHeap(),0,pSD);
	HeapFree(GetProcessHeap(), 0, pNewSD);
	HeapFree(GetProcessHeap(), 0, pUltimateSD);
}

void Help()
{
	wprintf(L"\n#0: RunJob /PId pid /JobProcessLimit limit (appplies quota to running process)\n\n");
	wprintf(L"#1: RunJob /Image pathImage [/JobProcessLimit limit] [[[/Domain sDomain] /User sUser] /Password sPassword] [/SessionId id] [/args ...] (creates a process with various attributes)\n\n");
	wprintf(L"#2: RunJob /Image pathImage /UseRunAs [/args ...] (spawns a process using RunAs verb)\n\n");
	wprintf(L"#3: RunJob /WindowStationPermission [/Domain sDomain] /User sUser (allows user access to session window station, use before #1)\n\n");
	exit(0);
}

int main()
{
	//// do not debug if running in session 0
	//DWORD mysessionid = 65536;
	//ok = ProcessIdToSessionId(GetCurrentProcessId(), &mysessionid);
	//Error(L"ProcessIdToSessionId");
	//if (0 == mysessionid) { debug = FALSE; }
	//if (debug) { wprintf(L"Not running in session 0.\n"); }

	// read command line
	LPWSTR sCmdLine = GetCommandLineW();
	int args = 0;
	LPWSTR* aCmdLine = CommandLineToArgvW(sCmdLine, &args);
	if (args < 2) {
		Help();
	}//if

	if (debug) {
		for (int i = 0; i < args; i++) {
			wprintf(L"%d [%s]\n", i, aCmdLine[i]);
		}//for
	}//if

	// get arguments
	BOOL tfArgs = FALSE;
	BOOL tfPid = FALSE;
	DWORD pid = -1;
	BOOL tfImage = FALSE;
	LPWSTR pathImage = NULL;
	DWORD processlimit = 0;
	DWORD argsstart = 0;
	DWORD sessionid = 65536;
	LPWSTR sDomain = NULL;
	LPWSTR sUser = NULL;
	LPWSTR sPassword = NULL;
	DWORD cDomainUserPassword = 0;
	LPWSTR sJobName = L"UnnamedJob";
	BOOL tfCreateJob = FALSE;
	BOOL tfRunAs = FALSE;
	BOOL tfWindowStationPermission = FALSE;

	for (int i = 1; i < args; i++) {
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCmdLine[i], -1, L"/args", 5, NULL, NULL, 0)) {
			tfArgs = TRUE;
			break;
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCmdLine[i], -1, L"/PId", 4, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			pid = _wtoi(aCmdLine[i + 1]);
			tfPid = TRUE;
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCmdLine[i], -1, L"/Image", 6, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			pathImage = aCmdLine[i + 1];
			tfImage = TRUE;
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCmdLine[i], -1, L"/JobProcessLimit", 16, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			processlimit = _wtoi(aCmdLine[i + 1]);
			tfCreateJob = TRUE;
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCmdLine[i], -1, L"/SessionId", 10, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			sessionid = _wtoi(aCmdLine[i + 1]);
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCmdLine[i], -1, L"/Domain", 7, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			sDomain = aCmdLine[i + 1];
			cDomainUserPassword++;
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCmdLine[i], -1, L"/User", 5, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			sUser = aCmdLine[i + 1];
			cDomainUserPassword++;
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCmdLine[i], -1, L"/Password", 9, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			sPassword = aCmdLine[i + 1];
			cDomainUserPassword++;
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCmdLine[i], -1, L"/JobName", 8, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			sJobName = aCmdLine[i + 1];
			tfCreateJob = TRUE;
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCmdLine[i], -1, L"/UseRunAs", 9, NULL, NULL, 0)) {
			tfRunAs = TRUE;
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCmdLine[i], -1, L"/WindowStationPermission", 24, NULL, NULL, 0)) {
			tfWindowStationPermission = TRUE;
		}//if
	}//for

	// check for missing image or pid
	if ((!tfPid)&&(!pathImage)&&(!tfWindowStationPermission)) {
		wprintf(L"pathImage or pid are mandatory unless setting permissions.\n");
		return 0;
	}//if

	// find args for client program
	LPWSTR sNewCmdLine = NULL;
	if (tfArgs) {
		sNewCmdLine = wcsstr(sCmdLine, L"/args");
		if (NULL == sNewCmdLine) { sNewCmdLine = L""; }
		size_t length = wcslen(L"/args");
		sNewCmdLine += length + 1;
	}//if

	// configure process creation flags
	DWORD dwCreationFlags = 0;
	if (tfCreateJob) { dwCreationFlags += CREATE_SUSPENDED; }

	// spawn process
	if (tfRunAs) {
		if (!pathImage) { exit(1); }
		if (debug) { wprintf(L"Spawning process with RunAs...\n"); }
		ShellExecuteW(NULL, L"RunAs", pathImage, sNewCmdLine, NULL, SW_NORMAL);
		error = GetLastError();
		Error(L"ShellExecuteW");
		return error;
	}//if

	// check for domain, user, and password
	if (cDomainUserPassword) {
		if (!sDomain) {
			DWORD cchComputerName = 0;
			ok = GetComputerNameExW(ComputerNameNetBIOS, NULL, &cchComputerName);
			Error(L"GetComputerNameExW");
			LPWSTR sComputerName = (LPWSTR)GlobalAlloc(0, (cchComputerName + 1) * sizeof(WCHAR));
			ok = GetComputerNameExW(ComputerNameNetBIOS, sComputerName, &cchComputerName);
			Error(L"GetComputerNameExW");
			if (debug) { fwprintf(stderr, L"Computer name is [%s].\n", sComputerName); }
			sDomain = sComputerName;
			cDomainUserPassword++;
		}//if
		if ((!sPassword)&&(!tfWindowStationPermission)) {
			wprintf(L"Enter password (which will NOT be echoed):");
			sPassword = (LPWSTR)GlobalAlloc(0, PASSWORDBUFFERSIZE);
			if (!sPassword) { exit(1); }
			DWORD i = 0;
			WCHAR c;
			while ((c = _getwch()) != L'\r') {
				wprintf(L"*");
				sPassword[i] = c;
				i++;
			}//while
			wprintf(L"\n");
			sPassword[i] = 0;
			size_t cchPassword = wcslen(sPassword);
			if (debug) { fwprintf(stderr, L"Password is [%s].\n", sPassword); }
			cDomainUserPassword++;
		}//if
	}//if

	if (tfWindowStationPermission) {

		if (debug) { wprintf(L"Window station permissions\n"); }

		if ((!sUser) || (!sDomain)) {
			wprintf(L"Missing user name or unclear domain namen.\n");
			exit(1);
		}//if
		DWORD cchUser = wcslen(sUser);
		DWORD cchDomain = wcslen(sDomain);
		DWORD cchDomainUser = cchDomain + 1 + cchUser;
		LPWSTR sDomainUser = HeapAlloc(GetProcessHeap(), 0, cchDomainUser * sizeof(WCHAR));
		if (!sDomainUser) { exit(1); }
		wcscpy_s(sDomainUser, cchDomain+1, sDomain);
		Error(L"wcscpy_s");
		sDomainUser[cchDomain] = '\\';
		wcscpy_s(sDomainUser+cchDomain+1, cchUser+1, sUser);
		Error(L"wcscpy_s");
		if (debug) { wprintf(L"DomainUser [%s]\n", sDomainUser); }

		DWORD cbSid = 0;
		SID_NAME_USE use = 0;
		DWORD cchReferencedDomainName = 0;
		LookupAccountNameW(NULL, sDomainUser, NULL, &cbSid, NULL, &cchReferencedDomainName, &use);
		Error(L"LookupAccountNameW");
		PSID pSid = HeapAlloc(GetProcessHeap(), 0, cbSid);
		LPWSTR sDomainName = HeapAlloc(GetProcessHeap(), 0, cchReferencedDomainName * sizeof(WCHAR));
		LookupAccountNameW(NULL, sDomainUser, pSid, &cbSid, sDomainName, &cchReferencedDomainName, &use);
		Error(L"LookupAccountNameW");

		if (debug) {
			LPWSTR szSid = L"SID was not translated";
			wprintf(L"%s\n", szSid);
			if (NULL != pSid) { ConvertSidToStringSidW(pSid, &szSid); }
			wprintf(L"%s\n", szSid);
			LocalFree(szSid);
		}//if

		SetWindowStationSecurity(pSid);

		exit(0);

	}//if


	// start process
	PROCESS_INFORMATION pi;
	if (tfImage) {

		STARTUPINFOW si;
		si.cb = sizeof(STARTUPINFOW);
		ZeroMemory(&si, si.cb);
		ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
		dwCreationFlags += CREATE_NEW_CONSOLE;

		if (sessionid != 65536) {
			HANDLE hToken = NULL;
			if (3 == cDomainUserPassword) {
				if (debug) { wprintf(L"SessionId is [%d]. User is [%s]. Domain is [%s]. Password is [%s].\n", sessionid, sUser, sDomain, sPassword); }

				ok = LogonUserW(sUser, sDomain, sPassword, LOGON32_LOGON_INTERACTIVE, LOGON32_PROVIDER_WINNT50, &hToken);
				Error(L"LogonUserW");
			
				EnablePrivilege(L"SeTcbPrivilege");
				ok = SetTokenInformation(hToken, TokenSessionId, &sessionid, sizeof(DWORD));
				Error(L"SetTokenInformation");

				EnablePrivilege(L"SeIncreaseQuotaPrivilege");
				EnablePrivilege(L"SeAssignPrimaryTokenPrivilege");

				ok = CreateProcessAsUserW(hToken, pathImage, sNewCmdLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
				Error(L"CreateProcessAsUserW");

				CloseHandle(hToken);
				exit(0);
			} else {
				ok = WTSQueryUserToken(sessionid, &hToken);
				Error(L"WTSQueryUserToken");
				CreateProcessAsUserW(hToken, pathImage, sNewCmdLine, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &si, &pi);
				Error(L"CreateProcessAsUserW");
				CloseHandle(hToken);
			}//if
		} else {
			if (3 == cDomainUserPassword) {
				ok = CreateProcessWithLogonW(sUser, sDomain, sPassword, 0, pathImage, sNewCmdLine, dwCreationFlags, NULL, NULL, &si, &pi);
				Error(L"CreateProcessWithLogonW");
			} else {
				ok = CreateProcessW(pathImage, sNewCmdLine, NULL, NULL, FALSE, dwCreationFlags, NULL, NULL, &si, &pi);
				Error(L"CreateProcessW");
			}//if
		}//if
		pid = pi.dwProcessId;
	}//if

	if (tfCreateJob) {
		// get the process
		HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		Error(L"OpenProcess");
		
		// create a job object for the process
		HANDLE hJob = CreateJobObjectW(NULL, sJobName);
		JOBOBJECT_BASIC_LIMIT_INFORMATION basiclimit;
		if (processlimit) {
			wprintf(L"Setting job process limit to [%d].\n", processlimit);
			basiclimit.LimitFlags = JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
			basiclimit.ActiveProcessLimit = processlimit;
		}//if
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
	}//if

	// more clean up
	if (pi.hProcess) { CloseHandle(pi.hProcess); }
	if (pi.hThread) { CloseHandle(pi.hThread); }

	wprintf(L"%d\n", pid);
	if (tfCreateJob) { wprintf(L"Job Name: [%s]\n", sJobName); }
	
}