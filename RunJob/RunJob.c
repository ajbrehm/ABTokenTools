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
	PSECURITY_DESCRIPTOR psd = HeapAlloc(GetProcessHeap(), 0, size);
	if (!psd) { exit(1); }
	ok = GetUserObjectSecurity(hWindowStation, &secinfo, psd, size, &size);
	Error(L"GetUserObjectSecurity");

	PACL pdacl = NULL;
	BOOL tfDAclPresent = FALSE;
	BOOL tfDaclDefaulted = FALSE;
	ok = GetSecurityDescriptorDacl(psd, &tfDAclPresent, &pdacl, &tfDaclDefaulted);
	Error(L"GetSecurityDescriptorDacl");

	if (debug) {
		sddl = NULL;
		ok = ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, NULL);
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

	PACL pnewdacl;
	status = SetEntriesInAcl(1, &access, pdacl, &pnewdacl);
	Error(L"SetEntriesInAcl");

	PSECURITY_DESCRIPTOR pnewsd = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), 0, SECURITY_DESCRIPTOR_MIN_LENGTH);
	if (!pnewsd) { exit(1); }
	ok = InitializeSecurityDescriptor(pnewsd, SECURITY_DESCRIPTOR_REVISION);
	Error(L"InitializeSezurityDescriptor");

	ok = SetSecurityDescriptorDacl(pnewsd, TRUE, pnewdacl, TRUE);
	Error(L"SetSecurityDescriptorDacl");

	ok = SetUserObjectSecurity(hWindowStation, &secinfo, pnewsd);
	Error(L"SetUserObjectSecurity");

	ok = GetUserObjectSecurity(hWindowStation, &secinfo, NULL, 0, &size);
	Error(L"GetUserObjectSecurity");
	psd = HeapAlloc(GetProcessHeap(), 0, size);
	if (!psd) { exit(1); }
	ok = GetUserObjectSecurity(hWindowStation, &secinfo, psd, size, &size);
	Error(L"GetUserObjectSecurity");

	if (debug) {
		sddl = NULL;
		ok = ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, NULL);
		Error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
		wprintf(L"sddl after: [%s]\n", sddl);
	}//if

}

void Help()
{
	wprintf(L"\n#0: RunJob /PId pid /JobProcessLimit limit (appplies quota to running process)\n\n");
	wprintf(L"#1: RunJob /Image pathImage [/JobProcessLimit limit] [[[/Domain sDomain] /User sUser] /Password sPassword] [/SessionId id] [/args ...] (creates a process with various attributes)\n\n");
	wprintf(L"#2: RunJob /Image pathImage /UseRunAs [/args ...] (spawns a process using RunAs verb)\n\n");
	wprintf(L"#3: RunJob /WindowStationPermission /DomainUser sDomainUser (allows user access to session window station, use before #1)\n\n");
	exit(0);
}

int main()
{
	// do not debug if running in session 0
	DWORD mysessionid = 65536;
	ok = ProcessIdToSessionId(GetCurrentProcessId(), &mysessionid);
	Error(L"ProcessIdToSessionId");
	if (0 == mysessionid) { debug = FALSE; }
	if (debug) { wprintf(L"Not running in session 0.\n"); }

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
	BOOL tfCreateProcessThenRunAs = FALSE;
	BOOL tfWindowStationPermission = FALSE;
	LPWSTR sDomainUser = NULL;

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
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCmdLine[i], -1, L"/DomainUser", 11, NULL, NULL, 0)) {
			sDomainUser = aCmdLine[i + 1];
		}//if
	}//for

	// check for missing image or pid
	if ((!tfPid)&&(!pathImage)&&(!tfWindowStationPermission)) {
		wprintf(L"pathImage or pid are mandatory unless setting permissions.\n");
		return 0;
	}//if

	if (tfWindowStationPermission) {

		if (!sDomainUser) {
			wprintf(L"DomainUser is missing.\n");
			exit(1);
		}//if

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
		if (!sPassword) {
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

			
				EnablePrivilege(L"SeIncreaseQuotaPrivilege");

				size = 0;
				ok = GetTokenInformation(hToken, TokenUser, NULL, size, &size);
				Error(L"GetTokenInformation");
				PTOKEN_USER pUser = HeapAlloc(GetProcessHeap(), 0, size);
				ok = GetTokenInformation(hToken, TokenUser, pUser, size, &size);
				Error(L"GetTokenInformation");
				PSID pSid = pUser->User.Sid;
				LPWSTR szSid = NULL;
				ConvertSidToStringSidW(pSid, &szSid);
				wprintf(L"Sid is [%s].\n", szSid);

				HWINSTA hWindowStation = GetProcessWindowStation();
				SECURITY_INFORMATION secinfo = DACL_SECURITY_INFORMATION;
				size = 0;
				ok = GetUserObjectSecurity(hWindowStation, &secinfo, NULL, 0, &size);
				Error(L"GetUserObjectSecurity");
				PSECURITY_DESCRIPTOR psd = HeapAlloc(GetProcessHeap(), 0, size);
				ok = GetUserObjectSecurity(hWindowStation, &secinfo, psd, size, &size);
				Error(L"GetUserObjectSecurity");

				PACL pdacl = NULL;
				BOOL tfDAclPresent = FALSE;
				BOOL tfDaclDefaulted = FALSE;
				ok = GetSecurityDescriptorDacl(psd, &tfDAclPresent, &pdacl, &tfDaclDefaulted);
				Error(L"GetSecurityDescriptorDacl");
				
				EXPLICIT_ACCESS access;
				ZeroMemory(&access, sizeof(EXPLICIT_ACCESS));
				access.grfAccessMode = SET_ACCESS;
				access.grfAccessPermissions = WINSTA_ALL_ACCESS | READ_CONTROL;
				access.grfInheritance = NO_INHERITANCE;
				access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
				access.Trustee.TrusteeType = TRUSTEE_IS_USER;
				access.Trustee.ptstrName = pUser->User.Sid;
						

				PACL pnewdacl;
				status = SetEntriesInAcl(1, &access, pdacl, &pnewdacl);
				Error(L"SetEntriesInAcl");

				PSECURITY_DESCRIPTOR pnewsd = (PSECURITY_DESCRIPTOR)HeapAlloc(GetProcessHeap(), 0, SECURITY_DESCRIPTOR_MIN_LENGTH);
				ok = InitializeSecurityDescriptor(pnewsd, SECURITY_DESCRIPTOR_REVISION);
				Error(L"InitializeSezurityDescriptor");

				LPWSTR sddl = NULL;
				ok = ConvertSecurityDescriptorToStringSecurityDescriptor(pnewsd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, NULL);
				Error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
				wprintf(sddl);



				ok = SetSecurityDescriptorDacl(pnewsd, TRUE, pnewdacl, TRUE);
				Error(L"SetSecurityDescriptorDacl");

				//if (debug) {
				//	sddl = NULL;
				//	ok = ConvertSecurityDescriptorToStringSecurityDescriptor(pnewsd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, NULL);
				//	Error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
				//	wprintf(sddl);
				//}//if
				
				ok = SetUserObjectSecurity(hWindowStation, &secinfo, pnewsd);
				Error(L"SetUserObjectSecurity");

				ok = GetUserObjectSecurity(hWindowStation, &secinfo, NULL, 0, &size);
				Error(L"GetUserObjectSecurity");
				psd = HeapAlloc(GetProcessHeap(), 0, size);
				ok = GetUserObjectSecurity(hWindowStation, &secinfo, psd, size, &size);
				Error(L"GetUserObjectSecurity");

				if (debug) {
					sddl = NULL;
					ok = ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, NULL);
					Error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
					wprintf(sddl);
				}//if

				ok = CreateProcessAsUserW(hToken, pathImage, sNewCmdLine, NULL, NULL, FALSE, CREATE_NEW_CONSOLE, NULL, NULL, &si, &pi);
				Error(L"CreateProcessAsUserW");

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