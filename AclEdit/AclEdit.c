#include <Windows.h>
#include <wchar.h>
#include <sddl.h>
#include <AclAPI.h>
#include <winternl.h>

#define BUFFERSIZE 1024

LSTATUS status = 0;
BOOL ok = FALSE;
DWORD error = 0;
LPWSTR pathObject = (LPWSTR)L""; // a path to an object
LPWSTR sddl; // an sddl for a dacl
PSECURITY_DESCRIPTOR pSD = NULL; // a pointer to a security descriptor
PACL pdacl = NULL; // a pointer to a DACL
PSID owner = NULL; // a pointer to an owner
BOOL debug = FALSE;
HANDLE handle = NULL; // in case a handle is needed for something
DWORD pid = 0; // in case a pid is needed
DWORD result = 0; // store return code
LPWSTR sDomainAccountName = NULL;
PWSTR sSid = NULL;

int LookupAccountNameAndStore(LPWSTR sAccountName)
{
	DWORD cbSid = 0;
	DWORD cchDomainName = 0;
	SID_NAME_USE use = 0;
	LookupAccountNameW(NULL, sAccountName, NULL, &cbSid, NULL, &cchDomainName, &use);
	LPWSTR sDomainName = GlobalAlloc(0, cchDomainName * sizeof(WCHAR));
	PSID pSid = GlobalAlloc(0, cbSid);
	LookupAccountNameW(NULL, sAccountName, pSid, &cbSid, sDomainName, &cchDomainName, &use);
	sSid = NULL;
	if (NULL != pSid) { ConvertSidToStringSidW(pSid, &sSid); }
	GlobalFree(pSid);
	pSid = NULL;
	GlobalFree(sDomainName);
	sDomainName = NULL;
	return 0;
}

int LookupAccountSidAndStore(LPWSTR sSid)
{
	PSID pSid = GlobalAlloc(0, SECURITY_MAX_SID_SIZE);
	ConvertStringSidToSidW(sSid, &pSid);
	DWORD cchAccountName = 0;
	DWORD cchDomainName = 0;
	SID_NAME_USE use = 0;
	LookupAccountSidW(NULL, pSid, NULL, &cchAccountName, NULL, &cchDomainName, &use);
	LPWSTR sAccountName = GlobalAlloc(0, cchAccountName * sizeof(WCHAR));
	if (NULL == sAccountName) { return 8; }
	LPWSTR sDomainName = GlobalAlloc(0, cchDomainName * sizeof(WCHAR));
	if (NULL == sDomainName) { return 8; }
	LookupAccountSidW(NULL, pSid, sAccountName, &cchAccountName, sDomainName, &cchDomainName, &use);
	DWORD cchDomainAccountName = cchAccountName + sizeof(L"\\") + cchAccountName + sizeof(L"\0");
	sDomainAccountName = (LPWSTR)GlobalAlloc(0, cchDomainAccountName * sizeof(WCHAR));
	if (NULL == sDomainAccountName) { return 8; }
	wcscpy_s(sDomainAccountName, cchDomainAccountName, sDomainName);
	wcscat_s(sDomainAccountName, cchDomainAccountName, L"\\");
	wcscat_s(sDomainAccountName, cchDomainAccountName, sAccountName);
	GlobalFree(pSid);
	pSid = NULL;
	GlobalFree(sAccountName);
	sAccountName = NULL;
	GlobalFree(sDomainName);
	sDomainName = NULL;
	return 0;
}

int ConvertSddlWithAcountNamesToSddl(LPWSTR sddlWithAccountNames)
{
	DWORD cbSddlWithAccountNames = wcslen(sddlWithAccountNames) * sizeof(WCHAR) + wcslen(L"\0") * sizeof(WCHAR);
	LPWSTR sCopyOfSddlWithAccountNames = GlobalAlloc(0, cbSddlWithAccountNames);
	if (NULL == sCopyOfSddlWithAccountNames) { return 8; }
	wcscpy_s(sCopyOfSddlWithAccountNames, cbSddlWithAccountNames, sddlWithAccountNames);
	LPWSTR context = GlobalAlloc(0, wcslen(sddlWithAccountNames) * sizeof(WCHAR));
	if (NULL == context) { return 8; }
	LPWSTR token = wcstok_s(sddlWithAccountNames, L":;()", &context);
	DWORD cbSddlWithoutAccountNames = wcslen(token) * sizeof(WCHAR) + BUFFERSIZE;
	LPWSTR sddlWithoutAccountNames = (LPWSTR)GlobalAlloc(0, cbSddlWithoutAccountNames);
	if (NULL == sddlWithoutAccountNames) { return 8; }
	if (token) {
		wcscpy_s(sddlWithoutAccountNames, cbSddlWithoutAccountNames, L"");
	}//if
	while (token) {
		sSid = NULL;
		LookupAccountNameAndStore(token);
		if (NULL != sSid) { token = sSid; }
		//wprintf(L"Token [%s]\n", token);
		//wprintf(L"Context [%s]\n",context);
		wcscat_s(sddlWithoutAccountNames, cbSddlWithoutAccountNames, token);
		//wprintf(L"sddlWithoutAccountNames [%s]\n", sddlWithoutAccountNames);
		WCHAR delimiter = sCopyOfSddlWithAccountNames[token - sddlWithAccountNames + wcslen(token)];
		wprintf(L"Delimiter [%c]\n", delimiter);
		DWORD posDelimiter = wcslen(sddlWithoutAccountNames);
		sddlWithoutAccountNames[posDelimiter] = delimiter;
		sddlWithoutAccountNames[posDelimiter + 1] = L'\0';
		wprintf(L"sddlWithoutAccountNames [%s]\n", sddlWithoutAccountNames);
		token = wcstok_s(NULL, L":;()", &context);
	}//while
	DWORD posDelimiter = wcslen(sddlWithoutAccountNames);
	sddlWithoutAccountNames[posDelimiter] = L')';
	sddlWithoutAccountNames[posDelimiter + 1] = L'\0';
	sddl = sddlWithoutAccountNames;
	return 0;
}

void help()
{
	wprintf(L"\nAclEdit type pathObject [<sddl>] [D|E]\n");
	wprintf(L"%s\n", L"0\tSE_UNKNOWN_OBJECT_TYPE");
	wprintf(L"%s\n", L"1\tSE_FILE_OBJECT");
	wprintf(L"%s\n", L"2\tSE_SERVICE");
	wprintf(L"%s\n", L"3\tSE_PRINTER");
	wprintf(L"%s\n", L"4\tSE_REGISTRY_KEY");
	wprintf(L"%s\n", L"5\tSE_LMSHARE");
	wprintf(L"%s\n", L"6\tSE_KERNEL_OBJECT");
	wprintf(L"%s\n", L"7\tSE_WINDOW_OBJECT");
	wprintf(L"%s\n", L"8\tSE_DS_OBJECT");
	wprintf(L"%s\n", L"9\tSE_DS_OBJECT_ALL");
	wprintf(L"%s\n", L"10\tSE_PROVIDER_DEFINED_OBJECT");
	wprintf(L"%s\n", L"11\tSE_WMIGUID_OBJECT");
	wprintf(L"%s\n", L"12\tSE_REGISTRY_WOW64_32KEY");
	wprintf(L"%s\n", L"13\tSE_REGISTRY_WOW64_64KEY\n");
	wprintf(L"Currently supports setting DACLs and owners. Setting an owner might require the appropriate privilege.\n");
	wprintf(L"Disable or enable inheritance with \"AclEdit type pathObject sddl D|E\".\n");
	wprintf(L"Account name will be translated into SIDs. Hopefully.\n");
	wprintf(L"File, service, printer, registry, and share objects take UNC paths. DS_OBJECT takes X.500 format.\n");
	wprintf(L"Registry paths start with \"CLASSES_ROOT\", \"CURRENT_USER\", \"MACHINE\", and \"USERS\". \"MACHINE\\SOFTWARE\" is a key.\n");
	wprintf(L"Registry paths starting with \"HKLM:\" or \"HKCU:\" will be translated into native path names.\n");
	wprintf(L"\"AclEdit 6 pid\" will display ACL of process with id pid\n");
	wprintf(L"\"AclEdit 6 \\KernelObjects\\Session#\" will display ACL of session number #.\n");
	wprintf(L"\"AclEdit 7 WinSta0\" or \"AclEdit 7 Default\" will display permissions of the current session's window station 0 or default desktop.\n\n");
}

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

void GetSecurityInfoWrapper(HANDLE handle, LPWSTR pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID* ppsidOwner, PSID* ppsidGroup, PACL* ppDacl, PACL* ppSacl, PSECURITY_DESCRIPTOR* ppSecurityDescriptor)
{
	if (handle) {
		status = GetSecurityInfo(handle, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor);
		Error(L"GetSecurityInfo");
	} else {
		status = GetNamedSecurityInfo(pObjectName, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor);
		Error(L"GetNamedSecurityInfo");
	}//if
}

void SetSecurityInfoWrapper(HANDLE handle, LPWSTR pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID psidOwner, PSID psidGroup, PACL pDacl, PACL pSacl)
{
	if (handle) {
		status = SetSecurityInfo(handle, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl);
		Error(L"SetSecurityInfo");
	} else {
		status = SetNamedSecurityInfo(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl);
		Error(L"SetNamedSecurityInfo");
	}//if
}

typedef NTSTATUS(WINAPI* NtOpenSessionCall) (
	PHANDLE SessionHandle,
	ACCESS_MASK DesiredAccess,
	POBJECT_ATTRIBUTES ObjectAttributes);

int main()
{
	LPWSTR szCommandLine = GetCommandLineW();
	int args = 0;
	LPWSTR* aCommandLine = CommandLineToArgvW(szCommandLine, &args);

	if (args < 3) {
		help();
		exit(0);
	}//if

	int objecttype = 0;
	LPWSTR sObjectType = aCommandLine[1];
	objecttype = (int)_wtoi(sObjectType);
	Error(L"_wtoi");

	pathObject = aCommandLine[2];

	DWORD pid = 0;
	if (SE_KERNEL_OBJECT == objecttype) {
		pid = (int)_wtoi(pathObject);
		if (pid) {
			handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
		}//if
		if (NULL == handle) {
			HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
			if (NULL == hNtdll) { return 8; }
			Error(L"GetModuleHandleW");
			NtOpenSessionCall NtOpenSession = (NtOpenSessionCall)GetProcAddress(hNtdll, "NtOpenSession");
			Error(L"GetProcAddress");
			UNICODE_STRING ucsPathObject;
			ucsPathObject.Buffer = pathObject;
			ucsPathObject.Length = wcslen(pathObject) * sizeof(WCHAR);
			ucsPathObject.MaximumLength = ucsPathObject.Length;
			OBJECT_ATTRIBUTES oa;
			InitializeObjectAttributes(&oa, &ucsPathObject, 0, NULL, NULL);
			Error(L"InitializeObjectAttributes");
			status = NtOpenSession(&handle, GENERIC_ALL, &oa);
			Error(L"NtOpenSession");
		}//if
	}//if

	if (SE_WINDOW_OBJECT == objecttype) {
		handle = OpenWindowStationW(pathObject, FALSE, GENERIC_ALL);
		Error(L"OpenWindowStationW");
		if (NULL == handle) {
			handle = OpenDesktopW(pathObject, 0, FALSE, GENERIC_ALL);
			Error(L"OpenDesktopW");
		}//if
	}//if

	SECURITY_INFORMATION DACL_AND_OWNER_SECURITY_INFORMATION = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
	SECURITY_INFORMATION DACL_SECURITY_INFORMATION_AND_THEN_SOME = DACL_SECURITY_INFORMATION;

	if (args >= 4) {

		if (5 == args) {

			LPWSTR sInheritance = aCommandLine[4];
			if (0 == wcscmp(L"D", sInheritance)) {
				if (debug) { fwprintf(stderr, L"Disabling inheritance.\n"); }
				DACL_SECURITY_INFORMATION_AND_THEN_SOME = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
			}//if
			if (0 == wcscmp(L"E", sInheritance)) {
				DACL_SECURITY_INFORMATION_AND_THEN_SOME = DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION;
				if (debug) { fwprintf(stderr, L"Enabling inheritance.\n"); }
			}//if

		}//if

		sddl = aCommandLine[3];

		wprintf(L"%s\n", sddl);
		ConvertSddlWithAcountNamesToSddl(sddl);
		wprintf(L"%s\n", sddl);
		exit(0);

		if (debug) { fwprintf(stderr, L"SDDL given:\t%s\n", sddl); }

		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, sddl, -1, L"+", 1, NULL, NULL, 0)) {
			GetSecurityInfoWrapper(handle, pathObject, (SE_OBJECT_TYPE)objecttype, DACL_AND_OWNER_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pSD);
		}//if

		if (debug) { fwprintf(stderr, L"SDDL given after checking for addition:\t%s\n", sddl); }

		ok = ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, SDDL_REVISION_1, &pSD, NULL);
		Error(L"ConvertStringSecurityDescriptorToSecurityDescriptor");

		BOOL tfOwnerDefaulted = FALSE;
		ok = GetSecurityDescriptorOwner(pSD, &owner, &tfOwnerDefaulted);
		Error(L"GetSecurityDescriptorOwner");

		if (NULL != owner) {
			EnablePrivilege(L"SeRestorePrivilege");
			EnablePrivilege(L"SeTakeOwnershipPrivilege");
			SetSecurityInfoWrapper(handle, pathObject, (SE_OBJECT_TYPE)objecttype, OWNER_SECURITY_INFORMATION, owner, NULL, NULL, NULL);
		}//if

		BOOL tfDaclpresent = FALSE;
		BOOL tfDaclDefaulted = FALSE;
		ok = GetSecurityDescriptorDacl(pSD, &tfDaclpresent, &pdacl, &tfDaclDefaulted);
		Error(L"GetSecurityDescriptorDacl");

		if (NULL != pdacl) {
			SetSecurityInfoWrapper(handle, pathObject, (SE_OBJECT_TYPE)objecttype, DACL_SECURITY_INFORMATION_AND_THEN_SOME, NULL, NULL, pdacl, NULL);
		}//if

	}//if

	GetSecurityInfoWrapper(handle, pathObject, (SE_OBJECT_TYPE)objecttype, DACL_AND_OWNER_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &pSD);
	ok = ConvertSecurityDescriptorToStringSecurityDescriptor(pSD, SDDL_REVISION_1, DACL_AND_OWNER_SECURITY_INFORMATION, &sddl, NULL);
	Error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
	wprintf(L"%s\n", sddl);
	LocalFree(sddl);
	LocalFree(pSD);

	if (pid) {
		CloseHandle(handle);
	}//if

	return result;

}
