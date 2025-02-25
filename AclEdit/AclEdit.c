#include <Windows.h>
#include <wchar.h>
#include <sddl.h>
#include <AclAPI.h>
#include <winternl.h>

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

void help()
{
	wprintf(L"AclEdit type pathObject [sddl] [D|E]\n\n");
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
	wprintf(L"Disable or enable inheritance with AclEdit type pathObject sddl D|E.\n");
	wprintf(L"File, service, printer, registry, and share objects take UNC paths. DS_OBJECT takes X.500 format.\n");
	wprintf(L"Registry paths start with \"CLASSES_ROOT\", \"CURRENT_USER\", \"MACHINE\", and \"USERS\". \"MACHINE\\SOFTWARE\" is a key.\n");
	wprintf(L"\"6 pid\" will display ACL of process with id pid\n");
	wprintf(L"\"6 \\KernelObjects\\Session#\" will display ACL of session number #.\n");
	wprintf(L"\"7 WinSta0 or 7 Default\" will display permissions of the current session's window station 0 or default desktop.\n\n");
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

	if (SE_SERVICE == objecttype) {
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, pathObject, -1, L"SCManager", 9, NULL, NULL, 0)) {
			handle = OpenSCManager(NULL, NULL, GENERIC_ALL);
			Error(L"OpenSCManager");
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
		if (debug) { fwprintf(stderr, L"SDDL given:\t%s\n", sddl); }

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
