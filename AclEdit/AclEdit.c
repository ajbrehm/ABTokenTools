#include <Windows.h>
#include <wchar.h>
#include <sddl.h>
#include <AclAPI.h>

BOOL debug = FALSE;

BOOL confirm = TRUE;
LSTATUS status = 0;
BOOL ok = TRUE;
LPWSTR pathObject = NULL; // a path to an object
LPWSTR sddl = NULL; // an sddl for a dacl
PSECURITY_DESCRIPTOR psd = NULL; // a pointer to a security descriptor
PACL pdacl = NULL; // a pointer to a DACL
PSID owner = NULL; // a pointer to an owner
HANDLE handle = NULL; // in case a handle is needed for something
DWORD pid = 0; // in case a pid is needed
DWORD result = 0; // store return code

void Help()
{
	wprintf(L"AclEdit /Type type /Object pathObject /PId pid /SDDL sddl /Inheritance D|E\n");
	wprintf(L" /Value sRegistryValueName /ScheduledTask pathScheduledTask /TakeOwnership\n\n");
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
	wprintf(L"%s\n", L"13\tSE_REGISTRY_WOW64_64KEY");
	wprintf(L"\nCurrently supports setting DACLs and owners. Setting an owner might require the appropriate privilege.\n");
	wprintf(L"File, service, printer, registry, and share objects take UNC paths, DS_OBJECT takes X.500 format.\n");
	wprintf(L"Registry hives are CLASSES_ROOT, CONFIG, USER, MACHINE, and USERS.\n\n");
}

void Error(LPCWSTR sz)
{
	if (!debug) { return; }
	fwprintf(stderr, sz);
	if (0 != status) { ok = FALSE; }
	if (ok) {
		fwprintf(stderr, L"\tOK\n");
	} else {		
		fwprintf(stderr, L"\tSTATUS: [%d], Last Error: [%d]\n", status, GetLastError());
	}//if
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

DWORD GetSecurityInfoWrapper(HANDLE handle, LPWSTR pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID* ppsidOwner, PSID* ppsidGroup, PACL* ppDacl, PACL* ppSacl, PSECURITY_DESCRIPTOR* ppSecurityDescriptor)
{
	if (handle) {
		status = GetSecurityInfo(handle, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor);
		Error(L"GetSecurityInfo");
	} else {
		status = GetNamedSecurityInfo(pObjectName, ObjectType, SecurityInfo, ppsidOwner, ppsidGroup, ppDacl, ppSacl, ppSecurityDescriptor);
		Error(L"GetNamedSecurityInfo");
	}//if
}

DWORD SetSecurityInfoWrapper(HANDLE handle, LPWSTR pObjectName, SE_OBJECT_TYPE ObjectType, SECURITY_INFORMATION SecurityInfo, PSID psidOwner, PSID psidGroup, PACL pDacl, PACL pSacl)
{
	if (handle) {
		status = SetSecurityInfo(handle, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl);
		Error(L"SetSecurityInfo");
	} else {
		status = SetNamedSecurityInfo(pObjectName, ObjectType, SecurityInfo, psidOwner, psidGroup, pDacl, pSacl);
		Error(L"SetNamedSecurityInfo");
	}//if
}

DWORD GetSetSddlFromToSecurityInfo(int objecttype, LPWSTR sInheritance)
{
	SECURITY_INFORMATION DACL_AND_OWNER_SECURITY_INFORMATION = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
	SECURITY_INFORMATION DACL_SECURITY_INFORMATION_AND_THEN_SOME = DACL_SECURITY_INFORMATION;

	if (sddl) {

		if (sInheritance) {
			if (0 == wcscmp(L"D", sInheritance)) {
				if (debug) { fwprintf(stderr, L"Disabling inheritance.\n"); }
				DACL_SECURITY_INFORMATION_AND_THEN_SOME = DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION;
			}//if
			if (0 == wcscmp(L"E", sInheritance)) {
				DACL_SECURITY_INFORMATION_AND_THEN_SOME = DACL_SECURITY_INFORMATION | UNPROTECTED_DACL_SECURITY_INFORMATION;
				if (debug) { fwprintf(stderr, L"Enabling inheritance.\n"); }
			}//if
		}//if

		if (debug) { fwprintf(stderr, L"SDDL given: %s\n", sddl); }

		ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &psd, NULL);
		Error(L"ConvertStringSecurityDescriptorToSecurityDescriptor");

		BOOL tfOwnerDefaulted = FALSE;
		status = GetSecurityDescriptorOwner(psd, &owner, &tfOwnerDefaulted);
		Error(L"GetSecurityDescriptorOwner");

		if (NULL != owner) {
			EnablePrivilege(L"SeRestorePrivilege");
			EnablePrivilege(L"SeTakeOwnershipPrivilege");
			status = SetSecurityInfoWrapper(handle, pathObject, (SE_OBJECT_TYPE)objecttype, OWNER_SECURITY_INFORMATION, owner, NULL, NULL, NULL);
			result = status;
			Error(L"SetNamedSecurityInfo");
		}//if

		BOOL tfDaclPresent = FALSE;
		BOOL tfDaclDefaulted = FALSE;
		status = GetSecurityDescriptorDacl(psd, &tfDaclPresent, &pdacl, &tfDaclDefaulted);
		Error(L"GetSecurityDescriptorDacl");

		if (NULL != pdacl) {
			status = SetSecurityInfoWrapper(handle, pathObject, (SE_OBJECT_TYPE)objecttype, DACL_SECURITY_INFORMATION_AND_THEN_SOME, NULL, NULL, pdacl, NULL);
			result = status;
			Error(L"SetNamedSecurityInfo");
		}//if

	}//if

	status = GetSecurityInfoWrapper(handle, pathObject, (SE_OBJECT_TYPE)objecttype, DACL_AND_OWNER_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &psd);
	ok = ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, DACL_AND_OWNER_SECURITY_INFORMATION, &sddl, NULL);
	Error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
}

DWORD GetSddlFromBinaryRegistryValue(HKEY hKey, LPWSTR pathRegistryKey, LPWSTR pathRegistrySubKey, LPWSTR sValueName)
{
	status = RegOpenKeyExW(hKey, pathRegistryKey, 0, KEY_READ, &hKey);
	Error(L"RegOpenKeyExW KEY_READ");
	DWORD cbData = 0;
	if (debug) { fwprintf(stderr, L"Registry value [%s] data has size of [%u].\n", sValueName, cbData); }
	status = RegGetValueW(hKey, pathRegistrySubKey, sValueName, RRF_RT_REG_BINARY, NULL, NULL, &cbData);
	Error(L"RegGetValueW");
	if (debug) { fwprintf(stderr, L"Registry value [%s] data has size of [%u].\n", sValueName, cbData); }
	PVOID pData = GlobalAlloc(0, cbData);
	status = RegGetValueW(hKey, pathRegistrySubKey, sValueName, RRF_RT_REG_BINARY, NULL, pData, &cbData);
	Error(L"RegGetValueW");
	RegCloseKey(hKey);
	Error(L"RegCloseKey");
	psd = (PSECURITY_DESCRIPTOR)pData;
	if (!psd) { return 1; }
	DWORD cbSddl = 0;
	SECURITY_INFORMATION secinfo = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;// | SACL_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION;
	status = ConvertSecurityDescriptorToStringSecurityDescriptorW(psd, SDDL_REVISION_1, secinfo, &sddl, &cbSddl);
	Error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
	GlobalFree(pData);
}

DWORD SetSddlToBinaryRegistryValue(HKEY hKey, LPWSTR pathRegistryKey, LPWSTR pathRegistrySubKey, LPWSTR sValueName)
{
	status = RegOpenKeyExW(hKey, pathRegistryKey, 0, KEY_WRITE, &hKey);
	if (debug) { fwprintf(stderr, L"Trying to open key [%s\\%s].\n", pathRegistryKey, pathRegistrySubKey); }
	Error(L"RegOpenKeyExW KEY_WRITE");
	LONG cbData = 0;
	ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &psd, &cbData);
	Error(L"ConvertStringSecurityDescriptorToSecurityDescriptor");
	if (debug) { fwprintf(stderr, L"Registry data to be written has size of [%u].\n", cbData); }
	status = RegSetValueExW(hKey, sValueName, 0, REG_BINARY, psd, cbData);
	Error(L"RegSetValueExW");
	RegCloseKey(hKey);
	Error(L"RegCloseKey");
}

DWORD GetSetSddlFromToBinaryRegistryValue(HKEY hKey, LPWSTR pathRegistryKey, LPWSTR pathRegistrySubKey, LPWSTR sValueName)
{
	if (sddl) {
		return SetSddlToBinaryRegistryValue(hKey, pathRegistryKey, pathRegistrySubKey, sValueName);
	} else {
		return GetSddlFromBinaryRegistryValue(hKey, pathRegistryKey, pathRegistrySubKey, sValueName);
	}//if
}

int main()
{
	LPWSTR szCommandLine = GetCommandLineW();
	int args = 0;
	LPWSTR* aCommandLine = CommandLineToArgvW(szCommandLine, &args);

	if (args < 3) {
		Help();
		exit(0);
	}//if

	int objecttype = 0;
	DWORD pid = 0;
	LPWSTR sInheritance = NULL;
	LPWSTR sValueName = NULL;
	LPWSTR pathScheduledTask = NULL;
	LPWSTR pathRegistryKey = NULL;
	HKEY hKey = NULL;

	for (int i = 1; i < args; i = i + 2) {
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCommandLine[i], -1, L"/TYPE", 5, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			objecttype = (int)_wtoi(aCommandLine[i + 1]);
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCommandLine[i], -1, L"/OBJECT", 7, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			pathObject = aCommandLine[i + 1];
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCommandLine[i], -1, L"/PID", 4, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			pid = (int)_wtoi(aCommandLine[i + 1]);
			if (pid) {
				handle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
				Error(L"OpenProcess");
			}//if
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCommandLine[i], -1, L"/SDDL", 5, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			sddl = aCommandLine[i + 1];
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCommandLine[i], -1, L"/INHERITANCE", 12, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			sInheritance = aCommandLine[i + 1];
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCommandLine[i], -1, L"/VALUE", 6, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			sValueName = aCommandLine[i + 1];
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCommandLine[i], -1, L"/SCHEDULEDTASK", 14, NULL, NULL, 0)) {
			if (i + 1 == args) { Help(); }
			pathScheduledTask = aCommandLine[i + 1];
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, aCommandLine[i], -1, L"/TAKEOWNERSHIP", 14, NULL, NULL, 0)) {
			sddl = L"O:BA";
		}//if
	}//for

	if (debug) {
		fwprintf(stderr, L"Type: [%d]\n", objecttype);
		fwprintf(stderr, L"Object: [%s]\n", pathObject);
		fwprintf(stderr, L"PId: [%d]\n", pid);
		fwprintf(stderr, L"SDDL: [%s]\n", sddl);
		fwprintf(stderr, L"Inheritance: [%s]\n", sInheritance);
		fwprintf(stderr, L"Value: [%s]\n", sValueName);
		fwprintf(stderr, L"ScheduledTask: [%s]\n", pathScheduledTask);
	}//if

	if (objecttype && pathObject) {
		GetSetSddlFromToSecurityInfo(objecttype, sInheritance);
	}//if

	if (pid) {
		GetSetSddlFromToSecurityInfo(SE_KERNEL_OBJECT, sInheritance);
	}//if

	if (sValueName && pathObject) {
		if (debug) { fwprintf(stderr, L"Path is [%s].\n", pathObject); }
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, pathObject, 12, L"CLASSES_ROOT", 12, NULL, NULL, 0)) {
			hKey = HKEY_LOCAL_MACHINE;
			pathObject = pathObject + 13;
			if (debug) { fwprintf(stderr, L"Hive is CLASSES_ROOT.\n"); }
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, pathObject, 6, L"CONFIG", 6, NULL, NULL, 0)) {
			hKey = HKEY_LOCAL_MACHINE;
			pathObject = pathObject + 7;
			if (debug) { fwprintf(stderr, L"Hive is CONFIG.\n"); }
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, pathObject, 7, L"MACHINE", 7, NULL, NULL, 0)) {
			hKey = HKEY_LOCAL_MACHINE;
			pathObject = pathObject + 8;
			if (debug) { fwprintf(stderr, L"Hive is MACHINE.\n"); }
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, pathObject, 4, L"USER", 4, NULL, NULL, 0)) {
			hKey = HKEY_LOCAL_MACHINE;
			pathObject = pathObject + 5;
			if (debug) { fwprintf(stderr, L"Hive is USER.\n"); }
		}//if
		if (CSTR_EQUAL == CompareStringEx(NULL, LINGUISTIC_IGNORECASE, pathObject, 5, L"USERS", 5, NULL, NULL, 0)) {
			hKey = HKEY_LOCAL_MACHINE;
			pathObject = pathObject + 6;
			if (debug) { fwprintf(stderr, L"Hive is (all) USERS.\n"); }
		}//if
		GetSetSddlFromToBinaryRegistryValue(hKey, pathObject, NULL, sValueName);
		sddl = NULL;
		GetSetSddlFromToBinaryRegistryValue(hKey, pathObject, NULL, sValueName);
	}//if

	if (pathScheduledTask) {
		GetSetSddlFromToBinaryRegistryValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree", pathScheduledTask, L"SD");
		sddl = NULL;
		GetSetSddlFromToBinaryRegistryValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree", pathScheduledTask, L"SD");
	}//if

	if (debug) { fwprintf(stderr, L"Resulting SDDL: [%s]\n", sddl); }
	wprintf(L"%s", sddl);
	
	if (sddl) {
		LocalFree(sddl);
	}//if
	if (psd) { LocalFree(psd); }
	if (pid) { CloseHandle(handle); }

	return result;
}