#include <Windows.h>
#include <wchar.h>
#include <sddl.h>
#include <AclAPI.h>

LSTATUS status = 0;
BOOL ok = FALSE;
LPWSTR pathObject = (LPWSTR)L""; // a registry path
LPWSTR sddl = (LPWSTR)L""; // an sddl for a dacl
unsigned long size = 0; // a size for various purposes
PSECURITY_DESCRIPTOR psd = NULL; // a pointer to a security descriptor
PACL pdacl = NULL; // a pointer to a DACL
PSID owner = NULL; // a pointer to an owner
BOOL debug = TRUE;
HANDLE handle = NULL; // in case a handle is needed for something
DWORD pid = 0; // in case a pid is needed
DWORD result = 0; // store return code

void help()
{
	wprintf(L"DaclEdit type pathObject [sddl]\n\n");
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
}

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

void EnablePrivilege(LPWSTR sPrivilegeName)
{
	HANDLE hCurrentProcessToken;
	OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hCurrentProcessToken);
	TOKEN_PRIVILEGES privs;
	LUID luid;
	ok = LookupPrivilegeValue(NULL, sPrivilegeName, &luid);
	error(L"LookupPrivilegeValue");
	privs.PrivilegeCount = 1;
	privs.Privileges[0].Luid = luid;
	privs.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	ok = AdjustTokenPrivileges(hCurrentProcessToken, FALSE, &privs, sizeof(TOKEN_PRIVILEGES), NULL, NULL);
	error(L"AdjustTokenPrivileges");
}

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
	//error(L"_wtoi");

	pathObject = aCommandLine[2];

	SECURITY_INFORMATION DACL_OWNER = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;

	if (5 == args) {

		EnablePrivilege(L"SeTakeOwnershipPrivilege");

		sddl = aCommandLine[4];
		if (debug) { fwprintf(stderr, L"SDDL given:\t%s\n", sddl); }
		ok = ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, SDDL_REVISION_1, &psd, NULL);
		error(L"ConvertStringSecurityDescriptorToSecurityDescriptor");

		ok = ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, OWNER_SECURITY_INFORMATION, &sddl, NULL);
		error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
		if (debug) { fwprintf(stderr, L"SDDL for owner of new security descriptor:\t%s\n", sddl); }

		BOOL tfOwnerDefaulted = FALSE;
		status = GetSecurityDescriptorOwner(psd, &owner, &tfOwnerDefaulted);
		error(L"GetSecurityDescriptorOwner");

		status = SetNamedSecurityInfo(pathObject, (SE_OBJECT_TYPE)objecttype, OWNER_SECURITY_INFORMATION, owner, NULL, NULL, NULL);
		result = status;
		error(L"SetNamedSecurityInfo");

		

	}//if

	if (args >= 4) {

		sddl = aCommandLine[3];
		if (debug) { fwprintf(stderr, L"SDDL given:\t%s\n", sddl); }
		ok = ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, SDDL_REVISION_1, &psd, NULL);
		error(L"ConvertStringSecurityDescriptorToSecurityDescriptor");

		ok = ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, NULL);
		error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
		if (debug) { fwprintf(stderr, L"SDDL for DACL of new security descriptor:\t%s\n", sddl); }

		BOOL tfDaclpresent = FALSE;
		BOOL tfDaclDefaulted = FALSE;
		status = GetSecurityDescriptorDacl(psd, &tfDaclpresent, &pdacl, &tfDaclDefaulted);
		error(L"GetSecurityDescriptorDacl");
		
		status = SetNamedSecurityInfo(pathObject, (SE_OBJECT_TYPE)objecttype, DACL_SECURITY_INFORMATION, NULL, NULL, pdacl, NULL);
		result = status;
		error(L"SetNamedSecurityInfo");

		LocalFree(psd);

	}//if

	status = GetNamedSecurityInfo(pathObject, (SE_OBJECT_TYPE)objecttype, DACL_OWNER , NULL, NULL, NULL, NULL, &psd);
	error(L"GetNamedSecurityInfo");
	ok = ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, DACL_OWNER, &sddl, &size);
	error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
	wprintf(L"%s\n", sddl);

	LocalFree(psd);
	LocalFree(sddl);
	LocalFree(owner);

	return result;



}