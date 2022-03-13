#include <Windows.h>
#include <wchar.h>
#include <sddl.h>
#include <AclAPI.h>

#define SDDLLENGTH 256

LSTATUS status = 0;
BOOL ok = FALSE;
LPWSTR pathObject = (LPWSTR)L""; // a registry path
LPWSTR sddl = (LPWSTR)L""; // an sddl for a dacl
unsigned long size = 0; // a size for various purposes
PSECURITY_DESCRIPTOR psd = NULL; // a pointer to a security descriptor
PACL pdacl = NULL; // a pointer to a DACL
BOOL debug = TRUE;
HANDLE handle = NULL; // in case a handle is needed for something
DWORD pid = 0; // in case a pid is needed

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

	if (4 == args) {

		sddl = aCommandLine[3];
		if (debug) { wprintf(L"SDDL given:\t%s\n", sddl); }
		ok = ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, SDDL_REVISION_1, &psd, &size);
		error(L"ConvertStringSecurityDescriptorToSecurityDescriptor");

		sddl = (LPWSTR)GlobalAlloc(0, SDDLLENGTH);
		ok = ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, &size);
		error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
		if (debug) { wprintf(L"SDDL from security descriptor:\t%s\n", sddl); }

		BOOL tfDaclpresent = FALSE;
		BOOL tfDaclDefaulted = FALSE;
		status = GetSecurityDescriptorDacl(psd, &tfDaclpresent, &pdacl, &tfDaclDefaulted);
		error(L"GetSecurityDescriptorDacl");

		status = SetNamedSecurityInfo(pathObject, (SE_OBJECT_TYPE)objecttype, DACL_SECURITY_INFORMATION, NULL, NULL, pdacl, NULL);
		error(L"SetNamedSecurityInfo");


	}//if

	status = GetNamedSecurityInfo(pathObject, (SE_OBJECT_TYPE)objecttype, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &psd);
	error(L"GetNamedSecurityInfo");
	sddl = (LPWSTR)GlobalAlloc(0, SDDLLENGTH);
	ok = ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, &size);
	error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
	wprintf(L"%s\n", sddl);





}