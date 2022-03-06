#include <Windows.h>
#include <wchar.h>
#include <sddl.h>
#include <AclAPI.h>

#define SDDLLENGTH 256

LSTATUS status = 0;
BOOL ok = FALSE;
LPWSTR pathKey = L""; // a registry path
LPWSTR sddl = L""; // an sddl for a dacl coming from user and/or registry
int size = 0; // a size for various purposes
PSECURITY_DESCRIPTOR psd = NULL; // a pointer to a security descriptor
PACL pdacl = NULL; // a pointer to a DACL
BOOL debug = TRUE;

void error(LPCWSTR sz)
{
	if (!debug) { return; }
	fwprintf(stderr, sz);
	if ((0 == status)||(!ok)) {
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

	if (args < 2) {
		wprintf(L"Syntax: RegACL pathKey [sddl]");
		exit(0);
	}//if
	
	pathKey = aCommandLine[1];
	
	if (3 == args) {

		sddl = aCommandLine[2];
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

		status = SetNamedSecurityInfo(pathKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, pdacl, NULL);
		error(L"SetNamedSecurityInfo");
	

	}//if
		
	status = GetNamedSecurityInfo(pathKey, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, NULL, NULL, &psd);
	error(L"GetNamedSecurityInfo");

	sddl = (LPWSTR)GlobalAlloc(0, SDDLLENGTH);
	ok = ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, &size);
	error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
	wprintf(L"%s\n", sddl);





}