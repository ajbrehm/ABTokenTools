#include <Windows.h>
#include <wchar.h>
#include <sddl.h>

#define SDDLLENGTH 256

LSTATUS status = 0;
BOOL ok = FALSE;
HANDLE hHive = NULL; // a registry hive
HANDLE hKey = NULL; // a registry key, first a hive
LPWSTR szKey = L""; // a registry path, used to point hKey into the hive
LPWSTR sddl = L""; // an sddl for a dacl coming from user and/or registry
int size = 0; // a size for various purposes
PSECURITY_DESCRIPTOR psd = NULL; // a pointer to a security descriptor
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

	if (args < 3) {
		wprintf(L"Syntax: RegACL HKCU|HKLM pathKey [sddl]");
		exit(0);
	}//if
	
	szKey = aCommandLine[1];
	if (CSTR_EQUAL==CompareStringW(LOCALE_SYSTEM_DEFAULT,0,szKey,4,L"HKCU",4)) {
		hHive = HKEY_CURRENT_USER;
	} else if (CSTR_EQUAL == CompareStringW(LOCALE_SYSTEM_DEFAULT, 0, szKey, 4, L"HKLM", 4)) {
		hHive = HKEY_LOCAL_MACHINE;
	} else {
		exit(1);
	}//if

	szKey = aCommandLine[2];

	if (4 == args) {

		sddl = aCommandLine[3];
		if (debug) { wprintf(L"SDDL given:\t%s\n", sddl); }
		ok = ConvertStringSecurityDescriptorToSecurityDescriptor(sddl, SDDL_REVISION_1, &psd, &size);
		error(L"ConvertStringSecurityDescriptorToSecurityDescriptor");
		
		sddl = (LPWSTR)GlobalAlloc(0, SDDLLENGTH);
		ok = ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, &size);
		error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
		if (debug) { wprintf(L"SDDL from security descriptor:\t%s\n", sddl); }

		status = RegOpenKeyEx(hHive, szKey, 0, KEY_ALL_ACCESS, &hKey);
		error(L"RegOpenKeyEx");

		status = RegSetKeySecurity(hKey, DACL_SECURITY_INFORMATION, psd);
		error(L"RegSetKeySecurity");

		status = RegCloseKey(hKey);
		error(L"RegCloseKey");

		//exit(0);
		

	}//if

	status = RegOpenKeyEx(hHive, szKey, 0, KEY_READ, &hKey);
	error(L"RegOpenKeyEx");

	size = 0;
	status = RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, NULL, &size);
	error(L"RegGetKeySecurity");
	psd = GlobalAlloc(0, size);
	if (NULL == psd) { return; }
	status = RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, psd, &size);
	error(L"RegGetKeySecurity");

	sddl = (LPWSTR)GlobalAlloc(0, SDDLLENGTH);
	ok = ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, &size);
	error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
	wprintf(L"%s\n", sddl);

	status = RegCloseKey(hKey);
	error(L"RegCloseKey");




}