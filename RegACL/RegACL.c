#include <Windows.h>
#include <wchar.h>
#include <sddl.h>

#define SDDLLENGTH 256

LSTATUS status = 0;
BOOL ok = FALSE;

void error(LPCWSTR sz)
{
	wprintf(sz);
	if ((0 == status)||(!ok)) {
		wprintf(L"\tOK\n");
	} else {
		wprintf(L"\t%d\n", status);
	}//if
	status = 0;
	ok = TRUE;
}

int main()
{

	LPCWSTR szKey = L"TestKey";
	HANDLE hKey = HKEY_CURRENT_USER;

	status = RegOpenKeyEx(hKey, szKey, 0, KEY_READ, &hKey);
	error(L"RegOpenKeyEx");

	int size = 0;
	status = RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, NULL, &size);
	error(L"RegGetKeySecurity");
	PSECURITY_DESCRIPTOR psd = GlobalAlloc(0, size);
	if (NULL == psd) { return; }
	status = RegGetKeySecurity(hKey, DACL_SECURITY_INFORMATION, psd, &size);
	error(L"RegGetKeySecurity");

	LPWSTR sddl = (LPWSTR)GlobalAlloc(0, SDDLLENGTH);
	ok = ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, DACL_SECURITY_INFORMATION, &sddl, &size);
	error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
	wprintf(L"%s\n", sddl);



	status = RegCloseKey(hKey);
	error(L"RegCloseKey");




}