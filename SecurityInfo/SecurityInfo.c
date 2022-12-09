#include <Windows.h>
#include <wchar.h>
#include <sddl.h>
#include <AclAPI.h>
#include <WinUser.h>

LSTATUS status = 0;
BOOL ok = FALSE;
LPWSTR sddl; // an sddl for a dacl
PSECURITY_DESCRIPTOR psd = NULL; // a pointer to a security descriptor
PACL pdacl = NULL; // a pointer to a DACL
PSID owner = NULL; // a pointer to an owner
BOOL debug = TRUE;
//HWINSTA hWinStation = NULL;
HDESK hDesktop = NULL;
errno_t errno;

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
	wprintf(L"%d\n", args);

	//hWinStation = GetProcessWindowStation();
	hDesktop = OpenDesktop(L"default", 0, FALSE, GENERIC_ALL | GENERIC_WRITE);
	
	SECURITY_INFORMATION DACL_AND_OWNER_SECURITY_INFORMATION = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
	//status = GetSecurityInfo(hWinStation, SE_WINDOW_OBJECT, DACL_AND_OWNER_SECURITY_INFORMATION, &owner, NULL, &pdacl, NULL, &psd);
	status = GetSecurityInfo(hDesktop, SE_WINDOW_OBJECT, DACL_AND_OWNER_SECURITY_INFORMATION, &owner, NULL, &pdacl, NULL, &psd);
	error(L"GetSecurityInfo");

	ok = ConvertSecurityDescriptorToStringSecurityDescriptor(psd, SDDL_REVISION_1, DACL_AND_OWNER_SECURITY_INFORMATION, &sddl, NULL);
	error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
	wprintf(L"%s\n", sddl);
	LocalFree(psd);

	if (2 <= args) {

		wprintf(L"Setting new DACL...\n");
		size_t sddlsize = wcslen(sddl);
		LPWSTR ace = L"(A;NP;0x20327;;;AU)";
		size_t acesize = wcslen(ace);
		size_t newsize = sddlsize + acesize;
		LPWSTR newsddl = GlobalAlloc(0, newsize * sizeof(WCHAR) + sizeof(WCHAR));
		if (!newsddl) { return; }
		wcscpy_s(newsddl, sddlsize+1, sddl);
		wcscpy_s(newsddl + sddlsize, acesize+1, ace);
		wprintf(L"%s\n", newsddl);
		ok = ConvertStringSecurityDescriptorToSecurityDescriptor(newsddl, SDDL_REVISION_1, &psd, NULL);
		error(L"ConvertStringSecurityDescriptorToSecurityDescriptor");
		BOOL tfDaclpresent = FALSE;
		BOOL tfDaclDefaulted = FALSE;
		status = GetSecurityDescriptorDacl(psd, &tfDaclpresent, &pdacl, &tfDaclDefaulted);
		error(L"GetSecurityDescriptorDacl");
		//status = SetSecurityInfo(hWinStation, SE_WINDOW_OBJECT, DACL_AND_OWNER_SECURITY_INFORMATION, owner, NULL, pdacl, NULL);
		status = SetSecurityInfo(hDesktop, SE_WINDOW_OBJECT, DACL_AND_OWNER_SECURITY_INFORMATION, owner, NULL, pdacl, NULL);
		error(L"SetSecurityInfo");
		LocalFree(psd);
		GlobalFree(newsddl);

	}//if

	LocalFree(sddl);
	CloseDesktop(hDesktop);
	
}