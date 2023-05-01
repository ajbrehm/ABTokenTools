#include <Windows.h>
#include <wchar.h>
#include <sddl.h>
#include <AclAPI.h>

BOOL debug = FALSE;
LSTATUS status = 0;
BOOL ok = TRUE;
DWORD error = 0;
LPWSTR sddl = NULL; // an sddl for a dacl
PSECURITY_DESCRIPTOR psd = NULL; // a pointer to a security descriptor

void Help()
{
	wprintf(L"ScheduledTaskAclEdit pathScheduledTask [sddl]\n\n");
	wprintf(L"pathScheduledTask can be a scheduled task or a folder of scheduled tasks.\n\n");
}

void Error(LPCWSTR sz)
{
	if (!debug) { return; }
	error = GetLastError();
	fwprintf(stderr, L"%s\tOK: [%d]\tSTATUS: [%d], Error: [%d]\n", sz, ok, status, error);
	error = 0;
	status = 0;
	ok = TRUE;
}

DWORD GetSddlFromBinaryRegistryValue(HKEY hKey, LPWSTR pathRegistryKey, LPWSTR pathRegistrySubKey, LPWSTR sValueName)
{
	status = RegOpenKeyExW(hKey, pathRegistryKey, 0, KEY_READ, &hKey);
	Error(L"RegOpenKeyExW KEY_READ");
	DWORD cbData = 0;
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
	SECURITY_INFORMATION secinfo = DACL_SECURITY_INFORMATION | OWNER_SECURITY_INFORMATION;
	ok = ConvertSecurityDescriptorToStringSecurityDescriptorW(psd, SDDL_REVISION_1, secinfo, &sddl, &cbSddl);
	Error(L"ConvertSecurityDescriptorToStringSecurityDescriptor");
	GlobalFree(pData);
}

DWORD SetSddlToBinaryRegistryValue(HKEY hKey, LPWSTR pathRegistryKey, LPWSTR pathRegistrySubKey, LPWSTR sValueName)
{
	status = RegOpenKeyExW(hKey, pathRegistryKey, 0, KEY_READ, &hKey);
	if (debug) { fwprintf(stderr, L"Trying to open key [%s].\n", pathRegistryKey); }
	Error(L"RegOpenKeyExW KEY_READ");
	status = RegOpenKeyExW(hKey, pathRegistrySubKey, 0, KEY_WRITE, &hKey);
	if (debug) { fwprintf(stderr, L"Trying to open key [%s].\n", pathRegistrySubKey); }
	Error(L"RegOpenKeyExW KEY_WRITE");
	LONG cbData = 0;
	ok = ConvertStringSecurityDescriptorToSecurityDescriptorW(sddl, SDDL_REVISION_1, &psd, &cbData);
	Error(L"ConvertStringSecurityDescriptorToSecurityDescriptor");
	if (debug) { fwprintf(stderr, L"Registry data to be written has size of [%u].\n", cbData); }
	status = RegSetValueExW(hKey, sValueName, 0, REG_BINARY, psd, cbData);
	Error(L"RegSetValueExW");
	RegCloseKey(hKey);
	Error(L"RegCloseKey");
	LocalFree(psd);
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
	LPWSTR pathScheduledTask = NULL;

	if (args < 2) {
		Help();
		exit(0);
	}//if

	pathScheduledTask = aCommandLine[1];
	if (args >= 2) {
		sddl = aCommandLine[2];
	}//if

	if (debug) { wprintf(L"sddl: [%s]\n", sddl); }
	GetSetSddlFromToBinaryRegistryValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree", pathScheduledTask, L"SD");
	sddl = NULL;
	GetSetSddlFromToBinaryRegistryValue(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree", pathScheduledTask, L"SD");
	if (sddl) { wprintf(sddl); }

}