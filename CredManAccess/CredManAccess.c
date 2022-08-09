#include <Windows.h>
#include <wincred.h>
#include <wchar.h>

BOOL ok;
int error;
LPWSTR* aCommandLine;
int args = 0;
BOOL debug = TRUE;

void ConfigureCommandLine()
{
	LPWSTR szCommandLine = GetCommandLineW();
	aCommandLine = CommandLineToArgvW(szCommandLine, &args);
}

void Error(LPCWSTR szFunctionName)
{
	if (debug) {
		error = GetLastError();
		wprintf(L"%s: %d\n", szFunctionName, error);
		error = 0;
	}//if
}

int main()
{
	ConfigureCommandLine();
	if (args != 3 && args != 5) {

		// display help
		wprintf(L"CredManAccess type sTargetName sUserName\n");
		wprintf(L"CredManAccess type sTargetName sUserName sPassword\n");
		wprintf(L"1 CRED_TYPE_GENERIC\n");
		wprintf(L"2 CRED_TYPE_DOMAIN_PASSWORD\n");
		wprintf(L"3 CRED_TYPE_DOMAIN_CERTIFICATE\n");
		wprintf(L"4 CRED_TYPE_DOMAIN_VISIBLE_PASSWORD\n");
		wprintf(L"5 CRED_TYPE_GENERIC_CERTIFICATE5\n");
		wprintf(L"6 CRED_TYPE_DOMAIN_EXTENDED\n");
		exit(0);

	}//if
	LPWSTR sType = aCommandLine[1];
	int type = _wtoi(sType);
	LPWSTR sTargetName = aCommandLine[2];

	if (3 == args) {
		
		PCREDENTIAL pcredential;
		ok = CredReadW(sTargetName, type, 0, &pcredential);
		error = GetLastError();
		wprintf(L"%d\n", error);
		LPWSTR sUserName = pcredential->UserName;
		wprintf(L"%s\n", sUserName);
		DWORD cbCredentialBlobSize = pcredential->CredentialBlobSize;
		DWORD cchCredentialBlobSize = (DWORD)(cbCredentialBlobSize / sizeof(WCHAR));
		wprintf(L"%d\n", cbCredentialBlobSize);
		LPWSTR sPassword = (LPWSTR)pcredential->CredentialBlob;
		wprintf(L"%.*s\n", cchCredentialBlobSize, sPassword);
		CredFree(pcredential);

	}//if

	if (5 == args) {

		// write credential
		LPWSTR sUserName = aCommandLine[3];
		LPWSTR sPassword = aCommandLine[4];
		DWORD cbCredentialBlobSize = (DWORD)(wcslen(sPassword) * sizeof(WCHAR));
		CREDENTIAL credential = { 0 };

		credential.Type = type;
		credential.TargetName = sTargetName;
		credential.Persist = CRED_PERSIST_LOCAL_MACHINE;
		credential.UserName = sUserName;
		credential.CredentialBlobSize = cbCredentialBlobSize;
		credential.CredentialBlob = (LPBYTE)sPassword;
		ok = CredWriteW(&credential, 0);
		error = GetLastError();
		wprintf(L"%d\n", error);

	}//if

	return error;
}
