#include <Windows.h>
#include <NTSecAPI.h>
#include "HelperFunctions.h"

LSA_HANDLE hPolicy;
PSID pSid = NULL;
LPWSTR* aCommandLine;
int args = 0;

void OpenPolicy()
{
	LSA_OBJECT_ATTRIBUTES attributes;
	ZeroMemory(&attributes, sizeof(attributes));
	error = LsaOpenPolicy(NULL, &attributes, POLICY_ALL_ACCESS, &hPolicy);
}

void ClosePolicy()
{
	LsaClose(hPolicy);
}

void TranslateUserNameToSid(LPCWSTR szUserName)
{
	DWORD sidsize = 0;
	DWORD domainsize = 0;
	SID_NAME_USE use = 0;
	LookupAccountNameW(NULL, szUserName, NULL, &sidsize, NULL, &domainsize, &use);
	pSid = GlobalAlloc(0, sidsize);
	LPWSTR szDomain = GlobalAlloc(0, domainsize * sizeof(WCHAR));
	LookupAccountNameW(NULL, szUserName, pSid, &sidsize, szDomain, &domainsize, &use);
	GlobalFree(szDomain);
}

DWORD AccountRights(PSID pSid)
{
	DWORD rights = 0;
	PLSA_UNICODE_STRING aUserRight = NULL;
	error = LsaEnumerateAccountRights(hPolicy, pSid, &aUserRight, &rights);
	for (DWORD right = 0; right < rights; right++)
	{
		LSA_UNICODE_STRING lsaUserRight = aUserRight[right];
		LPWSTR szUserRight = lsaUserRight.Buffer;
		WriteLine(szUserRight);
	}//for
	return rights;
}

void AddAccountRight(PSID pSid, LPWSTR szPrivilege, BOOL tfRemove)
{
	USHORT cbPrivilege = (USHORT)(lstrlenW(szPrivilege) * sizeof(WCHAR));
	LSA_UNICODE_STRING lusPrivilege;
	lusPrivilege.Buffer = szPrivilege;
	lusPrivilege.Length = cbPrivilege;
	lusPrivilege.MaximumLength = cbPrivilege;
	if (tfRemove) {
		error = LsaRemoveAccountRights(hPolicy, pSid, FALSE, &lusPrivilege, 1L);
	} else {
		error = LsaAddAccountRights(hPolicy, pSid, &lusPrivilege, 1L);
	}//if
}

void ConfigureCommandLine()
{
	LPWSTR szCommandLine = GetCommandLineW();
	aCommandLine = CommandLineToArgvW(szCommandLine, &args);
}

int main()
{
	ConfigureCommandLine();
	if (args < 2) { return 0; }
	OpenPolicy();

	LPWSTR szUserName = aCommandLine[1];
	//LPWSTR szUserName = L"administrators";
	TranslateUserNameToSid(szUserName);

	DWORD rights = AccountRights(pSid);
	WriteDW(rights);
	if (args < 3) { return 0; }

	LPWSTR szPrivilege = aCommandLine[2];
	if (args < 4) {
		AddAccountRight(pSid, szPrivilege, FALSE);
	} else {
		LPWSTR szCommand = aCommandLine[3];
		DWORD cchCommand = lstrlenW(szCommand);
		LPWSTR szRemoveCommand = L"REMOVE";
		DWORD cchRemoveCommand = lstrlenW(szRemoveCommand);
		if (CSTR_EQUAL == CompareStringW(LOCALE_SYSTEM_DEFAULT, NORM_IGNORECASE, szCommand, cchCommand, szRemoveCommand, cchRemoveCommand)) {
			AddAccountRight(pSid, szPrivilege, TRUE);
		}//if
	}//if

	rights = AccountRights(pSid);
	WriteDW(rights);

	GlobalFree(pSid);
	ClosePolicy();
	return 0;
}
