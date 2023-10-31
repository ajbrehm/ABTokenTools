#include <Windows.h>
#include <stdio.h>
#include <shellapi.h>

DWORD error;

int main(int argc, char* argv[])
{
	if (argc != 3) {
		printf("ShellExecute edit|explore|find|open|print|runas pathFile\n");
		return 0;
	}//if

	LPSTR sVerb = argv[1];
	LPSTR pathFile = argv[2];
	ShellExecuteA(NULL, sVerb, pathFile, NULL, NULL, SW_NORMAL);
	error = GetLastError();
	printf("Error: %d\n", error);
	return error;
}