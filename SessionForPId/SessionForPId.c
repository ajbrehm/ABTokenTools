#include <Windows.h>
#include <stdio.h>

BOOL ok = FALSE;
DWORD error = 0;

int main(int argc, char* argv[])
{
	DWORD pid = 0;
	if (2 > argc) {
		pid = GetCurrentProcessId();
		printf("Using current process id %d.\n", pid);
	} else {
		pid = strtoul(argv[1], NULL, 10);
		printf("Using process id %d.\n", pid);
	}//if
	DWORD sessionid = 999;
	ok = ProcessIdToSessionId(pid, &sessionid);
	if (ok) {
		printf("This is session %d.\n", sessionid);
		return 0;
	} else {
		error = GetLastError();
		printf("Error %x\n", error);
		return error;		
	}//if
}
