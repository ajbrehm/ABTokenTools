#include "HelperFunctions.h"



void Write(LPCWSTR sz)
{
	if (NULL == hOut) {
		hOut = GetStdHandle(STD_OUTPUT_HANDLE);
	}//if
	DWORD length = lstrlenW(sz);
	DWORD written = 0;
	WriteConsoleW(hOut, sz, length, &written, NULL);
}

void WriteLine(LPCWSTR sz)
{
	Write(sz);
	Write(L"\n");
}

void WriteDW(DWORD dw)
{
	size_t buffersize = 20 * sizeof(WCHAR);
	LPWSTR sz = GlobalAlloc(0, buffersize);
	_ultow_s(dw, sz, buffersize, 10);
	WriteLine(sz);
}