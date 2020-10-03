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
	size_t cch = 20;
	size_t cb = cch * sizeof(WCHAR);
	LPWSTR sz = (LPWSTR)GlobalAlloc(0, cb);
	if (NULL == sz) { return; }
	_ultow_s(dw, sz, cch, 10);
	WriteLine(sz);
}
