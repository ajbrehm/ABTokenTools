#include <Windows.h>

HANDLE hOut;
DWORD error;

void Write(LPCWSTR sz);
void WriteLine(LPCWSTR sz);
void WriteDW(DWORD dw);