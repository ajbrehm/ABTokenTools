//MIT License
//
//Copyright(c) 2022 Andrew J. Brehm
//
//Permission is hereby granted, free of charge, to any person obtaining a copy
//of this softwareand associated documentation files(the "Software"), to deal
//in the Software without restriction, including without limitation the rights
//to use, copy, modify, merge, publish, distribute, sublicense, and /or sell
//copies of the Software, and to permit persons to whom the Software is
//furnished to do so, subject to the following conditions :
//
//The above copyright noticeand this permission notice shall be included in all
//copies or substantial portions of the Software.
//
//THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
//IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
//FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.IN NO EVENT SHALL THE
//AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
//LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
//OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
//SOFTWARE.

#include <Windows.h>
#include <wchar.h>
#include <WtsApi32.h>
#include <sysinfoapi.h>

DWORD ok = 0;

int main()
{
	// get current access token and elevation type
	HANDLE hToken = GetCurrentProcessToken();
	DWORD size = 0;
	ok = GetTokenInformation(hToken, TokenElevationType, NULL, 0, &size);
	PTOKEN_ELEVATION_TYPE pType = HeapAlloc(GetProcessHeap(), 0, size);
	ok = GetTokenInformation(hToken, TokenElevationType, pType, size, &size);
	TOKEN_ELEVATION_TYPE type = *pType;
	wprintf(L"Token elevation type is [%d]. (1=default, 2=elevated, 3=limited)\n", type);
	HeapFree(GetProcessHeap(), 0, pType);

	// if uac is not active, leave
	if (TokenElevationTypeDefault == type) {
		wprintf(L"UAC does not appear to be active.\n");
		return 0;
	}//if

	// if uac is active, get linked token
	ok = GetTokenInformation(hToken, TokenLinkedToken, NULL, 0, &size);
	PTOKEN_LINKED_TOKEN pLinkedToken = HeapAlloc(GetProcessHeap(), 0, size);
	ok = GetTokenInformation(hToken, TokenLinkedToken, pLinkedToken, size, &size);
	HANDLE hLinkedToken = pLinkedToken->LinkedToken;

	// get elevation type of linked token
	ok = GetTokenInformation(hLinkedToken, TokenElevationType, NULL, 0, &size);
	pType = HeapAlloc(GetProcessHeap(), 0, size);
	ok = GetTokenInformation(hLinkedToken, TokenElevationType, pType, size, &size);
	type = *pType;
	wprintf(L"Linked token elevation type is [%d].\n", type);
	HeapFree(GetProcessHeap(), 0, pType);
	HeapFree(GetProcessHeap(), 0, pLinkedToken);
	CloseHandle(hToken);

}