//MIT License
//
//Copyright(c) 2020 Andrew J. Brehm
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
