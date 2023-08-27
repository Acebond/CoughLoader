#include <windows.h>
#include <stdio.h>

// DECLSPEC_IMPORT <return_type> WINAPI <LIB>$<FUNCNAME>(param1, param2, ...);
// ex. DECLSPEC_IMPORT HANDLE WINAPI KERNEL32$CreateToolhelp32Snapshot(DWORD, DWORD th32ProcessID);

DECLSPEC_IMPORT HANDLE WINAPI ADVAPI32$GetUserNameA(LPSTR, LPDWORD);

// WINBASEAPI <return_type> __cdecl MSVCRT$<FUNCNAME>(param1, param2, ...);
// ex. WINBASEAPI int __cdecl MSVCRT$getchar(void);
WINBASEAPI int __cdecl MSVCRT$printf(const char * _Format,...);

// global variable declaration
int globalVal = 0;

int testing(void){
	char funcname[] = "ZwAddBootEntry";
	
	void * addr = GetProcAddress(GetModuleHandleA("ntdll.dll"), funcname);
    MSVCRT$printf("Function %s() @ %p\n", funcname, addr);	
    return 0;
}

int go(int argc, char* argv[]) {

	for (int i = 0; i < argc; i++) {
		MSVCRT$printf("%d - %s\n", i, argv[i]);
	}

	DWORD usernameSize = 100;
	char username[100] = {0};
	ADVAPI32$GetUserNameA(&username[0], &usernameSize);
	MSVCRT$printf("Username: %s\n", username);

	int inc = 2;

	MSVCRT$printf("Test value 1: %d\n", globalVal);
    globalVal += inc + 1;
    MSVCRT$printf("Test value 2: %d\n", globalVal);
	testing();

	return 0;
}
