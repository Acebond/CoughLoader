#include <cstdio>

#include <Windows.h>

#include "Loader.hpp"

int main(int argc, char* argv[]) {

	if (argc < 2) {
		printf("[!] ERROR! Run: %s <coff_file> <coff_args>\n", argv[0]);
		return -1;
	}

	HANDLE COFFfile = CreateFileA(argv[1], GENERIC_READ, 0, NULL, OPEN_EXISTING, 0, NULL);
	if (COFFfile == INVALID_HANDLE_VALUE) {
		printf("[!] ERROR! Could not open file: %s (%#x)\n", argv[1], GetLastError());
		return -1;
	}

	HANDLE FileMapping = CreateFileMappingA(COFFfile, NULL, PAGE_READONLY, 0, 0, NULL);
	if (FileMapping == NULL) {
		printf("[!] ERROR! Could not call CreateFileMapping (%#x)\n", GetLastError());
		return -1;
	}

	LPVOID COFF_data = MapViewOfFile(FileMapping, FILE_MAP_READ, 0, 0, 0);
	if (COFF_data == NULL) {
		printf("[!] ERROR! Could not call MapViewOfFile (%#x)\n", GetLastError());
		return -1;
	}

	if (LoadCOFF(static_cast<uint8_t*>(COFF_data), argc - 2, argv + 2)) {
		printf("[!] Something went wrong\n");
	}

	UnmapViewOfFile(COFF_data);
	CloseHandle(FileMapping);
	CloseHandle(COFFfile);
	return 0;
}
