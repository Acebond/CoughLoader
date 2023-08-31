#include <memory>
#include <string>
#include <vector>

#include <Windows.h>
#include "Loader.hpp"

std::string GetSymbolName(COFF_SYMBOL* symbol, char* stringsTable) {
	// According to COFF docs this is IMAGE_SYM_UNDEFINED
	if (symbol->SectionNumber == 0 && symbol->StorageClass == 0) {
		return std::string("__UNDEFINED");
	}
	else if (symbol->Name.Zeros != 0) {
		size_t count = strnlen(symbol->Name.ShortName, sizeof(symbol->Name.ShortName));
		return std::string(symbol->Name.ShortName, count);
	}
	else {
		return std::string(stringsTable + symbol->Name.Offset);
	}
}

uint64_t ResolveExternal(std::string symbolName) {

	std::string DLLname;
	std::string FuncName;

	if (auto split = symbolName.find('$'); split == std::string::npos) {
		DLLname = "kernel32";
		FuncName = symbolName;
	}
	else {
		DLLname = symbolName.substr(0, split);
		FuncName = symbolName.substr(split + 1);
	}

	HMODULE lib = LoadLibraryA(DLLname.c_str());
	if (lib != NULL) {
		return (uint64_t)GetProcAddress(lib, FuncName.c_str());
	}
	return 0;
}

int LoadCOFF(uint8_t* data, int argc, char *argv[]) {

	auto header = reinterpret_cast<PIMAGE_FILE_HEADER>(data);
	auto sections = reinterpret_cast<PIMAGE_SECTION_HEADER>(data + sizeof(IMAGE_FILE_HEADER));
	auto symbolTable = reinterpret_cast<COFF_SYMBOL*>(data + header->PointerToSymbolTable);
	auto stringsTable = (char*)(data + header->PointerToSymbolTable + header->NumberOfSymbols * sizeof(COFF_SYMBOL));

	auto sectionsBase = std::vector<LPVOID>(header->NumberOfSections);
	auto GOT = std::vector<uint64_t>(header->NumberOfSymbols);
	COFFEntry LaunchGO = nullptr;
	
	for (WORD i = 0; i < header->NumberOfSections; i++) {

		if (sections[i].SizeOfRawData == 0) {
			continue;
		}

		DWORD InMemorySize = sections[i].SizeOfRawData + (0x1000 - sections[i].SizeOfRawData % 0x1000); // align to page size

		sectionsBase[i] = VirtualAlloc(NULL, InMemorySize, MEM_COMMIT | MEM_RESERVE,
			(sections[i].Characteristics & IMAGE_SCN_CNT_CODE) ? PAGE_EXECUTE_READWRITE : PAGE_READWRITE);

		if (sections[i].PointerToRawData > 0) {
			memcpy(sectionsBase[i], data + sections[i].PointerToRawData, sections[i].SizeOfRawData);
		}
	}

	for (DWORD i = 0; i < header->NumberOfSymbols; i++) {

		auto symbolName = GetSymbolName(&symbolTable[i], stringsTable);

		// Skip IMAGE_SYM_ABSOLUTE, IMAGE_SYM_DEBUG, IMAGE_SYM_UNDEFINED symbols
		if (symbolTable[i].SectionNumber > 0xFF || symbolName == "__UNDEFINED") {
			continue;
		}

		// Resolve external functions
		constexpr auto importPrefixToken = "__imp_";
		if (symbolName.starts_with(importPrefixToken)) {
			GOT[i] = ResolveExternal(symbolName.substr(strlen(importPrefixToken)));
		}
		else if (symbolName == "go") {
			int section = symbolTable[i].SectionNumber - 1;
			LaunchGO = reinterpret_cast<decltype(LaunchGO)>(reinterpret_cast<uintptr_t>(sectionsBase[section]) + symbolTable[i].Value);
		}
	}

	// Fix relocations
	for (WORD i = 0; i < header->NumberOfSections; i++) {
		for (WORD j = 0; j < sections[i].NumberOfRelocations; j++) {

			auto coffReloc = reinterpret_cast<PIMAGE_RELOCATION>(data + sections[i].PointerToRelocations + sizeof(IMAGE_RELOCATION) * j);
			auto symbol = symbolTable[coffReloc->SymbolTableIndex];
			auto relocAddr = reinterpret_cast<uintptr_t>(sectionsBase[i]) + coffReloc->VirtualAddress;
			auto relocVal = static_cast<uint32_t>(relocAddr);

			switch (coffReloc->Type) {

				case IMAGE_REL_AMD64_ADDR32NB: 
					*reinterpret_cast<uint32_t*>(relocAddr) = symbol.Value;
					break;

				case IMAGE_REL_AMD64_REL32:
					if (GOT[coffReloc->SymbolTableIndex] != NULL) {
						*reinterpret_cast<uint32_t*>(relocAddr) = static_cast<uint32_t>(reinterpret_cast<uint64_t>(&GOT[coffReloc->SymbolTableIndex]) - (relocVal + 4));
					}
					else if (int sectionIndex = symbol.SectionNumber - 1; sectionIndex >= 0) {
						uint64_t wtf = *reinterpret_cast<int32_t*>(relocAddr) + reinterpret_cast<uint64_t>(sectionsBase[sectionIndex]);
						*reinterpret_cast<uint32_t*>(relocAddr) = static_cast<uint32_t>(wtf + symbol.Value - (relocVal + 4));
					}
					break;

				default:
					printf("[!] ERROR! Reloc type %#x is not supported (SECT = %d : REL = %d)\n", coffReloc->Type, i, j);
			}
		}
	}
	
	if (LaunchGO == nullptr) {
		return -1;
	} else {
		LaunchGO(argc, argv);
	}

	for (WORD i = 0; i < header->NumberOfSections; i++) {
		VirtualFree(sectionsBase[i], 0, MEM_RELEASE);
	}
	
	return 0;
}
