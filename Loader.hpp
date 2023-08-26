#pragma once
#include <cstdint>

#define TOKEN_imp "__imp_"

int LoadCOFF(unsigned char* COFF_data);

typedef void (*COFFEntry)(void);

#pragma pack(push,1)
/* size of 10 */
typedef struct _COFF_RELOCATION {
    uint32_t VirtualAddress;
    uint32_t SymbolTableIndex;
    uint16_t Type;
} COFF_RELOCATION;

/* size of 18 */
typedef struct _COFF_SYMBOL {
    union {
        char ShortName[8];
		struct {
			uint32_t Zeros;
			uint32_t Offset;
		};
    } Name;
    uint32_t Value;
    uint16_t SectionNumber;
    uint16_t Type;
    uint8_t StorageClass;
    uint8_t NumberOfAuxSymbols;
} COFF_SYMBOL;

#pragma pack(pop)
