#pragma once
#include <cstdint>

int LoadCOFF(uint8_t* data);

typedef void (*COFFEntry)(void);

#pragma pack(push,1)
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
