/*
 *This header file contains fundamental structure definitions for working with the Windows
 *Portable Executable (PE) file format. It provides the complete set of data structures needed
 *to parse and analyze PE files
 */


#pragma once

#include <header.h>

#ifndef _WIN32


constexpr int IMAGE_NUMBEROF_DIRECTORY_ENTRIES  = 16;
constexpr int IMAGE_SIZEOF_SHORT_NAME = 8;


constexpr WORD IMAGE_DOS_SIGNATURE = 0x5A4D; // MZ
constexpr DWORD IMAGE_NT_SIGNATURE = 0x00004550; // PE00
constexpr WORD IMAGE_NT_OPTIONAL_HDR32_MAGIC = 0x10b;
constexpr WORD IMAGE_NT_OPTIONAL_HDR64_MAGIC = 0x20b;


// Data directory indices
constexpr int IMAGE_DIRECTORY_ENTRY_EXPORT = 0;
constexpr int IMAGE_DIRECTORY_ENTRY_IMPORT = 1;
constexpr int IMAGE_DIRECTORY_ENTRY_RESOURCE = 2;
constexpr int IMAGE_DIRECTORY_ENTRY_BASE_RELOC = 5;
constexpr int IMAGE_DIRECTORY_ENTRY_DEBUG = 6;
constexpr int IMAGE_DIRECTORY_ENTRY_TLS = 9;
constexpr int IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG = 10;
constexpr int IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT = 11;
constexpr int IMAGE_DIRECTORY_ENTRY_IAT = 12;
constexpr int IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT = 13;
constexpr int IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR = 14;

// Other constants


#pragma pack(push,1)


struct IMAGE_DOS_HEADER{
    WORD   e_magic;                     // Magic number
    WORD   e_cblp;                      // Bytes on last page of file
    WORD   e_cp;                        // Pages in file
    WORD   e_crlc;                      // Relocations
    WORD   e_cparhdr;                   // Size of header in paragraphs
    WORD   e_minalloc;                  // Minimum extra paragraphs needed
    WORD   e_maxalloc;                  // Maximum extra paragraphs needed
    WORD   e_ss;                        // Initial (relative) SS value
    WORD   e_sp;                        // Initial SP value
    WORD   e_csum;                      // Checksum
    WORD   e_ip;                        // Initial IP value
    WORD   e_cs;                        // Initial (relative) CS value
    WORD   e_lfarlc;                    // File address of relocation table
    WORD   e_ovno;                      // Overlay number
    WORD   e_res[4];                    // Reserved WORDs
    WORD   e_oemid;                     // OEM identifier (for e_oeminfo)
    WORD   e_oeminfo;                   // OEM information; e_oemid specific
    WORD   e_res2[10];                  // Reserved WORDs
    DWORD   e_lfanew;                    // File address of new exe header
};


struct IMAGE_FILE_HEADER {
    WORD    Machine;
    WORD    NumberOfSections;
    DWORD   TimeDateStamp;
    DWORD   PointerToSymbolTable;
    DWORD   NumberOfSymbols;
    WORD    SizeOfOptionalHeader;
    WORD    Characteristics;
};

struct IMAGE_DATA_DIRECTORY {
    DWORD   VirtualAddress;
    DWORD   Size;
};

struct IMAGE_OPTIONAL_HEADER32 {
    //
    // Standard fields.
    //

    WORD    Magic;
    BYTE    MajorLinkerVersion;
    BYTE    MinorLinkerVersion;
    DWORD   SizeOfCode;
    DWORD   SizeOfInitializedData;
    DWORD   SizeOfUninitializedData;
    DWORD   AddressOfEntryPoint;
    DWORD   BaseOfCode;
    DWORD   BaseOfData;

    //
    // NT additional fields.
    //

    DWORD   ImageBase;
    DWORD   SectionAlignment;
    DWORD   FileAlignment;
    WORD    MajorOperatingSystemVersion;
    WORD    MinorOperatingSystemVersion;
    WORD    MajorImageVersion;
    WORD    MinorImageVersion;
    WORD    MajorSubsystemVersion;
    WORD    MinorSubsystemVersion;
    DWORD   Win32VersionValue;
    DWORD   SizeOfImage;
    DWORD   SizeOfHeaders;
    DWORD   CheckSum;
    WORD    Subsystem;
    WORD    DllCharacteristics;
    DWORD   SizeOfStackReserve;
    DWORD   SizeOfStackCommit;
    DWORD   SizeOfHeapReserve;
    DWORD   SizeOfHeapCommit;
    DWORD   LoaderFlags;
    DWORD   NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_OPTIONAL_HEADER64 {
    WORD        Magic;
    BYTE        MajorLinkerVersion;
    BYTE        MinorLinkerVersion;
    DWORD       SizeOfCode;
    DWORD       SizeOfInitializedData;
    DWORD       SizeOfUninitializedData;
    DWORD       AddressOfEntryPoint;
    DWORD       BaseOfCode;
    ULONGLONG   ImageBase;
    DWORD       SectionAlignment;
    DWORD       FileAlignment;
    WORD        MajorOperatingSystemVersion;
    WORD        MinorOperatingSystemVersion;
    WORD        MajorImageVersion;
    WORD        MinorImageVersion;
    WORD        MajorSubsystemVersion;
    WORD        MinorSubsystemVersion;
    DWORD       Win32VersionValue;
    DWORD       SizeOfImage;
    DWORD       SizeOfHeaders;
    DWORD       CheckSum;
    WORD        Subsystem;
    WORD        DllCharacteristics;
    ULONGLONG   SizeOfStackReserve;
    ULONGLONG   SizeOfStackCommit;
    ULONGLONG   SizeOfHeapReserve;
    ULONGLONG   SizeOfHeapCommit;
    DWORD       LoaderFlags;
    DWORD       NumberOfRvaAndSizes;
    IMAGE_DATA_DIRECTORY DataDirectory[IMAGE_NUMBEROF_DIRECTORY_ENTRIES];
};

struct IMAGE_NT_HEADERS32 {
    DWORD             Signature;
    IMAGE_FILE_HEADER    FileHeader;
    IMAGE_OPTIONAL_HEADER32 OptionalHeader;
};

struct IMAGE_NT_HEADERS64 {
    DWORD             Signature;
    IMAGE_FILE_HEADER    FileHeader;
    IMAGE_OPTIONAL_HEADER64 OptionalHeader;
};

struct IMAGE_SECTION_HEADER {
    BYTE    Name[IMAGE_SIZEOF_SHORT_NAME];
    union {
            DWORD   PhysicalAddress;
            DWORD   VirtualSize;
    } Misc;
    DWORD   VirtualAddress;
    DWORD   SizeOfRawData;
    DWORD   PointerToRawData;
    DWORD   PointerToRelocations;
    DWORD   PointerToLinenumbers;
    WORD    NumberOfRelocations;
    WORD    NumberOfLinenumbers;
    DWORD   Characteristics;
};

struct IMAGE_IMPORT_DESCRIPTOR {
    union {
        DWORD Characteristics;       // 0 for terminating null import descriptor
        DWORD OriginalFirstThunk;    // RVA to original unbound IAT (PIMAGE_THUNK_DATA)
    } DUMMYUNIONNAME;
    DWORD TimeDateStamp;             // 0 if not bound,
                                        // -1 if bound, and real date\time stamp
                                        // in IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT (new BIND)
                                        // O.W. date/time stamp of DLL bound to (Old BIND)

    DWORD ForwarderChain;            // -1 if no forwarders
    DWORD Name;                      // RVA to DLL name (ASCII string)
    DWORD FirstThunk;                // RVA to IAT (if bound this IAT has actual addresses)
};


struct IMAGE_THUNK_DATA32 {
    union {
        DWORD ForwarderString;      // PBYTE
        DWORD Function;             // PDWORD
        DWORD Ordinal;
        DWORD AddressOfData;        // PIMAGE_IMPORT_BY_NAME
    } u1;
};

struct IMAGE_THUNK_DATA64 {
    union {
        ULONGLONG ForwarderString;  // PBYTE
        ULONGLONG Function;         // PDWORD
        ULONGLONG Ordinal;
        ULONGLONG AddressOfData;    // PIMAGE_IMPORT_BY_NAME
    } u1;
};

struct IMAGE_IMPORT_BY_NAME {
    WORD    Hint;
    CHAR   Name[1];
};

struct IMAGE_EXPORT_DIRECTORY {
    DWORD   Characteristics;
    DWORD   TimeDateStamp;
    WORD    MajorVersion;
    WORD    MinorVersion;
    DWORD   Name;
    DWORD   Base;
    DWORD   NumberOfFunctions;
    DWORD   NumberOfNames;
    DWORD   AddressOfFunctions;     // RVA from base of image
    DWORD   AddressOfNames;         // RVA from base of image
    DWORD   AddressOfNameOrdinals;  // RVA from base of image
};


#pragma pack(pop)

// Characteristics
constexpr WORD IMAGE_FILE_EXECUTABLE_IMAGE = 0x0002;
constexpr WORD IMAGE_FILE_SYSTEM =  0x1000;
constexpr WORD IMAGE_FILE_DLL =  0x2000;

// machine type
constexpr WORD IMAGE_FILE_MACHINE_UNKNOWN   = 0x0;
constexpr WORD IMAGE_FILE_MACHINE_I386      = 0x014c;  // Intel 386. (x86)
constexpr WORD IMAGE_FILE_MACHINE_R4000     = 0x0166;  // MIPS little-endian
constexpr WORD IMAGE_FILE_MACHINE_WCEMIPSV2 = 0x0169;  // MIPS little-endian WCE v2
constexpr WORD IMAGE_FILE_MACHINE_ALPHA     = 0x0184;  // Alpha_AXP
constexpr WORD IMAGE_FILE_MACHINE_SH3       = 0x01a2;  // SH3 little-endian
constexpr WORD IMAGE_FILE_MACHINE_SH3DSP    = 0x01a3;
constexpr WORD IMAGE_FILE_MACHINE_SH4       = 0x01a6;  // SH4 little-endian
constexpr WORD IMAGE_FILE_MACHINE_SH5       = 0x01a8;  // SH5
constexpr WORD IMAGE_FILE_MACHINE_ARM       = 0x01c0;  // ARM Little-Endian
constexpr WORD IMAGE_FILE_MACHINE_THUMB     = 0x01c2;  // ARM Thumb/Thumb-2 Little-Endian
constexpr WORD IMAGE_FILE_MACHINE_ARMNT     = 0x01c4;  // ARM Thumb-2 Little-Endian (Same as Thumb usually)
constexpr WORD IMAGE_FILE_MACHINE_AM33      = 0x01d3;
constexpr WORD IMAGE_FILE_MACHINE_POWERPC   = 0x01F0;  // PowerPC Little-Endian
constexpr WORD IMAGE_FILE_MACHINE_POWERPCFP = 0x01f1;
constexpr WORD IMAGE_FILE_MACHINE_IA64      = 0x0200;  // Intel Itanium 64
constexpr WORD IMAGE_FILE_MACHINE_MIPS16    = 0x0266;  // MIPS16
constexpr WORD IMAGE_FILE_MACHINE_MIPSFPU   = 0x0366;  // MIPS with FPU
constexpr WORD IMAGE_FILE_MACHINE_MIPSFPU16 = 0x0466;  // MIPS16 with FPU
constexpr WORD IMAGE_FILE_MACHINE_ALPHA64   = 0x0284;  // ALPHA64 (obsolete)
constexpr WORD IMAGE_FILE_MACHINE_TRICORE   = 0x0520;  // Infineon Tricore
constexpr WORD IMAGE_FILE_MACHINE_CEF       = 0x0CEF;
constexpr WORD IMAGE_FILE_MACHINE_EBC       = 0x0EBC;  // EFI Byte Code
constexpr WORD IMAGE_FILE_MACHINE_AMD64     = 0x8664;  // AMD64 (x64)
constexpr WORD IMAGE_FILE_MACHINE_M32R      = 0x9041;  // M32R little-endian
constexpr WORD IMAGE_FILE_MACHINE_ARM64     = 0xAA64;  // ARM64 Little-Endian
constexpr WORD IMAGE_FILE_MACHINE_CEE       = 0xC0EE;

#endif



// Other constants

constexpr int IMAGE_NT_SIGNATURE_SIZE  =  sizeof(IMAGE_NT_SIGNATURE);
constexpr int IMAGE_DOS_HEADER_SIZE  = sizeof(IMAGE_DOS_HEADER);
constexpr int IMAGE_FILE_HEADER_SIZE = sizeof(IMAGE_FILE_HEADER);
constexpr int IMAGE_NT_HEADERS32_SIZE = sizeof(IMAGE_NT_HEADERS32);
constexpr int IMAGE_NT_HEADERS64_SIZE = sizeof(IMAGE_NT_HEADERS64);
constexpr int IMAGE_OPTIONAL_HEADER32_SIZE = sizeof(IMAGE_OPTIONAL_HEADER32);
constexpr int IMAGE_OPTIONAL_HEADER64_SIZE =  sizeof(IMAGE_OPTIONAL_HEADER64);
constexpr int IMAGE_OPTIONAL_HEADER32_MINSIZE = IMAGE_OPTIONAL_HEADER32_SIZE -  8 * IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
constexpr int IMAGE_OPTIONAL_HEADER64_MINSIZE = IMAGE_OPTIONAL_HEADER64_SIZE -  8 * IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
constexpr int IMAGE_DATA_DIRECTORY_SIZE =  sizeof(IMAGE_DATA_DIRECTORY);
constexpr int IMAGE_SECTION_HEADER_SIZE = sizeof(IMAGE_SECTION_HEADER);
constexpr int TIMESTAMP_LEN = 80;
