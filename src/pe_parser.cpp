#include <Utils.h>
#include <header.h>
#include <pe_parser.h>
#include <pe_structs.h>



PEFile::PEFile(const char *filePath) {
#ifdef _WIN32
    hFile  =  CreateFileA(filePath, GENERIC_READ , FILE_SHARE_READ|FILE_SHARE_WRITE , nullptr , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL , nullptr);
    if (hFile == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        Utils::SystemError(static_cast<int>(err), "[!] Failed to open the file ");
    }

    LARGE_INTEGER li;
    if (!GetFileSizeEx(hFile, &li)) {
        const DWORD err = GetLastError();
        CloseHandle(hFile);
        Utils::SystemError(static_cast<int>(err), "[!] Failed to get file size ");
    }

    size = li.QuadPart;
    if (size < IMAGE_DOS_HEADER_SIZE) Utils::FatalError("[!] File is too small ");
    hMapFile = CreateFileMappingA(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (hMapFile == nullptr) {
        const DWORD err = GetLastError();
        CloseHandle(hFile);
        Utils::SystemError(static_cast<int>(err), "[!] Failed to create the file mapping ");
    }
    lpAddress = MapViewOfFile(hMapFile, FILE_MAP_READ, 0, 0, size);
    if (lpAddress == nullptr) {
        const DWORD err = GetLastError();
        CloseHandle(hMapFile);
        CloseHandle(hFile);
        Utils::SystemError(static_cast<int>(err), "[!] Failed to map view of the file ");
    }

    #ifdef DEBUG 
    	std::cout << "[*] File opened successfully " << std::endl;
    #endif

#else
    fd  =  open(filePath , O_RDONLY);
    if (fd == -1) Utils::SystemError(errno , "[!] Failed to open the file ");
    struct stat sb;
    if (fstat(fd , &sb) == -1) {
        close(fd);
        Utils::SystemError(errno , "[!] Failed to stat the file ");
    }
    size = sb.st_size;
    if (size < IMAGE_DOS_HEADER_SIZE) Utils::FatalError("File is too small ");
    lpAddress  =  mmap(nullptr , size , PROT_READ , MAP_PRIVATE , fd , 0);
    close(fd);
    fd = -1;
    if (lpAddress == MAP_FAILED) {
        Utils::SystemError(errno , "[!] Failed to map the file ");
    }

    #ifdef DEBUG 
        std::cout << "[*] File opened successfully ..." << '\n';
    #endif

#endif

}


PEFile::~PEFile(){
    #ifdef _WIN32
        UnmapViewOfFile(lpAddress);
        CloseHandle(hMapFile);
        CloseHandle(hFile);
    #else
        munmap(lpAddress , size);
    #endif
}



bool PEFile::IsValidPE() {
    const auto DosHeader=  static_cast<IMAGE_DOS_HEADER*>(lpAddress);
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const DWORD PeOffset = DosHeader->e_lfanew;
    this->e_lfanew = PeOffset;
    CHECK_OFFSET(PeOffset + IMAGE_FILE_HEADER_SIZE + IMAGE_NT_SIGNATURE_SIZE + 4, size); // We can check more size here , 4 to include magic for arch
    return *(reinterpret_cast<DWORD*>(reinterpret_cast<ULONGLONG>(lpAddress)+PeOffset)) == IMAGE_NT_SIGNATURE;
}


void PEFile::GetCharacteristics(){
    const size_t headerOffset = e_lfanew + IMAGE_NT_SIGNATURE_SIZE;
    const auto   fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(
        reinterpret_cast<ULONGLONG>(lpAddress) + headerOffset);
    auto& characteristics = this->PeInfo.Characteristics;
    uint8_t* ptr = characteristics.data();
    if (fileHeader->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE){
        strncpy(reinterpret_cast<char *>(ptr) , "EXE" , 4);
        return;
    }
    if (fileHeader->Characteristics & IMAGE_FILE_DLL) {
        strncpy(reinterpret_cast<char *>(ptr) , "DLL" , 4);
        return;
    }
    if (fileHeader->Characteristics & IMAGE_FILE_SYSTEM) {
        strncpy(reinterpret_cast<char *>(ptr) , "SYS" , 4);
        return ;
    }

    strncpy(reinterpret_cast<char *>(ptr) , "UNK" , 4);

}

void PEFile::GetMachine(){
    const size_t headerOffset = e_lfanew + IMAGE_NT_SIGNATURE_SIZE;
    const auto fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(
        reinterpret_cast<ULONGLONG>(lpAddress) + headerOffset);
    auto& architecture = this->PeInfo.Machine;
    uint8_t* ptr  =  architecture.data();
    switch (fileHeader->Machine) {
        case IMAGE_FILE_MACHINE_I386:      strncpy(reinterpret_cast<char *>(ptr) ,"I386 (x86)" , 16); break;
        case IMAGE_FILE_MACHINE_AMD64:     strncpy(reinterpret_cast<char *>(ptr) ,"AMD64 (x64)", 16); break;
        case IMAGE_FILE_MACHINE_IA64:      strncpy(reinterpret_cast<char *>(ptr) ,"IA64 (Itanium)", 16); break;
        case IMAGE_FILE_MACHINE_ARM:       strncpy(reinterpret_cast<char *>(ptr) ,"ARM" , 16); break;
        case IMAGE_FILE_MACHINE_ARMNT:     strncpy(reinterpret_cast<char *>(ptr) , "ARM Thumb-2", 16); break;; // Often indicates WinRT ARM
        case IMAGE_FILE_MACHINE_ARM64:     strncpy(reinterpret_cast<char *>(ptr) , "ARM64", 16); break;;
        case IMAGE_FILE_MACHINE_EBC:       strncpy(reinterpret_cast<char *>(ptr) , "EFI Byte Code", 16); break;;
        case IMAGE_FILE_MACHINE_MIPS16:    strncpy(reinterpret_cast<char *>(ptr) , "MIPS16", 16); break;;
        case IMAGE_FILE_MACHINE_MIPSFPU:   strncpy(reinterpret_cast<char *>(ptr) , "MIPS FPU", 16); break;;
        case IMAGE_FILE_MACHINE_MIPSFPU16: strncpy(reinterpret_cast<char *>(ptr) , "MIPS FPU16", 16); break;;
        case IMAGE_FILE_MACHINE_POWERPC:   strncpy(reinterpret_cast<char *>(ptr) , "PowerPC", 16); break;;
        case IMAGE_FILE_MACHINE_POWERPCFP: strncpy(reinterpret_cast<char *>(ptr) , "PowerPC FP", 16); break;;
        case IMAGE_FILE_MACHINE_R4000:     strncpy(reinterpret_cast<char *>(ptr) , "MIPS R4000", 16); break;;
        case IMAGE_FILE_MACHINE_SH3:       strncpy(reinterpret_cast<char *>(ptr) , "SH3", 16); break;;
        case IMAGE_FILE_MACHINE_SH4:       strncpy(reinterpret_cast<char *>(ptr) , "SH4", 16); break;;
        case IMAGE_FILE_MACHINE_THUMB:     strncpy(reinterpret_cast<char *>(ptr) , "ARM Thumb", 16); break;;
        case IMAGE_FILE_MACHINE_UNKNOWN:   strncpy(reinterpret_cast<char *>(ptr) , "Unknown", 16); break;
        default: strncpy(reinterpret_cast<char *>(ptr) , "Error" , 16);
    }
}


void PEFile::GetMagic(){
    const size_t magicOffset  =  e_lfanew + IMAGE_NT_SIGNATURE_SIZE + IMAGE_FILE_HEADER_SIZE;
    auto magic  =  *reinterpret_cast<WORD*>(
        reinterpret_cast<ULONGLONG>(lpAddress) + magicOffset);
    switch (magic) {
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:  // 0x10B
            this->PeInfo.Is32Magic = true;
            break;
        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:  // 0x20B
            this->PeInfo.Is32Magic = false;
            break;
        default:
            Utils::FatalError("Invalid PE architecture (unknown Magic value)");
    }
}


void PEFile::GetHashes(){
    Utils::GetSha256(lpAddress , size , PeInfo.Sha256);
}

void PEFile::Parse(){
    (IsValidPE()) ? (void)(std::cout << "[*] Initial validation passed ...\n") : std::exit(EXIT_FAILURE);
    GetMachine();
    GetCharacteristics();
    GetMagic();
    GetHashes();
}
