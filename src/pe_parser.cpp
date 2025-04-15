#include <Utils.h>
#include <header.h>
#include <pe_parser.h>
#include <pe_structs.h>



/**
 * Loads a Portable Executable (PE) file into memory.
 * 
 * This method opens a PE file from disk, retrieves its size, and maps its contents
 * into memory for further analysis or processing. It handles both Windows and 
 * Unix-like systems using platform-specific APIs. On Windows, it uses CreateFile,
 * CreateFileMapping, and MapViewOfFile. On Unix-like systems, it uses open, fstat, 
 * and mmap.
 * 
 * Errors encountered during the file loading process are handled through the Utils 
 * error reporting system. If the file is too small or mapping fails, a fatal error 
 * is triggered.
 * 
 * @param filePath Path to the PE file on disk.
 */


void PEFile::LoadFromFile(const char *filePath) {
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



PEFile::PEFile(const char *filePath){
    PEFile::LoadFromFile(filePath);
}

/**
 * Destructor for the PEFile class.
 * 
 * Releases memory and file resources associated with the mapped PE file.
 * On Windows, it unmaps the file view and closes the file and mapping handles.
 * On Unix-like systems, it unmaps the memory using munmap.
 */

PEFile::~PEFile(){
    #ifdef _WIN32
        UnmapViewOfFile(lpAddress);
        CloseHandle(hMapFile);
        CloseHandle(hFile);
    #else
        munmap(lpAddress , size);
    #endif
}


/**
 * Validates whether the loaded file is a proper PE (Portable Executable) file.
 * 
 * This method performs structural validation on the memory-mapped file to determine
 * if it conforms to the PE format. It begins by interpreting the start of the mapped
 * memory as an IMAGE_DOS_HEADER and checks for the 'MZ' DOS signature (`0x5A4D`).
 * 
 * If the DOS header is valid, it retrieves the `e_lfanew` field — the offset to the
 * NT header — and stores it internally for later access. Then, it ensures the offset
 * is within valid bounds to avoid accessing memory outside the mapped file.
 * 
 * It finally checks whether the DWORD located at `e_lfanew` corresponds to the NT
 * signature (`PE\0\0`, or `0x00004550`).
 * 
 * @note Some PE files, especially highly packed, crafted, or legacy ones, merge
 *       the NT header with unused fields of the DOS header. This means
 *       NT headers can start at lower offsets than typical compiler-generated files.
 *       As such, hard assumptions about minimum size or padding can be misleading.
 * 
 * @note The smallest known valid PE file is only 76 bytes in size, crafted to
 *       exploit minimal structural requirements. Because of this, this function
 *       uses a strict boundary check based on the exact required number of bytes,
 *       rather than assuming a standard or padded layout.
 * 
 * @return true if the file has a valid DOS and NT signature and offset; false otherwise.
 */

bool PEFile::IsValidPE() {
    const auto DosHeader=  static_cast<IMAGE_DOS_HEADER*>(lpAddress);
    if (DosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const DWORD PeOffset = DosHeader->e_lfanew;
    this->e_lfanew = PeOffset;
    CHECK_OFFSET(PeOffset + IMAGE_FILE_HEADER_SIZE + IMAGE_NT_SIGNATURE_SIZE + 4, size);
    return *(reinterpret_cast<DWORD*>(reinterpret_cast<ULONGLONG>(lpAddress)+PeOffset)) == IMAGE_NT_SIGNATURE;
}

/**
 * Extracts and classifies the PE file type (EXE, DLL, SYS, or UNK).
 * 
 * Parses the IMAGE_FILE_HEADER to inspect the `Characteristics` field and 
 * stores a short string label ("EXE", "DLL", "SYS", or "UNK") in the internal 
 * `PeInfo` structure based on the file's purpose.
 */

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


/**
 * Determines the target architecture of the PE file.
 * 
 * Parses the `Machine` field in the IMAGE_FILE_HEADER to identify the processor 
 * architecture (e.g., x86, x64, ARM, Itanium, etc.). Stores the result as a short 
 * descriptive string in the internal `PeInfo.Machine` buffer.
 */


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


/**
 * Identifies whether the PE file is 32-bit or 64-bit.
 * 
 * Reads the `Magic` field from the Optional Header to determine the architecture 
 * type (`0x10B` for PE32 or `0x20B` for PE32+). Stores the result in `PeInfo.Is32Magic`.
 * Triggers a fatal error if the magic value is invalid.
 */

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

/**
 * Computes and stores cryptographic hashes of the entire PE file.
 * 
 * Generates MD5, SHA-1, and SHA-256 hashes of the mapped file content and stores 
 * them in the corresponding fields of the `PeInfo` structure for identification, 
 * integrity checking, or malware signature matching. Support for ssdeep (fuzzy 
 * hashing) will be added later for improved similarity-based file matching.
 */


void PEFile::GetHashes(){
    Utils::GetMd5(lpAddress , size , PeInfo.Md5);
    Utils::GetSha1(lpAddress , size , PeInfo.Sha1);
    Utils::GetSha256(lpAddress , size , PeInfo.Sha256);
}

void PEFile::GetTimeDateStamp(){
    const size_t headerOffset = e_lfanew + IMAGE_NT_SIGNATURE_SIZE;
    const auto   fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(
        reinterpret_cast<ULONGLONG>(lpAddress) + headerOffset);
    TimeDateStamp =  fileHeader->TimeDateStamp;
}

/**
 * Parses and stores section headers from a Portable Executable (PE) file.
 *
 * This function extracts the section headers from the PE file mapped at `lpAddress`
 * and stores them in the internal `PeInfo` structure. It supports both PE32 and PE32+ formats
 * by interpreting the correct optional header and determining the number of data directories.
 * 
 * The function dynamically allocates memory for section metadata if the number of sections
 * exceeds a defined threshold (`INITIAL_SECTION_NUMBER`). This ensures flexibility when dealing
 * with non-standard or maliciously crafted PE files that declare a large number of sections.
 *
 * @details
 * - Determines the offset of the optional header based on the PE magic.
 * - Validates memory bounds to prevent out-of-bounds access using `CHECK_OFFSET`.
 * - Calculates the address of the section header table.
 * - If the section count exceeds `INITIAL_SECTION_NUMBER`, it dynamically allocates space
 *   using `new InfoSection[]`, capped at `PeInfo.MaxSectionNumber` for safety.
 * - Copies each `IMAGE_SECTION_HEADER` into `InfoSection` entries.
 *
 * @warning
 * - Malformed or malicious PE files may report extremely high `NumberOfSections`.
 *   This implementation limits allocation to a max (`MaxSectionNumber`) to avoid OOM or DoS.
 * - If the `NumberOfRvaAndSizes` field is below 16, a warning is shown since it's uncommon.
 * 
 * @note
 * - The entropy or other metadata for each section is not calculated here — this is purely
 *   structural extraction.
 * - The original pointer `lpAddress` must point to a fully loaded or memory-mapped PE file,
 *   and the total file size (`size`) must be known beforehand.
 *
 * @see PEFile::ParseOptionalHeader(), Utils::CalculateEntropy()
 */


void PEFile::GetSections(){

    union OptionalHeaderPtr {
        IMAGE_OPTIONAL_HEADER32* h32;
        IMAGE_OPTIONAL_HEADER64* h64;
    };

    DWORD dirNumber{} ;

    InfoSection* infoSection =  nullptr;
    OptionalHeaderPtr optHeader = {};
    IMAGE_SECTION_HEADER* startSectionHeader =  nullptr;

    const DWORD optionalHeaderOffset =  e_lfanew + IMAGE_NT_SIGNATURE_SIZE + IMAGE_FILE_HEADER_SIZE;
    if(PeInfo.Is32Magic){
        CHECK_OFFSET(optionalHeaderOffset + IMAGE_OPTIONAL_HEADER32_MINSIZE , size);
        optHeader.h32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(
            reinterpret_cast<ULONGLONG>(lpAddress) + optionalHeaderOffset);

    }else{
        CHECK_OFFSET(optionalHeaderOffset + IMAGE_OPTIONAL_HEADER64_MINSIZE , size);
        optHeader.h64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(
            reinterpret_cast<ULONGLONG>(lpAddress) + optionalHeaderOffset);
    }

    const size_t headerOffset = e_lfanew + IMAGE_NT_SIGNATURE_SIZE;
    const auto   fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(
        reinterpret_cast<ULONGLONG>(lpAddress) + headerOffset);


    PeInfo.SectionNumber = fileHeader->NumberOfSections;
    if (PeInfo.SectionNumber > INITIAL_SECTION_NUMBER){
        if (PeInfo.SectionNumber > PeInfo.MaxSectionNumber)
            std::cout << "[?] WARNING : PE file has a high NumberOfSections " << PeInfo.SectionNumber
            << " , for memory safety the maximim NumberOfSections is 20 but u can change it with -nsections argument" << '\n';
        PeInfo.SectionNumber = std::min(PeInfo.SectionNumber , PeInfo.MaxSectionNumber); 
        PeInfo.ExceededStackSections = true;
        try{
            PeInfo.ptr =  new InfoSection[PeInfo.SectionNumber];
        }catch(std::bad_alloc&){
            std::cerr << "[!] ERROR: Failed to allocate memory for sections\n";
            return;
        }
        infoSection = PeInfo.ptr;

    }else{
        infoSection =  PeInfo.Sections;

    }

    if (PeInfo.Is32Magic) {

        if ((optHeader.h32)->NumberOfRvaAndSizes < 16){
            std::cout << "[?] NOTE : Non-standard NumberOfRvaAndSizes (" << optHeader.h32->NumberOfRvaAndSizes
            << ")\n";
        }

        dirNumber = std::min((optHeader.h32)->NumberOfRvaAndSizes ,  static_cast<DWORD>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES));
        CHECK_OFFSET(optionalHeaderOffset + IMAGE_OPTIONAL_HEADER32_MINSIZE + 
            (IMAGE_DATA_DIRECTORY_SIZE * dirNumber) + (IMAGE_SECTION_HEADER_SIZE * (PeInfo.SectionNumber)) , size);
        startSectionHeader =  reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<ULONGLONG>(lpAddress)+
            optionalHeaderOffset + IMAGE_OPTIONAL_HEADER32_MINSIZE + IMAGE_DATA_DIRECTORY_SIZE*dirNumber);
    }else{

        if ((optHeader.h64)->NumberOfRvaAndSizes < 16){
            std::cout << "[?] NOTE : Non-standard NumberOfRvaAndSizes (" << optHeader.h64->NumberOfRvaAndSizes
            << ")\n";
        }

        dirNumber =  std::min(((optHeader.h64)->NumberOfRvaAndSizes) ,  static_cast<DWORD>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES));
        CHECK_OFFSET(optionalHeaderOffset + IMAGE_OPTIONAL_HEADER64_MINSIZE + 
            (IMAGE_DATA_DIRECTORY_SIZE * dirNumber) + (IMAGE_SECTION_HEADER_SIZE * (PeInfo.SectionNumber)), size);
        startSectionHeader =  reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<ULONGLONG>(lpAddress)+
            optionalHeaderOffset + IMAGE_OPTIONAL_HEADER64_MINSIZE + IMAGE_DATA_DIRECTORY_SIZE*dirNumber);
    
    }


    for (size_t section = 0  ; section < PeInfo.SectionNumber ; section++ ){
        memcpy(reinterpret_cast<void *>(&(infoSection->sectionHeader)) ,
         startSectionHeader + section ,
         IMAGE_SECTION_HEADER_SIZE);
        infoSection++;
    }

}


void PEFile::ChangeMaxSectionNumber(DWORD Max){
    PeInfo.MaxSectionNumber =  std::max(Max , PeInfo.MaxSectionNumber);
}

/**
 * @brief Computes the entropy for each section in the PE file.
 *
 * This function iterates over all parsed section headers and calculates the Shannon
 * entropy of each section's raw data using `Utils::CalculateEntropy()`. The result
 * is stored in the corresponding `InfoSection::entropy` field for each section.
 *
 * @details
 * - Before analyzing each section, it validates that the section's raw data boundaries
 *   (i.e., `PointerToRawData + SizeOfRawData`) fall within the bounds of the loaded
 *   PE image (`size`) using `CHECK_OFFSET`.
 * - Handles both static and dynamically allocated section arrays depending on the
 *   section count and memory model used.
 * - Entropy helps identify suspicious sections that may be packed, encrypted,
 *   or otherwise obfuscated.
 *
 * @warning
 * - Fails hard with a fatal error if a section points outside the bounds of the PE image.
 * - Assumes that `lpAddress` and `size` refer to the full loaded file in memory.
 *
 * @see Utils::CalculateEntropy()
 * @see PEFile::GetSections()
 */

void PEFile::GetSectionsEntropy(){
    InfoSection* ptr = nullptr;
    (PeInfo.SectionNumber > INITIAL_SECTION_NUMBER) ? ptr =  PeInfo.ptr :
        ptr =  PeInfo.Sections;


    for (size_t nsection = 0 ; nsection < PeInfo.SectionNumber ; nsection++,ptr++ ){
        CHECK_OFFSET((ptr->sectionHeader).PointerToRawData + (ptr->sectionHeader).SizeOfRawData , size);
        Utils::CalculateEntropy(reinterpret_cast<LPCVOID>(
            (ptr->sectionHeader).PointerToRawData + 
            reinterpret_cast<ULONGLONG>(lpAddress)) , (ptr->sectionHeader).SizeOfRawData,
            &(ptr->entropy));
    }
}

void PEFile::Parse(){
    (IsValidPE()) ? (void)(std::cout << "[*] Initial validation passed ...\n") : std::exit(EXIT_FAILURE);
    GetMachine();
    GetCharacteristics();
    GetMagic();
    GetHashes();
    GetTimeDateStamp();
    GetSections();
    GetSectionsEntropy();
    for (size_t nsection= 0 ; nsection < PeInfo.SectionNumber ; nsection++){
        std::cout << PeInfo.Sections[nsection].entropy << std::endl;
    }
}
