#include <utils.h>
#include <header.h>
#include <pe_parser.h>
#include <pe_structs.h>

/*
 *
 * @details
 * This module provides comprehensive parsing and analysis of PE files (Windows executables and DLLs).
 * It extracts structural information, performs basic security analysis, and calculates various hashes.
 * 
 * Each function is described for better understanding.
 *
 * Key features:
 * - Extracts PE header information including:
 *   - Machine architecture (x86/x64/ARM etc.)
 *   - File type (EXE/DLL/SYS)
 *   - Subsystem (Console/GUI/Driver etc.)
 *   - Compilation timestamp
 *   - 32/64-bit flag
 * - Extracts section information including:
 *   - Section names
 *   - Virtual/physical sizes
 *   - Characteristics
 *   - Entropy calculation per section
 * - Extracts import/export tables
 * - Calculates file and sections hashes:
 *   - MD5
 *   - SHA-1
 *   - SHA-256
 * - Calculates entropy for:
 *   - Entire file
 *   - Each individual section
 * 
 * @author Noureddine Azfar
 */


/**
 * Loads a Portable Executable (PE) file into memory.
 * 
 * This method opens a PE file from disk, retrieves its size, and maps its contents
 * into memory for further analysis or processing. It handles both Windows and 
 * Unix-like systems using platform-specific APIs. On Windows, it uses CreateFile,
 * CreateFileMapping, and MapViewOfFile. On Unix-like systems, it uses open, fstat, 
 * and mmap.
 * 
 * If the file is too small or mapping fails, a fatal error is triggered.
 * 
 * @param filePath Path to the PE file on disk.
 */


int ThreadPool::s_numberOfProcessors = 0;

void PEFile::loadFromFile(const std::string& filePath) {
#ifdef _WIN32
    m_hFile  =  CreateFileA(filePath.c_str(), GENERIC_READ , FILE_SHARE_READ|FILE_SHARE_WRITE , nullptr , OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL , nullptr);
    if (m_hFile == INVALID_HANDLE_VALUE) {
        const DWORD err = GetLastError();
        utils::systemError(static_cast<int>(err), "[!] Failed to open the file ");
    }

    LARGE_INTEGER li;
    if (!GetFileSizeEx(m_hFile, &li)) {
        const DWORD err = GetLastError();
        CloseHandle(m_hFile);
        utils::systemError(static_cast<int>(err), "[!] Failed to get file size ");
    }

    m_size = li.QuadPart;
    if (m_size < IMAGE_DOS_HEADER_SIZE) utils::fatalError("[!] File is too small ");
    m_hMapFile = CreateFileMappingA(m_hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (m_hMapFile == nullptr) {
        const DWORD err = GetLastError();
        CloseHandle(m_hFile);
        utils::systemError(static_cast<int>(err), "[!] Failed to create the file mapping ");
    }
    m_lpAddress = MapViewOfFile(m_hMapFile, FILE_MAP_READ, 0, 0, m_size);
    if (m_lpAddress == nullptr) {
        const DWORD err = GetLastError();
        CloseHandle(m_hMapFile);
        CloseHandle(m_hFile);
        utils::systemError(static_cast<int>(err), "[!] Failed to map view of the file ");
    }

    #ifdef DEBUG 
    	std::cout << "[*] File opened successfully " << std::endl;
    #endif

#else
    m_fd  =  open(filePath.c_str() , O_RDONLY);
    if (m_fd == -1) utils::systemError(errno , "[!] Failed to open the file ");
    struct stat sb;
    if (fstat(m_fd , &sb) == -1) {
        close(m_fd);
        utils::systemError(errno , "[!] Failed to stat the file ");
    }
    m_size = sb.st_size;
    if (m_size < IMAGE_DOS_HEADER_SIZE) utils::fatalError("File is too small ");
    m_lpAddress  =  mmap(nullptr , m_size , PROT_READ , MAP_PRIVATE , m_fd , 0);
    close(m_fd);
    m_fd = -1;
    if (m_lpAddress == MAP_FAILED) {
        utils::systemError(errno , "[!] Failed to map the file ");
    }

    #ifdef DEBUG 
        std::cout << "[*] File opened successfully ..." << '\n';
    #endif

#endif

}



PEFile::PEFile(const std::string& filePath){
    PEFile::loadFromFile(filePath);
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
        UnmapViewOfFile(m_lpAddress);
        CloseHandle(m_hMapFile);
        CloseHandle(m_hFile);
    #else
        munmap(m_lpAddress , m_size);
    #endif
}


/**
 * Validates whether the loaded file is a proper PE (Portable Executable) file.
 * 
 * This method performs structural validation on the memory-mapped file to determine
 * if it conforms to the PE format. It begins by interpreting the start of the mapped
 * memory as an IMAGE_DOS_HEADER and checks for the 'MZ' DOS signature (`0x5A4D`).
 * 
 * If the DOS header is valid, it retrieves the `m_elfanew` field — the offset to the
 * NT header — and stores it internally for later access. Then, it ensures the offset
 * is within valid bounds to avoid accessing memory outside the mapped file.
 * 
 * It finally checks whether the DWORD located at `m_elfanew` corresponds to the NT
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

bool PEFile::isValidPe() {
    const auto dosHeader =  static_cast<IMAGE_DOS_HEADER*>(m_lpAddress);
    if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const DWORD PeOffset = dosHeader->e_lfanew;
    this->m_elfanew = PeOffset;
    //The added 4 for magic , major and minor in optional header
    CHECK_OFFSET(PeOffset + IMAGE_FILE_HEADER_SIZE + IMAGE_NT_SIGNATURE_SIZE + 4, m_size);
    return *(reinterpret_cast<DWORD*>(reinterpret_cast<ULONGLONG>(m_lpAddress)+PeOffset)) == IMAGE_NT_SIGNATURE;
}

/**
 * Extracts and classifies the PE file type (EXE, DLL, SYS, or UNK).
 * 
 * Parses the IMAGE_FILE_HEADER to inspect the `Characteristics` field and 
 * stores a short string label ("EXE", "DLL", "SYS", or "UNK") in the internal 
 * `m_peInfo` structure based on the file's purpose.
 */

void PEFile::getCharacteristics(){
    const size_t headerOffset = m_elfanew + IMAGE_NT_SIGNATURE_SIZE;
    const auto fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(
        reinterpret_cast<ULONGLONG>(m_lpAddress) + headerOffset);
    auto& characteristics = this->m_peInfo.m_characteristics;
    uint8_t* ptr = characteristics.data();
    if (fileHeader->Characteristics & IMAGE_FILE_SYSTEM){
        strncpy(reinterpret_cast<char *>(ptr) , "SYS" , 4);
        return;
    }
    else if (fileHeader->Characteristics & IMAGE_FILE_DLL) {
        strncpy(reinterpret_cast<char *>(ptr) , "DLL" , 4);
        return;
    }
    else if (fileHeader->Characteristics & IMAGE_FILE_EXECUTABLE_IMAGE) {
        strncpy(reinterpret_cast<char *>(ptr) , "EXE" , 4);
        getSubsystem();
        return;
    }

    strncpy(reinterpret_cast<char *>(ptr) , "UNK" , 4);
}


/**
 * @brief Retrieves the subsystem type of the PE file.
 * 
 * Determines whether the PE file is a GUI, CUI, EFI, or other subsystem type by
 * examining the optional header (32-bit or 64-bit). The result is stored as a
 * human-readable string in `m_peInfo.m_subsystem`.
 * 
 * @note The function handles both 32-bit and 64-bit PE files. If the subsystem
 * is unrecognized, "undefined" is stored.
 */

void PEFile::getSubsystem(){

    union OptionalHeaderPtr {
        IMAGE_OPTIONAL_HEADER32* h32;
        IMAGE_OPTIONAL_HEADER64* h64;
    };

    WORD subsystem;
    uint8_t *ptr = m_peInfo.m_subsystem.data();
    OptionalHeaderPtr optHeader = {};

    const DWORD optionalHeaderOffset =  m_elfanew + IMAGE_NT_SIGNATURE_SIZE + IMAGE_FILE_HEADER_SIZE;

    if(m_peInfo.m_is32Magic){
        optHeader.h32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(
            reinterpret_cast<ULONGLONG>(m_lpAddress) + optionalHeaderOffset);
        subsystem = optHeader.h32->Subsystem;
    }else{
        optHeader.h64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(
            reinterpret_cast<ULONGLONG>(m_lpAddress) + optionalHeaderOffset);
        subsystem = optHeader.h32->Subsystem;        
    }
    switch(subsystem){
        case IMAGE_SUBSYSTEM_UNKNOWN :                  strncpy(reinterpret_cast<char *>(ptr) , "Unkown" , 24); break;
        case IMAGE_SUBSYSTEM_NATIVE:                    strncpy(reinterpret_cast<char *>(ptr) , "Native" , 24); break;
        case IMAGE_SUBSYSTEM_WINDOWS_GUI:               strncpy(reinterpret_cast<char *>(ptr) , "Windows GUI" , 24); break;
        case IMAGE_SUBSYSTEM_WINDOWS_CUI:               strncpy(reinterpret_cast<char *>(ptr) , "Windows CUI" , 24); break;
        case IMAGE_SUBSYSTEM_OS2_CUI:                   strncpy(reinterpret_cast<char *>(ptr) , "OS/2 CUI" , 24); break;
        case IMAGE_SUBSYSTEM_POSIX_CUI:                 strncpy(reinterpret_cast<char *>(ptr) , "POSIX CUI" , 24); break;
        case IMAGE_SUBSYSTEM_NATIVE_WINDOWS:            strncpy(reinterpret_cast<char *>(ptr) , "Native Win9x" , 24); break;
        case IMAGE_SUBSYSTEM_WINDOWS_CE_GUI:            strncpy(reinterpret_cast<char *>(ptr) , "Windows CE GUI",24); break;
        case IMAGE_SUBSYSTEM_EFI_APPLICATION:           strncpy(reinterpret_cast<char *>(ptr) , "EFI Application",24); break;
        case IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:   strncpy(reinterpret_cast<char *>(ptr) , "EFI BOOT Driver" , 24); break;
        case IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:        strncpy(reinterpret_cast<char *>(ptr) , "EFI Runtime Driver" , 24); break;
        case IMAGE_SUBSYSTEM_EFI_ROM:                   strncpy(reinterpret_cast<char *>(ptr) , "EFI ROM" , 24); break;
        case IMAGE_SUBSYSTEM_XBOX:                      strncpy(reinterpret_cast<char *>(ptr) , "Xbox" , 24); break;
        case IMAGE_SUBSYSTEM_WINDOWS_BOOT_APPLICATION:  strncpy(reinterpret_cast<char *>(ptr) , "Windows BOOT App" , 24); break;
        case IMAGE_SUBSYSTEM_XBOX_CODE_CATALOG:         strncpy(reinterpret_cast<char *>(ptr) , "Xbox Code Catalog" ,24); break;
        default:                                        strncpy(reinterpret_cast<char *>(ptr) , "undefined" , 24); break;
    }
}
/**
 * @brief Determines the target architecture of the PE file.
 * 
 * Parses the `Machine` field in the IMAGE_FILE_HEADER to identify the processor 
 * architecture (e.g., x86, x64, ARM, Itanium, etc.). Stores the result as a short 
 * descriptive string in the internal `m_peInfo.Machine` buffer.
 */


void PEFile::getMachine(){
    //Check that we can read at headerOffset is made in isValidPe
    const size_t headerOffset = m_elfanew + IMAGE_NT_SIGNATURE_SIZE;
    const auto fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(
        reinterpret_cast<ULONGLONG>(m_lpAddress) + headerOffset);
    auto& machine = m_peInfo.m_machine;
    uint8_t* ptr  =  machine.data();
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
        default: strncpy(reinterpret_cast<char *>(ptr) , "Undefined" , 16);
    }
}


/**
 * Identifies whether the PE file is 32-bit or 64-bit.
 * 
 * Reads the `Magic` field from the Optional Header to determine the architecture 
 * type (`0x10B` for PE32 or `0x20B` for PE32+). Stores the result in `m_peInfo.Is32Magic`.
 * Triggers a fatal error if the magic value is invalid.
 */

void PEFile::getMagic(){
    //Check that we can read at magic offset is made in isValidPe
    const size_t magicOffset  =  m_elfanew + IMAGE_NT_SIGNATURE_SIZE + IMAGE_FILE_HEADER_SIZE;
    auto magic  =  *reinterpret_cast<WORD*>(
        reinterpret_cast<ULONGLONG>(m_lpAddress) + magicOffset);
    switch (magic) {
        case IMAGE_NT_OPTIONAL_HDR32_MAGIC:  // 0x10B
            this->m_peInfo.m_is32Magic = true;
            break;
        case IMAGE_NT_OPTIONAL_HDR64_MAGIC:  // 0x20B
            this->m_peInfo.m_is32Magic = false;
            break;
        default:
            utils::fatalError("Invalid PE architecture (unknown Magic value)");
    }
}


/**
 * Computes and stores cryptographic hashes of the entire PE file.
 * 
 * Generates MD5, SHA-1, and SHA-256 hashes of the mapped file content and stores 
 * them in the corresponding fields of the `m_peInfo` structure for identification, 
 * integrity checking, or malware signature matching. Support for ssdeep (fuzzy 
 * hashing) will be added later for improved similarity-based file matching.
 */


void PEFile::getFileHashes(){
    std::array<uint8_t , MD5_HASH_LEN> md5{};
    std::array<uint8_t , SHA1_HASH_LEN> sha1{};
    std::array<uint8_t , SHA256_HASH_LEN> sha256{};

    utils::getMd5(m_lpAddress , m_size , md5);
    utils::getSha1(m_lpAddress , m_size , sha1);
    utils::getSha256(m_lpAddress , m_size , sha256);

    utils::bytesToHexString(md5.data() , MD5_HASH_LEN , m_peInfo.m_md5.data());
    utils::bytesToHexString(sha1.data() , SHA1_HASH_LEN , m_peInfo.m_sha1.data());
    utils::bytesToHexString(sha256.data() , SHA256_HASH_LEN , m_peInfo.m_sha256.data());

}

void PEFile::getTimeDateStamp(){
    const size_t headerOffset = m_elfanew + IMAGE_NT_SIGNATURE_SIZE;
    const auto   fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(
        reinterpret_cast<ULONGLONG>(m_lpAddress) + headerOffset);
    utils::convertTimeStamp(fileHeader->TimeDateStamp , m_peInfo.m_timeStampString);
}

/**
 * Parses and stores section headers from a Portable Executable (PE) file.
 *
 * This function extracts the section headers from the PE file mapped at `m_lpAddress`
 * and stores them in the internal `m_peInfo` structure. It supports both PE32 and PE32+ formats
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
 *   using `new InfoSection[]`.
 * - Copies each `IMAGE_SECTION_HEADER` into `InfoSection` entries.
 *
 * @warning
 * - If the `NumberOfRvaAndSizes` field is below 16, a warning is shown since it's uncommon.
 * 
 * @note
 * - The entropy or other metadata for each section is not calculated here — this is purely
 *   structural extraction.
 * - The original pointer `m_lpAddress` must point to a fully loaded or memory-mapped PE file,
 *   and the total file size (`m_size`) must be known beforehand.
 *
 */


void PEFile::getSections(){

    union OptionalHeaderPtr {
        IMAGE_OPTIONAL_HEADER32* h32;
        IMAGE_OPTIONAL_HEADER64* h64;
    };

    DWORD dirNumber{} ;

    InfoSection* infoSection =  nullptr;
    OptionalHeaderPtr optHeader = {};
    IMAGE_SECTION_HEADER* startSectionHeader =  nullptr;

    const DWORD optionalHeaderOffset =  m_elfanew + IMAGE_NT_SIGNATURE_SIZE + IMAGE_FILE_HEADER_SIZE;
    if(m_peInfo.m_is32Magic){
        CHECK_OFFSET(optionalHeaderOffset + IMAGE_OPTIONAL_HEADER32_MINSIZE , m_size);
        optHeader.h32 = reinterpret_cast<IMAGE_OPTIONAL_HEADER32*>(
            reinterpret_cast<ULONGLONG>(m_lpAddress) + optionalHeaderOffset);

    }else{
        CHECK_OFFSET(optionalHeaderOffset + IMAGE_OPTIONAL_HEADER64_MINSIZE , m_size);
        optHeader.h64 = reinterpret_cast<IMAGE_OPTIONAL_HEADER64*>(
            reinterpret_cast<ULONGLONG>(m_lpAddress) + optionalHeaderOffset);
    }

    const size_t headerOffset = m_elfanew + IMAGE_NT_SIGNATURE_SIZE;
    const auto   fileHeader = reinterpret_cast<IMAGE_FILE_HEADER*>(
        reinterpret_cast<ULONGLONG>(m_lpAddress) + headerOffset);


    m_peInfo.m_sectionNumber = fileHeader->NumberOfSections;
    if (m_peInfo.m_sectionNumber > INITIAL_SECTION_NUMBER){
        m_peInfo.m_exceededStackSections = true;
        try{
            m_peInfo.m_ptr =  new InfoSection[m_peInfo.m_sectionNumber];
        }catch(std::bad_alloc&){
            utils::fatalError("Failed to allocate memory");
        }

    }else{
        m_peInfo.m_ptr = m_peInfo.m_sections;

    }

    infoSection = m_peInfo.m_ptr;

    if (m_peInfo.m_is32Magic) {

        if ((m_peInfo.m_numberOfRvaAndSizes = (optHeader.h32)->NumberOfRvaAndSizes) < 16){
            std::cout << "[?] NOTE : Non-standard NumberOfRvaAndSizes (" << optHeader.h32->NumberOfRvaAndSizes
            << ")\n";
        }

        dirNumber = std::min((optHeader.h32)->NumberOfRvaAndSizes ,  static_cast<DWORD>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES));
        CHECK_OFFSET(optionalHeaderOffset + IMAGE_OPTIONAL_HEADER32_MINSIZE + 
            (IMAGE_DATA_DIRECTORY_SIZE * dirNumber) + (IMAGE_SECTION_HEADER_SIZE * (m_peInfo.m_sectionNumber)) , m_size);
        m_lpDataDirectory = reinterpret_cast<LPVOID>(reinterpret_cast<ULONGLONG>(m_lpAddress) +
            optionalHeaderOffset + IMAGE_OPTIONAL_HEADER32_MINSIZE);
        startSectionHeader =  reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<ULONGLONG>(m_lpDataDirectory) +
            IMAGE_DATA_DIRECTORY_SIZE * dirNumber);
    }else{

        if ((m_peInfo.m_numberOfRvaAndSizes = (optHeader.h64)->NumberOfRvaAndSizes) < 16){
            std::cout << "[?] NOTE : Non-standard NumberOfRvaAndSizes (" << optHeader.h64->NumberOfRvaAndSizes
            << ")\n";
        }

        dirNumber =  std::min(((optHeader.h64)->NumberOfRvaAndSizes) ,  static_cast<DWORD>(IMAGE_NUMBEROF_DIRECTORY_ENTRIES));
        CHECK_OFFSET(optionalHeaderOffset + IMAGE_OPTIONAL_HEADER64_MINSIZE + 
            (IMAGE_DATA_DIRECTORY_SIZE * dirNumber) + (IMAGE_SECTION_HEADER_SIZE * (m_peInfo.m_sectionNumber)), m_size);
        m_lpDataDirectory = reinterpret_cast<LPVOID>(reinterpret_cast<ULONGLONG>(m_lpAddress) + 
            optionalHeaderOffset + IMAGE_OPTIONAL_HEADER64_MINSIZE);
        startSectionHeader =  reinterpret_cast<IMAGE_SECTION_HEADER*>(reinterpret_cast<ULONGLONG>(m_lpDataDirectory) +
            IMAGE_DATA_DIRECTORY_SIZE*dirNumber);
    
    }


    for (size_t section = 0  ; section < m_peInfo.m_sectionNumber ; section++ ){
        memcpy(reinterpret_cast<void *>(&(infoSection->m_sectionHeader)) ,
         startSectionHeader + section ,
         IMAGE_SECTION_HEADER_SIZE);
        infoSection++;
    }

}



/**
 * @brief Computes the entropy for each section in the PE file.
 *
 * This function iterates over all parsed section headers and calculates the Shannon
 * entropy of each section's raw data using `utils::CalculateEntropy()`. The result
 * is stored in the corresponding `InfoSection::entropy` field for each section.
 *
 * @details
 * - Before analyzing each section, it validates that the section's raw data boundaries
 *   (i.e., `PointerToRawData + SizeOfRawData`) fall within the bounds of the loaded
 *   PE image (`m_size`) using `CHECK_OFFSET`.
 * - Handles both static and dynamically allocated section arrays depending on the
 *   section count and memory model used.
 * - Entropy helps identify suspicious sections that may be packed, encrypted,
 *   or otherwise obfuscated.
 *
 * @warning
 * - Fails hard with a fatal error if a section points outside the bounds of the PE image.
 *
 * @see utils::calculateEntropy()
 * @see PEFile::getSections()
 */

void PEFile::getSectionsEntropy(){
    InfoSection* ptr = m_peInfo.m_ptr;
    
    if(!ptr){
        utils::fatalError("[!] Trying to calculate sections entropy before getting sections");
    }

    for (size_t nsection = 0 ; nsection < m_peInfo.m_sectionNumber ; nsection++,ptr++ ){
        CHECK_OFFSET((ptr->m_sectionHeader).PointerToRawData + (ptr->m_sectionHeader).SizeOfRawData , m_size);
        utils::calculateEntropy(reinterpret_cast<LPCVOID>(
            (ptr->m_sectionHeader).PointerToRawData + 
            reinterpret_cast<ULONGLONG>(m_lpAddress)) , (ptr->m_sectionHeader).SizeOfRawData,
            &(ptr->m_entropy));
    }
}


/**
 * @brief Calculates MD5, SHA1, and SHA256 hashes for each PE section.
 * 
 * Computes cryptographic hashes (MD5, SHA1, SHA256) for every section in the PE file
 * using the raw section data. The resulting hash strings are stored in each section's
 * InfoSection structure (m_md5, m_sha1, m_sha256).
 *
 * @warning Requires sections to be loaded first (via getSections).
 * Will trigger a fatal error if called before section data is available.
 */

void PEFile::getSectionsHashes(){
    InfoSection* ptr =  m_peInfo.m_ptr;
    
    if(!ptr){
        utils::fatalError("[!] Trying to calculate sections hashes before getting sections");
    }

    std::array<uint8_t , MD5_HASH_LEN> md5{};
    std::array<uint8_t , SHA1_HASH_LEN> sha1{};
    std::array<uint8_t , SHA256_HASH_LEN> sha256{};

    for(size_t nsection = 0; nsection < m_peInfo.m_sectionNumber ; nsection++ , ptr++){
        // At this point we already check offsets in getSectionsEntropy , so we won't do it here
        utils::getMd5(reinterpret_cast<LPCVOID>(
            (ptr->m_sectionHeader).PointerToRawData + 
            reinterpret_cast<ULONGLONG>(m_lpAddress)) , (ptr->m_sectionHeader).SizeOfRawData,
            md5);

        utils::getSha1(reinterpret_cast<LPCVOID>(
            (ptr->m_sectionHeader).PointerToRawData + 
            reinterpret_cast<ULONGLONG>(m_lpAddress)) , (ptr->m_sectionHeader).SizeOfRawData,
            sha1);

        utils::getSha256(reinterpret_cast<LPCVOID>(
            (ptr->m_sectionHeader).PointerToRawData + 
            reinterpret_cast<ULONGLONG>(m_lpAddress)) , (ptr->m_sectionHeader).SizeOfRawData,
            sha256);

        utils::bytesToHexString(md5.data() , MD5_HASH_LEN , ptr->m_md5.data());
        utils::bytesToHexString(sha1.data() , SHA1_HASH_LEN , ptr->m_sha1.data());
        utils::bytesToHexString(sha256.data() , SHA256_HASH_LEN , ptr->m_sha256.data()); 
    }
}

/**
 * @brief Parses and retrieves all imported DLLs and their functions from the PE file.
 * 
 * This function analyzes the PE import directory to extract:
 * - All imported DLL names
 * - Each function imported from those DLLs
 * 
 * The results are stored in m_peInfo.m_allImports as a vector of Import structures,
 * where each Import contains:
 * - m_dllName: The DLL name being imported from
 * - m_apisVector: List of function names imported from this DLL
 *
 * @note Handles both 32-bit and 64-bit PE files automatically
 * @note Uses safe RVA-to-offset conversion with bounds checking
 * @note Skips imports by ordinal (only captures named imports)
 * 
 * @warning Will return early if:
 *          - Import directory doesn't exist (numberOfRvaAndSizes too small)
 *          - Import table has zero size
 *          - Memory allocation fails (throws fatal error)
 */

void PEFile::getImports(){


    DWORD apiNameOffset;
    DWORD apiNameRva;

    DWORD nameRva;
    DWORD nameOffset;
    DWORD iltRva;
    DWORD iltOffset;
    Import* dllImport;

    if (m_peInfo.m_numberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_IMPORT + 1)
        return;

    const DWORD importTableRva = (
        (static_cast<IMAGE_DATA_DIRECTORY*>(m_lpDataDirectory) + 
        IMAGE_DIRECTORY_ENTRY_IMPORT)->VirtualAddress);

    const DWORD importTableSize = (
        (static_cast<IMAGE_DATA_DIRECTORY*>(m_lpDataDirectory) + 
        IMAGE_DIRECTORY_ENTRY_IMPORT)->Size);

    if (!importTableRva || !importTableSize){
        return;
    }
    const DWORD importTableOffset  = utils::safeRvaToFileOffset(importTableRva, m_peInfo.m_ptr ,
                                         m_peInfo.m_sectionNumber,__FUNCTION__);

    CHECK_OFFSET(importTableOffset + sizeof(IMAGE_IMPORT_DESCRIPTOR), m_size);
    auto importTable = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(
        reinterpret_cast<ULONGLONG>(m_lpAddress) + importTableOffset);

    while((nameRva = importTable->Name)){
        nameOffset = utils::safeRvaToFileOffset(nameRva , m_peInfo.m_ptr , m_peInfo.m_sectionNumber , __FUNCTION__);

        CHECK_OFFSET(nameOffset , m_size);
        try{
            dllImport = new Import;
        }catch(std::bad_alloc&){
            utils::fatalError("Failed to allocate memory");
        }
        m_peInfo.m_allImports.push_back(dllImport);
        dllImport->m_dllName = static_cast<char*>(m_lpAddress) + nameOffset;
#ifndef _WIN32
        iltRva = (importTable->DUMMYUNIONNAME.OriginalFirstThunk) ?
         importTable->DUMMYUNIONNAME.OriginalFirstThunk : importTable->FirstThunk;
#else
        iltRva = (importTable->OriginalFirstThunk) ?
            importTable->OriginalFirstThunk : importTable->FirstThunk;
#endif
        if (!iltRva) goto Next;
        iltOffset  =  utils::safeRvaToFileOffset(iltRva , m_peInfo.m_ptr , m_peInfo.m_sectionNumber , __FUNCTION__);
        
        if (m_peInfo.m_is32Magic){
            CHECK_OFFSET(iltOffset + sizeof(IMAGE_THUNK_DATA32) , m_size);
            auto thunk = reinterpret_cast<IMAGE_THUNK_DATA32*>(
                reinterpret_cast<ULONGLONG>(m_lpAddress) + iltOffset);
            while(thunk->u1.AddressOfData){
                if (!(thunk->u1.Ordinal & ORDINAL_32_FLAG)){
                    apiNameRva = thunk->u1.AddressOfData;
                    apiNameOffset = utils::safeRvaToFileOffset(apiNameRva , m_peInfo.m_ptr , m_peInfo.m_sectionNumber , __FUNCTION__);
                    CHECK_OFFSET(apiNameOffset + sizeof(WORD), m_size);
                    const auto importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(static_cast<BYTE *>(m_lpAddress) + apiNameOffset);
                    auto apiName = (char*)importByName->Name;
                    dllImport->m_apisVector.push_back(apiName);
                }
                thunk++;
            }        
        }else{
            CHECK_OFFSET(iltOffset + sizeof(IMAGE_THUNK_DATA64) , m_size);
            auto thunk = reinterpret_cast<IMAGE_THUNK_DATA64*>(
                reinterpret_cast<ULONGLONG>(m_lpAddress) + iltOffset);
            while(thunk->u1.AddressOfData){
                if (!(thunk->u1.Ordinal & ORDINAL_64_FLAG)){
                    apiNameRva = thunk->u1.AddressOfData & IMPORT_BY_NAME_64_MASK;
                    apiNameOffset = utils::safeRvaToFileOffset(apiNameRva , m_peInfo.m_ptr , m_peInfo.m_sectionNumber , __FUNCTION__);
                    CHECK_OFFSET(apiNameOffset +sizeof(WORD) , m_size);
                    const auto importByName = reinterpret_cast<IMAGE_IMPORT_BY_NAME *>(static_cast<BYTE *>(m_lpAddress) + apiNameOffset);
                    auto apiName = static_cast<char *>(importByName->Name);
                    dllImport->m_apisVector.push_back(apiName);
                }
                thunk++;
           }
        }

        Next:
            importTable++;
    }

}


void PEFile::checkNetAssembly(){
    if (m_peInfo.m_is32Magic){
        auto ntHeaders =  reinterpret_cast<IMAGE_NT_HEADERS32*>(reinterpret_cast<ULONGLONG>(m_lpAddress)
            + m_elfanew);
        if (m_peInfo.m_numberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
            return;

        IMAGE_OPTIONAL_HEADER32& optionalHeader =  ntHeaders->OptionalHeader;
        IMAGE_DATA_DIRECTORY& clrDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];

        m_peInfo.m_NetAssembly = (static_cast<ULONGLONG>(clrDirectory.VirtualAddress) * 0x100000000ULL ) | clrDirectory.Size ;
    }else{
        auto ntHeaders =  reinterpret_cast<IMAGE_NT_HEADERS64*>(reinterpret_cast<ULONGLONG>(m_lpAddress)
            + m_elfanew);
        if (m_peInfo.m_numberOfRvaAndSizes <= IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR)
            return;

        IMAGE_OPTIONAL_HEADER64& optionalHeader =  ntHeaders->OptionalHeader;
        IMAGE_DATA_DIRECTORY& clrDirectory = optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR];

        m_peInfo.m_NetAssembly  = (static_cast<ULONGLONG>(clrDirectory.VirtualAddress) * 0x100000000ULL) | clrDirectory.Size ;
    }

    return;
}

/**
 * @brief Retrieves all exported functions from the PE file.
 * 
 * Parses the PE export directory to extract all named exported functions.
 * The exported function names are stored in m_peInfo.m_allExports vector.
 *
 * @details The function:
 * - Verifies the export directory exists and has valid size
 * - Performs safe RVA-to-offset conversion with bounds checking
 * - Handles export directory anomalies (warns about ordinal-only exports)
 * - Only captures named exports (ignores ordinal-only exports)
 *
 * @note Generates warnings for:
 *       - Potential ordinal-only exports (NumberOfNames < NumberOfFunctions)
 *       - Suspicious case where NumberOfNames > NumberOfFunctions
 *
 * @warning Returns early if:
 *          - Export directory doesn't exist (numberOfRvaAndSizes too small)
 *          - Export table has zero size
 *          - No named exports exist (NumberOfNames == 0)
 */


void PEFile::getExports(){

    DWORD nameRva{};
    DWORD nameOffset{};

    if (m_peInfo.m_numberOfRvaAndSizes < IMAGE_DIRECTORY_ENTRY_EXPORT +1)
        return;

    const DWORD exportDirRva = (
        (static_cast<IMAGE_DATA_DIRECTORY*>(m_lpDataDirectory) + 
        IMAGE_DIRECTORY_ENTRY_EXPORT)->VirtualAddress);


    const DWORD exportDirSize = (
        (static_cast<IMAGE_DATA_DIRECTORY*>(m_lpDataDirectory) + 
        IMAGE_DIRECTORY_ENTRY_EXPORT)->Size);

    if (!exportDirRva || !exportDirSize)
        return;

    const DWORD exportDirOffset  = utils::safeRvaToFileOffset(exportDirRva, m_peInfo.m_ptr ,
                                         m_peInfo.m_sectionNumber,__FUNCTION__);

    CHECK_OFFSET(exportDirOffset + sizeof(IMAGE_EXPORT_DIRECTORY) , m_size);
    auto exportDir = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(
        reinterpret_cast<ULONGLONG>(m_lpAddress) + exportDirOffset);


    if (exportDir->NumberOfNames < exportDir->NumberOfFunctions){
        std::cout << "[?] WARNING : Some or all exports are only exported by ordinal\n";
    }
    else if(exportDir->NumberOfNames > exportDir->NumberOfFunctions){
        std::cout << "[?] WARNING : In Export directory , number of names is greater than number of functions????\n";
    }

    if(!(exportDir->NumberOfNames)) return;
    DWORD addressOfNamesRva =  exportDir->AddressOfNames;
    if (!addressOfNamesRva)
        return;

    DWORD addressOfNamesOffset = utils::safeRvaToFileOffset(addressOfNamesRva ,m_peInfo.m_ptr ,
                                         m_peInfo.m_sectionNumber,__FUNCTION__);
    CHECK_OFFSET(addressOfNamesOffset + exportDir->NumberOfNames * sizeof(DWORD) , m_size);
    for (DWORD nameIter = 0 ; nameIter < exportDir->NumberOfNames ; nameIter++ ){
        nameRva =  *reinterpret_cast<DWORD*>(reinterpret_cast<ULONGLONG>(m_lpAddress) + 
            addressOfNamesOffset + nameIter * sizeof(DWORD));

        nameOffset = utils::safeRvaToFileOffset(nameRva , m_peInfo.m_ptr ,
                    m_peInfo.m_sectionNumber,__FUNCTION__);
        m_peInfo.m_allExports.push_back(reinterpret_cast<char *>(m_lpAddress) + nameOffset);
    }
}

/**
 * @brief Executes the complete PE file parsing pipeline with optimized parallel processing
 * 
 * Coordinates the analysis of a Portable Executable (PE) file, automatically selecting
 * between parallel and sequential processing modes based on file size and available
 * CPU cores. The function maintains strict operation ordering to ensure dependencies
 * are respected.
 *
 * @details The parsing occurs in three phases:
 * 1. Mandatory Sequential Initialization:
 *
 * 2. Conditional Parallel Processing (if m_size > CONCURRENCY_THRESHOLD):
 *    - Creates a ThreadPool for concurrent execution
 *    - Processes in parallel:
 *      - File hashing (getFileHashes)
 *      - Import table parsing (getImports)
 *      - Export table parsing (getExports)
 *    - Falls back to sequential if <2 CPU cores available
 *
 * 3. Sequential Processing (small files or single-core):
 *    - Performs all operations serially with additional:
 *      - Section entropy analysis (getSectionsEntropy)
 *      - Per-section hashing (getSectionsHashes)
 *
 * @note Operation ordering is critical:
 *       - Validation must complete before analysis
 *       - Section data must be loaded before entropy/hashing
 *       - Thread pool is scoped to ensure proper cleanup
 *
 * @warning Parallel mode only activates when:
 *          - File exceeds CONCURRENCY_THRESHOLD size
 *          - System has multiple CPU cores
 *          - No failures in initial sequential phase
 */

void PEFile::parse(){
    isValidPe();
    getMachine();
    getMagic();
    getTimeDateStamp();
    getSections();
    getCharacteristics();
    checkNetAssembly();

    ThreadPool::getProcessorsCount();
    
    if (m_size > CONCURRENCY_THRESHOLD && ThreadPool::s_numberOfProcessors >=2) 
    {
        // Engage file hashing with section hashing , no point main thread sits idle
        {
            ThreadPool t_pool{*this};
            t_pool.start();
            getFileHashes();
        }
    }else{
        getFileHashes();
        getSectionsEntropy();
        getSectionsHashes();
    }

    getImports();
    getExports();

}

/**
 * @brief Prints comprehensive analysis results of the PE file in human-readable format.
 * 
 * Outputs all collected PE file information including:
 * - File type and subsystem
 * - Architecture (32/64-bit)
 * - Compilation timestamp
 * - File-level hashes (MD5, SHA1, SHA256)
 * - Machine type
 * - Section details (name, entropy, hashes)
 * - Import table (DLLs and their functions)
 * - Export table (exported functions)
 *
 * @details The output format is organized as:
 * 1. Header information (type, arch, timestamp, hashes)
 * 2. Sections table with cryptographic hashes and entropy
 * 3. Imports list (DLLs with their API functions)
 * 4. Exports list
 * 
 * @note Handles empty cases gracefully (shows "No Imports"/"No Exports")
 * @note Entropy values are displayed with 4 decimal places
 */


void PEFile::printResult(){
    InfoSection infoSection{} ;
    DWORD iter{};
    char sectionName[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
    printf("Type : %s(%s)\n",m_peInfo.m_characteristics.data(),m_peInfo.m_subsystem.data());
    
    if ((m_peInfo.m_NetAssembly & 0xFFFFFFFF) && (m_peInfo.m_NetAssembly >> 32))
        puts(".Net Assembly : YES");
    else
        puts(".Net Assembly : NO");

    if(m_peInfo.m_is32Magic)
        puts("Architecture : 32-bit\n");
    else
        puts("Architecture : 64-bit\n");

    printf("TimeDateStamp : %s\n\n",m_peInfo.m_timeStampString);
    printf("md5 : %s\n",m_peInfo.m_md5.data());
    printf("sha1 : %s\n",m_peInfo.m_sha1.data());
    printf("sha256 : %s\n",m_peInfo.m_sha256.data());
    printf("Machine : %s\n\n",m_peInfo.m_machine.data());
    puts("Sections:");
    for (DWORD nsection = 0; nsection < m_peInfo.m_sectionNumber ; nsection++){
        infoSection = m_peInfo.m_ptr[nsection];
        strncpy(sectionName , (const char *)infoSection.m_sectionHeader.Name,IMAGE_SIZEOF_SHORT_NAME);
        printf("\t%u : %s\n\t\tentropy : %.4f\n\t\tmd5 : %s\n\t\tsha1 : %s\n\t\tsha256 : %s\n\n",
            nsection + 1,
            sectionName,
            infoSection.m_entropy,
            infoSection.m_md5.data(),
            infoSection.m_sha1.data(),
            infoSection.m_sha256.data());
    }
    
    puts("Imports:");
    if(m_peInfo.m_allImports.empty()){
        puts("\tNo Imports");
    }else{
        for (const auto& import :m_peInfo.m_allImports){
            printf("\t%u : %s\n" , iter + 1, import->m_dllName);
            for (const auto api : import->m_apisVector){
                printf("\t\t%s\n",api);
            }
            iter++;
        }    
    }

    puts("Exports:");
    if (m_peInfo.m_allExports.empty()){
        puts("\tNo Exports");
    }else{
        for (const auto& export_: m_peInfo.m_allExports){
            printf("\t%s\n",export_);
        }
    }
}


/**
 * @WARNING : MultiThreading is not `SAFE` Yet
 *
 */

/**
 * @brief Retrieves the number of available CPU cores/processors on the system.
 * 
 * Provides a cross-platform way to determine the number of logical processors:
 * - On Windows: Uses `GetSystemInfo()` Win32 API
 * - On Unix-like systems: Uses `sysconf(_SC_NPROCESSORS_ONLN)`
 * 
 * 
 * @note This count includes hyper-threaded cores on supporting systems
 * @note The result is typically used for thread pool sizing optimization
 */

void ThreadPool::getProcessorsCount(){
    #ifdef _WIN32
        SYSTEM_INFO sysInfo{};
        GetSystemInfo(&sysInfo);
        ThreadPool::s_numberOfProcessors = sysInfo.dwNumberOfProcessors;
    #else
        ThreadPool::s_numberOfProcessors = sysconf(_SC_NPROCESSORS_ONLN);
    #endif
}


ThreadPool::ThreadPool(PEFile& _pe) : pe{_pe}{

}

/**
 * @brief Launches worker threads to process PE file sections in parallel
 * 
 * Creates N-1 worker threads (where N = CPU cores) that:
 * - Atomically fetch section indices
 * - Process each section via doWork()
 * - Automatically terminate when all sections are processed
 */

void ThreadPool::start(){
    for (int i  = 0 ; i < s_numberOfProcessors - 1 ; i++){
        workers.emplace_back([this] () {
            while(true){
                int index = m_index.fetch_add(1);
                if (index >= pe.m_peInfo.m_sectionNumber) return;
                doWork(index);
            }

        });
    }
}

/**
 * @brief Processes a single PE section (worker thread task)
 * @param index Section index to process
 * @details For the given section:
 *          - Calculates entropy
 *          - Computes MD5/SHA1/SHA256 hashes
 *          - Stores results in section info
 * @warning Performs bounds checking via CHECK_OFFSET
 */

void ThreadPool::doWork(int index){
    InfoSection* ptr =  pe.m_peInfo.m_ptr + index ;

    std::array<uint8_t , MD5_HASH_LEN> md5{};
    std::array<uint8_t , SHA1_HASH_LEN> sha1{};
    std::array<uint8_t , SHA256_HASH_LEN> sha256{};


    CHECK_OFFSET((ptr->m_sectionHeader).PointerToRawData + (ptr->m_sectionHeader).SizeOfRawData , pe.m_size);
    
    utils::calculateEntropy(reinterpret_cast<LPCVOID>(
        (ptr->m_sectionHeader).PointerToRawData + 
        reinterpret_cast<ULONGLONG>(pe.m_lpAddress)) , (ptr->m_sectionHeader).SizeOfRawData,
        &(ptr->m_entropy));
    
    utils::getMd5(reinterpret_cast<LPCVOID>(
        (ptr->m_sectionHeader).PointerToRawData + 
        reinterpret_cast<ULONGLONG>(pe.m_lpAddress)) , (ptr->m_sectionHeader).SizeOfRawData,
        md5);
    utils::getSha1(reinterpret_cast<LPCVOID>(
        (ptr->m_sectionHeader).PointerToRawData + 
        reinterpret_cast<ULONGLONG>(pe.m_lpAddress)) , (ptr->m_sectionHeader).SizeOfRawData,
        sha1);
    utils::getSha256(reinterpret_cast<LPCVOID>(
        (ptr->m_sectionHeader).PointerToRawData + 
        reinterpret_cast<ULONGLONG>(pe.m_lpAddress)) , (ptr->m_sectionHeader).SizeOfRawData,
        sha256);

    utils::bytesToHexString(md5.data() , MD5_HASH_LEN , ptr->m_md5.data());
    utils::bytesToHexString(sha1.data() , SHA1_HASH_LEN , ptr->m_sha1.data());
    utils::bytesToHexString(sha256.data() , SHA256_HASH_LEN , ptr->m_sha256.data());
}

/**
 * @brief ThreadPool destructor
 * @note Safely joins all worker threads before destruction
 * @warning Blocks until all threads complete their work
 */

ThreadPool::~ThreadPool(){
    for (auto& worker : workers){
        if (worker.joinable())
            worker.join();
    }
}
