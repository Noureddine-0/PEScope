#pragma once
#include <pe_structs.h>



constexpr int  INITIAL_SECTION_NUMBER = 10 ;

struct InfoSection{

    double entropy{};
    
    IMAGE_SECTION_HEADER sectionHeader{};
    

    std::array<uint8_t , 2 * MD5_HASH_LEN + 1> Md5{};
    std::array<uint8_t , 2 * SHA1_HASH_LEN + 1> Sha1{};
    std::array<uint8_t , 2 * SHA256_HASH_LEN + 1> Sha256{};
};


struct PEInfo{


    PEInfo() =  default;
    ~PEInfo() {
        if (ptr){
            delete[] ptr;
        }
    }
    char TimeStampString[80];
    DWORD SectionNumber = 10;
    DWORD MaxSectionNumber = 20; 

    InfoSection Sections[INITIAL_SECTION_NUMBER];
    InfoSection *ptr = nullptr;


    std::array<uint8_t , 16> Machine{};
    std::array<uint8_t ,  4> Characteristics{};

    std::array<uint8_t , 2 * MD5_HASH_LEN + 1> Md5{};
    std::array<uint8_t , 2 * SHA1_HASH_LEN + 1> Sha1{};
    std::array<uint8_t , 2 * SHA256_HASH_LEN + 1> Sha256{};


    bool  Is32Magic = false;
    bool  ExceededStackSections  = false;
};

struct PEFile {

    PEFile() = default;
    explicit PEFile(const char* filePath);
    ~PEFile() noexcept ;

    void Parse();
    

private:

    void LoadFromFile(const char *);
    void ChangeMaxSectionNumber(DWORD);
    bool IsValidPE()  ;
    void GetMachine() ;
    void GetCharacteristics();
    void GetMagic();
    void GetFileHashes();
    void GetTimeDateStamp();
    void GetSections();
    void GetSectionsEntropy();
    void GetFileEntropy();
    void GetSectionsHashes();
    void GetImports();

    #ifdef _WIN32
        HANDLE hFile = INVALID_HANDLE_VALUE;
        HANDLE hMapFile = nullptr;
    #else
        int fd = -1;
    #endif

    struct PEInfo PeInfo{};

    

    LPVOID lpAddress = nullptr;
    LPVOID lpDataDirectory =  nullptr;
    size_t size = 0;
    double fentropy{};
    
    DWORD e_lfanew{};
};