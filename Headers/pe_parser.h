#pragma once
#include <pe_structs.h>



constexpr int  INITIAL_SECTION_NUMBER = 8 ;

struct InfoSection{

    IMAGE_SECTION_HEADER sectionHeader;
    
    double entropy;

    char  Md5[16];
    char  Sha1[20];
    char  Sha256[32];
};

union SectionsData{
        InfoSection Sections[INITIAL_SECTION_NUMBER];
        InfoSection *ptr;
    };

struct PEInfo{

    DWORD SectionNumber = 6; 

    SectionsData Data;


    std::array<uint8_t , 16> Machine{};
    std::array<uint8_t ,  4> Characteristics{};

    std::array<uint8_t , 16> Md5{};
    std::array<uint8_t , 20> Sha1{};
    std::array<uint8_t , 32> Sha256{};


    bool  Is32Magic = false;
    bool  ExceededStackSections  = false;
};

struct PEFile {

    explicit PEFile(const char* filePath);
    ~PEFile() noexcept ;

    void Parse();
    

private:

    void LoadFromFile(const char *);
    bool IsValidPE()  ;
    void GetMachine() ;
    void GetCharacteristics();
    void GetMagic();
    void GetHashes();
    void GetTimeDateStamp();
    void GetSections();


    #ifdef _WIN32
        HANDLE hFile = INVALID_HANDLE_VALUE;
        HANDLE hMapFile = nullptr;
    #else
        int fd = -1;
    #endif

    struct PEInfo PeInfo;

    

    LPVOID lpAddress = nullptr;
    size_t size = 0;

    DWORD e_lfanew{};

    DWORD TimeDateStamp{};
};