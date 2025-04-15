#pragma once
#include <pe_structs.h>



constexpr int  INITIAL_SECTION_NUMBER = 10 ;

struct InfoSection{

    IMAGE_SECTION_HEADER sectionHeader{};
    
    double entropy{};

    char  Md5[16];
    char  Sha1[20];
    char  Sha256[32];
};



struct PEInfo{


    PEInfo() =  default;
    ~PEInfo() {
        if (ptr){
            printf("%p\n",ptr );
            delete[] ptr;
        }
    }

    DWORD SectionNumber = 10;
    DWORD MaxSectionNumber = 16; 

    InfoSection Sections[INITIAL_SECTION_NUMBER];
    InfoSection *ptr = nullptr;


    std::array<uint8_t , 16> Machine{};
    std::array<uint8_t ,  4> Characteristics{};

    std::array<uint8_t , 16> Md5{};
    std::array<uint8_t , 20> Sha1{};
    std::array<uint8_t , 32> Sha256{};


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
    void GetHashes();
    void GetTimeDateStamp();
    void GetSections();
    void GetSectionsEntropy();
    void GetFileEntropy();


    #ifdef _WIN32
        HANDLE hFile = INVALID_HANDLE_VALUE;
        HANDLE hMapFile = nullptr;
    #else
        int fd = -1;
    #endif

    struct PEInfo PeInfo{};

    

    LPVOID lpAddress = nullptr;
    size_t size = 0;
    double fentropy{};
    
    DWORD e_lfanew{};

    DWORD TimeDateStamp{};
};