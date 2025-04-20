#pragma once
#include <pe_structs.h>



constexpr int  INITIAL_SECTION_NUMBER = 10 ;

struct InfoSection{

    double m_entropy{};
    
    IMAGE_SECTION_HEADER m_sectionHeader{};
    

    std::array<uint8_t , 2 * MD5_HASH_LEN + 1> m_md5{};
    std::array<uint8_t , 2 * SHA1_HASH_LEN + 1> m_sha1{};
    std::array<uint8_t , 2 * SHA256_HASH_LEN + 1> m_sha256{};
};


struct PEInfo{


    PEInfo() =  default;
    ~PEInfo() {
        if (m_exceededStackSections){
            delete[] m_ptr;
        }
    }
    char m_timeStampString[80];
    DWORD m_sectionNumber = 10;
    DWORD m_maxSectionNumber = 20; 

    InfoSection m_sections[INITIAL_SECTION_NUMBER];
    InfoSection *m_ptr = nullptr;


    std::array<uint8_t , 16> m_machine{};
    std::array<uint8_t ,  4> m_characteristics{};

    std::array<uint8_t , 2 * MD5_HASH_LEN + 1> m_md5{};
    std::array<uint8_t , 2 * SHA1_HASH_LEN + 1> m_sha1{};
    std::array<uint8_t , 2 * SHA256_HASH_LEN + 1> m_sha256{};


    bool  m_is32Magic = false;
    bool  m_exceededStackSections  = false;
};

struct PEFile {

    PEFile() = default;
    explicit PEFile(const char* filePath);
    ~PEFile() noexcept ;

    void parse();
    

private:

    void loadFromFile(const char *);
    void changeMaxSectionNumber(DWORD);
    bool isValidPe()  ;
    void getMachine() ;
    void getCharacteristics();
    void getMagic();
    void getFileHashes();
    void getTimeDateStamp();
    void getSections();
    void getSectionsEntropy();
    void getFileEntropy();
    void getSectionsHashes();
    void getImports();

    #ifdef _WIN32
        HANDLE m_hFile = INVALID_HANDLE_VALUE;
        HANDLE m_hMapFile = nullptr;
    #else
        int m_fd = -1;
    #endif

    PEInfo m_peInfo{};

    
    LPVOID m_lpAddress = nullptr;
    LPVOID m_lpDataDirectory =  nullptr;
    size_t m_size = 0;
    double m_entropy{};
    
    DWORD m_elfanew{};
};