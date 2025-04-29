#pragma once
#include <pe_structs.h>



constexpr unsigned int  INITIAL_SECTION_NUMBER = 10 ;


struct InfoSection{

    double m_entropy{};
    
    IMAGE_SECTION_HEADER m_sectionHeader{};
    

    std::array<uint8_t , 2 * MD5_HASH_LEN + 1> m_md5{};
    std::array<uint8_t , 2 * SHA1_HASH_LEN + 1> m_sha1{};
    std::array<uint8_t , 2 * SHA256_HASH_LEN + 1> m_sha256{};
};


struct Import{
    char *m_dllName;
    std::vector<char*> m_apisVector{};
};



struct PEInfo{


    PEInfo() =  default;
    ~PEInfo() noexcept {
        if (m_exceededStackSections){
            delete[] m_ptr;
        }

        for (auto& import: m_allImports){
            delete import;
        }
    }
    
    InfoSection m_sections[INITIAL_SECTION_NUMBER];
    InfoSection *m_ptr = nullptr;

    std::vector<Import*> m_allImports{};
    std::vector<char *> m_allExports{};
    WORD m_sectionNumber{10};

    char m_timeStampString[80];

    std::array<uint8_t , 16> m_machine{};
    std::array<uint8_t ,  4> m_characteristics{};
    std::array<uint8_t , 24> m_subsystem{};

    std::array<uint8_t , 2 * MD5_HASH_LEN + 1> m_md5{};
    std::array<uint8_t , 2 * SHA1_HASH_LEN + 1> m_sha1{};
    std::array<uint8_t , 2 * SHA256_HASH_LEN + 1> m_sha256{};

    WORD m_numberOfRvaAndSizes{};

    bool  m_is32Magic{false};
    bool  m_exceededStackSections{false};
};

struct PEFile {

    PEFile() = default;
    explicit PEFile(const std::string& filePath);
    ~PEFile() noexcept ;

    void parse();
    void printResult();
    void getFileHashes();

    PEInfo m_peInfo{};

    
    LPVOID m_lpAddress{};
    LPVOID m_lpDataDirectory{};
    size_t m_size{};
    
    DWORD m_elfanew{};

private:

    void loadFromFile(const std::string&);
    bool isValidPe()  ;
    void getMachine() ;
    void getCharacteristics();
    void getSubsystem() ;
    void getMagic();
    void getTimeDateStamp();
    void getSections();
    void getSectionsEntropy();
    void getFileEntropy();
    void getSectionsHashes();
    void getImports();
    void getExports();

    #ifdef _WIN32
        HANDLE m_hFile{INVALID_HANDLE_VALUE};
        HANDLE m_hMapFile{};
    #else
        int m_fd{-1};
    #endif

};

struct ThreadPool{
    ThreadPool(PEFile&);
    ~ThreadPool();
    void start();

    static int s_numberOfProcessors;

    static void getProcessorsCount();

private:
    
    std::vector<std::thread> workers{};
    std::atomic<int> m_index;
        
    PEFile& pe;


    void doWork(int);
};

