#pragma once
#include <header.h>


struct PEInfo{
    std::array<uint8_t , 16> Machine{};
    std::array<uint8_t , 4> Characteristics{};
    std::array<uint8_t , 16> Md5{};
    std::array<uint8_t , 20> Sha1{};
    std::array<uint8_t , 32> Sha256{};
    bool  Is32Magic = false;

};

struct PEFile {

    explicit PEFile(const char* filePath);
    ~PEFile() noexcept ;

    void Parse();
    

private:

    bool IsValidPE()  ;
    void GetMachine() ;
    void GetCharacteristics();
    void GetMagic();
    void GetHashes();


    #ifdef _WIN32
        HANDLE hFile = INVALID_HANDLE_VALUE;
        HANDLE hMapFile = nullptr;
    #else
        int fd = -1;
    #endif
        struct PEInfo PeInfo;
        LPVOID lpAddress = nullptr;
        size_t size = 0;
        DWORD e_lfanew;
};