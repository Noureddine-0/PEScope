#pragma once
#include <header.h>

namespace Utils {
    void SystemError(int , const char * );
    void FatalError(const char*);
    void GetSha256(LPCVOID , size_t , std::array<uint8_t , 32>&);
    void GetSha1(LPCVOID , size_t , std::array<uint8_t , 20>&);
    void GetMd5(LPCVOID , size_t , std::array<uint8_t , 16>&);
}
