#pragma once
#include <header.h>

namespace Utils {
    void SystemError(int , const char * );
    void FatalError(const char*);
    void GetSha256(LPCVOID , size_t , std::array<uint8_t , 32>&);
}
