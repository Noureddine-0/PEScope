#pragma once
#include <header.h>

namespace Utils {
    void SystemError(int , const char * );
    void FatalError(const char*);
    void GetMd5(LPCVOID , size_t , std::array<uint8_t , MD5_HASH_LEN>&);
    void GetSha1(LPCVOID , size_t , std::array<uint8_t , SHA1_HASH_LEN>&);
    void GetSha256(LPCVOID , size_t , std::array<uint8_t , SHA256_HASH_LEN>&);
    void CalculateEntropy(LPCVOID , size_t , double*);
    void ConvertTimeStamp(uint32_t, char*);
    void bytesToHexString(const uint8_t*, size_t, uint8_t*);
}
