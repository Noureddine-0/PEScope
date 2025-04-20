#pragma once
#include <header.h>
#include <pe_parser.h>

namespace utils {
    void systemError(int , const char * );
    void fatalError(const char*);
    void getMd5(LPCVOID , size_t , std::array<uint8_t , MD5_HASH_LEN>&);
    void getSha1(LPCVOID , size_t , std::array<uint8_t , SHA1_HASH_LEN>&);
    void getSha256(LPCVOID , size_t , std::array<uint8_t , SHA256_HASH_LEN>&);
    void calculateEntropy(LPCVOID ,size_t , double*);
    void convertTimeStamp(uint32_t, char*);
    void bytesToHexString(const uint8_t*,size_t, uint8_t*);
    DWORD rvaToFileOffset(DWORD , const InfoSection* , size_t);
    DWORD safeRvaToFileOffset(DWORD , const InfoSection* , size_t , const char*);
}
