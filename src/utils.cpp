#include <utils.h>
#include <pe_structs.h>
#include <openssl/md5.h>


/**
 * Handles system errors by throwing and catching a system_error exception.
 * 
 * @param ErrorCode System-specific error code
 * @param ErrorMessage Description of the error
 * 
 * Behavior:
 * - Throws a system_error exception with the appropriate error category
 *   (Windows: system_category, others: generic_category)
 * - Catches the exception and prints the error message
 * - Terminates the program with EXIT_FAILURE
 */

void utils::systemError(int ErrorCode, const char *ErrorMessage) {
    try{
#ifdef _WIN32
    throw std::system_error(ErrorCode , std::system_category() , ErrorMessage);
#else
     throw std::system_error(ErrorCode , std::generic_category() , ErrorMessage);
#endif
    }catch(std::system_error& e) {
        std::cerr << e.what() << '\n';
        std::cerr << "[*] Exiting ..."<< '\n';
        std::exit(EXIT_FAILURE);
    }
}

/**
 * Handles fatal errors by displaying an error message and terminating the program.
 * 
 * @param Error Null-terminated string describing the error condition
 * 
 * Behavior:
 * - Prints the error message to stderr with formatting
 * - Announces program termination
 * - Exits with failure status code (EXIT_FAILURE)
 */

void utils::fatalError(const char* Error){
    std::cerr << "[!] FATAL ERROR: "<< Error << '\n';
    std::cerr << "[*] Exiting ..." << '\n';
    std::exit(EXIT_FAILURE);
}


/**
 * Computes MD5 hash using OpenSSL's EVP interface (modern approach).
 * 
 * Note: The legacy MD5() function was deprecated in OpenSSL 3.0 due to:
 * - EVP provides a consistent API for all digest algorithms
 * - Future compatibility with OpenSSL versions
 * 
 * @param lpAddress Input data to hash
 * @param size Length of input data in bytes
 * @param hash Output array (must be 16 bytes)
 */

void utils::getMd5(LPCVOID lpAddress , size_t size , std::array<uint8_t , MD5_HASH_LEN>& hash){
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    
    if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) &&
        EVP_DigestUpdate(ctx, lpAddress, size) &&
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr)) {
    }
    EVP_MD_CTX_free(ctx);
}


/**
 * Computes SHA-1 hash of input data using OpenSSL's EVP interface.
 * 
 * @param lpAddress Pointer to input data
 * @param size Length of input data in bytes
 * @param hash Output array for the hash (20 bytes)
 */

void utils::getSha1(LPCVOID lpAddress, const size_t size, std::array<uint8_t, SHA1_HASH_LEN>& hash) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) &&
        EVP_DigestUpdate(ctx, lpAddress, size) &&
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr)) {
    }
    
    EVP_MD_CTX_free(ctx);
}


/**
 * Computes SHA-256 hash of input data using OpenSSL's EVP interface.
 * 
 * @param lpAddress Pointer to input data
 * @param size Length of input data in bytes
 * @param hash Output array for the hash (32 bytes)
 */

void utils::getSha256(LPCVOID lpAddress, const size_t size, std::array<uint8_t, SHA256_HASH_LEN>& hash) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) &&
        EVP_DigestUpdate(ctx, lpAddress, size) &&
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr)) {
    }
    
    EVP_MD_CTX_free(ctx);
}

/**
 * Calculates the Shannon entropy of a memory buffer.
 *
 * This function analyzes a block of memory pointed to by `lpAddress` and computes
 * its Shannon entropy based on the frequency distribution of byte values (0x00 to 0xFF).
 * The entropy value reflects the randomness of the data, where higher entropy indicates
 * more randomness (e.g., compressed or encrypted data), and lower entropy suggests
 * more predictable content (e.g., zeroed memory or plain text).
 *
 * @param lpAddress Pointer to the memory buffer to analyze.
 * @param size The size of the buffer in bytes.
 * @param entropy Pointer to a double where the resulting entropy will be stored.
 *
 * @note If the buffer size is 0, the function returns immediately without modifying entropy.
 *       The entropy value is **accumulated** onto the value pointed by `entropy`.
 * 
 * Now calculateEntropy uses a simple array instead of std::unordered_map
 *
 */

void utils::calculateEntropy(LPCVOID lpAddress, size_t size, double* entropy) {
    if (!size || !entropy) return;

    std::array<size_t, 256> frequency = {0};

    const unsigned char* bytes = static_cast<const unsigned char*>(lpAddress);

    for (size_t i = 0; i < size; ++i)
        frequency[bytes[i]]++;

    for (size_t i = 0; i < 256; ++i) {
        if (frequency[i] == 0)
            continue;

        double probability = static_cast<double>(frequency[i]) / size;
        *entropy -= probability * log2(probability);
    }
}

void utils::convertTimeStamp(uint32_t TimeStamp , char* TimeStampString){
    
    struct tm time_info;

    time_t raw_time  =  static_cast<time_t>(TimeStamp);


    #ifdef _WIN32
    localtime_s(&time_info , &raw_time);
    #else
    localtime_r(&raw_time, &time_info);
    #endif

    strftime(TimeStampString, TIMESTAMP_LEN , "%Y-%m-%d %H:%M:%S" , &time_info);
}

void utils::bytesToHexString(const uint8_t* bytes,const size_t size, uint8_t* hexOutput) {
    const uint8_t hexChars[] = "0123456789abcdef";  // Lowercase
    for (size_t i = 0; i < size; ++i) {
        hexOutput[i * 2]     = hexChars[(bytes[i] >> 4) & 0x0F];  // High nibble
        hexOutput[i * 2 + 1] = hexChars[bytes[i] & 0x0F];         // Low nibble
    }
    hexOutput[size * 2] = '\0';  // Null-terminate
}

DWORD utils::rvaToFileOffset(DWORD dwRva ,const InfoSection* infoSections , size_t sectionCount){
    for (size_t nsection = 0 ;  nsection < sectionCount ; nsection++ ,infoSections++){
        DWORD vAddr = infoSections->m_sectionHeader.VirtualAddress;
        DWORD vSize = infoSections->m_sectionHeader.Misc.VirtualSize;
        if (dwRva >=  vAddr && dwRva < vSize + vAddr)
            return (dwRva - vAddr) + infoSections->m_sectionHeader.PointerToRawData;
    }

    throw std::runtime_error("RVA can't be converted to file offset");
}

DWORD utils::safeRvaToFileOffset(DWORD dwRva ,const InfoSection* infoSections , size_t sectionCount ,
 const char *callerFunction){
    try{
        return utils::rvaToFileOffset(dwRva , infoSections , sectionCount);
    }catch(std::runtime_error& e){
        std::cerr << "[!] ERROR: At function " << callerFunction<<  " : " << e.what() << '\n';
        std::cerr << "[*] Exiting ..."<< '\n';
        std::exit(EXIT_FAILURE);
    }
}