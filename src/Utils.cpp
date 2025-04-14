#include <Utils.h>
#include <header.h>
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

void Utils::SystemError(int ErrorCode, const char *ErrorMessage) {
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

void Utils::FatalError(const char* Error){
    std::cerr << "[!] Fatal Error: "<< Error << '\n';
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
 * @param Address Input data to hash
 * @param size Length of input data in bytes
 * @param hash Output array (must be 16 bytes)
 */

void Utils::GetMd5(LPCVOID Address , size_t size , std::array<uint8_t , 16>& hash){
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    
    if (EVP_DigestInit_ex(ctx, EVP_md5(), nullptr) &&
        EVP_DigestUpdate(ctx, Address, size) &&
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr)) {
    }
    EVP_MD_CTX_free(ctx);
}


/**
 * Computes SHA-1 hash of input data using OpenSSL's EVP interface.
 * 
 * @param Address Pointer to input data
 * @param size Length of input data in bytes
 * @param hash Output array for the hash (20 bytes)
 */

void Utils::GetSha1(LPCVOID Address, size_t size, std::array<uint8_t, 20>& hash) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha1(), nullptr) &&
        EVP_DigestUpdate(ctx, Address, size) &&
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr)) {
    }
    
    EVP_MD_CTX_free(ctx);
}


/**
 * Computes SHA-256 hash of input data using OpenSSL's EVP interface.
 * 
 * @param Address Pointer to input data
 * @param size Length of input data in bytes
 * @param hash Output array for the hash (32 bytes)
 */

void Utils::GetSha256(LPCVOID Address, size_t size, std::array<uint8_t, 32>& hash) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) return;
    
    if (EVP_DigestInit_ex(ctx, EVP_sha256(), nullptr) &&
        EVP_DigestUpdate(ctx, Address, size) &&
        EVP_DigestFinal_ex(ctx, hash.data(), nullptr)) {
    }
    
    EVP_MD_CTX_free(ctx);
}