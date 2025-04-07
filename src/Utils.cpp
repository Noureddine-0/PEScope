#include <Utils.h>
#include <header.h>



void Utils::SystemError(int ErrorCode, const char *ErrorMessage) {
    try{
#ifdef _WIN32
    throw std::system_error(ErrorCode , std::system_category() , ErrorMessage);
#else
     throw std::system_error(ErrorCode , std::generic_category() , ErrorMessage);
#endif
    }catch(std::system_error& e) {
        std::cerr << e.what() << '\n';
        std::cerr << "[*] Existing ..."<< '\n';
        std::exit(EXIT_FAILURE);
    }
}


void Utils::FatalError(const char* Error){
    std::cerr << "[!] Fatal Error: "<< Error << '\n';
    std::cerr << "[*] Exiting ..." << '\n';
    std::exit(EXIT_FAILURE);
}


void Utils::GetSha256(LPCVOID Address , size_t size , std::array<uint8_t , 32>& hash ){
    SHA256(reinterpret_cast<const uint8_t *>(Address) , size , hash.data());
}
