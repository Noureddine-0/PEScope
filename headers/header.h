#pragma once 


#include <cstdint>

#ifdef _WIN32
	#ifndef NOMINMAX
		#define NOMINMAX
	#endif
	#include <windows.h>
	#include <winnt.h>
#else
	using CHAR =  char;
	using BYTE = std::uint8_t;
	using WORD = std::uint16_t;
	using DWORD =  std::uint32_t;
	using ULONGLONG =  std::uint64_t;
	using LONG =  std::int32_t;
	using LPVOID  = void*;
	using LPCVOID  = const void *;

	#include <sys/stat.h>
    #include <fcntl.h>
    #include <dlfcn.h>
    #include <sys/mman.h>
    #include <unistd.h>
	#include <cerrno>

	#define UNREFERENCED_PARAMETER(_x_) (void)_x_
#endif

#include <array>
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <mutex>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <system_error>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#include <version.h>

#define CHECK_OFFSET(X, Y) \
    do { \
        if ((X) > (Y)) { \
            utils::fatalError("Invalid Offset encountered while parsing"); \
        } \
    } while (0)


#define CHECK_OFFSET_PLUGIN_NO_EXIT(RESULTS , X , Y , OUTFILE , MUTEX)\
    do{ \
    	if ((X) > (Y)){ \
    		RESULTS += "\tInvalid Offset encountered while parsing\n";\
    		writeResults(OUTFILE , MUTEX);\
    		return ;\
    	} \
    } while(0)


#ifdef _WIN32
    #define NEWLINE "\r\n"
#else
    #define NEWLINE "\n"
#endif

#define PLUGIN_ENTRY(RESULTS , _NEWLINE , NAME , VERSION) \
    do{\
		RESULTS += "=====================================================";\
		RESULTS += _NEWLINE;\
		RESULTS +="\t\t";\
		RESULTS += NAME;\
		RESULTS += " v";\
		RESULTS += VERSION;\
		RESULTS += _NEWLINE;\
		RESULTS += "=====================================================";\
		RESULTS += _NEWLINE;\
    }while(0)

constexpr int MD5_HASH_LEN =  16;
constexpr int SHA1_HASH_LEN  = 20;
constexpr int SHA256_HASH_LEN = 32;


constexpr unsigned int CONCURRENCY_THRESHOLD = 1 << 21;

struct Arguments {
    bool plugins{};
    DWORD pluginDir{};
    std::vector<std::string> files{};
};
