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
    #include <sys/mman.h>
    #include <unistd.h>
	#include <cerrno>
#endif

#include <array>
#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstddef>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <iostream>
#include <memory>
#ifndef _PLUGIN
	#include <openssl/evp.h>
	#include <openssl/sha.h>
#endif
#include <system_error>
#include <thread>
#include <unordered_map>
#include <vector>

#include <version.h>

#define CHECK_OFFSET(X, Y) \
    do { \
        if ((X) > (Y)) { \
            utils::fatalError("Invalid Offset encountered while parsing"); \
        } \
    } while (0)


constexpr int MD5_HASH_LEN =  16;
constexpr int SHA1_HASH_LEN  = 20;
constexpr int SHA256_HASH_LEN = 32;


constexpr unsigned int CONCURRENCY_THRESHOLD = 1 << 20;
