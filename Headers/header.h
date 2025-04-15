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
#include <cmath>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <system_error>
#include <unordered_map>
#include <openssl/sha.h>
#include <openssl/evp.h>


#define CHECK_OFFSET(X, Y) \
    do { \
        if ((X) > (Y)) { \
            Utils::FatalError("Invalid Offset encountered while parsing"); \
        } \
    } while (0)
