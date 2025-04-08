cmake_minimum_required(VERSION 3.21)
project(PEScope VERSION 0.1.0 LANGUAGES CXX)



include(TestBigEndian)
test_big_endian(IS_BIG_ENDIAN)
if (IS_BIG_ENDIAN)
    message(FATAL_ERROR "This project requires a little-endian system.")
endif()


add_executable(PEScope
			 src/main.cpp
			 src/pe_parser.cpp
			 src/Utils.cpp)



set(CMAKE_CXX_STANDARD 17)
set (CMAKE_CXX_STANDARD_REQUIRED ON)

if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|clang")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} -Wall -Wshadow -Wextra -DDEBUG")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall -Wshadow -Wextra ")
endif()

message(STATUS "Release Flags : ${CMAKE_CXX_FLAGS_RELEASE}")
message(STATUS "Debug flags : ${CMAKE_CXX_FLAGS_DEBUG}")

include_directories(Headers)

# OpenSSL
add_subdirectory("external/openssl-cmake")

option(CROSS "Enable cross-compilation" OFF)
option(BUILD_OPENSSL "Build OpenSSL from source" ON)
set(OPENSSL_BUILD_VERSION "3.1.5" CACHE STRING "OpenSSL version to build")

target_link_libraries(PEScope PUBLIC ssl crypto)