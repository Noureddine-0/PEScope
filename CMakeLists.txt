include(TestBigEndian)
include(cmake/version.cmake)


cmake_minimum_required(VERSION 3.21)
project(PEScope VERSION ${PROJECT_VERSION} LANGUAGES CXX)

test_big_endian(IS_BIG_ENDIAN)
if (IS_BIG_ENDIAN)
    message(FATAL_ERROR "This project requires a little-endian system.")
endif()

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

configure_file(
    ${CMAKE_CURRENT_SOURCE_DIR}/conf/version.h.in
    ${CMAKE_CURRENT_SOURCE_DIR}/headers/version.h)


add_executable(PEScope
			 src/main.cpp
			 src/pe_parser.cpp
			 src/utils.cpp
             src/plugin_manager.cpp)

target_compile_definitions(PEScope PRIVATE PLUGIN_DIRECTORY="${CMAKE_BINARY_DIR}/plugins")


if(CMAKE_CXX_COMPILER_ID MATCHES "GNU|Clang")
	set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG}  -Wall -Wshadow -Wextra -DDEBUG")
	set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -Wall -Wshadow -Wextra -march=native")
endif()

if(WIN32)
    include(GenerateExportHeader)
    
    set(RESOURCE_FILE ${CMAKE_CURRENT_BINARY_DIR}/version.rc)
    configure_file(
        ${CMAKE_CURRENT_SOURCE_DIR}/conf/version.rc.in
        ${RESOURCE_FILE}
    )
    
    target_sources(PEScope PRIVATE ${RESOURCE_FILE})
endif()

target_include_directories(PEScope PRIVATE headers)
target_include_directories(PEScope PRIVATE headers/plugins_include)

# OpenSSL
set(OPENSSL_BUILD_VERSION "3.1.5" CACHE STRING "OpenSSL version to build")


add_subdirectory("external/openssl-cmake")

target_link_libraries(PEScope PUBLIC ssl crypto)

if(WIN32)

    set(OPENSSL_DLL_DIR "${CMAKE_BINARY_DIR}/external/openssl-cmake/openssl-prefix/src/openssl/usr/local/bin")

    # Copy DLLs to the PEScope output directory
    add_custom_command(TARGET PEScope POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy_if_different
            "${OPENSSL_DLL_DIR}/libcrypto-3-x64.dll"
            "${OPENSSL_DLL_DIR}/libssl-3-x64.dll"
            $<TARGET_FILE_DIR:PEScope>
    )
endif()

#Build plugins
file(GLOB plugin_dirs LIST_DIRECTORIES true "src/plugins_src/*")
foreach(plugin_dir ${plugin_dirs})
    if(IS_DIRECTORY "${plugin_dir}")
        get_filename_component(plugin_name "${plugin_dir}" NAME)
        add_subdirectory(
            "${plugin_dir}"
            "plugins/${plugin_name}"
        )
    endif()
endforeach()