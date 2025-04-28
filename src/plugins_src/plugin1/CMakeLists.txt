include(${CMAKE_SOURCE_DIR}/cmake/plugins/plugin1.cmake)

project(plugin1 LANGUAGES CXX)

configure_file(
    ${CMAKE_SOURCE_DIR}/conf/plugins/plugin1.h.in
    ${CMAKE_SOURCE_DIR}/headers/plugins_include/plugin1.h)

add_library(plugin1 SHARED plugin1.cpp)

target_include_directories(plugin1 PRIVATE ${CMAKE_SOURCE_DIR}/headers)
target_include_directories(plugin1 PRIVATE ${CMAKE_SOURCE_DIR}/headers/plugins_include)

set_target_properties(plugin1 PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins
)