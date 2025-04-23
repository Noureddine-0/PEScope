project(plugin1 LANGUAGES CXX)


add_library(plugin1 SHARED plugin1.cpp)

target_include_directories(plugin1 PRIVATE ${CMAKE_SOURCE_DIR}/headers)
target_include_directories(plugin1 PRIVATE ${CMAKE_SOURCE_DIR}/headers/plugins_include)

set_target_properties(plugin1 PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins
)