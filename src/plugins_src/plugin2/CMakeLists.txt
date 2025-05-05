include(${CMAKE_SOURCE_DIR}/cmake/plugins/plugin2.cmake)
project(plugin2 LANGUAGES CXX)
configure_file(
	${CMAKE_SOURCE_DIR}/conf/plugins/plugin2.h.in
	${CMAKE_SOURCE_DIR}/headers/plugins_include/plugin2.h)

add_library(plugin2 SHARED plugin2.cpp)
target_include_directories(plugin2 PRIVATE ${CMAKE_SOURCE_DIR}/headers)
target_include_directories(plugin2 PRIVATE ${CMAKE_SOURCE_DIR}/headers/plugins_include)

set_target_properties(plugin1 PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins
    RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/plugins
)