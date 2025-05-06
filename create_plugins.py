import os
import re
import argparse

def find_next_plugin_index(base_dir):
    existing_indices = []
    if not os.path.exists(base_dir):
        os.makedirs(base_dir)

    for name in os.listdir(base_dir):
        match = re.match(r"plugin(\d+)", name)
        if match:
            existing_indices.append(int(match.group(1)))

    index = 1
    while index in existing_indices:
        index += 1
    return index

def create_plugin_structure(index, name, description):
    print(f"[+] Creating plugin{index} with name '{name}' and description '{description}'")

    # Paths
    root_dir = os.getcwd()
    plugins_src_dir = os.path.join(root_dir, "src", "plugins_src")
    plugin_dir = os.path.join(plugins_src_dir, f"plugin{index}")
    cmake_dir = os.path.join(root_dir, "cmake", "plugins")
    conf_dir = os.path.join(root_dir, "conf", "plugins")
    headers_plugin_include = os.path.join(root_dir, "headers", "plugins_include")

    os.makedirs(plugin_dir, exist_ok=True)
    os.makedirs(cmake_dir, exist_ok=True)
    os.makedirs(conf_dir, exist_ok=True)
    os.makedirs(headers_plugin_include, exist_ok=True)

    # 1. CMake plugin config
    plugin_cmake = f"""set(PLUGIN_NAME "{name}")
set(PLUGIN_DESCRIPTION "{description}")
set(PLUGIN_VERSION_MAJOR 0)
set(PLUGIN_VERSION_MINOR 1)
set(PLUGIN_VERSION_PATCH 0)
set(PLUGIN_VERSION "${{PLUGIN_VERSION_MAJOR}}.${{PLUGIN_VERSION_MINOR}}.${{PLUGIN_VERSION_PATCH}}")
"""
    with open(os.path.join(cmake_dir, f"plugin{index}.cmake"), "w") as f:
        f.write(plugin_cmake)

    # 2. pluginX.h.in
    plugin_h_in = """#pragma once

#define PLUGIN_NAME "@PLUGIN_NAME@"
#define PLUGIN_DESCRIPTION "@PLUGIN_DESCRIPTION@"
#define PLUGIN_VERSION "@PLUGIN_VERSION@"
#define PLUGIN_VERSION_MAJOR "@PLUGIN_VERSION_MAJOR@"
#define PLUGIN_VERSION_MINOR "@PLUGIN_VERSION_MINOR@"
#define PLUGIN_VERSION_PATCH "@PLUGIN_VERSION_PATCH@"

constexpr const char* GetPluginName(){{ return PLUGIN_NAME; }}
constexpr const char* GetPluginDescription(){{ return PLUGIN_DESCRIPTION; }}
constexpr const char* GetPluginVersion(){{ return PLUGIN_VERSION; }}
"""
    with open(os.path.join(conf_dir, f"plugin{index}.h.in"), "w") as f:
        f.write(plugin_h_in)

    # 3. CMakeLists.txt
    plugin_cmakelists = f"""include(${{CMAKE_SOURCE_DIR}}/cmake/plugins/plugin{index}.cmake)

project(plugin{index} LANGUAGES CXX)

configure_file(
    ${{CMAKE_SOURCE_DIR}}/conf/plugins/plugin{index}.h.in
    ${{CMAKE_SOURCE_DIR}}/headers/plugins_include/plugin{index}.h)

add_library(plugin{index} SHARED plugin{index}.cpp ${{CMAKE_SOURCE_DIR}}/src/utils.cpp)

target_include_directories(plugin{index} PRIVATE ${{CMAKE_SOURCE_DIR}}/headers)
target_include_directories(plugin{index} PRIVATE ${{CMAKE_SOURCE_DIR}}/headers/plugins_include)
target_include_directories(plugin{index} PRIVATE ${{CMAKE_BINARY_DIR}}/external/openssl-cmake/openssl-prefix/src/openssl/usr/local/include/)

set_target_properties(plugin{index} PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY ${{CMAKE_BINARY_DIR}}/plugins
    RUNTIME_OUTPUT_DIRECTORY ${{CMAKE_BINARY_DIR}}/plugins)
"""
    with open(os.path.join(plugin_dir, "CMakeLists.txt"), "w") as f:
        f.write(plugin_cmakelists)

    # 4. pluginX.cpp
    plugin_cpp = f"""#include <plugins.h>
#include <plugin{index}.h>
#include <utils.h>

PluginInfo thisPlugin{{}};

#ifdef _WIN32
BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved) {{
    switch (ul_reason_for_call) {{
    case DLL_PROCESS_ATTACH:
        thisPlugin.m_name = GetPluginName();
        thisPlugin.m_version = GetPluginVersion();
        thisPlugin.m_description = GetPluginDescription();
        break;
    }}
    return true;
}}
#else
__attribute__((constructor))
void onLoad() {{
    thisPlugin.m_name = GetPluginName();
    thisPlugin.m_version = GetPluginVersion();
    thisPlugin.m_description = GetPluginDescription();
}}
#endif

PluginInfo getPluginInfo() {{
    return thisPlugin;
}}

void scan(PEFile& pe, std::string& outfile, std::mutex& mutex) {{
    // code goes here
}}
"""
    with open(os.path.join(plugin_dir, f"plugin{index}.cpp"), "w") as f:
        f.write(plugin_cpp)

    print(f"[✓] Plugin plugin{index} created successfully.")

def main():
    parser = argparse.ArgumentParser(description="Create a new plugin skeleton.")
    parser.add_argument("--name", required=True, help="Plugin name (e.g., SecScanner)")
    parser.add_argument("--description", required=True, help="Plugin description")

    args = parser.parse_args()

    try:
        plugins_src_dir = os.path.join(os.getcwd(), "src", "plugins_src")
        index = find_next_plugin_index(plugins_src_dir)
        print(f"[+] Detected next plugin index: {index}")
        create_plugin_structure(index, args.name, args.description)
    except Exception as e:
        print(f"[!] Unexpected error: {e}")

if __name__ == "__main__":
    main()
