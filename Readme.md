# PEScope :crossed_swords:  
*A lightweight PE (Portable Executable) file analyzer for Windows/Linux/macOS*  

[![CMake](https://img.shields.io/badge/CMake-3.21+-064F8C?logo=cmake)](https://cmake.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/Windows%20%7C%20Linux%20%7C%20macOS-cross--platform-brightgreen)]()

## :mag_right: Project Overview  
PEScope is an **early-stage** cross-platform tool for parsing and analyzing PE files (EXE/DLL/SYS). Designed for malware analysts, reverse engineers, and security researchers, it provides:  

- :bar_chart: **Import/Export Table Analysis**  
- :microscope: **Basic Static Analysis**  
- :gear: **CMake-based Build System**  

> **Note**: This project is in active development. Core functionality is being implemented.

## :hammer_and_wrench: Build Instructions  

### Prerequisites  
- CMake 3.21+  
- C++17 compiler (GCC/Clang/MSVC)  

### Build Steps
In Linux, you can build the project using Ninja, or you can choose to build it without it , the following steps show how to build the project with ninja.
```bash
git clone --recursive https://github.com/Noureddine-0/PEScope.git
cd PEScope
cmake -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```

You can also build the project normally without ninja as follow.
```bash
git clone --recursive https://github.com/Noureddine-0/PEScope.git
cd PEScope
mkdir build && cd build
cmake -DCMAKE_BUILD_TYPE=Release ..
cmake --build .
```

Unfortunately , to build the project in `windows` without problems we must use ninja as shown below.
```bash
git clone --recursive https://github.com/Noureddine-0/PEScope.git
cd PEScope
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
```
## :page_facing_up: Note on OpenSSL Integration
###  ⚠️ Current OpenSSL Build Strategy

> For now, this project relies on an **external CMake integration repository** for building OpenSSL automatically. This handles downloading, configuring, and building both libssl and libcrypto as shared libraries (.dll or .so depending on platform).

###  :hammer_and_wrench: Planned Improvement

> In the future, I intend to **fully manage the OpenSSL build process**, by individually building `libssl` and `libcrypto` from the official OpenSSL sources. This will give us better control, allow for static linking, and improve reproducibility and security.

## 🌐 Cross-Platform Support
| Platform | Status              | Notes                                   |
|----------|---------------------|-----------------------------------------|
| Windows  | :gear:              | In progress – Testing on Windows 10     |
| Linux    | :gear:              | In progress – Testing on Ubuntu 22.04   |
| macOS    | :construction:      | Planned – ARM64 support coming          |

The project has been successfully built and tested on:
- Windows 10/11:
	- Microsoft Visual Studio 2022 (MSVC 19)
- Linux:
	- GCC [11.4.0]
	- Clang [14.0.0]
## 🔌 Adding a New Plugin
To streamline plugin development, use the provided Python script to auto-generate all necessary files and CMake configurations for a new plugin.
### :page_facing_up: Prerequisites
Ensure Python 3 is installed and accessible from your command line. This script should be run from the root of the project.
### :hammer_and_wrench: Usage
```bash
python create_plugins.py --name PLUGIN_NAME --description "PLUGIN_DESCRIPTION"
```
This will:

- Automatically detect the next available plugin index (e.g. `plugin3`)
- Create:
	- `cmake/plugins/plugin3.cmake`
	- `conf/plugins/plugin3.h.in`
	- `src/plugins_src/plugin3/plugin3.cpp`
	- `src/plugins_src/plugin3/CMakeLists.txt`
- Populate each file with boilerplate code and CMake logic
- Set the plugin’s metadata (name, version, description)

## :handshake: Contributing
Contributions are welcome! Please:

- **Fork the repository**

- **Create a feature branch**

- **Submit a pull request**

## :page_facing_up: License

> MIT License - See [LICENSE](https://github.com/Noureddine-0/PEScope/blob/main/LICENSE) for details.