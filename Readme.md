# PEScope :crossed_swords:  
*A lightweight PE (Portable Executable) file analyzer for Windows/Linux/macOS*  

[![CMake](https://img.shields.io/badge/CMake-3.21+-064F8C?logo=cmake)](https://cmake.org)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Platforms](https://img.shields.io/badge/Windows%20%7C%20Linux%20%7C%20macOS-cross--platform-brightgreen)]()

## :mag_right: Project Overview  
PEScope is an **early-stage** cross-platform tool for parsing and analyzing PE files (EXE/DLL/SYS). Designed for malware analysts, reverse engineers, and security researchers, it provides:  

- :file_folder: **PE Header Parsing** (DOS, NT, Sections)  
- :bar_chart: **Import/Export Table Analysis**  
- :microscope: **Basic Static Analysis**  
- :gear: **CMake-based Build System**  

> **Note**: This project is in active development. Core functionality is being implemented.

## :hammer_and_wrench: Build Instructions  

### Prerequisites  
- CMake 3.21+  
- C++17 compiler (GCC/Clang/MSVC)  
- OpenSSL (for cryptographic hashes)  

### Build Steps  
```bash
git clone https://github.com/yourusername/PEScope.git
cd PEScope
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```
