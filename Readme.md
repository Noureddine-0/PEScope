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
```bash
git clone https://github.com/Noureddine-0/PEScope.git
cd PEScope
mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
cmake --build .
```
## :page_facing_up: Note on OpenSSL Integration
###  ⚠️ Current OpenSSL Build Strategy

> For now, this project relies on an **external CMake integration repository** for building OpenSSL automatically. This handles downloading, configuring, and building both libssl and libcrypto as shared libraries (.dll or .so depending on platform).

###  :hammer_and_wrench: Planned Improvement

> In the future, I intend to **fully manage the OpenSSL build process**, by individually building `libssl` and `libcrypto` from the official OpenSSL sources. This will give us better control, allow for static linking, and improve reproducibility and security.

## 🌐 Cross-Platform Support
| Platform | Status              | Notes                                   |
|----------|---------------------|-----------------------------------------|
| Windows  | :gear:              | In progress                             |
| Linux    | :gear:              | In progress – Testing on Ubuntu 22.04   |
| macOS    | :construction:      | Planned – ARM64 support coming          |

## :handshake: Contributing
Contributions are welcome! Please:

- **Fork the repository**

- **Create a feature branch**

- **Submit a pull request**

## :page_facing_up: License

> MIT License - See [LICENSE](https://github.com/Noureddine-0/PEScope/blob/main/LICENSE) for details.