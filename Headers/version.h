#pragma once 


#define PROJECT_NAME "PEScope"
#define PROJECT_VERSION "0.1.0"
#define PROJECT_VERSION_MAJOR 0
#define PROJECT_VERSION_MINOR 1
#define PROJECT_VERSION_PATCH 0

constexpr const char* GetProjectName() { return PROJECT_NAME; }
constexpr const char* GetProjectVersion() { return PROJECT_VERSION; }
constexpr int GetProjectVersionMajor() { return PROJECT_VERSION_MAJOR; }
constexpr int GetProjectVersionMinor() { return PROJECT_VERSION_MINOR; }
constexpr int GetProjectVersionPatch() { return PROJECT_VERSION_PATCH; }
