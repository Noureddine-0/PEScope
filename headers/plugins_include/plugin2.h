#pragma once

#define PLUGIN_NAME "NetAssemblyAnalyzer"
#define PLUGIN_DESCRIPTION "NET assemblies in PE files and extracts detailed CLR metadata"
#define PLUGIN_VERSION "0.1.0"
#define PLUGIN_VERSION_MAJOR "0"
#define PLUGIN_VERSION_MINOR "1"
#define PLUGIN_VERSION_PATCH "0"

constexpr const char* GetPluginName(){return PLUGIN_NAME ;}
constexpr const char* GetPluginDescription(){return PLUGIN_DESCRIPTION;}
constexpr const char* GetPluginVersion(){return PLUGIN_VERSION;}
