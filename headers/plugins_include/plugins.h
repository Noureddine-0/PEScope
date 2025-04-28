#pragma once
#define _PLUGIN
#include <pe_parser.h>

#ifdef _WIN32
	#define PLUGIN_EXPORT __declspec(dllexport)
#else
	#define PLUGIN_EXPORT __attribute__((visibility("default")))
#endif

extern "C"{
	struct PluginInfo{
		const char *m_name;
		const char *m_description;
		const char *m_version;
	};

	PLUGIN_EXPORT PluginInfo& getPluginInfo();
	PLUGIN_EXPORT void scan(PEFile& );
}