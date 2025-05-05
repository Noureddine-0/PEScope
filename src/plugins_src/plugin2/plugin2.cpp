#include <plugins.h>
#include <plugin2.h>


PluginInfo thisPlugin{};

#ifdef _WIN32
BOOL APIENTRY DllMain(HMODULE hModule,
                      DWORD ul_reason_for_call,
                      LPVOID lpReserved){
	switch (ul_reason_for_call){
	case DLL_PROCESS_ATTACH:
		thisPlugin.m_name = GetPluginName();
		thisPlugin.m_version = GetPluginVersion();
		thisPlugin.m_description = GetPluginDescription();
		break;
	}

	return true;
}
#else
__attribute__((constructor))
void onLoad(){
	thisPlugin.m_name = GetPluginName();
	thisPlugin.m_version = GetPluginVersion();
	thisPlugin.m_description = GetPluginDescription();
}
#endif

