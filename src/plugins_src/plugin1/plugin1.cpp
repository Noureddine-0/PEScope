#include <plugins.h>

PluginInfo thisPlugin{};

PluginInfo& getPluginInfo(){
	thisPlugin.m_name = "Plugin1";
	return thisPlugin;
}


void scan(PEFile& pe){
	puts("tested");
}



