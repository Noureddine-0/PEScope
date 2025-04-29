#include <plugins.h>
#include <plugin1.h>


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


//returns copy of thisPlugi
PluginInfo getPluginInfo(){
	return thisPlugin;
}


bool hasOverlay(const InfoSection* infoSections , WORD count , size_t size){
	size_t lastSectionEnd{};
	for (int i =0 ; i < count ; i++ , infoSections++){
		size_t sectionEnd = static_cast<size_t>(infoSections->m_sectionHeader.PointerToRawData + infoSections->m_sectionHeader.SizeOfRawData);
		if (sectionEnd > lastSectionEnd)
			lastSectionEnd =  sectionEnd;		
	}
	return size > lastSectionEnd;
}


void scan(PEFile& pe){
	std::cout << "Start scanning" << '\n';
	if (hasOverlay(pe.m_peInfo.m_ptr ,pe.m_peInfo.m_sectionNumber, pe.m_size )){
		std::cout << "Has overlay" << '\n';
	}
	else{
		std::cout << "Dont have overlay" << '\n';
	}
}



