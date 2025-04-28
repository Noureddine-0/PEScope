#include <plugins.h>
#include <plugin1.h>


PluginInfo thisPlugin{};

PluginInfo& getPluginInfo(){
	thisPlugin.m_name = GetPluginName();
	thisPlugin.m_description = GetPluginDescription();
	thisPlugin.m_version = GetPluginVersion();
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
	if (hasOverlay(pe.m_peInfo.m_ptr ,pe.m_peInfo.m_sectionNumber, pe.m_size )){
		std::cout << "Has overlay" << '\n';
	}
	else{
		std::cout << "Dont have overlay" << '\n';
	}
}



