#include <plugins.h>
#include <plugin2.h>
#include <utils.h>

PluginInfo thisPlugin{};

std::string g_results{};




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

PluginInfo getPluginInfo(){
	return thisPlugin;
}



void writeResults(std::string& outfile , std::mutex& mutex){
	std::lock_guard<std::mutex> lock(mutex);

	std::ofstream file{outfile};
	file << g_results;
	file.close();
}

void scan(PEFile& peFile , std::string& outfile , std::mutex& mutex){

	PLUGIN_ENTRY(g_results , NEWLINE , PLUGIN_NAME , PLUGIN_VERSION);

	DWORD corOffset{};
	PEInfo& peInfo  =  peFile.m_peInfo;

	if (!peInfo.m_ptr){
		g_results += "\tError reading sections";
		writeResults(outfile , mutex);
		return;
	}

	if (!(peInfo.m_NetAssembly >> 32) || !(peInfo.m_NetAssembly & 0xFFFFFFFF)){
		g_results +="\tFile is not a .NET executable";
		writeResults(outfile , mutex);
		return;
	}
	
	DWORD rva =  peInfo.m_NetAssembly >> 32;
	std::cout << "RVA :" << rva << '\n'; 
	try{
		corOffset  =  utils::rvaToFileOffset(rva , peInfo.m_ptr , peInfo.m_sectionNumber);
		std::cout << corOffset << '\n';
	}catch(std::runtime_error& e){
		g_results += "\tError while analyzing file :";
		g_results += e.what();
		g_results +=NEWLINE;
		writeResults(outfile , mutex);
		return;
	}

	CHECK_OFFSET_PLUGIN_NO_EXIT(g_results , corOffset+ sizeof(IMAGE_COR20_HEADER) , peFile.m_size , outfile , mutex);
	auto clr =  reinterpret_cast<IMAGE_COR20_HEADER*>(reinterpret_cast<ULONGLONG>(peFile.m_lpAddress) + corOffset);
	g_results += "\t- CLR Runtime Version: ";
	g_results += std::to_string(clr->MajorRuntimeVersion);
	g_results += ".";
	g_results += std::to_string(clr->MinorRuntimeVersion);
	g_results += "";
	g_results += NEWLINE;
	writeResults(outfile , mutex);
	return;
}
