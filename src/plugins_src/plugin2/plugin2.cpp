#include <plugins.h>
#include <plugin2.h>
#include <utils.h>

PluginInfo thisPlugin{};

static std::string s_results{};


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

	std::ofstream file{outfile , std::ios::app};

	if (!file.is_open()) {
		std::cerr << "[ERROR] Failed to open file: " << outfile << std::endl;
		return;
	}
	
	file << s_results;
	file.close();
}

void scan(PEFile& peFile , std::string& outfile , std::mutex& mutex){

	PLUGIN_ENTRY(s_results , NEWLINE , PLUGIN_NAME , PLUGIN_VERSION);

	DWORD corOffset{};
	PEInfo& peInfo  =  peFile.m_peInfo;

	if (!peInfo.m_ptr){
		s_results += "\tError reading sections";
		s_results += NEWLINE;
		writeResults(outfile , mutex);
		return;
	}

	if (!(peInfo.m_NetAssembly >> 32) || !(peInfo.m_NetAssembly & 0xFFFFFFFF)){
		s_results += "\tFile is not a .NET executable";
		s_results += NEWLINE;
		writeResults(outfile , mutex);
		return;
	}
	
	DWORD rva =  peInfo.m_NetAssembly >> 32;
	try{
		corOffset  =  utils::rvaToFileOffset(rva , peInfo.m_ptr , peInfo.m_sectionNumber);
	}catch(std::runtime_error& e){
		s_results += "\tError while analyzing file :";
		s_results += e.what();
		s_results +=NEWLINE;
		writeResults(outfile , mutex);
		return;
	}

	CHECK_OFFSET_PLUGIN_NO_EXIT(s_results , corOffset+ sizeof(IMAGE_COR20_HEADER) , peFile.m_size , outfile , mutex);
	auto clr =  reinterpret_cast<IMAGE_COR20_HEADER*>(reinterpret_cast<ULONGLONG>(peFile.m_lpAddress) + corOffset);
	s_results += "\t- CLR Runtime Version: ";
	s_results += std::to_string(clr->MajorRuntimeVersion);
	s_results += ".";
	s_results += std::to_string(clr->MinorRuntimeVersion);
	s_results += "";
	s_results += NEWLINE;
	writeResults(outfile , mutex);
	return;
}
