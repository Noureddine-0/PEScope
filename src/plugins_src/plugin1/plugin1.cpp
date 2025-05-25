#include <plugins.h>
#include <plugin1.h>
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


//returns copy of thisPlugin
PluginInfo getPluginInfo(){
	return thisPlugin;
}


void writeResults(std::string& outfile , std::mutex& mutex){
	std::lock_guard<std::mutex> lock(mutex);

	std::ofstream file{outfile , std::ios::app	};
	
	if (!file.is_open()) {
		std::cerr << "[ERROR] Failed to open file: " << outfile << std::endl;
		return;
	}

	file << s_results;
	file.close();
}

ULONGLONG hasOverlay(const InfoSection* infoSections , WORD count , size_t size){
	
	size_t lastSectionEnd{};
	for (int i =0 ; i < count ; i++ , infoSections++){
		size_t sectionEnd = static_cast<size_t>(infoSections->m_sectionHeader.PointerToRawData + infoSections->m_sectionHeader.SizeOfRawData);
		if (sectionEnd > lastSectionEnd)
				lastSectionEnd =  sectionEnd;		
	}
	return (size > lastSectionEnd) | (static_cast<ULONGLONG>(lastSectionEnd) * 0x100000000ULL);
}


void detectPacker(PEFile& pe , std::string& outfile , std::mutex& mutex){
	UNREFERENCED_PARAMETER(outfile);
	UNREFERENCED_PARAMETER(mutex);

	DWORD nsection{};
	std::vector<std::pair<std::string , double>> malEntropySections{};
	PEInfo& peInfo =  pe.m_peInfo;
	bool isImportSegmentDestroyed = true;
	s_results += "\tPacker IOC :";
	s_results += NEWLINE;
	for (; nsection < peInfo.m_sectionNumber ; nsection++){
		InfoSection& infoSection = peInfo.m_ptr[nsection];
		if (infoSection.m_entropy > 7.49999)
			malEntropySections.push_back(std::make_pair(
				std::string(reinterpret_cast<char*>(infoSection.m_sectionHeader.Name)), infoSection.m_entropy));
		if (!strncmp(reinterpret_cast<char *>(infoSection.m_sectionHeader.Name) , ".idata" , 8)){
			isImportSegmentDestroyed =  false;
		}
	}

	if (isImportSegmentDestroyed){
		s_results += "\t\t- Import segment destroyed";
		s_results += NEWLINE;
	}

	if(!malEntropySections.empty()){
		s_results += "\t\t- High entropy :";
		s_results += NEWLINE;
		for (const auto& iter : malEntropySections){
			s_results += "\t\t\t- ";
			s_results += iter.first;
			s_results += ": ";
			s_results += std::to_string(iter.second);
			s_results += NEWLINE;
		}
	}
}



void detectUpx(PEFile& pe , std::string& outfile , std::mutex& mutex){
	UNREFERENCED_PARAMETER(pe);
	UNREFERENCED_PARAMETER(outfile);
	UNREFERENCED_PARAMETER(mutex);
}

void  compareVirtualAndRawSize(PEFile& pe){
	PEInfo& peInfo=  pe.m_peInfo;
	
}

void scan(PEFile& pe , std::string& outfile , std::mutex& mutex){

	PLUGIN_ENTRY(s_results , NEWLINE , PLUGIN_NAME , PLUGIN_VERSION);

	PEInfo& peInfo  =  pe.m_peInfo;
	
	if (!peInfo.m_ptr){
		s_results += "\tError reading sections";
		s_results += NEWLINE;
		writeResults(outfile , mutex);
		return;
	}

	double entropy{};

	ULONGLONG overlay =  hasOverlay(peInfo.m_ptr , peInfo.m_sectionNumber , pe.m_size);
	if(overlay & 0xFFFFFFFF){
		s_results += "\tOverlay : Yes";	
		s_results += NEWLINE;
		std::array<uint8_t , MD5_HASH_LEN> md5{};
		std::array<uint8_t , SHA1_HASH_LEN> sha1{};
		std::array<uint8_t , SHA256_HASH_LEN> sha256{};

		std::array<uint8_t , 2 * MD5_HASH_LEN + 1> strMd5{};
    	std::array<uint8_t , 2 * SHA1_HASH_LEN + 1> strSha1{};
    	std::array<uint8_t , 2 * SHA256_HASH_LEN + 1> strSha256{};

    	//No need to check offset , size already greater than last section
    	utils::getMd5(reinterpret_cast<LPCVOID>(
    		reinterpret_cast<ULONGLONG>(pe.m_lpAddress) + (overlay >> 32)) ,
    		pe.m_size - (overlay >> 32) , md5 );
    	utils::getSha1(reinterpret_cast<LPCVOID>(
    		reinterpret_cast<ULONGLONG>(pe.m_lpAddress) + (overlay >> 32)) ,
    		pe.m_size - (overlay >> 32) , sha1 );
    	utils::getSha256(reinterpret_cast<LPCVOID>(
    		reinterpret_cast<ULONGLONG>(pe.m_lpAddress) + (overlay >> 32)) ,
    		pe.m_size - (overlay >> 32) , sha256 );

    	utils::bytesToHexString(md5.data() , MD5_HASH_LEN , strMd5.data());
    	utils::bytesToHexString(sha1.data() , SHA1_HASH_LEN , strSha1.data());
    	utils::bytesToHexString(sha256.data() , SHA256_HASH_LEN , strSha256.data());
    	utils::calculateEntropy(reinterpret_cast<LPCVOID>(
    		reinterpret_cast<ULONGLONG>(pe.m_lpAddress) + (overlay >> 32)) ,
    		pe.m_size - (overlay >> 32) , &entropy);

    	s_results += "\t\tentropy : ";
    	s_results += std::to_string(entropy);
    	s_results += NEWLINE	;
    	s_results += "\t\tMd5 : " ;
    	s_results += (char *)strMd5.data();
    	s_results += NEWLINE;
    	s_results += "\t\tSha1 : ";
    	s_results += (char *)strSha1.data();
    	s_results += NEWLINE;
    	s_results += "\t\tSha256 : ";
    	s_results += (char *)strSha256.data();
    	s_results += NEWLINE;
    	detectPacker(pe , outfile , mutex);
    	writeResults(outfile , mutex);
    	return;
	}


	s_results += "\tOverlay : No";
	s_results += NEWLINE;
	writeResults(outfile , mutex);
	return;
}



