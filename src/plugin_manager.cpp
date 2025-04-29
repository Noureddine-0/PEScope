#include <plugin_manager.h>


std::mutex PluginManager::s_mutex{};

SharedLibrary::SharedLibrary(const std::string& path , const char *outfile) 
					: m_path(path),
					  m_outfile(outfile){

}

SharedLibrary::~SharedLibrary() noexcept{
	unload();
}


SharedLibrary::SharedLibrary(SharedLibrary&& other) noexcept
    : m_path(std::move(other.m_path)),
      m_outfile(std::exchange(other.m_outfile , nullptr)),
      m_handle(std::exchange(other.m_handle, nullptr))
      
{
}

bool SharedLibrary::load(){
	#ifdef _WIN32
		m_handle = LoadLibraryA(m_path.c_str());
	#else
		m_handle = dlopen(m_path.c_str() , RTLD_LAZY);
	#endif
		if(!m_handle){
			fprintf(stderr, "Failed to load library\n");
			return false;
		}
		return true;
}

void SharedLibrary::unload(){
	if (m_handle){
		#ifdef _WIN32
			FreeLibrary(m_handle);
		#else
			dlclose(m_handle);
		#endif
	}
}

template<typename T>
T SharedLibrary::getSymbol(const char *symbol){
	#ifdef _WIN32
		return reinterpret_cast<T>(GetProcAddress(m_handle , symbol));
	#else
		return reinterpret_cast<T>(dlsym(m_handle , symbol));
	#endif
}

PluginManager::PluginManager(const char *outfile , const char * directory ,PEFile& pe) :m_outfile(outfile),m_directory(directory),m_pe(pe){
	std::cout << "Directory is:" <<directory <<'\n'; 
}

void PluginManager::loadAllPlugins(){
	namespace fs = std::filesystem;
	try{
		for (const auto& entry: fs::directory_iterator(m_directory)){
			if(!entry.is_regular_file())
				continue;

			const auto& path  =  entry.path();
			std::string extension  = path.extension().string();
	#ifdef _WIN32
			if (extension != ".dll")
				continue;
	#else
			if (extension != ".so")
				continue;
	#endif
			SharedLibrary lib(path.string() , m_outfile);
			if (lib.load()){
				printf("[*] Library %s load successfully...\n" , path.string().c_str());
				funcInfo  getPluginInfo =  lib.getSymbol<funcInfo>((const char *)"getPluginInfo");
				if (!getPluginInfo){
					fprintf(stderr , "\tNo funtion named getPluginInfo found\n");
					continue;
				}
				PluginInfo pluginInfo = getPluginInfo();
				printf("\tPLUGIN_NAME : %s\n",pluginInfo.m_name);
				printf("\tPLUGIN_VERSION : %s\n",pluginInfo.m_version);
				printf("\tPLUGIN_DESCRIPTION : %s\n",pluginInfo.m_description);

				funcScan scan =  lib.getSymbol<funcScan>((const char *)"scan");

				if (!scan){
					fprintf(stderr , "\tNo function named scan found");
					continue;

				}
				scan(m_pe);
				m_libraries.push_back(std::move(lib));
			}
		}
	}catch(const fs::filesystem_error& e){
		std::cerr << "[!] Error while loading plugins :" << e.what()<<'\n';
		std::exit(EXIT_FAILURE);
	}
}