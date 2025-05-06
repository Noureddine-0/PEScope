#include <header.h>
#include <utils.h>
#include <plugins.h>

struct SharedLibrary{
	
	SharedLibrary() = delete;
	SharedLibrary(const std::string& path, std::string& outfile);
	~SharedLibrary() noexcept;

	SharedLibrary(SharedLibrary&&) noexcept;

	bool load();
	void unload();
	
	template<typename T>
	T getSymbol(const char *symbol);

private:
	std::string m_path;
	std::string m_outfile;

	#ifdef _WIN32
		HMODULE m_handle = nullptr;
	#else
		void* m_handle = nullptr;
	#endif


	void writeResult(){
		(void)m_outfile;
	}
};

struct PluginManager{
	PluginManager(std::string& outfile , const char* m_directory, PEFile& pe);
	void loadAllPlugins();

	//The mutex will be used later to sunchronize write to the analysis.txt file
	static std::mutex s_mutex;
private:

	std::vector<SharedLibrary> m_libraries{};
	std::string m_outfile;
	const char *m_directory;
	
	PEFile& m_pe;
};