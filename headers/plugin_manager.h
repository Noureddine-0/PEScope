#include <header.h>
#include <utils.h>
#include <plugins.h>

struct SharedLibrary{
	
	SharedLibrary() = delete;
	SharedLibrary(const std::string& path, const char* outfile);
	~SharedLibrary() noexcept;

	SharedLibrary(SharedLibrary&&) noexcept;

	bool load();
	void unload();
	
	template<typename T>
	T getSymbol(const char *symbol);

private:
	std::string m_path;
	const char *m_outfile;

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
	PluginManager(const char* outfile , const char* m_directory, PEFile& pe);
	void loadAllPlugins();

private:

	std::vector<SharedLibrary> m_libraries{};
	const char *m_outfile{};
	const char *m_directory;
	//The mutex will be used later to sunchronize write to the analysis.txt file
	static std::mutex s_mutex;
	PEFile& m_pe;
};