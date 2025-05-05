#include <pe_parser.h>
#include <iostream>
#include <plugin_manager.h>


void printUsage(const char* program) {
    std::cout << "Usage: " <<program <<" [options] file1 file2 ..." <<'\n';
    std::cout << "Options:\n";
    std::cout << "  plugins=yes|no            : Enable or disable plugins (default: no)\n";
    std::cout << "  plugins_dir=directory     : Specify the directory for plugins (automatically enable plugins)\n";
    std::cout << "  file1, file2, ...         : Files to be analyzed\n";
    std::cout << "Example:\n";
    std::cout << "  " << program <<" plugins=yes plugins_dir=/path/to/plugins file1.exe file2.exe ...\n";
}

void parseArguments(int argc, char* argv[], Arguments& args) {
    bool pluginsSet = false;
    bool pluginsDirSet = false;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];

        
        size_t pos = arg.find('=');
        if (pos != std::string::npos) {
            std::string key = arg.substr(0, pos);
            std::string value = arg.substr(pos + 1);

            if (key == "plugins") {
                if (value == "yes") {
                    args.plugins = true;
                } else if (value == "no") {
                    args.plugins = false;
                } else {
                    std::cerr << "Invalid value for plugins: " << value << std::endl;
                    printUsage(argv[0]);
                    std::exit(EXIT_FAILURE);
                }
                pluginsSet = true;
            } else if (key == "plugins_dir") {
                args.pluginDir = i;
                pluginsDirSet = true;
            } else {
                std::cerr << "\nUnknown argument: " << key << "\n\n";
                printUsage(argv[0]);
                std::exit(EXIT_FAILURE);
            }
        } else {
            
            args.files.push_back(arg);
        }
    }

    
    if (!pluginsSet) {
        args.plugins = false;
    }

    if (pluginsDirSet) {
        args.plugins = true;
    }

    if (args.files.empty()) {
        std::cerr << "No files specified to analyze.\n";
        printUsage(argv[0]);
        std::exit(EXIT_FAILURE);
    }
}


int main(int argc, char  *argv[])
{
	Arguments args;
    std::string outfile  = "analysis.txt";

    printf("=====================================================\n\t\tPEScope v%s\n=====================================================\n",PROJECT_VERSION);

	if(argc < 2) {
		printUsage(argv[0]);
		return 1;
	}

    parseArguments(argc, argv, args);

	PluginManager* pm = nullptr;
	
	for(const auto& file : args.files){

		PEFile pe{file};
		pe.parse();
		pe.printResult();
		if (args.plugins){
			if (args.pluginDir)
				pm = new PluginManager{outfile, argv[args.pluginDir] + strlen("plugins_dir="), pe};
			else
				pm = new PluginManager{outfile, PLUGIN_DIRECTORY, pe};
			
			pm->loadAllPlugins();
		}
	}

	delete pm;

	return 0;
}