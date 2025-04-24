#include <pe_parser.h>
#include <iostream>


int main(int argc, char const *argv[])
{

    printf("=====================================================\n\t\tPEScope v%s\n=====================================================\n",PROJECT_VERSION);
	auto start =  std::chrono::high_resolution_clock::now();
	if(argc < 2) {
		std::cerr << "Usage: " << argv[0] << " <pe_file>" << '\n';
		return 1;
	}

	PEFile pe{argv[1]};
	pe.parse();
	pe.printResult();
	auto end = std::chrono::high_resolution_clock::now();
	std::chrono::duration<double , std::milli> duration_ms  =  end - start;
	std::cout << duration_ms.count() << '\n';
	return 0;
}