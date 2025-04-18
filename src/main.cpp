#include <pe_parser.h>
#include <iostream>


int main(int argc, char const *argv[])
{
	if(argc < 2) {
		std::cerr << "Usage: " << argv[0] << " <pe_file>" << '\n';
		return 1;
	}

	PEFile pe{argv[1]};
	pe.Parse();

	return 0;
}