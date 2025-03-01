#pragma once
#include <Windows.h>
#include <vector>
#include <cstddef>
#include <fstream>
#include <algorithm>
#include <TlHelp32.h>

class redir_mapper
{
private:
	HANDLE process;
	HANDLE thread;
	std::vector<std::byte> file_bytes;
	std::vector<std::byte> read_bytes(const char* fp);

	IMAGE_DOS_HEADER* get_dos();
	IMAGE_NT_HEADERS* get_nt();

	void inject_dll(const std::string& dll);

	std::string read_unknown_string(void* address);

	void write_sections(void* allocation);
	void handle_relocations(void* allocation);
	void resolve_imports(void* allocation);

public:
	redir_mapper(HANDLE hp, HANDLE ht) : process(hp), thread(ht) {}
	
	bool map(const char* file_path);
};

