/*
   Copyright 2025 ssnob

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

	   http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.
*/

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

