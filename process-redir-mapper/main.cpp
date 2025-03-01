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

#include "framework.h"
#include "redir_mapper.h"

typedef void(__fastcall* tNtResumeProcess)(HANDLE phandle);

int main(int argc, char* argv[])
{
	// Get ResumeProcess addr
	tNtResumeProcess NtResumeProcess = (tNtResumeProcess)GetProcAddress(GetModuleHandleA("ntdll"), "NtResumeProcess");

	STARTUPINFOA startup_info{ 0 };
	PROCESS_INFORMATION process_info{ 0 };

	// Create a dummy process
	BOOL status = CreateProcessA("C:\\Windows\\System32\\Calc.exe", nullptr,
			nullptr, nullptr, FALSE, CREATE_SUSPENDED | DETACHED_PROCESS, nullptr,
			nullptr, &startup_info, &process_info);

	// PROCESS_ALL_ACCESS handle
	HANDLE h_process = process_info.hProcess;
	
	redir_mapper mapper(h_process, process_info.hThread);
	const std::string path = std::string(argv[0], strlen(argv[0]) - sizeof("process-redir-mapper.exe")) + "\\test-dll.dll";
	printf("%s\n", path.c_str());
	if (!mapper.map(path.c_str()))
	{
		printf("[-] Failed to map!\n");
		TerminateProcess(h_process, 0);
		return 1;
	}

	printf("[+] Mapped succesfully!");
	NtResumeProcess(h_process);
	return 0;
}