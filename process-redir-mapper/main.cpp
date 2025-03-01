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