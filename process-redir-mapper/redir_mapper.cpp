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

#include "redir_mapper.h"

std::vector<std::byte> redir_mapper::read_bytes(const char* fp)
{
    std::ifstream file_stream(fp, std::ios_base::binary);

    if (!file_stream.is_open() || !file_stream.good())
    {
        printf("[-] Invalid file\n");
        return std::vector<std::byte>();
    }

    std::vector<char> buffer((std::istreambuf_iterator<char>(file_stream)),
        std::istreambuf_iterator<char>());

    std::vector<std::byte> result(buffer.size());
    std::transform(buffer.begin(), buffer.end(), result.begin(),
        [](char c) { return static_cast<std::byte>(c); });
    return result;
}

IMAGE_DOS_HEADER* redir_mapper::get_dos()
{
    return (IMAGE_DOS_HEADER*)file_bytes.data();
}

IMAGE_NT_HEADERS* redir_mapper::get_nt()
{
    return (IMAGE_NT_HEADERS*)(get_dos()->e_lfanew + file_bytes.data());
}

void redir_mapper::inject_dll(const std::string& dll)
{
    void* name_addy = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    WriteProcessMemory(process, name_addy, dll.c_str(), dll.size(), nullptr);
    HANDLE thread = CreateRemoteThread(process, nullptr, NULL, (LPTHREAD_START_ROUTINE)LoadLibraryA, name_addy, NULL, nullptr);
    WaitForSingleObject(thread, INFINITE);
    printf("[+] DLL Loaded: %s\n", dll.c_str());
    CloseHandle(thread);
    VirtualFreeEx(process, name_addy, MEM_RELEASE, 0);
}

std::string redir_mapper::read_unknown_string(void* address)
{
    std::string imported_dll_name = "";

    char character = 1;
    int loops = 0;
    do
    {
        ReadProcessMemory(process, (void*)((SIZE_T)address + loops), &character, sizeof(char), nullptr);
        loops++;
        if (character)
        {
            imported_dll_name += character;
        }

    } while (character);

    return imported_dll_name;
}

void redir_mapper::write_sections(void* allocation)
{
    IMAGE_SECTION_HEADER* section = IMAGE_FIRST_SECTION(get_nt());
    for (int i = 0; i < get_nt()->FileHeader.NumberOfSections; i++, section++)
    {
        if (!WriteProcessMemory(process,
            (void*)((SIZE_T)allocation + section->VirtualAddress),
            file_bytes.data() + section->PointerToRawData, section->SizeOfRawData, nullptr
        ))
        {
            printf("\t[-] Failed to write section: %s\n", section->Name);
        }
        else 
        {
            printf("\t[+] Wrote section: %s\n", section->Name);
        }
    }
}

void redir_mapper::handle_relocations(void* allocation)
{
    IMAGE_NT_HEADERS* nt = get_nt();
    IMAGE_OPTIONAL_HEADER* opt_header = &nt->OptionalHeader;

    SIZE_T delta = (SIZE_T)allocation - opt_header->ImageBase;
    IMAGE_DATA_DIRECTORY* reloc_directory = &opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (reloc_directory->Size)
    {
        IMAGE_BASE_RELOCATION* reloc_addy = (IMAGE_BASE_RELOCATION*)((SIZE_T)allocation + reloc_directory->VirtualAddress);
        SIZE_T max_relocation = (SIZE_T)reloc_addy + reloc_directory->Size;

        IMAGE_BASE_RELOCATION reloc;
        ReadProcessMemory(process, reloc_addy, &reloc, sizeof(IMAGE_BASE_RELOCATION), nullptr);

        while ((SIZE_T)reloc_addy < max_relocation && reloc.SizeOfBlock)
        {
            UINT num_entries = (reloc.SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            SIZE_T delta_flag_addy = (SIZE_T)(reloc_addy + 1);
            
            for (UINT i = 0; i != num_entries; ++i)
            {
                UINT delta_flag = 0;
                ReadProcessMemory(process, (void*)delta_flag_addy, &delta_flag, sizeof(UINT), nullptr);

                if (((delta_flag >> 0x0C) == IMAGE_REL_BASED_DIR64))
                {
                    PUINT patch_location = (PUINT)(SIZE_T(allocation) + reloc.VirtualAddress + ((delta_flag) & 0xFFF));
                    UINT rel_addy = 0;
                    ReadProcessMemory(process, patch_location, &rel_addy, sizeof(UINT), nullptr);
                    rel_addy += delta;
                    
                    WriteProcessMemory(process, patch_location, &rel_addy, sizeof(UINT), nullptr);
                }
            }

            reloc_addy = (IMAGE_BASE_RELOCATION*)((SIZE_T)reloc_addy + reloc.SizeOfBlock);
        }

    }
}

void redir_mapper::resolve_imports(void* allocation)
{
    IMAGE_NT_HEADERS* nt = get_nt();
    IMAGE_OPTIONAL_HEADER* opt_header = &nt->OptionalHeader;

    IMAGE_DATA_DIRECTORY* import_directory = &opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (import_directory->Size)
    {
        IMAGE_IMPORT_DESCRIPTOR* descriptor_addy = (IMAGE_IMPORT_DESCRIPTOR*)((SIZE_T)allocation + import_directory->VirtualAddress);
        IMAGE_IMPORT_DESCRIPTOR descriptor;

        ReadProcessMemory(process, descriptor_addy, &descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), nullptr);

        while (descriptor.Name)
        {
            SIZE_T dll_name = (SIZE_T)allocation + descriptor.Name;
            std::string imported_dll_name = read_unknown_string((void*)dll_name);
            inject_dll(imported_dll_name);

            SIZE_T original_thunk_addy = (SIZE_T)allocation + descriptor.OriginalFirstThunk;
            SIZE_T first_thunk_addy = (SIZE_T)allocation + descriptor.FirstThunk;

            ULONG original_value = 0;
            ReadProcessMemory(process, (void*)original_thunk_addy, &original_value, sizeof(ULONG), nullptr);
            while (original_value) 
            {
                if (IMAGE_SNAP_BY_ORDINAL(original_value))
                {
                    SIZE_T import_addy = (SIZE_T)GetProcAddress(LoadLibraryA(imported_dll_name.c_str()), (char*)(original_value & 0xFFFF));
                    WriteProcessMemory(process, (void*)first_thunk_addy, &import_addy, sizeof(SIZE_T), nullptr);
                }
                else
                {
                    IMAGE_IMPORT_BY_NAME* import_by_name_addy = (IMAGE_IMPORT_BY_NAME*)((SIZE_T)allocation + original_value);
                    char import_by_name[sizeof(IMAGE_IMPORT_BY_NAME)+0x1000];
                    ReadProcessMemory(process, import_by_name_addy, &import_by_name, sizeof(import_by_name), nullptr);

                    std::string imported_function = std::string(((IMAGE_IMPORT_BY_NAME*)import_by_name)->Name);
                    SIZE_T import_addy = (SIZE_T)GetProcAddress(LoadLibraryA(imported_dll_name.c_str()), imported_function.c_str());
                    WriteProcessMemory(process, (void*)first_thunk_addy, &import_addy, sizeof(SIZE_T), nullptr);
                }
                
                original_thunk_addy += sizeof(SIZE_T);
                first_thunk_addy += sizeof(SIZE_T);
                ReadProcessMemory(process, (void*)original_thunk_addy, &original_value, sizeof(ULONG), nullptr);
            }

            descriptor_addy++;
            ReadProcessMemory(process, descriptor_addy, &descriptor, sizeof(IMAGE_IMPORT_DESCRIPTOR), nullptr);
        }
    }
}

#pragma optimize("", off)
__declspec(noinline) void entry_caller(void* allocation)
{
    IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)allocation;
    IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)((char*)allocation + dos->e_lfanew);
    IMAGE_OPTIONAL_HEADER* opt_header = &nt->OptionalHeader;
    IMAGE_DATA_DIRECTORY* tls_dir = &opt_header->DataDirectory[IMAGE_DIRECTORY_ENTRY_TLS];


    // call tls callbacks if they exist
    if (tls_dir->Size) 
    {
        IMAGE_TLS_DIRECTORY* cb_tls_dir = (IMAGE_TLS_DIRECTORY*)((SIZE_T)allocation + tls_dir->VirtualAddress);
        PIMAGE_TLS_CALLBACK* callback = (PIMAGE_TLS_CALLBACK*)(cb_tls_dir->AddressOfCallBacks);
        for (; callback && *callback; ++callback)
            (*callback)(allocation, DLL_PROCESS_ATTACH, nullptr);
    }

    // this is the new main function, when it returns the process will exit
    ((void(*)(void*, void*, void*))((SIZE_T)allocation + nt->OptionalHeader.AddressOfEntryPoint))
        (allocation, (void*)DLL_PROCESS_ATTACH, nullptr);

}
#pragma optimize("", on) 

bool redir_mapper::map(const char* file_path)
{
    file_bytes = read_bytes(file_path);
    if (file_bytes.size() == 0)
    {
        printf("[-] Failed to read file\n");
        return false;
    }

    printf("[+] Read %i bytes\n", file_bytes.size());
    printf("[+] File Pointer: %p\n", file_bytes.data());

    if (*(__int16*)file_bytes.data() != 'ZM')
    {
        printf("[-] Invalid PE File\n");
        return false;
    }

    IMAGE_NT_HEADERS* nt = get_nt();
    IMAGE_OPTIONAL_HEADER* opt_header = &nt->OptionalHeader;

    printf("[+] Trying to allocate at: %p\n", opt_header->ImageBase);
    
    void* allocation = VirtualAllocEx(process, (void*)opt_header->ImageBase,
        opt_header->SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

    bool needs_reloc = false;

    if (allocation == nullptr)
    {
        needs_reloc = true;
        printf("\t[-] Default allocation failed\n");

        allocation = VirtualAllocEx(process, nullptr,
            opt_header->SizeOfImage, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    }

    printf("[~] Memory allocation: %p\n", allocation);

    if (!WriteProcessMemory(process, allocation, file_bytes.data(), 0x1000, nullptr))
    {
        printf("[-] Failed to write PE header (0x%x)\n", GetLastError());
        return false;
    }

    printf("[+] PE Header Written\n");
    
    write_sections(allocation);
    if (needs_reloc)
    {
        handle_relocations(allocation);
    }
    resolve_imports(allocation);

    void* entry_mem = VirtualAllocEx(process, nullptr, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    WriteProcessMemory(process, entry_mem, entry_caller, 0x1000, nullptr);

    CONTEXT context;
    context.ContextFlags = CONTEXT_ALL;
    GetThreadContext(thread, &context);

    context.Rcx = (DWORD64)allocation;
    context.Rip = (DWORD64)entry_mem;
    SetThreadContext(thread, &context);

    return true;
}
