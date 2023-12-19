// RemoteThread.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>

int err(const char* msg) {
    printf("%s (%u)", msg, GetLastError());
    return 1;
}

int main(int argc, const char* argv[]) {
    if (argc < 3) {
        printf("Usage: RemoteThread <pid> <dllpath>\n");
        return 0;
    }

    int pid = atoi(argv[1]);

    HANDLE hProcess = OpenProcess(PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_CREATE_THREAD, FALSE, pid);
    if (!hProcess)
        return err("Error OpenProcess");

    void* buf = VirtualAllocEx(hProcess, nullptr, 1 << 12, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!buf)
        return err("Error VirtualAllocEx");

    if (!WriteProcessMemory(hProcess, buf, argv[2], strlen(argv[2]), nullptr))
        return err("Error WriteProcessMemory");

    HANDLE hThread = CreateRemoteThread(hProcess, nullptr, 0,
        (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandle(L"kernel32"), "LoadLibraryA"),
        buf, 0, nullptr);
    if (!hThread)
        return err("Error CreateRemoteThread");

    return 0;
}
