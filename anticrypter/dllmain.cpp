#include "pch.h"
#include <Windows.h>
#include <winternl.h>
#include <iostream>
#include <fstream>
#include <cmath>
#include "detours.h"
#include <ntstatus.h>
#include <sstream> // For std::stringstream

// Function to calculate entropy
double calculateEntropy(const unsigned char* data, size_t size) {
    if (size == 0) return 0.0;

    double entropy = 0.0;
    unsigned int frequency[256] = { 0 };

    for (size_t i = 0; i < size; ++i) {
        frequency[data[i]]++;
    }

    for (int i = 0; i < 256; ++i) {
        if (frequency[i] > 0) {
            double prob = (double)frequency[i] / size;
            entropy -= prob * log2(prob);
        }
    }

    return entropy;
}

// Function to convert a double to string
std::string doubleToString(double value) {
    std::stringstream ss;
    ss << value;
    return ss.str();
}

// Define the original function pointers
extern "C" NTSTATUS NTAPI NtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
);

extern "C" BOOL WINAPI WriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
);

extern "C" BOOL WINAPI WriteFileEx(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPOVERLAPPED lpOverlapped,
    LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
);

static NTSTATUS(NTAPI* OriginalNtWriteFile)(HANDLE, HANDLE, PIO_APC_ROUTINE, PVOID, PIO_STATUS_BLOCK, PVOID, ULONG, PLARGE_INTEGER, PULONG) = NtWriteFile;
static BOOL(WINAPI* OriginalWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED) = WriteFile;
static BOOL(WINAPI* OriginalWriteFileEx)(HANDLE, LPCVOID, DWORD, LPOVERLAPPED, LPOVERLAPPED_COMPLETION_ROUTINE) = WriteFileEx;

typedef NTSTATUS(NTAPI* NtQueryInformationFile_t)(
    HANDLE FileHandle,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID FileInformation,
    ULONG Length,
    FILE_INFORMATION_CLASS FileInformationClass
    );

typedef NTSTATUS(NTAPI* NtReadFile_t)(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
    );

NtQueryInformationFile_t NtQueryInformationFile = nullptr;
NtReadFile_t NtReadFile = nullptr;

// Define the FILE_STANDARD_INFORMATION structure
typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, * PFILE_STANDARD_INFORMATION;

// Define the FILE_INFORMATION_CLASS enumeration value for FileStandardInformation
#ifndef FileStandardInformation
#define FileStandardInformation ((FILE_INFORMATION_CLASS)5)
#endif

// Function to log messages to a file
void logToFile(const std::string& message) {
    wchar_t tempPath[MAX_PATH];
    DWORD result = GetEnvironmentVariableW(L"TEMP", tempPath, MAX_PATH);
    if (result > 0 && result < MAX_PATH) {
        std::wstringstream wss;
        wss << tempPath << L"\\write_intercept.txt";
        std::wstring logFilePath = wss.str();

        // Convert std::wstring logFilePath to std::string
        std::string logFilePathStr(logFilePath.begin(), logFilePath.end());

        std::ofstream logFile(logFilePathStr, std::ios::app);
        if (logFile.is_open()) {
            logFile << message << std::endl;
            logFile.close();
        }
    }
}

// Thread-local storage to prevent recursion
__declspec(thread) bool tls_inMyWriteFile = false;
__declspec(thread) bool tls_inNtWriteFile = false;

// Check file size and entropy
bool CheckFileSizeAndEntropy(HANDLE FileHandle) {
    FILE_STANDARD_INFORMATION fileInfo;
    IO_STATUS_BLOCK ioStatus;

    // Retrieve file size
    NTSTATUS status = NtQueryInformationFile(FileHandle, &ioStatus, &fileInfo, sizeof(fileInfo), FileStandardInformation);
    if (!NT_SUCCESS(status)) {
        return false;
    }

    const LARGE_INTEGER oneMB = { 1024 * 1024 };
    if (fileInfo.EndOfFile.QuadPart < oneMB.QuadPart) {

        // Read original content from the file
        BYTE originalBuffer[1024]; // Read up to 1024 bytes for simplicity
        LARGE_INTEGER offset = { 0 }; // Read from the beginning of the file

        status = NtReadFile(
            FileHandle,
            NULL,
            NULL,
            NULL,
            &ioStatus,
            originalBuffer,
            sizeof(originalBuffer),
            &offset,
            NULL
        );

        if (!NT_SUCCESS(status)) {
            return false;
        }

        double originalEntropy = calculateEntropy(reinterpret_cast<unsigned char*>(originalBuffer), ioStatus.Information);

        // Define a threshold for high entropy
        const double entropyThreshold = 7.5;

        if (originalEntropy > entropyThreshold) {
            return true; // Allow write operation
        }
    }

    return false; // Block the write operation if the conditions are not met
}

// Hooked NtWriteFile function
NTSTATUS NTAPI MyNtWriteFile(
    HANDLE FileHandle,
    HANDLE Event,
    PIO_APC_ROUTINE ApcRoutine,
    PVOID ApcContext,
    PIO_STATUS_BLOCK IoStatusBlock,
    PVOID Buffer,
    ULONG Length,
    PLARGE_INTEGER ByteOffset,
    PULONG Key
) {
    if (tls_inNtWriteFile) {
        return OriginalNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    }

    tls_inNtWriteFile = true;


    if (!CheckFileSizeAndEntropy(FileHandle)) {
        double entropy = calculateEntropy(reinterpret_cast<const unsigned char*>(Buffer), Length);

        const double entropyThreshold = 7.5;

        if (entropy > entropyThreshold) {
            tls_inNtWriteFile = false;
            return STATUS_ACCESS_DENIED;
        }
    }

    NTSTATUS result = OriginalNtWriteFile(FileHandle, Event, ApcRoutine, ApcContext, IoStatusBlock, Buffer, Length, ByteOffset, Key);
    tls_inNtWriteFile = false;
    return result;
}

// Hooked WriteFile function
BOOL WINAPI MyWriteFile(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten,
    LPOVERLAPPED lpOverlapped
) {
    if (tls_inMyWriteFile) {
        return OriginalWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    }

    tls_inMyWriteFile = true;


    if (!CheckFileSizeAndEntropy(hFile)) {
        double entropy = calculateEntropy(reinterpret_cast<const unsigned char*>(lpBuffer), nNumberOfBytesToWrite);

        const double entropyThreshold = 7.5;

        if (entropy > entropyThreshold) {
            tls_inMyWriteFile = false;
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }

    BOOL result = OriginalWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
    tls_inMyWriteFile = false;
    return result;
}

// Hooked WriteFileEx function
BOOL WINAPI MyWriteFileEx(
    HANDLE hFile,
    LPCVOID lpBuffer,
    DWORD nNumberOfBytesToWrite,
    LPOVERLAPPED lpOverlapped,
    LPOVERLAPPED_COMPLETION_ROUTINE lpCompletionRoutine
) {
    if (tls_inMyWriteFile) {
        return OriginalWriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
    }

    tls_inMyWriteFile = true;


    if (!CheckFileSizeAndEntropy(hFile)) {
        double entropy = calculateEntropy(reinterpret_cast<const unsigned char*>(lpBuffer), nNumberOfBytesToWrite);

        const double entropyThreshold = 7.5;

        if (entropy > entropyThreshold) {
            tls_inMyWriteFile = false;
            SetLastError(ERROR_ACCESS_DENIED);
            return FALSE;
        }
    }

    BOOL result = OriginalWriteFileEx(hFile, lpBuffer, nNumberOfBytesToWrite, lpOverlapped, lpCompletionRoutine);
    tls_inMyWriteFile = false;
    return result;
}

void InstallHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
    NtQueryInformationFile = reinterpret_cast<NtQueryInformationFile_t>(GetProcAddress(ntdll, "NtQueryInformationFile"));
    NtReadFile = reinterpret_cast<NtReadFile_t>(GetProcAddress(ntdll, "NtReadFile"));

    if (DetourAttach(&(PVOID&)OriginalNtWriteFile, MyNtWriteFile) == NO_ERROR) {
    }
    else {
        logToFile("DetourAttach for NtWriteFile failed.");
    }

    if (DetourAttach(&(PVOID&)OriginalWriteFile, MyWriteFile) == NO_ERROR) {
    }
    else {
        logToFile("DetourAttach for WriteFile failed.");
    }

    if (DetourAttach(&(PVOID&)OriginalWriteFileEx, MyWriteFileEx) == NO_ERROR) {
    }
    else {
        logToFile("DetourAttach for WriteFileEx failed.");
    }

    DetourTransactionCommit();
}

void UninstallHooks() {
    DetourTransactionBegin();
    DetourUpdateThread(GetCurrentThread());

    DetourDetach(&(PVOID&)OriginalNtWriteFile, MyNtWriteFile);
    DetourDetach(&(PVOID&)OriginalWriteFile, MyWriteFile);
    DetourDetach(&(PVOID&)OriginalWriteFileEx, MyWriteFileEx);

    DetourTransactionCommit();
}

BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD  ul_reason_for_call,
    LPVOID lpReserved
) {
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
        InstallHooks(); // Install the hooks when the DLL is loaded
        DisableThreadLibraryCalls(hModule); // Optional: Disable DLL_THREAD_ATTACH and DLL_THREAD_DETACH to optimize performance
        break;
    case DLL_THREAD_ATTACH:
        break;
    case DLL_THREAD_DETACH:
        break;
    case DLL_PROCESS_DETACH:
        UninstallHooks();
        break;
    }
    return TRUE;
}
