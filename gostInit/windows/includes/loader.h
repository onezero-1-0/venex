#include <winternl.h>
#include <stdio.h>
#include <stdint.h>
#include <winbase.h>
#include <winhttp.h>


//#define WIN_API_FUNC(name, ret_type, ...) ret_type(WINAPI *name)(__VA_ARGS__);
#define WIN_API_FUNC(name, ret_type, ...) ret_type(WINAPI *name)(__VA_ARGS__)

#define CUSTOM_ZeroMemory(Destination,Length) custom_memset((Destination),0,(Length))

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
    WIN_API_FUNC(CloseHandle, BOOL, HANDLE hObject);
    WIN_API_FUNC(VirtualAlloc, LPVOID, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect);
    WIN_API_FUNC(VirtualFree, BOOL, LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType);
    WIN_API_FUNC(VirtualProtect, BOOL, LPVOID lpAddress, SIZE_T dwSize, DWORD flNewProtect, PDWORD lpflOldProtect);
    WIN_API_FUNC(ReadFile, BOOL, HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);
    WIN_API_FUNC(CreateFileA, HANDLE, LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);
    WIN_API_FUNC(GetFileSize, DWORD, HANDLE hFile, LPDWORD lpFileSizeHigh);
    WIN_API_FUNC(SetFilePointer, DWORD, HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);
} KERNEL32_TABLE, *PKERNEL32_TABLE;

typedef struct _ADVAPI32_TABLE {
    WIN_API_FUNC(GetUserNameA, BOOL, LPSTR lpBuffer, LPDWORD pcbBuffer);
} ADVAPI32_TABLE, *PADVAPI32_TABLE;


typedef struct _FUNCTION_TABLE {
    KERNEL32_TABLE Kernel32;
    ADVAPI32_TABLE Advapi32;
} FUNCTION_TABLE;
