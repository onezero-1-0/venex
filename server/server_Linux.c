#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/queue.h>

#define CONTROL_PORT 7777
#define HTTP_PORT 80
#define BUFFER_SIZE 4096
#define MAX_CLIENTS 100

typedef struct {
    int socket;
    struct sockaddr_in address;
    int is_authority;
    char target_id[50];
} client_t;

typedef struct {
    char target_id[50];
    char message[BUFFER_SIZE];
    time_t timestamp;
} queued_message_t;

typedef struct message_node {
    queued_message_t message;
    SLIST_ENTRY(message_node) entries;
} message_node_t;

// Global variables
pthread_mutex_t clients_mutex = PTHREAD_MUTEX_INITIALIZER;
pthread_mutex_t messages_mutex = PTHREAD_MUTEX_INITIALIZER;
client_t *clients[MAX_CLIENTS];
int http_listener_active = 0;
int http_socket = -1;

// Message queue
SLIST_HEAD(message_list, message_node) message_queue;

void broadcast_to_clients(const char *message, int exclude_socket) {
    pthread_mutex_lock(&clients_mutex);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->socket != exclude_socket) {
            send(clients[i]->socket, message, strlen(message), 0);
        }
    }
    
    pthread_mutex_unlock(&clients_mutex);
}

void send_to_target(const char *target_id, const char *message) {
    pthread_mutex_lock(&clients_mutex);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && strcmp(clients[i]->target_id, target_id) == 0) {
            send(clients[i]->socket, message, strlen(message), 0);
            pthread_mutex_unlock(&clients_mutex);
            return;
        }
    }
    
    // Target not found, queue the message
    pthread_mutex_lock(&messages_mutex);
    
    message_node_t *new_node = malloc(sizeof(message_node_t));
    strncpy(new_node->message.target_id, target_id, sizeof(new_node->message.target_id) - 1);
    strncpy(new_node->message.message, message, sizeof(new_node->message.message) - 1);
    new_node->message.timestamp = time(NULL);
    
    SLIST_INSERT_HEAD(&message_queue, new_node, entries);
    
    pthread_mutex_unlock(&messages_mutex);
    pthread_mutex_unlock(&clients_mutex);
}

void deliver_queued_messages(const char *target_id, int target_socket) {
    pthread_mutex_lock(&messages_mutex);
    
    message_node_t *current, *temp;
    SLIST_FOREACH_SAFE(current, &message_queue, entries, temp) {
        if (strcmp(current->message.target_id, target_id) == 0) {
            send(target_socket, current->message.message, strlen(current->message.message), 0);
            SLIST_REMOVE(&message_queue, current, message_node, entries);
            free(current);
        }
    }
    
    pthread_mutex_unlock(&messages_mutex);
}

void add_client(int socket, struct sockaddr_in address) {
    pthread_mutex_lock(&clients_mutex);
    
    for (int i = 0; i < MAX_CLIENTS; i++) {
        if (!clients[i]) {
            clients[i] = malloc(sizeof(client_t));
            clients[i]->socket = socket;
            clients[i]->address = address;
            clients[i]->is_authority = 0;
            memset(clients[i]->target_id, 0, sizeof(clients[i]->target_id));
            
            pthread_mutex_unlock(&clients_mutex);
            return;
        }
    }
    
    pthread_mutex_unlock(&clients_mutex);
}

void remove_client(int socket) {
    pthread_mutex_lock(&clients_mutex);
    
    for (int int i = 0; i < MAX_CLIENTS; i++) {
        if (clients[i] && clients[i]->socket == socket) {
            free(clients[i]);
            clients[i] = NULL;
            break;
        }
    }
    
    pthread_mutex_unlock(&clients_mutex);
}

int start_http_listener() {
    if (http_listener_active) {
        return 0; // Already running
    }
    
    http_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (http_socket < 0) {
        perror("HTTP socket creation failed");
        return -1;
    }
    
    int opt = 1;
    if (setsockopt(http_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("HTTP setsockopt failed");
        close(http_socket);
        return -1;
    }
    
    struct sockaddr_in http_addr;
    http_addr.sin_family = AF_INET;
    http_addr.sin_addr.s_addr = INADDR_ANY;
    http_addr.sin_port = htons(HTTP_PORT);
    
    if (bind(http_socket, (struct sockaddr *)&http_addr, sizeof(http_addr)) < 0) {
        perror("HTTP bind failed");
        close(http_socket);
        return -1;
    }
    
    if (listen(http_socket, 10) < 0) {
        perror("HTTP listen failed");
        close(http_socket);
        return -1;
    }
    
    http_listener_active = 1;
    printf("HTTP listener started on port %d\n", HTTP_PORT);
    return 0;
}

void stop_http_listener() {
    if (http_listener_active) {
        close(http_socket);
        http_listener_active = 0;
        printf("HTTP listener stopped\n");
    }
}

void *handle_http_connections(void *arg) {
    while (http_listener_active) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(http_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            if (http_listener_active) {
                perror("HTTP accept failed");
            }
            continue;
        }
        
        char buffer[BUFFER_SIZE];
        int bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0);
        
        if (bytes_received > 0) {
            buffer[bytes_received] = '\0';
            printf("Received HTTP request:\n%s\n", buffer);
            
            // Broadcast to all control clients
            char broadcast_msg[BUFFER_SIZE + 100];
            snprintf(broadcast_msg, sizeof(broadcast_msg), 
                    "HTTP_REQUEST from %s:%d:\n%s",
                    inet_ntoa(client_addr.sin_addr),
                    ntohs(client_addr.sin_port),
                    buffer);
            
            broadcast_to_clients(broadcast_msg, -1);
            
            // Send basic HTTP response
            const char *response = 
                "HTTP/1.1 200 OK\r\n"
                "Content-Type: text/plain\r\n"
                "Connection: close\r\n"
                "\r\n"
                "Request received by server";
            
            send(client_socket, response, strlen(response), 0);
        }
        
        close(client_socket);
    }
    
    return NULL;
}

void *handle_client(void *arg) {
    int client_socket = *(int *)arg;
    free(arg);
    
    char buffer[BUFFER_SIZE];
    int bytes_received;
    
    while ((bytes_received = recv(client_socket, buffer, sizeof(buffer) - 1, 0)) > 0) {
        buffer[bytes_received] = '\0';
        
        // Check if this is an authority client command
        if (strncmp(buffer, "AUTH:", 5) == 0) {
            char *command = buffer + 5;
            
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i] && clients[i]->socket == client_socket) {
                    clients[i]->is_authority = 1;
                    break;
                }
            }
            pthread_mutex_unlock(&clients_mutex);
            
            if (strncmp(command, "START_HTTP", 10) == 0) {
                if (start_http_listener() == 0) {
                    send(client_socket, "HTTP listener started\n", 22, 0);
                    
                    // Start HTTP listener thread
                    pthread_t http_thread;
                    pthread_create(&http_thread, NULL, handle_http_connections, NULL);
                    pthread_detach(http_thread);
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
            char *target_id = buffer + 7;
            target_id[strcspn(target_id, "\r\n")] = '\0'; // Remove newline
            
            pthread_mutex_lock(&clients_mutex);
            for (int i = 0; i < MAX_CLIENTS; i++) {
                if (clients[i] && clients[i]->socket == client_socket) {
                    strncpy(clients[i]->target_id, target_id, sizeof(clients[i]->target_id) - 1);
                    break;
                }
            }
            pthread_mutex_unlock(&clients_mutex);
            
            // Deliver any queued messages for this target
            deliver_queued_messages(target_id, client_socket);
            
            send(client_socket, "Target registered\n", 18, 0);
        }
        // Check if this is a message to a specific target
        else if (strncmp(buffer, "SEND_TO:", 8) == 0) {
            char *rest = buffer + 8;
            char *target_id = strtok(rest, ":");
            char *message = strtok(NULL, "");
            
            if (target_id && message) {
                send_to_target(target_id, message);
                send(client_socket, "Message sent to target\n", 23, 0);
            } else {
                send(client_socket, "Invalid SEND_TO format. Use: SEND_TO:target:message\n", 50, 0);
            }
        }
        else {
            // Regular message, broadcast to all clients
            char broadcast_msg[BUFFER_SIZE + 50];
            snprintf(broadcast_msg, sizeof(broadcast_msg), "CLIENT_%d: %s", client_socket, buffer);
            broadcast_to_clients(broadcast_msg, client_socket);
        }
    }
    
    remove_client(client_socket);
    close(client_socket);
    return NULL;
}

int main() {
    int server_socket;
    struct sockaddr_in server_addr;
    
    // Initialize message queue
    SLIST_INIT(&message_queue);
    
    // Initialize clients array
    for (int i = 0; i < MAX_CLIENTS; i++) {
        clients[i] = NULL;
    }
    
    // Create server socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    
    // Set socket options
    int opt = 1;
    if (setsockopt(server_socket, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("Setsockopt failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    
    // Configure server address
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(CONTROL_PORT);
    
    // Bind socket
    if (bind(server_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    
    // Listen for connections
    if (listen(server_socket, 10) < 0) {
        perror("Listen failed");
        close(server_socket);
        exit(EXIT_FAILURE);
    }
    
    printf("Server running on port %d\n", CONTROL_PORT);
    
    // Main server loop
    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        
        int client_socket = accept(server_socket, (struct sockaddr *)&client_addr, &client_len);
        if (client_socket < 0) {
            perror("Accept failed");
            continue;
        }
        
        printf("New client connected: %s:%d\n", 
               inet_ntoa(client_addr.sin_addr), ntohs(client_addr.sin_port));
        
        add_client(client_socket, client_addr);
        
        // Create thread for client
        pthread_t thread_id;
        int *client_sock_ptr = malloc(sizeof(int));
        *client_sock_ptr = client_socket;
        
        if (pthread_create(&thread_id, NULL, handle_client, client_sock_ptr) != 0) {
            perror("Thread creation failed");
            close(client_socket);
            free(client_sock_ptr);
        } else {
            pthread_detach(thread_id);
        }
    }
    
    close(server_socket);
    return 0;
}