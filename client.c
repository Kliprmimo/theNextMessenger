#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>

// Multicast discovery settings
#define MULTICAST_ADDR "239.0.0.1"
#define MULTICAST_PORT 12345

// TCP port for actual client-server communication
#define TCP_PORT 54321

// Constants for buffer sizes
#define BUFFER_SIZE 512
#define USERNAME_MAX 16
#define MESSAGE_MAX 512
#define INPUT_MAX 255

// Message structure
typedef struct {
    uint64_t timestamp;
    char sender[USERNAME_MAX];
    char message[MESSAGE_MAX];
} __attribute__((packed)) Message;

// Function to discover the server via UDP multicast
void discover_server(char *server_ip) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    int reuse = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &reuse, sizeof(reuse)) < 0) {
        perror("setsockopt failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Setup multicast address
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MULTICAST_PORT);
    if (inet_pton(AF_INET, MULTICAST_ADDR, &addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Send discovery message
    const char *query = "DISCOVER_SERVER";
    ssize_t sent = sendto(sock, query, strlen(query), 0,
                          (struct sockaddr *)&addr, sizeof(addr));
    if (sent < 0) {
        perror("sendto failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Receive server response
    struct sockaddr_in from = {0};
    socklen_t fromlen = sizeof(from);
    char buf[BUFFER_SIZE] = {0};

    ssize_t received = recvfrom(sock, buf, sizeof(buf) - 1, 0,
                                (struct sockaddr *)&from, &fromlen);
    if (received < 0) {
        perror("recvfrom failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    buf[received] = '\0'; // Null-terminate the received string

    // Parse server IP from response
    if (strncmp(buf, "theNextMessenger[", 17) == 0) {
        if (sscanf(buf, "theNextMessenger[%31[^]]", server_ip) != 1) {
            fprintf(stderr, "Failed to parse server IP\n");
            close(sock);
            exit(EXIT_FAILURE);
        }
        printf("Discovered server: %s\n", server_ip);
    } else {
        fprintf(stderr, "Invalid server response: %s\n", buf);
        close(sock);
        exit(EXIT_FAILURE);
    }

    close(sock);
}

// Establish a TCP connection to the discovered server
int connect_to_server(const char *server_ip) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in serv_addr = {0};
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(TCP_PORT);

    if (inet_pton(AF_INET, server_ip, &serv_addr.sin_addr) <= 0) {
        perror("inet_pton failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("connect failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    return sock;
}

// Main chat interaction loop: handles both incoming and outgoing messages
void chat_loop(int sock, char *session_token) {
    fd_set read_fds;
    char input[INPUT_MAX] = {0};

    // Clear newline buffer from previous input
    int c;
    while ((c = getchar()) != '\n' && c != EOF)
        ;

    while (1) {
        printf("You: ");
        fflush(stdout);

        FD_ZERO(&read_fds);
        FD_SET(STDIN_FILENO, &read_fds); // Watch for user input
        FD_SET(sock, &read_fds);         // Watch for incoming server data

        int retval = select(sock + 1, &read_fds, NULL, NULL, NULL);
        if (retval < 0) {
            if (errno == EINTR)
                continue; 
            perror("select failed");
            break;
        }

        // Incoming message from server
        if (FD_ISSET(sock, &read_fds)) {
            char buffer[BUFFER_SIZE] = {0};
            ssize_t n = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (n < 0) {
                perror("recv failed");
                break;
            } else if (n == 0) {
                printf("\nServer disconnected\n");
                break;
            }
            buffer[n] = '\0';
            printf("\n%s\n", buffer);
        }

        // User input
        if (FD_ISSET(STDIN_FILENO, &read_fds)) {
            if (fgets(input, sizeof(input), stdin) == NULL) {
                if (feof(stdin)) {
                    printf("\nEOF detected, exiting...\n");
                } else {
                    perror("fgets failed");
                }
                break;
            }

            char out_buff[MESSAGE_MAX];
            snprintf(out_buff, MESSAGE_MAX, "%s %s", session_token, input);

            // Remove trailing newline
            out_buff[strcspn(out_buff, "\n")] = '\0';

            if (strcmp(input, "/quit\n") == 0) {
                printf("Quitting...\n");
                break;
            }

            // Send user message to server
            ssize_t sent = send(sock, out_buff, strlen(out_buff), 0);
            if (sent < 0) {
                perror("send failed");
                break;
            }
        }
    }
}

int main() {
    char server_ip[32] = {0};

    // Step 1: Discover server via multicast
    discover_server(server_ip);

    // Step 2: Connect to discovered server via TCP
    int sock = connect_to_server(server_ip);

    // Step 3: Login or Register
    int choice;
    char username[32] = {0};
    char password[32] = {0};
    char buffer[BUFFER_SIZE] = {0};

    printf("1. Login\n2. Register\n");
    if (scanf(" %d", &choice) != 1) {
        fprintf(stderr, "Failed to read choice\n");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Username: ");
    if (scanf("%15s", username) != 1) {
        fprintf(stderr, "Failed to read username\n");
        close(sock);
        exit(EXIT_FAILURE);
    }

    printf("Password: ");
    if (scanf("%15s", password) != 1) {
        fprintf(stderr, "Failed to read password\n");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Send login/register request
    if (choice == 1) {
        snprintf(buffer, sizeof(buffer), "LOGIN %s %s", username, password);
    } else if (choice == 2){
        snprintf(buffer, sizeof(buffer), "REGISTER %s %s", username, password);
    } else{
        printf("Wrong operation");
        exit(EXIT_FAILURE);
    }

    ssize_t sent = send(sock, buffer, strlen(buffer), 0);
    if (sent < 0) {
        perror("send failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    // Receive server response
    ssize_t received = recv(sock, buffer, sizeof(buffer) - 1, 0);
    if (received < 0) {
        perror("recv failed");
        close(sock);
        exit(EXIT_FAILURE);
    }
    buffer[received] = '\0';
    printf("Server: %s\n", buffer);

    // If server returns error, exit
    if (strncmp(buffer, "ERROR", 5) == 0){
        close(sock);
        exit(EXIT_SUCCESS);
    }

    // Extract session token
    char *token_prefix = "SetCookie: ";
    char *token_start = strstr(buffer, token_prefix);
    if (token_start) {
        token_start += strlen(token_prefix);
    }

    // Store session token (assuming max token length = 64)
    char *session_token = malloc(sizeof(char) * 65);
    strncpy(session_token, token_start, 65);
    session_token[64] = 0;

    // Step 4: Post-auth options
    while (1) {
        int choice2;
        printf("1. Read unseen messages\n2. Start chat\n");
        if (scanf("%d", &choice2) != 1) {
            fprintf(stderr, "Failed to read second choice\n");
            close(sock);
            exit(EXIT_FAILURE);
        }

        if (choice2 == 1) {
            // Request unread messages
            snprintf(buffer, sizeof(buffer), "%s GET_UNREAD %s", session_token, username);
            sent = send(sock, buffer, strlen(buffer), 0);
            if (sent < 0) {
                perror("send failed");
                close(sock);
                exit(EXIT_FAILURE);
            }

            received = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (received < 0) {
                perror("recv failed");
                close(sock);
                exit(EXIT_FAILURE);
            }
            buffer[received] = '\0';
            printf("Messages:\n%s", buffer);
        } else if (choice2 == 2) {
            // Initiate chat with another user
            printf("Enter user to chat with: ");
            if (scanf("%15s", username) != 1) {
                fprintf(stderr, "Failed to read recipient username\n");
                close(sock);
                exit(EXIT_FAILURE);
            }

            snprintf(buffer, sizeof(buffer), "%s CHATWITH %s", session_token, username);
            sent = send(sock, buffer, strlen(buffer), 0);
            if (sent < 0) {
                perror("send failed");
                close(sock);
                exit(EXIT_FAILURE);
            }

            received = recv(sock, buffer, sizeof(buffer) - 1, 0);
            if (received < 0) {
                perror("recv failed");
                close(sock);
                exit(EXIT_FAILURE);
            }
            buffer[received] = '\0';
            printf("Server: %s\n", buffer);

            // Launch chat loop
            chat_loop(sock, session_token);

            close(sock);
            return EXIT_SUCCESS;
        } else {
            printf("Undefined choice\nTry again (1 or 2)\n");
        }
    }
}
