#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <libpq-fe.h>

#define MULTICAST_ADDR "239.0.0.1"
#define MULTICAST_PORT 12345
#define TCP_PORT 54321

#define USERNAME_MAX 16
#define MESSAGE_MAX 255
#define MAX_USERS 100
#define MAX_MESSAGES 1024

typedef struct {
    uint64_t timestamp;
    char sender[USERNAME_MAX];
    char message[MESSAGE_MAX];
    char recipient[USERNAME_MAX];
} __attribute__((packed)) Message;

typedef struct {
    char username[USERNAME_MAX];
} User;

User users[MAX_USERS];
int user_count = 0;

Message messages[MAX_MESSAGES];
int message_count = 0;

pthread_mutex_t data_lock = PTHREAD_MUTEX_INITIALIZER;

int get_id(PGconn *conn, const char *username) {
    const char *paramValues[1] = { username };
    PGresult *res = PQexecParams(conn,
        "SELECT id FROM users WHERE username = $1",
        1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Query failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -2;
    }

    if (PQntuples(res) == 0) {
        PQclear(res);
        return -1; 
    }

    char *user_id_str = PQgetvalue(res, 0, 0);
    int user_id = atoi(user_id_str);
    PQclear(res);
    return user_id;
}

int check_login(PGconn *conn, const char *username, const char *password) {
    const char *paramValues[2] = { username, password };
    PGresult *res = PQexecParams(conn,
        "SELECT id FROM users WHERE username = $1 AND password = $2",
        2, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Query failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -2;
    }

    if (PQntuples(res) == 1) {
        char *user_id_str = PQgetvalue(res, 0, 0);
        int user_id = atoi(user_id_str);
        PQclear(res);
        return user_id;
    }

    PQclear(res);
    return -1;
}

int register_user(PGconn *conn, const char *username, const char *password) {
    const char *checkParams[1] = { username };
    PGresult *res = PQexecParams(conn,
        "SELECT id FROM users WHERE username = $1",
        1, NULL, checkParams, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Check query failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -2;
    }

    if (PQntuples(res) > 0) {
        PQclear(res);
        return -1;
    }
    PQclear(res);

    const char *insertParams[2] = { username, password };
    res = PQexecParams(conn,
        "INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id",
        2, NULL, insertParams, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Insert failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -2;
    }

    char *user_id_str = PQgetvalue(res, 0, 0);
    int user_id = atoi(user_id_str);
    PQclear(res);
    return user_id;
}

void handle_client(int client_sock) {
    char buffer[512] = {0};
    char current_user[USERNAME_MAX] = {0};
    char chat_with[USERNAME_MAX] = {0};

    PGconn *conn = PQconnectdb("host=localhost dbname=chat_db user=admin password=admin");

    if (PQstatus(conn) != CONNECTION_OK) {
        PQfinish(conn);
        send(client_sock, "ERROR: DB fail\n", 15, 0);
        close(client_sock);
        return;
    }

    // Login/Register
    ssize_t bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        perror("recv failed");
        close(client_sock);
        return;
    }
    buffer[bytes_received] = '\0';
    char type[32], username[32], password[32];

    if (sscanf(buffer, "%31s %31s %31s", type, username, password) != 3) {
        send(client_sock, "ERROR: Invalid input format.\n", 30, 0);
        close(client_sock);
        return;
    }
    if (strcmp(type, "LOGIN") == 0) {
        pthread_mutex_lock(&data_lock);
        int idx = check_login(conn, username, password);
        pthread_mutex_unlock(&data_lock);

        if (idx == -1) {
            send(client_sock, "ERROR: user not found\n", 22, 0);
            close(client_sock);
            return;
        }
        if (send(client_sock, "OK\n", 3, 0) <= 0) {
            perror("send failed");
            close(client_sock);
            return;
        }
    } 
    else 
    if (strcmp(type, "REGISTER") == 0) {
        
        pthread_mutex_lock(&data_lock);
        int idx = register_user(conn, username, password);
        if (idx != -1) {
            pthread_mutex_unlock(&data_lock);
            if (send(client_sock, "OK\n", 3, 0) <= 0) {
                perror("send failed");
                close(client_sock);
                return;
            }
        } else {
            pthread_mutex_unlock(&data_lock);
            send(client_sock, "ERROR: user exists\n", 19, 0);
            close(client_sock);
            return;
        }
    } 
    else {
        send(client_sock, "ERROR: invalid command\n", 23, 0);
        close(client_sock);
        return;
    }

    // Choose chat partner
    bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
    if (bytes_received <= 0) {
        perror("recv failed");
        close(client_sock);
        return;
    }
    buffer[bytes_received] = '\0';

    if (strncmp(buffer, "CHATWITH ", 9) == 0) {
        if (sscanf(buffer + 9, "%15s", chat_with) != 1) {
            send(client_sock, "ERROR: invalid username format\n", 31, 0);
            close(client_sock);
            return;
        }

        pthread_mutex_lock(&data_lock);
        int idx = get_id(conn, username);
        pthread_mutex_unlock(&data_lock);

        if (idx == -1) {
            send(client_sock, "ERROR: user not found\n", 22, 0);
            close(client_sock);
            return;
        }
        if (send(client_sock, "OK\n", 3, 0) <= 0) {
            perror("send failed");
            close(client_sock);
            return;
        }
    }

    // Chat loop
    while (1) {
        bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            if (bytes_received == 0) {
                printf("Client disconnected\n");
            } else {
                perror("recv failed");
            }
            break;
        }
        buffer[bytes_received] = '\0';

        Message msg = {0};
        msg.timestamp = time(NULL);
        strncpy(msg.sender, current_user, USERNAME_MAX);
        strncpy(msg.recipient, chat_with, USERNAME_MAX);
        strncpy(msg.message, buffer, MESSAGE_MAX);
		printf("%s -> %s : %s\n", msg.sender, msg.recipient, msg.message);
		fflush(stdout);

        pthread_mutex_lock(&data_lock);
        if (message_count < MAX_MESSAGES) {
            messages[message_count++] = msg;
        }
        pthread_mutex_unlock(&data_lock);
    }

    close(client_sock);
}

void *tcp_listener(void *_) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(TCP_PORT);
    addr.sin_addr.s_addr = INADDR_ANY;

    if (bind(server_sock, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("bind failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    if (listen(server_sock, 10)) {
        perror("listen failed");
        close(server_sock);
        exit(EXIT_FAILURE);
    }

    printf("[TCP] Server listening on port %d\n", TCP_PORT);

    while (1) {
        int client_sock = accept(server_sock, NULL, NULL);
        if (client_sock < 0) {
            perror("accept failed");
            continue;
        }

        printf("[TCP] Accepted new connection\n");
        pthread_t tid;
        if (pthread_create(&tid, NULL, (void *(*)(void *))handle_client,
                          (void *)(intptr_t)client_sock)) {
            perror("pthread_create failed");
            close(client_sock);
            continue;
        }
        pthread_detach(tid);
    }

    close(server_sock);
    return NULL;
}

void *udp_discovery_responder(void *_) {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(MULTICAST_PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr *)&addr, sizeof(addr))) {
        perror("bind failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    struct ip_mreq mreq = {0};
    mreq.imr_multiaddr.s_addr = inet_addr(MULTICAST_ADDR);
    mreq.imr_interface.s_addr = htonl(INADDR_ANY);

    if (setsockopt(sock, IPPROTO_IP, IP_ADD_MEMBERSHIP, &mreq, sizeof(mreq))) {
        perror("setsockopt failed");
        close(sock);
        exit(EXIT_FAILURE);
    }

    char buf[512] = {0};
    struct sockaddr_in cliaddr = {0};
    socklen_t clilen = sizeof(cliaddr);

    while (1) {
        ssize_t n = recvfrom(sock, buf, sizeof(buf) - 1, 0,
                            (struct sockaddr *)&cliaddr, &clilen);
        if (n <= 0) {
            perror("recvfrom failed");
            continue;
        }
        buf[n] = '\0';

        if (strcmp(buf, "DISCOVER_SERVER") == 0) {
            char response[512] = {0};
            char ip_str[INET_ADDRSTRLEN] = {0};

            int tmp = socket(AF_INET, SOCK_DGRAM, 0);
            if (tmp < 0) {
                perror("temp socket creation failed");
                continue;
            }

            struct sockaddr_in out = {0};
            out.sin_family = AF_INET;
            out.sin_port = htons(80);
            out.sin_addr.s_addr = inet_addr("8.8.8.8");

            if (connect(tmp, (struct sockaddr *)&out, sizeof(out))) {
                perror("connect failed");
                close(tmp);
                continue;
            }

            struct sockaddr_in local = {0};
            socklen_t len = sizeof(local);
            if (getsockname(tmp, (struct sockaddr *)&local, &len)) {
                perror("getsockname failed");
                close(tmp);
                continue;
            }

            close(tmp);

            if (!inet_ntop(AF_INET, &local.sin_addr, ip_str, sizeof(ip_str))) {
                perror("inet_ntop failed");
                continue;
            }

            snprintf(response, sizeof(response), "theNextMessenger[%s]", ip_str);
            if (sendto(sock, response, strlen(response), 0,
                      (struct sockaddr *)&cliaddr, clilen) <= 0) {
                perror("sendto failed");
            }
        }
    }

    close(sock);
    return NULL;
}

int main() {
    pthread_t tcp_thread, udp_thread;

    if (pthread_create(&tcp_thread, NULL, tcp_listener, NULL)) {
        perror("TCP thread creation failed");
        exit(EXIT_FAILURE);
    }

    if (pthread_create(&udp_thread, NULL, udp_discovery_responder, NULL)) {
        perror("UDP thread creation failed");
        exit(EXIT_FAILURE);
    }

    pthread_join(tcp_thread, NULL);
    pthread_join(udp_thread, NULL);

    return 0;
}
