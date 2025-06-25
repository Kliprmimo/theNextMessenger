#include <arpa/inet.h>
#include <fcntl.h>
#include <libpq-fe.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <openssl/sha.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#define MULTICAST_ADDR "239.0.0.1"
#define MULTICAST_PORT 12345
#define TCP_PORT 54321

#define USERNAME_MAX 16
#define MESSAGE_MAX 255
#define MAX_USERS 100
#define MAX_MESSAGES 1024

typedef struct connected_users_ll connected_users_ll;

struct connected_users_ll {
    int user_id;
    int socket_fd;
    char *session_token;
    connected_users_ll *next;
};

connected_users_ll *connected_users = NULL;

typedef struct {
    int sender_id;
    int receiver_id;
    char message[MESSAGE_MAX + 1];
    int status;
} __attribute__((packed)) Message;

pthread_mutex_t data_lock = PTHREAD_MUTEX_INITIALIZER;

void generate_session_token(char *output) {
    unsigned char buffer[32];
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0 || read(fd, buffer, sizeof(buffer)) != sizeof(buffer)) {
        perror("random read failed");
        exit(EXIT_FAILURE);
    }
    close(fd);

    for (int i = 0; i < 32; ++i) {
        sprintf(&output[i * 2], "%02x", buffer[i]);
    }
    output[64] = '\0'; // null terminator
}

connected_users_ll *add_connected_user(int user_id, int socket_fd) {
    connected_users_ll *curr = connected_users;
    while (curr != NULL) {
        if (curr->user_id == user_id) {
            curr->socket_fd = socket_fd;
            return curr;
        }
        curr = curr->next;
    }

    connected_users_ll *new_node = malloc(sizeof(connected_users_ll));
    if (!new_node) {
        perror("malloc");
        exit(EXIT_FAILURE);
    }
    char *session_token = malloc(sizeof(char) * 65);
    generate_session_token(session_token);
    new_node->user_id = user_id;
    new_node->socket_fd = socket_fd;
    new_node->next = connected_users;
    new_node->session_token = session_token;
    connected_users = new_node;
    return new_node;
}

int is_user_connected(int user_id) {
    connected_users_ll *curr = connected_users;
    while (curr != NULL) {
        if (curr->user_id == user_id) {
            return 1;
        }
        curr = curr->next;
    }
    return 0;
}

int get_socket_by_user_id(int user_id) {
    connected_users_ll *curr = connected_users;
    while (curr != NULL) {
        if (curr->user_id == user_id) {
            return curr->socket_fd;
        }
        curr = curr->next;
    }
    return -1;
}

void remove_connected_user(int user_id) {
    connected_users_ll *curr = connected_users;
    connected_users_ll *prev = NULL;
    free(curr->session_token);
    curr->session_token = 0;
    while (curr != NULL) {
        if (curr->user_id == user_id) {
            if (prev == NULL) {
                connected_users = curr->next;
            } else {
                prev->next = curr->next;
            }
            free(curr);
            curr = 0;
            return;
        }
        prev = curr;
        curr = curr->next;
    }
}
int get_id(PGconn *conn, const char *username) {
    const char *paramValues[1] = {username};
    PGresult *res =
        PQexecParams(conn, "SELECT id FROM users WHERE username = $1", 1, NULL,
                     paramValues, NULL, NULL, 0);

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
    const char *paramValues[2] = {username, password};
    PGresult *res = PQexecParams(
        conn, "SELECT id FROM users WHERE username = $1 AND password = $2", 2,
        NULL, paramValues, NULL, NULL, 0);

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

int insert_msg(PGconn *conn, int sender_id, int receiver_id,
               const char *message, int status) {

    char sender_str[12];
    char receiver_str[12];
    char status_str[6];

    snprintf(sender_str, sizeof(sender_str), "%d", sender_id);
    snprintf(receiver_str, sizeof(receiver_str), "%d", receiver_id);
    snprintf(status_str, sizeof(status_str), "%s", status ? "true" : "false");

    const char *insertParams[4] = {sender_str, receiver_str, message,
                                   status_str};

    PGresult *res = PQexecParams(
        conn,
        "INSERT INTO messages (sender_id, receiver_id, message, was_seen) "
        "VALUES ($1, $2, $3, $4) RETURNING id",
        4, NULL, insertParams, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Insert failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return -2;
    }

    int inserted_id = atoi(PQgetvalue(res, 0, 0));
    PQclear(res);
    return inserted_id;
}

int register_user(PGconn *conn, const char *username, const char *password) {
    const char *checkParams[1] = {username};
    PGresult *res =
        PQexecParams(conn, "SELECT id FROM users WHERE username = $1", 1, NULL,
                     checkParams, NULL, NULL, 0);

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

    const char *insertParams[2] = {username, password};
    res = PQexecParams(
        conn,
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

void hash_password(const char *password, char *output) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256((unsigned char *)password, strlen(password), hash);
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
        sprintf(output + (i * 2), "%02x", hash[i]);
    output[64] = '\0';
}

char *get_unseen_messages_for_user(PGconn *conn, int receiver_id) {
    char receiver_id_str[12];
    snprintf(receiver_id_str, sizeof(receiver_id_str), "%d", receiver_id);
    const char *paramValues[1] = {receiver_id_str};

    PGresult *res = PQexecParams(
        conn,
        "SELECT "
        "  s.username AS sender, "
        "  r.username AS receiver, "
        "  TO_CHAR(m.message_timestamp, 'YYYY-MM-DD HH24:MI') AS msg_time, "
        "  m.message, "
        "  m.id "
        "FROM messages m "
        "JOIN users s ON m.sender_id = s.id::text "
        "JOIN users r ON m.receiver_id = r.id::text "
        "WHERE m.was_seen = false AND m.receiver_id = $1 "
        "ORDER BY m.message_timestamp ASC",
        1, NULL, paramValues, NULL, NULL, 0);

    if (PQresultStatus(res) != PGRES_TUPLES_OK) {
        fprintf(stderr, "Query failed: %s\n", PQerrorMessage(conn));
        PQclear(res);
        return NULL;
    }

    int rows = PQntuples(res);
    if (rows == 0) {
        PQclear(res);
        return strdup("No new messages\n");
    }

    size_t total_size = 0;
    for (int i = 0; i < rows; i++) {
        total_size += strlen(PQgetvalue(res, i, 0)) + 2 +
                      strlen(PQgetvalue(res, i, 1)) + 2 +
                      strlen(PQgetvalue(res, i, 2)) + 3 +
                      strlen(PQgetvalue(res, i, 3)) + 1;
    }

    char *result = calloc(sizeof(char) * total_size + 1, 1);
    if (!result) {
        fprintf(stderr, "Memory allocation failed\n");
        PQclear(res);
        return NULL;
    }

    char update_query[1024] =
        "UPDATE messages SET was_seen = true WHERE id IN (";

    for (int i = 0; i < rows; i++) {
        strcat(result, PQgetvalue(res, i, 0)); // sender
        strcat(result, "->");
        strcat(result, PQgetvalue(res, i, 1)); // receiver
        strcat(result, " [");
        strcat(result, PQgetvalue(res, i, 2)); // timestamp
        strcat(result, "] ");
        strcat(result, PQgetvalue(res, i, 3)); // message
        strcat(result, "\n");

        strcat(update_query, PQgetvalue(res, i, 4)); // message id
        if (i < rows - 1)
            strcat(update_query, ",");
    }
    strcat(update_query, ")");

    PQclear(res);

    PGresult *update_res = PQexec(conn, update_query);
    if (PQresultStatus(update_res) != PGRES_COMMAND_OK) {
        fprintf(stderr, "Failed to update was_seen: %s\n",
                PQerrorMessage(conn));
    }
    PQclear(update_res);

    return result;
}

void handle_client(int client_sock) {
    int user_id;
    int peer_id;
    char buffer[512] = {0};
    char peer_username[USERNAME_MAX] = {0};

    PGconn *conn =
        PQconnectdb("host=localhost dbname=chat_db user=admin password=admin");

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

    char hash[64];
    hash_password(password, hash);

    if (strcmp(type, "LOGIN") == 0) {
        pthread_mutex_lock(&data_lock);
        user_id = check_login(conn, username, hash);
        pthread_mutex_unlock(&data_lock);

        if (user_id == -1) {
            send(client_sock, "ERROR: Bad credentials\n", 22, 0);
            close(client_sock);
            return;
        }
    } else if (strcmp(type, "REGISTER") == 0) {

        pthread_mutex_lock(&data_lock);
        user_id = register_user(conn, username, hash);
        if (user_id != -1) {
            pthread_mutex_unlock(&data_lock);
        } else {
            pthread_mutex_unlock(&data_lock);
            send(client_sock, "ERROR: user exists\n", 19, 0);
            close(client_sock);
            return;
        }
    } else {
        send(client_sock, "ERROR: invalid command\n", 23, 0);
        close(client_sock);
        return;
    }
    connected_users_ll *user_node = add_connected_user(user_id, client_sock);

    char cookie_buff[255];
    snprintf(cookie_buff, 255, "OK\nSetCookie: %s", user_node->session_token);
    if (send(client_sock, cookie_buff, 255, 0) <= 0) {
        perror("send failed");
        remove_connected_user(user_id);
        user_node = 0;
        close(client_sock);
        return;
    }

    while (1) {
        // Choose operation
        bytes_received = recv(client_sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes_received <= 0) {
            perror("recv failed");
            remove_connected_user(user_id);
            user_node = 0;
            close(client_sock);
            return;
        }
        buffer[bytes_received] = '\0';

        char type2[32], client_cookie[256];
        if (sscanf(buffer, "%255s %31s %15s", client_cookie, type2,
                   peer_username) != 3) {
            send(client_sock, "ERROR: Invalid input format.\n", 30, 0);
            close(client_sock);
            return;
        }

        if (strcmp(client_cookie, user_node->session_token) != 0) {
            send(client_sock, "ERROR: invalid cookie\n", 24, 0);
            remove_connected_user(user_id);
            close(client_sock);
            return;
        }

        if (strcmp(type2, "GET_UNREAD") == 0) {
            peer_id = get_id(conn, peer_username);
            char *messages = get_unseen_messages_for_user(conn, peer_id);
            if (messages) {
                if (send(client_sock, messages, strlen(messages), 0) < 0) {
                    perror("send failed");
                    remove_connected_user(user_id);
                    close(client_sock);
                    return;
                }
                free(messages);
            }

        } else if (strcmp(type2, "CHATWITH") == 0) {
            pthread_mutex_lock(&data_lock);
            peer_id = get_id(conn, peer_username);
            pthread_mutex_unlock(&data_lock);

            if (peer_id == -1) {
                send(client_sock, "ERROR: user not found\n", 22, 0);
                remove_connected_user(user_id);
                close(client_sock);
                return;
            }
            if (send(client_sock, "OK\n", 3, 0) <= 0) {
                perror("send failed");
                remove_connected_user(user_id);
                close(client_sock);
                return;
            }
            break;
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

        if (strncmp(buffer, user_node->session_token, 64) != 0) {
            send(client_sock, "ERROR: invalid cookie\n", 24, 0);
            remove_connected_user(user_id);
            close(client_sock);
            return;
        }

        char *no_cookie_buff = buffer + 65;

        Message msg = {0};
        msg.sender_id = user_id;
        msg.receiver_id = peer_id;
        msg.status = is_user_connected(peer_id);
        strncpy(msg.message, no_cookie_buff, MESSAGE_MAX);
        pthread_mutex_lock(&data_lock);
        int message_id = insert_msg(conn, msg.sender_id, msg.receiver_id,
                                    msg.message, msg.status);
        pthread_mutex_unlock(&data_lock);
        if (message_id < 0) {
            remove_connected_user(user_id);
            close(client_sock);
            return;
        }
        // to_do think if we want to just send messages of users are connected 1
        // to 1, send unread messages on connect change when messages are read
        // to read
        int peer_fd = get_socket_by_user_id(peer_id);
        int max_len = bytes_received + 2 + USERNAME_MAX;
        char out_buff[max_len];
        snprintf(out_buff, max_len, "%s: %s", username, msg.message);
        if (peer_fd != -1) {
            if (send(peer_fd, out_buff, max_len, 0) == -1) {
                perror("send failed");
            }
        }

        printf("%d -> %d : %s\n", msg.sender_id, msg.receiver_id, msg.message);
        fflush(stdout);
    }

    remove_connected_user(user_id);
    close(client_sock);
}

void *tcp_listener(void *_) {
    int server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock < 0) {
        perror("socket creation failed");
        exit(EXIT_FAILURE);
    }

    int opt = 1;
    if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) <
        0) {
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

            snprintf(response, sizeof(response), "theNextMessenger[%s]",
                     ip_str);
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
