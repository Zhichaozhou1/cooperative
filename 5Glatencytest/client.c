#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/time.h>

#define PORT 12345
#define BUFFER_SIZE 1024
#define ITERATIONS 1000

int main() {
    int sock = 0;
    struct sockaddr_in serv_addr;
    char buffer[BUFFER_SIZE] = {0};
    const char *require_msg = "Require";
    int i;

    if ((sock = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("Socket creation error");
        exit(EXIT_FAILURE);
    }

    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    if(inet_pton(AF_INET, "192.168.1.218", &serv_addr.sin_addr) <= 0) {
        perror("Invalid address / Address not supported");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection Failed");
        exit(EXIT_FAILURE);
    }

    struct timeval start, end;
    gettimeofday(&start, NULL);

    for (i = 0; i < ITERATIONS; i++) {
        if (send(sock, require_msg, strlen(require_msg), 0) != (ssize_t)strlen(require_msg)) {
            perror("send failed");
            exit(EXIT_FAILURE);
        }

        memset(buffer, 0, BUFFER_SIZE);
        int bytes_received = recv(sock, buffer, BUFFER_SIZE, 0);
        if (bytes_received <= 0) {
            perror("recv failed or connection closed");
            exit(EXIT_FAILURE);
        }

    }

    gettimeofday(&end, NULL);
    double elapsed = (end.tv_sec - start.tv_sec) + (end.tv_usec - start.tv_usec)/1000000.0;
    printf("Total execution time for %d iterations: %f seconds\n", ITERATIONS, elapsed);

    close(sock);
    return 0;
}
