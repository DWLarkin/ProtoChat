#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdio.h>

#define DOMAIN_MAX 4096
#define NAME_MAX 255
#define HELLO_HDR_LEN 2
#define GREET_BUF_LEN NAME_MAX + HELLO_HDR_LEN
#define PORT_DIGITS 5

#ifdef NDEBUG
#define debug_print(fmt, ...)                                                  \
    do {                                                                       \
    } while (0)
#else
#define debug_print(fmt, ...)                                                  \
    fprintf(stderr, "[%s@%d] " fmt, __FILE__, __LINE__, ##__VA_ARGS__)
#endif

enum protocol_codes {
    INVALID_CODE,
    CLIENT_HELLO,
    SERVER_ACK,
    CHAT_MESSAGE,
    CLIENT_DISCONNECT,
    CLIENT_LOST,
    OUT_OF_BOUNDS,
};

typedef struct protochat_state {
    char address[DOMAIN_MAX];
    char name[NAME_MAX];
    char server_name[NAME_MAX];
    int connfd;
    uint16_t port;
    uint8_t name_len;
} pstate_t;

#endif // COMMON_H