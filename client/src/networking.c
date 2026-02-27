#include "networking.h"
#include "input_output.h"

#include <assert.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

void push_short(void *buf, uint16_t val) {
    assert(NULL != buf);

    uint8_t *byte_buf = buf;

    byte_buf[0] = (uint8_t)(val >> 8);
    byte_buf[1] = (uint8_t)(val & 0xFF);
}

uint16_t pop_short(void *buf) {
    assert(NULL != buf);

    uint16_t ret = 0;
    uint8_t *byte_buf = buf;

    ret |= (uint16_t)byte_buf[0] << 8;
    ret |= (uint16_t)byte_buf[1];

    return ret;
}

int send_all(int sockfd, void *buf, size_t len) {
    assert(0 <= sockfd);
    assert(NULL != buf);

    size_t total_sent = 0;
    uint8_t *byte_buf = buf;

    if (0 == len) {
        return 0;
    }

    while (total_sent < len) {
        size_t to_send =
            ((len - total_sent) > SEND_MAX) ? SEND_MAX : len - total_sent;

        ssize_t send_ret = send(sockfd, &byte_buf[total_sent], to_send, 0);
        if (0 >= send_ret) {
            debug_print("Send failed\n");
            return -1;
        }

        total_sent += send_ret;
    }

    return 0;
}

int recv_all(int sockfd, void *buf, size_t len) {
    assert(0 <= sockfd);
    assert(NULL != buf);

    size_t total_received = 0;
    uint8_t *byte_buf = buf;

    if (0 == len) {
        return 0;
    }

    while (total_received < len) {
        size_t to_recv = ((len - total_received) > SEND_MAX)
                             ? SEND_MAX
                             : len - total_received;

        ssize_t recv_ret = recv(sockfd, &byte_buf[total_received], to_recv, 0);
        if (0 >= recv_ret) {
            debug_print("Recv failed\n");
            return -1;
        }

        total_received += recv_ret;
    }

    return 0;
}

int create_connection(struct addrinfo *current_addr) {
    assert(NULL != current_addr);

    int sockfd = socket(current_addr->ai_family, current_addr->ai_socktype,
                        current_addr->ai_protocol);
    if (0 > sockfd) {
        debug_print("Socket call failed\n");
        return -1;
    }

    if (0 != connect(sockfd, current_addr->ai_addr, current_addr->ai_addrlen)) {
        debug_print("Connect call failed\n");
        (void)close(sockfd);
        return -1;
    }

    return sockfd;
}

int attempt_addresses(pstate_t *proto_state) {
    assert(NULL != proto_state);

    char str_port[(PORT_DIGITS + 1)] = {0};
    struct addrinfo hints = {0};
    struct addrinfo *res = NULL;
    struct addrinfo *addriter = NULL;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (0 > snprintf(str_port, sizeof(str_port), "%hu", proto_state->port)) {
        debug_print("Unexpected error with stringifying port.\n");
        return -1;
    }

    int status = getaddrinfo(proto_state->address, str_port, &hints, &res);
    if (0 != status) {
        display_output("\nFailed to resolve address.\n");
        debug_print("GAI error: %s\n", gai_strerror(status));
        return -1;
    }

    display_output("\nAttempting to connect... ");

    for (addriter = res; addriter != NULL; addriter = addriter->ai_next) {
        switch (addriter->ai_family) {
        case AF_INET:
        case AF_INET6: {
            proto_state->connfd = create_connection(addriter);
            if (0 <= proto_state->connfd) {
                display_output("connection established!\n");
                freeaddrinfo(res);
                return 0;
            }

            break;
        }
        // Skip if anything not IP shows up (somehow).
        default: {
            break;
        }
        }
    }

    freeaddrinfo(res);

    display_output("\nFailed to make any connection.\n");

    return -1;
}

int greet_server(pstate_t *proto_state) {
    assert(NULL != proto_state);

    uint8_t ack_buffer[GREET_BUF_LEN];
    uint8_t buffer[GREET_BUF_LEN];

    buffer[0] = CLIENT_HELLO;
    buffer[1] = proto_state->name_len;

    if (0 >= snprintf((char *)(&buffer[HELLO_HDR_LEN]), NAME_MAX, "%s",
                      proto_state->name)) {
        debug_print("Snprintf failed\n");
        close(proto_state->connfd);
        return -1;
    }

    display_output("\nSending client hello... ");

    if (0 != send_all(proto_state->connfd, buffer,
                      (proto_state->name_len + HELLO_HDR_LEN))) {
        close(proto_state->connfd);
        return -1;
    }

    // Ack should mirror the greeting with server/group name.
    if (0 != recv_all(proto_state->connfd, ack_buffer, HELLO_HDR_LEN)) {
        close(proto_state->connfd);
        return -1;
    }

    if (SERVER_ACK != ack_buffer[0]) {
        close(proto_state->connfd);
        return -1;
    }

    if (0 != recv_all(proto_state->connfd, &ack_buffer[HELLO_HDR_LEN],
                      ack_buffer[1])) {
        close(proto_state->connfd);
        return -1;
    }

    (void)memcpy(proto_state->server_name, &ack_buffer[HELLO_HDR_LEN],
                 ack_buffer[1]);

    return 0;
}
