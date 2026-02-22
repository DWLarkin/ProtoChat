#include "protochat.h"

#include <assert.h>
#include <errno.h>
#include <limits.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <unistd.h>

/**
 * @brief Displays some string output to the user.
 * 
 * @param[in] fmt The format string to pass on to the output mechanism.
 * @param[in] args Any arguments corresponding to the format string.
 * 
 * @todo This is a simple print wrapper atm, will probably change later with ncurses.
 */
void display_output(const char *fmt, ...) {
    va_list args;

    va_start(args, fmt);
    (void)vprintf(fmt, args);
    va_end(args);
}

/**
 * @brief Flushes stdin.
 * 
 * @returns 0 on success, non-zero on error.
 * 
 * @todo Rework when error codes are available later.
 */
int flush_stdin(void) {
    char flush_buffer[FLUSH_BUF_LEN];

    do {
        if (NULL == fgets(flush_buffer, sizeof(flush_buffer), stdin)) {
            return -1;
        }

        char *fgets_newline = strrchr(flush_buffer, '\n');
        if (NULL == fgets_newline) {
            continue;
        }

        break;
    } while(1);

    return 0;
}

/**
 * @brief Gets a single line of input from the user.
 * 
 * @param[out] input_buffer The buffer to store the incoming input in.
 * @param[in] max_len The length of the buffer.
 * 
 * @todo This will probably need some expansion/redesign later for ncurses + input variety.
 */
ssize_t get_input_line(char *input_buffer, size_t max_len) {
    assert(NULL != input_buffer);

    // Constraining max_len for now to conform to fgets.
    if (max_len > INT_MAX) {
        debug_print("Max_len exceeded integer max\n");
        return -1;
    }

    if (NULL == fgets(input_buffer, (int)max_len, stdin)) {
        debug_print("Fgets call failed\n");
        return -1;
    }

    char *fgets_newline = strrchr(input_buffer, '\n');
    if (NULL == fgets_newline) {
        // TODO: Rewrite this a bit when error codes exist.
        (void)flush_stdin();

        return -1;
    }
    *fgets_newline = '\0';

    size_t current_len = strnlen(input_buffer, max_len);
    if (current_len >= max_len) {
        debug_print("Unexpected failure occurred with strnlen\n");
        return -1;
    }

    // Since we're currently constraining max_len to int, this cast always works.
    return (ssize_t)current_len;
}

int send_all(int sockfd, void *buf, size_t len) {
    size_t total_sent = 0;

    while (total_sent < len) {
        size_t to_send = ((len - total_sent) > SEND_MAX) ? SEND_MAX : len - total_sent;

        ssize_t send_ret = send(sockfd, buf, to_send, 0);
        if (0 >= send_ret) {
            debug_print("Send failed\n");
            return -1;
        }

        total_sent += send_ret;
    }

    return 0;
}

int recv_all(int sockfd, void *buf, size_t len) {
    size_t total_received = 0;

    while (total_received < len) {
        size_t to_recv = ((len - total_received) > SEND_MAX) ? SEND_MAX : len - total_received;

        ssize_t recv_ret = recv(sockfd, buf, to_recv, 0);
        if (0 >= recv_ret) {
            debug_print("Send failed\n");
            return -1;
        }

        total_received += recv_ret;
    }

    return 0;
}

/**
 * @brief Gets an address or domain name to connect to via user input.
 * 
 * @param[out] proto_state The state struct to update with gathered input.
 * 
 * @returns 0 on success, non-zero on failure.
 */
int get_address(pstate_t *proto_state) {
    char response_buffer[YN_RESP_LEN]; // For the confirmation prompt.

    while (1) {
        display_output("\nPlease enter an IPv4 address or domain name to connect to: ");

        ssize_t input_ret = get_input_line(proto_state->address, DOMAIN_MAX);
        if (0 > input_ret) {
            display_output("\tAddress or domain is too long, you're only allotted up to 4095 characters.\n");
            continue;
        }
        else if (0 == input_ret) {
            display_output("\tA valid address or domain must be entered.\n");
            continue;
        }

        display_output("\tThe address you entered is \"%s\". Is this correct? [y/N]: ", proto_state->address);

        input_ret = get_input_line(response_buffer, YN_RESP_LEN);
        if (1 != input_ret) {
            continue;
        }
        if (0 == strncmp(response_buffer, "y", 2)) {
            break;
        }
    }

    return 0;
}

int convert_port(pstate_t *proto_state, char *port_buffer) {
    char *check_ptr = NULL;

    unsigned long converted_val = strtoul(port_buffer, &check_ptr, 0);
    if (ERANGE == errno || EINVAL == errno) {
        return -1;
    }

    if (NULL == check_ptr || *check_ptr != '\0') {
        return -1;
    }

    if (UINT16_MAX < converted_val || 0 == converted_val) {
        return -1;
    }

    proto_state->port = (uint16_t)converted_val;

    return 0;
}

int get_port(pstate_t *proto_state) {
    char port_buffer[(PORT_DIGITS + 2)]; // For the stringified port.

    while (1) {
        display_output("\nPlease enter a valid port for the address: ");

        ssize_t input_ret = get_input_line(port_buffer, sizeof(port_buffer));
        if (0 > input_ret) {
            display_output("\tToo much input, enter no more than 5 digits.\n");
            continue;
        }
        if (0 == input_ret) {
            display_output("\tA valid port must be entered.\n");
            continue;
        }

        if (0 != convert_port(proto_state, port_buffer)) {
            display_output("\tPort number must be valid (in range 1-65535).\n");
            continue;
        }

        display_output("\tThe port is configured to %hu.\n", proto_state->port);

        break;
    }

    return 0;
}

int get_name(pstate_t *proto_state) {
    while (1) {
        display_output("\nLastly, what would you like your name to be? ");

        ssize_t input_ret = get_input_line(proto_state->name, sizeof(proto_state->name));
        if (0 > input_ret) {
            display_output("\tName has too many character (limit is 255).\n");
            continue;
        }
        if (0 == input_ret) {
            display_output("\tName must have at least one character.\n");
            continue;
        }

        proto_state->name_len = (uint8_t)input_ret;

        display_output("\tName is configured as %s.\n", proto_state->name);

        break;
    }

    return 0;
}

int create_connection(struct addrinfo *current_addr) {
    int sockfd = socket(current_addr->ai_family, current_addr->ai_socktype, current_addr->ai_protocol);
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
    uint8_t ack_buffer[GREET_BUF_LEN];
    uint8_t buffer[GREET_BUF_LEN];

    buffer[0] = CLIENT_HELLO;
    buffer[1] = proto_state->name_len;

    if (0 >= snprintf((char *)(&buffer[1]), (GREET_BUF_LEN - 2), "%s", proto_state->name)) {
        debug_print("Snprintf failed\n");
        close(proto_state->connfd);
        return -1;
    }

    display_output("\nSending client hello... ");

    if (0 != send_all(proto_state->connfd, buffer, (proto_state->name_len + 2))) {
        close(proto_state->connfd);
        return -1;
    }

    // Ack should mirror the greeting, just with a SERVER_ACK code.
    if (0 != recv_all(proto_state->connfd, ack_buffer, 2)) {
        close(proto_state->connfd);
        return -1;
    }

    if (SERVER_ACK != ack_buffer[0] || proto_state->name_len != ack_buffer[1]) {
        close(proto_state->connfd);
        return -1;
    }

    if (0 != recv_all(proto_state->connfd, &ack_buffer[2], proto_state->name_len)
        || 0 != memcmp(&ack_buffer[2], proto_state->name, proto_state->name_len)) {
        close(proto_state->connfd);
        return -1;
    }

    return 0;
}

/**
 * @brief Gets user input for basic client configuration + connection info.
 * 
 * @param[out] proto_state The state struct to update with gathered input.
 * 
 * @returns 0 on success, non-zero on error.
 */
int proto_setup(pstate_t *proto_state) {
    display_output(
        KONATA_ART
        "            Welcome to ProtoChat!\n\n"
        "Note: The program setup may be terminated at any time by Ctrl+C!\n"
    );

    if (0 != get_address(proto_state)) {
        return 1;
    }

    if (0 != get_port(proto_state)) {
        return 1;
    }

    if (0 != get_name(proto_state)) {
        return 1;
    }

    if (0 != attempt_addresses(proto_state)) {
        return 1;
    }

    if (0 != greet_server(proto_state)) {
        display_output("failed to exchange client hello.\n");
        return 1;
    }

    display_output("client hello successful!\n\n");

    return 0;
}
