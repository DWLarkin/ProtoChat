#include "protoclient.h"

#include "input_output.h"
#include "networking.h"

#include <assert.h>
#include <errno.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <unistd.h>

void handle_new_client(pstate_t *proto_state, char *io_buffer) {
    char *chatter_name = &io_buffer[(BASE_HDR_LEN + sizeof(uint8_t))];

    display_output("%s has joined the chat.\n\n", chatter_name);
}

void handle_chat_message(pstate_t *proto_state, char *io_buffer) {
    uint8_t name_len = io_buffer[BASE_HDR_LEN];
    char *chatter_name = &io_buffer[(BASE_HDR_LEN + sizeof(name_len))];
    char *msg = &io_buffer[(BASE_HDR_LEN + sizeof(name_len) + name_len)];

    display_output("%s:\n%s\n\n", chatter_name, msg);
}

void handle_disconnect_message(pstate_t *proto_state, char *io_buffer) {
    char *chatter_name = &io_buffer[(BASE_HDR_LEN + sizeof(uint8_t))];

    display_output("%s has disconnected.\n\n", chatter_name);
}

void handle_lost_message(pstate_t *proto_state, char *io_buffer) {
    char *chatter_name = &io_buffer[(BASE_HDR_LEN + sizeof(uint8_t))];

    display_output("%s lost connection.\n\n", chatter_name);
}

int get_messages(pstate_t *proto_state, char *io_buffer) {
    assert(NULL != proto_state);
    assert(NULL != io_buffer);

    while (1) {
        // Recv basic task header
        fd_set rfds;
        struct timeval tv = {0, 1000}; // 1 ms

        FD_ZERO(&rfds);
        FD_SET(proto_state->connfd, &rfds);

        // Zero input before we print out messages.
        (void)memset(io_buffer, 0, IO_BUF_LEN);

        // Guarantee there is at least one packet before we block on recv
        int select_ret =
            select(proto_state->connfd + 1, &rfds, NULL, NULL, &tv);
        if (0 > select_ret) {
            return -1;
        }
        if (0 == select_ret) {
            break;
        }

        if (0 != recv_all(proto_state->connfd, io_buffer, BASE_HDR_LEN)) {
            return -1;
        }

        uint8_t task_code = io_buffer[0];
        uint16_t data_len = pop_short(&io_buffer[1]);

        if (0 !=
            recv_all(proto_state->connfd, &io_buffer[BASE_HDR_LEN], data_len)) {
            return -1;
        }

        switch (task_code) {
        case CLIENT_HELLO: {
            handle_new_client(proto_state, io_buffer);
            break;
        }
        case CHAT_MESSAGE: {
            handle_chat_message(proto_state, io_buffer);
            break;
        }
        case CLIENT_DISCONNECT: {
            handle_disconnect_message(proto_state, io_buffer);
            break;
        }
        case CLIENT_LOST: {
            handle_lost_message(proto_state, io_buffer);
            break;
        }
        default: {
            display_output("\nGot bad task code from server.\n");
            return -1;
        }
        }
    }

    return 0;
}

int send_current_message(pstate_t *proto_state, char *io_buffer,
                         const uint16_t msg_index) {
    assert(NULL != proto_state);
    assert(NULL != io_buffer);

    size_t msg_len = strlen(&io_buffer[msg_index]);
    size_t to_send = BASE_HDR_LEN + sizeof(proto_state->name_len) +
                     proto_state->name_len + msg_len;

    io_buffer[0] = CHAT_MESSAGE;
    push_short(&io_buffer[1], to_send - BASE_HDR_LEN);
    io_buffer[3] = proto_state->name_len;
    (void)memcpy(&io_buffer[4], proto_state->name, proto_state->name_len);

    return send_all(proto_state->connfd, io_buffer, to_send);
}

void send_disconnect(pstate_t *proto_state, char *io_buffer) {
    assert(NULL != proto_state);
    assert(NULL != io_buffer);

    memset(io_buffer, 0, IO_BUF_LEN);
    uint16_t data_len = sizeof(proto_state->name_len) + proto_state->name_len;

    io_buffer[0] = CLIENT_DISCONNECT;
    push_short(&io_buffer[1], data_len);
    io_buffer[BASE_HDR_LEN] = proto_state->name_len;
    memcpy(&io_buffer[(BASE_HDR_LEN + sizeof(proto_state->name_len))],
           proto_state->name, proto_state->name_len);

    // We're disconnecting anyway so w/e
    (void)send_all(proto_state->connfd, io_buffer, (BASE_HDR_LEN + data_len));
}

void run_client(pstate_t *proto_state) {
    assert(NULL != proto_state);

    const uint16_t msg_index =
        BASE_HDR_LEN + sizeof(proto_state->name_len) + proto_state->name_len;
    const uint16_t max_input = IO_BUF_LEN - msg_index;

    // TODO: Make networking + IO async and remove refresh command.
    char *io_buffer = malloc(IO_BUF_LEN);
    if (NULL == io_buffer) {
        return;
    }

    while (1) {
        ssize_t input_ret = get_input_line(&io_buffer[msg_index], max_input);
        if (0 > input_ret) {
            display_output("\n\tMessage has too many characters.\n");
            continue;
        }
        if (0 == input_ret) {
            continue;
        }

        // Create a little spacer.
        display_output("\n");

        if (0 == strcmp(&io_buffer[msg_index], "/quit")) {
            send_disconnect(proto_state, io_buffer);
            break;
        }
        if (0 == strcmp(&io_buffer[msg_index], "/refresh")) {
            if (0 != get_messages(proto_state, io_buffer)) {
                break;
            }
            continue;
        }

        if (0 != send_current_message(proto_state, io_buffer, msg_index)) {
            break;
        }

        if (0 != get_messages(proto_state, io_buffer)) {
            break;
        }
    }

    memset(io_buffer, 0, IO_BUF_LEN);
    free(io_buffer);

    (void)close(proto_state->connfd);
}
