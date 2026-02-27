#include "setup.h"

#include "input_output.h"
#include "networking.h"

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/**
 * @brief Gets an address or domain name to connect to via user input.
 *
 * @param[out] proto_state The state struct to update with gathered input.
 *
 * @returns 0 on success, non-zero on failure.
 */
int get_address(pstate_t *proto_state) {
    assert(NULL != proto_state);

    char response_buffer[YN_RESP_LEN]; // For the confirmation prompt.

    while (1) {
        display_output(
            "\nPlease enter an IPv4 address or domain name to connect to: ");

        ssize_t input_ret = get_input_line(proto_state->address, DOMAIN_MAX);
        if (0 > input_ret) {
            display_output(
                "\tAddress or domain is too long, you're only allotted up "
                "to 4095 characters.\n");
            continue;
        } else if (0 == input_ret) {
            display_output("\tA valid address or domain must be entered.\n");
            continue;
        }

        display_output(
            "\tThe address you entered is \"%s\". Is this correct? [y/N]: ",
            proto_state->address);

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
    assert(NULL != proto_state);
    assert(NULL != port_buffer);

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
    assert(NULL != proto_state);

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
    assert(NULL != proto_state);

    while (1) {
        display_output("\nLastly, what would you like your name to be? ");

        ssize_t input_ret =
            get_input_line(proto_state->name, sizeof(proto_state->name));
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

/**
 * @brief Gets user input for basic client configuration + connection info.
 *
 * @param[out] proto_state The state struct to update with gathered input.
 *
 * @returns 0 on success, non-zero on error.
 */
int proto_setup(pstate_t *proto_state) {
    assert(NULL != proto_state);

    display_output(
        KONATA_ART
        "            Welcome to ProtoChat!\n\n"
        "Note: The program setup may be terminated at any time by Ctrl+C!\n");

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

    display_output("client hello successful!\n" DISPLAY_DELIMITER
                   "Welcome to %s!\n\n"
                   "NOTE: basic commands available "
                   "are:\n/quit\n/refresh\n" DISPLAY_DELIMITER,
                   proto_state->server_name);

    return 0;
}
