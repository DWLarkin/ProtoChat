#include "input_output.h"

#include <assert.h>
#include <limits.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief Displays some string output to the user.
 *
 * @param[in] fmt The format string to pass on to the output mechanism.
 * @param[in] args Any arguments corresponding to the format string.
 *
 * @todo This is a simple print wrapper atm, will probably change later with
 * ncurses.
 */
void display_output(const char *fmt, ...) {
    assert(NULL != fmt);

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
    } while (1);

    return 0;
}

/**
 * @brief Gets a single line of input from the user.
 *
 * @param[out] input_buffer The buffer to store the incoming input in.
 * @param[in] max_len The length of the buffer.
 *
 * @todo This will probably need some expansion/redesign later for ncurses +
 * input variety.
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

    // Since we're currently constraining max_len to int, this cast always
    // works.
    return (ssize_t)current_len;
}
