#ifndef INPUT_OUTPUT_H
#define INPUT_OUTPUT_H

#include "common.h"

#include <unistd.h>

#define FLUSH_BUF_LEN 4096

void display_output(const char *fmt, ...);
ssize_t get_input_line(char *input_buffer, size_t max_len);

#endif // INPUT_OUTPUT_H
