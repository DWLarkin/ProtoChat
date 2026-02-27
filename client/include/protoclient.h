#ifndef PROTOCLIENT_H
#define PROTOCLIENT_H

#include "common.h"

#define IO_BUF_LEN 65535
#define BASE_HDR_LEN 3

void run_client(pstate_t *proto_state);

#endif // PROTOCLIENT_H
