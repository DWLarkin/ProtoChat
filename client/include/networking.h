#ifndef NETWORKING_H
#define NETWORKING_H

#include "common.h"

#include <netdb.h>

#define SEND_MAX 4096

void push_short(void *buf, uint16_t val);
uint16_t pop_short(void *buf);
int send_all(int sockfd, void *buf, size_t len);
int recv_all(int sockfd, void *buf, size_t len);
int create_connection(struct addrinfo *current_addr);
int attempt_addresses(pstate_t *proto_state);
int greet_server(pstate_t *proto_state);

#endif // NETWORKING_H
