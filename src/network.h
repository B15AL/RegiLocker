#ifndef NETWORK_H
#define NETWORK_H

/* Create a listening TCP socket bound to addr:port. Returns fd or -1. */
int network_listen(const char *addr, int port);

/* Serve one client request on fd (caller closes fd). */
void network_handle_client(int fd);

#endif
