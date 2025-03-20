#ifndef SSL_HANDSHAKE_H
#define SSL_HANDSHAKE_H

#include "string.h"
#include "ssl_client.h"


#include "integer.h"
#include "ssl.h"

void generate_random(char*& random);

int send_hello(SSL* client, char* random);

int recv_hello(SSL* server, char*& client_random);

#endif //SSL_HANDSHAKE_H