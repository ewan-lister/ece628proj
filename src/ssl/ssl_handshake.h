#ifndef SSL_HANDSHAKE_H
#define SSL_HANDSHAKE_H

#include "string.h"
#include "ssl_client.h"

#include <openssl/evp.h>

#include "integer.h"
#include "ssl.h"

void generate_rsa_key(std::string privKeyFile, std::string pubKeyFile);

EVP_PKEY* load_crypto_rsa_key(const std::string& privKeyFile);

void generate_self_signed_cert(const char* privKeyFile, const char* certFile);

void generate_random(char*& random);

int send_hello(Ssl* client, char* random);

int recv_hello(Ssl* server, char*& client_random);

#endif //SSL_HANDSHAKE_H