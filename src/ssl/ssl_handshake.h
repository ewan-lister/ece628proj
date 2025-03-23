#ifndef SSL_HANDSHAKE_H
#define SSL_HANDSHAKE_H

#include "string.h"
#include "ssl_client.h"
#include <rsa.h>

#include <openssl/evp.h>

#include "integer.h"
#include "ssl.h"

void save_rsa_private_key(CryptoPP::RSA::PrivateKey private_key, std::string private_key_file);

EVP_PKEY* load_crypto_rsa_key(const std::string& privKeyFile);

void generate_self_signed_cert(const char* privKeyFile, const char* certFile);

int read_cert_file(char*& cert_contents, const std::string& file_path);

void generate_random(char*& random);

int send_client_hello(Ssl* client, char* random);

int send_server_hello(Ssl* client, char* random);

int send_cert(Ssl* client, char* cert);

int recv_data(Ssl* server, char*& data, const uint8_t type, const uint16_t version);

int recv_client_hello(Ssl* server, char*& data);

int recv_server_hello(Ssl* server, char*& data);

int recv_cert(Ssl* server, char*& data);

#endif //SSL_HANDSHAKE_H