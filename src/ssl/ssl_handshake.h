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

int load_and_verify_certificate(char*& certificate, CryptoPP::RSA::PublicKey& cryptopp_key);

int send_record(Ssl* cnx, uint8_t type, uint16_t version, char* data, size_t length);

int send_client_hello(Ssl* cnx, char* random, size_t length);

int send_client_key_exchange(Ssl* cnx, char*& data, size_t length);

int send_server_hello(Ssl* cnx, char* random, size_t length);

int send_cert(Ssl* cnx, char* cert);

int recv_data(Ssl* cnx, char*& data, const uint8_t type, const uint16_t version);

int recv_client_hello(Ssl* cnx, char*& data);

int recv_server_hello(Ssl* cnx, char*& data);

int recv_client_key_exchange(Ssl* cnx, char*& data);

int recv_cert(Ssl* cnx, char*& data);

int recv_server_hello_done(Ssl* cnx, char* data);

// Message packing
size_t store_byte_at_offset(char* buffer, size_t offset, uint8_t value);

int pack_client_key_exchange(char*& buffer, const char* pre_master_secret, size_t length);

int unpack_client_key_exchange(char* buffer, char*& data);

int pack_client_hello(
    char*& buffer,
    uint16_t version,
    char* random,
    std::vector<uint8_t>& cipher_suites
);

int unpack_client_hello(
    const char* buffer,
    uint16_t& version,
    char* random,
    std::vector<uint8_t>& cipher_suites
);

int pack_server_hello(
    char*& buffer,
    uint16_t version,
    char* random,      // 32 bytes
    uint8_t selected_suite
);

int unpack_server_hello(
    const char* buffer,
    uint16_t& version,
    char* random,
    uint8_t& selected_suite
);

int pack_client_key_exchange(char*& buffer, const char* pre_master_secret, size_t length);

void print_buffer_hex(char* buffer, size_t length);

int generate_premaster_secret(std::string& premaster_secret);

void printRSAPublicKey(const CryptoPP::RSA::PublicKey& key);

#endif //SSL_HANDSHAKE_H