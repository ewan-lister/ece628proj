#ifndef CRYPTO_ADAPTOR_H
#define CRYPTO_ADAPTOR_H

#include <openssl/bn.h>

#include "string.h"

#include "integer.h"
#include "rsa.h"

//////////////////////////////////////////////
// DHE
int generate_pqg(CryptoPP::Integer &p, CryptoPP::Integer &q, CryptoPP::Integer &g);

//////////////////////////////////////////////
// RSA
int generate_rsa_keys(CryptoPP::RSA::PrivateKey &private_key, CryptoPP::RSA::PublicKey &public_key);

//////////////////////////////////////////////
// Encryption
int aes_encrypt(const unsigned char* key, size_t key_len,
                std::string *cipher_text, const std::string &plain_text);

int aes_decrypt(const unsigned char* key, size_t key_len,
                std::string *plain_text, const std::string &cipher_text);

int rsa_encrypt(const CryptoPP::RSA::PublicKey &pub_key,
                std::string *cipher_text, const std::string &plain_text);

int rsa_decrypt(const CryptoPP::RSA::PrivateKey &priv_key,
                std::string *plain_text, const std::string &cipher_text);

int TLS12_KDF_AES256(
    const CryptoPP::SecByteBlock& premaster_secret,
    const CryptoPP::SecByteBlock& client_random,
    const CryptoPP::SecByteBlock& server_random,
    CryptoPP::SecByteBlock& master_secret,
    CryptoPP::SecByteBlock& client_write_key,
    CryptoPP::SecByteBlock& server_write_key,
    CryptoPP::SecByteBlock& client_write_iv,
    CryptoPP::SecByteBlock& server_write_iv
);

CryptoPP::Integer convert_bignum_to_integer(BIGNUM* bn);

#endif // CRYPTO_ADAPTOR_H






