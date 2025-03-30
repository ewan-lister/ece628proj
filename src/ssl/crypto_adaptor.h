#ifndef CRYPTO_ADAPTOR_H
#define CRYPTO_ADAPTOR_H

#include <dh.h>
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

std::vector<unsigned char> serialize_dhe_params(
    const CryptoPP::Integer& p,
    const CryptoPP::Integer& g,
    const CryptoPP::SecByteBlock& pubKey
);

int generate_dhe_client_keypair(
    const CryptoPP::Integer p,
    const CryptoPP::Integer g,
    CryptoPP::SecByteBlock& privKey,
    CryptoPP::SecByteBlock& pubKey,
    CryptoPP::DH& dh
);

std::vector<unsigned char> generate_dhe_server_key_exchange(
    const char* client_random,
    const char* server_random,
    const CryptoPP::RSA::PrivateKey& server_key,
    CryptoPP::DH*& out_dh,
    CryptoPP::SecByteBlock& privKey,
    CryptoPP::SecByteBlock& pubKey
);

int verify_dhe_server_key_exchange_signature(
    const char* client_random,
    const char* server_random,
    const std::vector<unsigned char>& serialized_params,
    const std::vector<unsigned char>& signature,
    const CryptoPP::RSA::PublicKey& server_public_key
);

CryptoPP::Integer convert_bignum_to_integer(BIGNUM* bn);

#endif // CRYPTO_ADAPTOR_H






