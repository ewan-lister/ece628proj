#include "crypto_adaptor.h"

#include <dh.h>
#include <iostream>
#include <openssl/bn.h>
#include <vector>
#include <string>

#include "integer.h"
#include "modes.h"
#include "rsa.h"
#include "osrng.h"
#include "sha.h"
#include "hmac.h"
#include "secblock.h"
#include "ssl_handshake.h"

using namespace std;
using namespace CryptoPP;

static const size_t RSA_KEY_LENGTH = 3072;


int generate_pqg(Integer &p, Integer &q, Integer &g) {
  // 256*4 bit = 1024 bits
  p = Integer("0xB10B8F96A080E01DDE92DE5EAE5D54EC52C99FBCFB06A3C6"
              "9A6A9DCA52D23B616073E28675A23D189838EF1E2EE652C0"
              "13ECB4AEA906112324975C3CD49B83BFACCBDD7D90C4BD70"
              "98488E9C219A73724EFFD6FAE5644738FAA31A4FF55BCCC0"
              "A151AF5F0DC8B4BD45BF37DF365C1A65E68CFDA76D4DA708"
              "DF1FB2BC2E4A4371");

  q = Integer("0xF518AA8781A8DF278ABA4E7D64B7CB9D49462353");    

  g = Integer("0xA4D1CBD5C3FD34126765A442EFB99905F8104DD258AC507F"
              "D6406CFF14266D31266FEA1E5C41564B777E690F5504F213"
              "160217B4B01B886A5E91547F9E2749F4D7FBD7D3B9A92EE1"
              "909D0D2263F80A76A6A24C087A091F531DBF0A0169B6A28A"
              "D662A4D18E73AFA32D779D5918D08BC8858F4DCEF97C2A24"
              "855E6EEB22B3B2E5");

  return 0;
}

int generate_rsa_keys(CryptoPP::RSA::PrivateKey &private_key, CryptoPP::RSA::PublicKey &public_key) {
  AutoSeededRandomPool rnd;
  CryptoPP::RSA::PrivateKey rsa_private_key;
  rsa_private_key.GenerateRandomWithKeySize(rnd, RSA_KEY_LENGTH);
  CryptoPP::RSA::PublicKey rsa_public_key(rsa_private_key);

  private_key = rsa_private_key;
  public_key = rsa_public_key;

  return 0;
}

int aes_encrypt(const unsigned char* key, size_t key_len,
                const unsigned char* mac_key, size_t mac_key_len,
                std::string *cipher_text, const std::string &plain_text,
                const unsigned char* iv, uint64_t seq_num) {
    // 1. Create MAC of the plaintext || sequence number
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(mac_key, mac_key_len);

    // Build authenticated data: seq_num (8 bytes) || content_type (1 byte) ||
    // version (2 bytes) || length (2 bytes) || plaintext
    std::vector<unsigned char> auth_data;
    auth_data.reserve(13 + plain_text.size());

    // Add sequence number (big-endian)
    for (int i = 7; i >= 0; --i) {
        auth_data.push_back((seq_num >> (i * 8)) & 0xFF);
    }

    // Add TLS record header (using application data type and TLS 1.2)
    auth_data.push_back(0x17);  // Application Data
    auth_data.push_back(0x03);  // TLS 1.2 version
    auth_data.push_back(0x03);

    // Add length of plaintext (2 bytes)
    auth_data.push_back((plain_text.size() >> 8) & 0xFF);
    auth_data.push_back(plain_text.size() & 0xFF);

    // Add plaintext
    auth_data.insert(auth_data.end(), plain_text.begin(), plain_text.end());

    // https://www.cryptopp.com/wiki/CBC_Mode
    SecByteBlock aes_key(key, key_len);

    // Create unique IV for each record by XORing with sequence number
    unsigned char record_iv[16];
    memcpy(record_iv, iv, 16);

    for(int i = 0; i < 8; i++) {
        record_iv[8+i] ^= (seq_num >> ((7-i)*8)) & 0xFF;
    }

    try {
        // Calculate MAC
        CryptoPP::SecByteBlock mac(hmac.DigestSize());
        hmac.CalculateDigest(mac, auth_data.data(), auth_data.size());

        CBC_Mode<AES>::Encryption aes_enc;
        aes_enc.SetKeyWithIV(aes_key, aes_key.size(), record_iv);

        std::string input = plain_text;
        input.append(reinterpret_cast<const char*>(mac.data()), mac.size());

        StringSource ss(
          input,
          true,
          new StreamTransformationFilter( aes_enc,
            new StringSink( *cipher_text )
            )
          );
    } catch(const CryptoPP::Exception &e) {
        cerr << e.what() << endl;
        return -1;
    }
    return 0;
}

int aes_decrypt(const unsigned char* key, size_t key_len,
                const unsigned char* mac_key, size_t mac_key_len,
                std::string *plain_text, const std::string &cipher_text,
                const unsigned char* iv, uint64_t seq_num) {
  SecByteBlock aes_key(key, key_len);

  // Create unique IV for each record by XORing with sequence number
  unsigned char record_iv[16];
  memcpy(record_iv, iv, 16);

  for(int i = 0; i < 8; i++) {
    record_iv[8+i] ^= (seq_num >> ((7-i)*8)) & 0xFF;
  }

  try {
    CBC_Mode<AES>::Decryption aes_dec;
    aes_dec.SetKeyWithIV(aes_key, aes_key.size(), record_iv);

    StringSource ss(
      cipher_text,
      true, 
      new StreamTransformationFilter( aes_dec,
        new StringSink( *plain_text )
      )
    );

    // 2. Split decrypted data into plaintext and MAC
    size_t mac_size = CryptoPP::HMAC<CryptoPP::SHA256>().DigestSize();
    if (plain_text->size() < mac_size) {
      cout << "Decrypted data is too short to contain MAC" << endl;
      return -1;
    }

    std::string received_mac = plain_text->substr(plain_text->size() - mac_size);
    *plain_text = plain_text->substr(0, plain_text->size() - mac_size);

    // 3. Verify MAC
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(mac_key, mac_key_len);

    // Rebuild authenticated data
    std::vector<unsigned char> auth_data;
    auth_data.reserve(13 + plain_text->size());

    // Add sequence number
    for (int i = 7; i >= 0; --i) {
        auth_data.push_back((seq_num >> (i * 8)) & 0xFF);
    }

    // Add TLS record header
    auth_data.push_back(0x17);  // Application Data
    auth_data.push_back(0x03);  // TLS 1.2 version
    auth_data.push_back(0x03);

    // Add length
    auth_data.push_back((plain_text->size() >> 8) & 0xFF);
    auth_data.push_back(plain_text->size() & 0xFF);

    // Add plaintext
    auth_data.insert(auth_data.end(), plain_text->begin(), plain_text->end());

    // Calculate and verify MAC
    CryptoPP::SecByteBlock calculated_mac(hmac.DigestSize());
    hmac.CalculateDigest(calculated_mac, auth_data.data(), auth_data.size());

    if (memcmp(calculated_mac, received_mac.data(), mac_size) != 0) {
        cout << "MAC verification failed" << endl;
        return -1; // MAC verification failed
    }
  } catch(const CryptoPP::Exception &e) {
    cout << e.what() << endl;
    return -1;
  }
  return 0;
}

int rsa_encrypt(const CryptoPP::RSA::PublicKey &pub_key,
                std::string *cipher_text, const std::string &plain_text) {

  AutoSeededRandomPool rng;
  const size_t BLOCK_SIZE = (RSA_KEY_LENGTH / 8) - 42;

  try {
    cipher_text->clear(); // Ensure the output is empty

    // Iterate through the plaintext in blocks
    for (size_t offset = 0; offset < plain_text.length(); offset += BLOCK_SIZE) {
      // Extract a block (or remaining bytes if less than BLOCK_SIZE)
      std::string block = plain_text.substr(offset, BLOCK_SIZE);

      std::string encrypted_block;
      RSAES_OAEP_SHA_Encryptor encryptor(pub_key);

      StringSource ss(
        block,
        true,
        new PK_EncryptorFilter(
          rng,
          encryptor,
          new StringSink(encrypted_block)
        )
      );

      // Append the encrypted block to the final cipher text
      *cipher_text += encrypted_block;
    }

  } catch(const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    return -1;
  }

  return 0;
}

int rsa_decrypt(const CryptoPP::RSA::PrivateKey &priv_key,
                std::string *plain_text, const std::string &cipher_text) {

  AutoSeededRandomPool rng;
  size_t BLOCK_SIZE = RSA_KEY_LENGTH / 8;

  try {
    plain_text->clear(); // Ensure the output is empty

    // Iterate through the cipher text in blocks
    for (size_t offset = 0; offset < cipher_text.length(); offset += BLOCK_SIZE) {
      // Extract a block (or remaining bytes if less than BLOCK_SIZE)
      std::string block = cipher_text.substr(offset, BLOCK_SIZE);

      std::string decrypted_block;
      RSAES_OAEP_SHA_Decryptor decryptor(priv_key);

      StringSource ss(
        block,
        true,
        new PK_DecryptorFilter(
          rng,
          decryptor,
          new StringSink(decrypted_block)
        )
      );

      // Append the decrypted block to the final plain text
      *plain_text += decrypted_block;
    }

  } catch(const CryptoPP::Exception &e) {
    cerr << e.what() << endl;
    return -1;
  }

  return 0;

}

CryptoPP::Integer convert_bignum_to_integer(BIGNUM* bn) {
  if (!bn) {
    throw std::runtime_error("Null BIGNUM pointer");
  }

  // Get the number of bytes required to represent the BIGNUM
  int bn_bytes = BN_num_bytes(bn);

  // Allocate buffer
  std::vector<unsigned char> buffer(bn_bytes);

  // Convert BIGNUM to byte array
  BN_bn2bin(bn, buffer.data());

  // Construct Crypto++ Integer from byte array
  return CryptoPP::Integer(buffer.data(), buffer.size());
}

// TLS 1.2 PRF (Pseudorandom Function) using HMAC-SHA256
void TLS12_PRF(
    const CryptoPP::SecByteBlock& secret,
    const std::string& label,
    const CryptoPP::SecByteBlock& seed,
    CryptoPP::SecByteBlock& output,
    size_t output_length
) {
    // Create the actual seed (label + seed)
    CryptoPP::SecByteBlock actual_seed(label.size() + seed.size());
    memcpy(actual_seed, label.data(), label.size());
    memcpy(actual_seed + label.size(), seed.data(), seed.size());

    // A(0) = seed, A(i) = HMAC(secret, A(i-1))
    CryptoPP::SecByteBlock A(actual_seed);
    CryptoPP::SecByteBlock hmac_output;

    // Initialize the output buffer
    output.resize(output_length);
    size_t bytes_generated = 0;

    // Create HMAC with SHA-256
    CryptoPP::HMAC<CryptoPP::SHA256> hmac(secret, secret.size());

    while (bytes_generated < output_length) {
        // Calculate A(i)
        hmac.Update(A.data(), A.size());
        A.resize(hmac.DigestSize());
        hmac.Final(A);

        // Calculate HMAC(secret, A(i) + seed)
        hmac.Update(A.data(), A.size());
        hmac.Update(actual_seed.data(), actual_seed.size());

        CryptoPP::SecByteBlock hmac_result(hmac.DigestSize());
        hmac.Final(hmac_result);

        // Copy as much as needed to the output
        size_t copy_size = std::min(output_length - bytes_generated, hmac_result.size());
        memcpy(output + bytes_generated, hmac_result.data(), copy_size);
        bytes_generated += copy_size;

        // Reset HMAC for next iteration
        hmac.Restart();
    }
}

// TLS 1.2 Key Derivation Function optimized for AES-256
int TLS12_KDF_AES256(
    const CryptoPP::SecByteBlock& premaster_secret,
    const CryptoPP::SecByteBlock& client_random,
    const CryptoPP::SecByteBlock& server_random,
    CryptoPP::SecByteBlock& master_secret,
    CryptoPP::SecByteBlock& client_write_key,
    CryptoPP::SecByteBlock& server_write_key,
    CryptoPP::SecByteBlock& client_mac_key,
    CryptoPP::SecByteBlock& server_mac_key,
    CryptoPP::SecByteBlock& client_write_iv,
    CryptoPP::SecByteBlock& server_write_iv
) {
    try {
        // AES-256 key size is 32 bytes (256 bits)
        const size_t aes256_key_size = 32;

        const size_t mac_key_size = 32;

        // IV size for AES in CBC mode is block size (16 bytes)
        const size_t iv_size = 16;

        // Master secret is always 48 bytes in TLS
        const size_t master_secret_length = 48;
        master_secret.resize(master_secret_length);

        // First, derive the master secret from the premaster secret
        std::string master_label = "master secret";
        CryptoPP::SecByteBlock seed(client_random.size() + server_random.size());
        memcpy(seed, client_random.data(), client_random.size());
        memcpy(seed + client_random.size(), server_random.data(), server_random.size());

        // Call the TLS 1.2 PRF function to generate the master secret
        TLS12_PRF(premaster_secret, master_label, seed, master_secret, master_secret_length);

        // Now derive the key material from the master secret
        std::string key_label = "key expansion";
        CryptoPP::SecByteBlock key_seed(server_random.size() + client_random.size());
        memcpy(key_seed, server_random.data(), server_random.size());
        memcpy(key_seed + server_random.size(), client_random.data(), client_random.size());

        // Total key material needed for AES-256:
        // - Client mac key (32 bytes)
        // - Server mac key (32 bytes)
        // - Client write key (32 bytes)
        // - Server write key (32 bytes)
        // - Client write IV (16 bytes)
        // - Server write IV (16 bytes)
        const size_t key_material_length = 2 * mac_key_size + 2 * aes256_key_size + 2 * iv_size;
        CryptoPP::SecByteBlock key_block(key_material_length);

        // Generate key block
        TLS12_PRF(master_secret, key_label, key_seed, key_block, key_material_length);

        // Extract keys and IVs from key block
        client_write_key.resize(aes256_key_size);
        server_write_key.resize(aes256_key_size);
        client_mac_key.resize(mac_key_size);
        server_mac_key.resize(mac_key_size);
        client_write_iv.resize(iv_size);
        server_write_iv.resize(iv_size);

        size_t offset = 0;

        // Copy client MAC key
        memcpy(client_mac_key, key_block + offset, mac_key_size);
        offset += mac_key_size;

        // Copy server MAC key
        memcpy(server_mac_key, key_block + offset, mac_key_size);
        offset += mac_key_size;

        // Copy client write key (32 bytes for AES-256)
        memcpy(client_write_key, key_block + offset, aes256_key_size);
        offset += aes256_key_size;

        // Copy server write key (32 bytes for AES-256)
        memcpy(server_write_key, key_block + offset, aes256_key_size);
        offset += aes256_key_size;

        // Copy client IV (16 bytes)
        memcpy(client_write_iv, key_block + offset, iv_size);
        offset += iv_size;

        // Copy server IV (16 bytes)
        memcpy(server_write_iv, key_block + offset, iv_size);

        return 0;
    } catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ exception: " << e.what() << std::endl;
        return -1;
    } catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << std::endl;
        return -1;
    }
}

void append_integer(std::vector<unsigned char>& output, const Integer& i) {
    size_t len = i.MinEncodedSize();

    output.push_back((len >> 8) & 0xFF);
    output.push_back(len & 0xFF);

    size_t offset = output.size();
    output.resize(offset + len);

    i.Encode(output.data() + offset, len);
}

int generate_dhe_client_keypair(
    const CryptoPP::Integer p,
    const CryptoPP::Integer g,
    CryptoPP::SecByteBlock& privKey,
    CryptoPP::SecByteBlock& pubKey,
    CryptoPP::DH& dh
) {
    CryptoPP::AutoSeededRandomPool rng;

    // Initialize DH object with server's parameters
    dh.AccessGroupParameters().Initialize(p, g);

    // Generate client's keypair
    privKey.resize(dh.PrivateKeyLength());
    pubKey.resize(dh.PublicKeyLength());
    dh.GenerateKeyPair(rng, privKey, pubKey);

    return 0;
}

std::vector<unsigned char> serialize_dhe_params(
    const CryptoPP::Integer& p,
    const CryptoPP::Integer& g,
    const CryptoPP::SecByteBlock& pubKey
) {
    std::vector<unsigned char> serialized_params;

    // Append p, g
    append_integer(serialized_params, p);
    append_integer(serialized_params, g);

    // Convert public key to Integer and append
    CryptoPP::Integer pub;
    pub.Decode(pubKey.BytePtr(), pubKey.SizeInBytes());
    append_integer(serialized_params, pub);

    return serialized_params;
}

std::vector<unsigned char> generate_dhe_server_key_exchange_signature(
    const char* client_random,
    const char* server_random,
    std::vector<unsigned char> serialized_params,
    const CryptoPP::RSA::PrivateKey server_key
) {
    CryptoPP::AutoSeededRandomPool rng;

    // Create data to be signed
    std::vector<unsigned char> data_to_sign;
    const size_t random_size = 32;
    data_to_sign.reserve(random_size * 2 + serialized_params.size());

    data_to_sign.insert(data_to_sign.end(),
        reinterpret_cast<const unsigned char*>(client_random),
        reinterpret_cast<const unsigned char*>(client_random + random_size));
    data_to_sign.insert(data_to_sign.end(),
        reinterpret_cast<const unsigned char*>(server_random),
        reinterpret_cast<const unsigned char*>(server_random + random_size));
    data_to_sign.insert(data_to_sign.end(),
        serialized_params.begin(), serialized_params.end());

    // Sign the data
    CryptoPP::RSASSA_PKCS1v15_SHA_Signer signer(server_key);
    std::vector<unsigned char> signature(signer.MaxSignatureLength());
    size_t sig_len = signer.SignMessage(
        rng,
        data_to_sign.data(),
        data_to_sign.size(),
        signature.data()
    );
    signature.resize(sig_len);

    return signature;
}

std::vector<unsigned char> generate_dhe_server_key_exchange(
    const char* client_random,
    const char* server_random,
    const CryptoPP::RSA::PrivateKey& server_key,
    CryptoPP::DH*& out_dh,
    SecByteBlock& privKey,
    SecByteBlock& pubKey
) {
    if (!client_random || !server_random) {
        throw std::invalid_argument("Invalid input parameters");
    }

    CryptoPP::AutoSeededRandomPool rng;

    // Create DH object with FFDHE2048 parameters from RFC 7919
    CryptoPP::Integer p, q, g;
    generate_pqg(p, q, g);

    // Initialize DH object with parameters
    out_dh = new CryptoPP::DH();
    out_dh->AccessGroupParameters().Initialize(p, g);

    privKey.resize(out_dh->PrivateKeyLength());
    pubKey.resize(out_dh->PublicKeyLength());
    // Generate ephemeral key pair
    out_dh->GenerateKeyPair(rng, privKey, pubKey);

    // Serialize parameters and public key
    std::vector<unsigned char> serialized_params = serialize_dhe_params(p, g, pubKey);

    std::vector<unsigned char> signature = generate_dhe_server_key_exchange_signature(
        client_random, server_random, serialized_params, server_key
    );

    // Assemble final message
    std::vector<unsigned char> server_key_exchange;
    server_key_exchange.reserve(serialized_params.size() + 4 + signature.size());

    // Add DH parameters
    server_key_exchange.insert(server_key_exchange.end(),
        serialized_params.begin(), serialized_params.end());

    // Add signature algorithm (0x0401 for RSA PKCS#1 + SHA-256)
    server_key_exchange.push_back(0x04);
    server_key_exchange.push_back(0x01);

    // Add signature length and value
    server_key_exchange.push_back((signature.size() >> 8) & 0xFF);
    server_key_exchange.push_back(signature.size() & 0xFF);
    server_key_exchange.insert(server_key_exchange.end(),
        signature.begin(), signature.end());

    return server_key_exchange;
}

int verify_dhe_server_key_exchange_signature(
    const char* client_random,
    const char* server_random,
    const std::vector<unsigned char>& serialized_params,
    const std::vector<unsigned char>& signature,
    const CryptoPP::RSA::PublicKey& server_public_key
) {
    try {
        // Recreate data that was signed
        std::vector<unsigned char> data_to_verify;
        const size_t random_size = 32;
        data_to_verify.reserve(random_size * 2 + serialized_params.size());

        // Add client random and server random
        data_to_verify.insert(data_to_verify.end(),
            reinterpret_cast<const unsigned char*>(client_random),
            reinterpret_cast<const unsigned char*>(client_random + random_size));
        data_to_verify.insert(data_to_verify.end(),
            reinterpret_cast<const unsigned char*>(server_random),
            reinterpret_cast<const unsigned char*>(server_random + random_size));

        // Add serialized DH parameters
        data_to_verify.insert(data_to_verify.end(),
            serialized_params.begin(), serialized_params.end());

        // Create verifier object
        CryptoPP::RSASSA_PKCS1v15_SHA_Verifier verifier(server_public_key);

        // Verify the signature
        return verifier.VerifyMessage(
            data_to_verify.data(),
            data_to_verify.size(),
            signature.data(),
            signature.size()
        ) ? 0 : -1;
    } catch(const CryptoPP::Exception& e) {
        std::cerr << "Signature verification failed: " << e.what() << std::endl;
        return -1;
    }
}