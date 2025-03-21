#define CERT_EXPIRY_DAYS 365  // 1 year validity

#include "stdlib.h"
#include "string.h"
#include "integer.h"

#include <iostream>
#include <fstream>
#include <iomanip>
#include <ctime>
#include <cryptlib.h>
#include <osrng.h>
#include <files.h>
#include <rsa.h>

#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/asn1.h>
#include <openssl/bn.h>
#include <openssl/evp.h>

#include "ssl_client.h"
#include "ssl.h"

using namespace std;

// Function to generate RSA keys using Crypto++
void generate_rsa_key(std::string privKeyFile, std::string pubKeyFile) {
    CryptoPP::AutoSeededRandomPool rng;

    // Generate 2048-bit RSA key pair
    CryptoPP::RSA::PrivateKey privateKey;
    privateKey.GenerateRandomWithKeySize(rng, 2048);

    CryptoPP::RSA::PublicKey publicKey;
    publicKey.AssignFrom(privateKey);

    // Save the private key in PEM format
    CryptoPP::FileSink privFile(privKeyFile.c_str());
    privateKey.Save(privFile);

    // Save the public key in PEM format
    CryptoPP::FileSink pubFile(pubKeyFile.c_str());
    publicKey.Save(pubFile);
}

// Function to load Crypto++ RSA key into OpenSSL EVP_PKEY format
EVP_PKEY* load_crypto_rsa_key(const std::string& privKeyFile) {
    FILE* file = fopen(privKeyFile.c_str(), "rb");
    if (!file) {
        std::cerr << "Error opening private key file: " << privKeyFile << std::endl;
        return nullptr;
    }

    EVP_PKEY* pkey = PEM_read_PrivateKey(file, nullptr, nullptr, nullptr);
    fclose(file);

    return pkey;
}

// Function to generate a self-signed certificate
void generate_self_signed_cert(const char* privKeyFile, const char* certFile) {
    EVP_PKEY* pkey = load_crypto_rsa_key(privKeyFile);
    if (!pkey) {
        std::cerr << "Failed to load private key.\n";
        return;
    }

    // Create X.509 certificate
    X509* x509 = X509_new();
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 60L * 60L * 24L * CERT_EXPIRY_DAYS);

    X509_set_pubkey(x509, pkey);

    // Set subject name
    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)"My Company", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"localhost", -1, -1, 0);

    X509_set_issuer_name(x509, name);  // Self-signed

    // Sign certificate with private key
    X509_sign(x509, pkey, EVP_sha256());

    // Write certificate to file
    FILE* cert_file = fopen(certFile, "wb");
    PEM_write_X509(cert_file, x509);
    fclose(cert_file);

    // Cleanup
    EVP_PKEY_free(pkey);
    X509_free(x509);
}

void generate_random(char*& random) {
    byte temp[32];
    // UNIX timestamp (4 bytes)
    std::time_t currentTime = std::time(nullptr);
    temp[0] = (currentTime >> 24) & 0xFF;
    temp[1] = (currentTime >> 16) & 0xFF;
    temp[2] = (currentTime >> 8) & 0xFF;
    temp[3] = currentTime & 0xFF;

    // 28 secure random bytes
    CryptoPP::AutoSeededRandomPool rng;
    rng.GenerateBlock(temp + 4, 28); // Fill remaining 28 bytes

    int size = sizeof(temp);
    random = (char*)malloc(size+1);
    memcpy(random, temp, size);
}

int send_hello(Ssl* client, char* random) {
    Ssl::Record send_record;
    send_record.hdr.type = Ssl::HS_CLIENT_HELLO;
    send_record.hdr.version = Ssl::VER_99;
    // string client_hello = "Client hello";
    // char* data = (char*)malloc(client_hello.length()*sizeof(char));
    // Replace client_hello with random
    // memcpy(data, client_hello.c_str(), client_hello.length());
    send_record.data = random;
    
    // send
    if(client->send(send_record) != 0) {
      // free(send_record.data);
      return -1;
    }
    
    // free(send_record.data);
    return 0;
}

int recv_hello(Ssl* server, char*& client_random) { 
    // receive record
    Ssl::Record recv_record;
    if ( server->recv(&recv_record) == -1 ) {
      cerr << "Couldn't receive." << endl;
      return -1;
    }
  
    // check type
    if (recv_record.hdr.type != Ssl::HS_CLIENT_HELLO) {
      cerr << "Not client Hello." << endl;
      return -1;
    }
  
    // check version
    if (recv_record.hdr.version != Ssl::VER_99) {
      cerr << "Not VER_99." << endl;
      return -1;
    }
  
    client_random = (char*)malloc(recv_record.hdr.length);
    memcpy(client_random, recv_record.data, recv_record.hdr.length);
    cout << "Received: " << client_random << endl;
  
    return 0;
}