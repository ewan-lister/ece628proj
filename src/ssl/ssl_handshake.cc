#define CERT_EXPIRY_DAYS 365  // 1 year validity

#include "ssl_handshake.h"

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

void save_rsa_private_key(CryptoPP::RSA::PrivateKey private_key, std::string private_key_file) {
  CryptoPP::FileSink privFile(private_key_file.c_str());
  private_key.Save(privFile);
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

    cout << "Private key ptr: " << pkey << endl;

    return pkey;
}

int read_cert_file(char*& cert_contents, const string& file_path) {
    // Open the certificate file
    FILE* cert_file = fopen(file_path.c_str(), "r");
    if (!cert_file) {
        std::cerr << "Error: Could not open certificate file: " << file_path << std::endl;
        return -1;
    }

    // Load the certificate into an X509 structure
    X509* cert = PEM_read_X509(cert_file, nullptr, nullptr, nullptr);
    fclose(cert_file);

    if (!cert) {
        std::cerr << "Error: Could not load certificate." << std::endl;
        return -1;
    }

    // Convert X509 to a memory BIO
    BIO* mem = BIO_new(BIO_s_mem());
    if (!PEM_write_bio_X509(mem, cert)) {
        std::cerr << "Error: Could not write certificate to BIO." << std::endl;
        X509_free(cert);
        BIO_free(mem);
        return -1;
    }

    // Get the length of the data and copy it into a char*
    char* cert_buffer;
    long cert_len = BIO_get_mem_data(mem, &cert_buffer);

    // Allocate memory for the content (since BIO_get_mem_data does not return a null-terminated string)
    cert_contents = static_cast<char *>(malloc(cert_len + 1));
    memcpy(cert_contents, cert_buffer, cert_len);
    cert_contents[cert_len] = '\0'; // Null-terminate

    // Free resources
    BIO_free(mem);
    X509_free(cert);

    return 0;
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
    if ( !PEM_write_X509(cert_file, x509)) {
        cerr << "Error writing certificate to file." << endl;
    }
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

int send_record(Ssl* client, uint8_t type, uint16_t version, char* data) {
    Ssl::Record send_record;
    send_record.hdr.type = type;
    send_record.hdr.version = version;
    if (data != nullptr) {
        send_record.hdr.length = strlen(data);
        send_record.data = data;
    } else {
        send_record.hdr.length = 0;
        send_record.data = data;
    }

    // send
    if(client->send(send_record) != 0) {
        return -1;
    }

    return 0;
}

int send_client_hello(Ssl* client, char* random) {
    return send_record(client, Ssl::HS_CLIENT_HELLO, Ssl::VER_99, random);
}

int send_server_hello(Ssl* client, char* random) {
    return send_record(client, Ssl::HS_SERVER_HELLO, Ssl::VER_99, random);
}

int send_cert(Ssl* client, char* cert) {
    return send_record(client, Ssl::HS_CERTIFICATE, Ssl::VER_99, cert);
}

int send_cert_request(Ssl* client) {
    return send_record(client, Ssl::HS_CERTIFICATE_REQUEST, Ssl::VER_99, nullptr);
}

int recv_data(Ssl* server, char*& data,const uint8_t type,const uint16_t version) {
    // receive record
    Ssl::Record recv_record;
    if ( server->recv(&recv_record) == -1 ) {
        cerr << "Couldn't receive." << endl;
        return -1;
    }

    // check type
    if (recv_record.hdr.type != type) {
        cerr << "Wrong message type" << endl;
        return -1;
    }

    // check version
    if (recv_record.hdr.version != version) {
        cerr << "Wrong version" << endl;
        return -1;
    }

    data = (char*)malloc(recv_record.hdr.length);
    memcpy(data, recv_record.data, recv_record.hdr.length);
    cout << "Received: " << data << endl;

    return 0;
}

int recv_server_hello(Ssl* server, char*& data) {
    return recv_data(server, data, Ssl::HS_SERVER_HELLO, Ssl::VER_99);
}

int recv_client_hello(Ssl* server, char*& data) {
    return recv_data(server, data, Ssl::HS_CLIENT_HELLO, Ssl::VER_99);
}

int recv_cert(Ssl* server, char*& data) {
    return recv_data(server, data, Ssl::HS_CERTIFICATE, Ssl::VER_99);
}