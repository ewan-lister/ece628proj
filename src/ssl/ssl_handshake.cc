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
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/x509v3.h>
#include <openssl/rsa.h>

#include "crypto_adaptor.h"
#include "ssl_client.h"
#include "ssl.h"

using namespace std;

const char* HOSTNAME = "localhost";

// Key exchange constants
static const size_t PREMASTER_SECRET_LENGTH = 48;
static const size_t RSA_KEY_LENGTH = 3072;


void save_rsa_private_key(CryptoPP::RSA::PrivateKey private_key, std::string private_key_file) {
    try {
        // Extract all components from the Crypto++ private key
        const CryptoPP::Integer& n = private_key.GetModulus();
        const CryptoPP::Integer& e = private_key.GetPublicExponent();
        const CryptoPP::Integer& d = private_key.GetPrivateExponent();
        const CryptoPP::Integer& p = private_key.GetPrime1();
        const CryptoPP::Integer& q = private_key.GetPrime2();
        CryptoPP::Integer dmp1 = d % (p-1);
        CryptoPP::Integer dmq1 = d % (q-1);
        CryptoPP::Integer iqmp = private_key.GetMultiplicativeInverseOfPrime2ModPrime1();

        // Convert Crypto++ Integers to OpenSSL BIGNUMs
        BIGNUM *bn_n = BN_new();
        BIGNUM *bn_e = BN_new();
        BIGNUM *bn_d = BN_new();
        BIGNUM *bn_p = BN_new();
        BIGNUM *bn_q = BN_new();
        BIGNUM *bn_dmp1 = BN_new();
        BIGNUM *bn_dmq1 = BN_new();
        BIGNUM *bn_iqmp = BN_new();

        if (!bn_n || !bn_e || !bn_d || !bn_p || !bn_q || !bn_dmp1 || !bn_dmq1 || !bn_iqmp) {
            std::cerr << "Error allocating BIGNUMs" << std::endl;
            return;
        }

        // Convert each component from Crypto++ Integer to OpenSSL BIGNUM
        unsigned char* n_bytes = new unsigned char[n.ByteCount()];
        unsigned char* e_bytes = new unsigned char[e.ByteCount()];
        unsigned char* d_bytes = new unsigned char[d.ByteCount()];
        unsigned char* p_bytes = new unsigned char[p.ByteCount()];
        unsigned char* q_bytes = new unsigned char[q.ByteCount()];
        unsigned char* dmp1_bytes = new unsigned char[dmp1.ByteCount()];
        unsigned char* dmq1_bytes = new unsigned char[dmq1.ByteCount()];
        unsigned char* iqmp_bytes = new unsigned char[iqmp.ByteCount()];

        // Encode integers to bytes
        n.Encode(n_bytes, n.ByteCount());
        e.Encode(e_bytes, e.ByteCount());
        d.Encode(d_bytes, d.ByteCount());
        p.Encode(p_bytes, p.ByteCount());
        q.Encode(q_bytes, q.ByteCount());
        dmp1.Encode(dmp1_bytes, dmp1.ByteCount());
        dmq1.Encode(dmq1_bytes, dmq1.ByteCount());
        iqmp.Encode(iqmp_bytes, iqmp.ByteCount());

        // Convert bytes to BIGNUMs
        BN_bin2bn(n_bytes, n.ByteCount(), bn_n);
        BN_bin2bn(e_bytes, e.ByteCount(), bn_e);
        BN_bin2bn(d_bytes, d.ByteCount(), bn_d);
        BN_bin2bn(p_bytes, p.ByteCount(), bn_p);
        BN_bin2bn(q_bytes, q.ByteCount(), bn_q);
        BN_bin2bn(dmp1_bytes, dmp1.ByteCount(), bn_dmp1);
        BN_bin2bn(dmq1_bytes, dmq1.ByteCount(), bn_dmq1);
        BN_bin2bn(iqmp_bytes, iqmp.ByteCount(), bn_iqmp);

        // Clean up byte arrays
        delete[] n_bytes;
        delete[] e_bytes;
        delete[] d_bytes;
        delete[] p_bytes;
        delete[] q_bytes;
        delete[] dmp1_bytes;
        delete[] dmq1_bytes;
        delete[] iqmp_bytes;

        // Create new RSA structure and set its components
        RSA* rsa = RSA_new();
        if (!rsa) {
            std::cerr << "Error creating RSA structure" << std::endl;
            return;
        }

        // Assign key components - these functions transfer ownership of the BIGNUMs to the RSA structure
        if (RSA_set0_key(rsa, bn_n, bn_e, bn_d) != 1) {
            std::cerr << "Error setting RSA key components" << std::endl;
            RSA_free(rsa);
            return;
        }

        if (RSA_set0_factors(rsa, bn_p, bn_q) != 1) {
            std::cerr << "Error setting RSA factors" << std::endl;
            RSA_free(rsa);
            return;
        }

        if (RSA_set0_crt_params(rsa, bn_dmp1, bn_dmq1, bn_iqmp) != 1) {
            std::cerr << "Error setting RSA CRT parameters" << std::endl;
            RSA_free(rsa);
            return;
        }

        // Create EVP_PKEY and assign RSA to it
        EVP_PKEY* pkey = EVP_PKEY_new();
        if (!pkey || EVP_PKEY_assign_RSA(pkey, rsa) != 1) {
            std::cerr << "Error creating EVP_PKEY" << std::endl;
            RSA_free(rsa);
            if (pkey) EVP_PKEY_free(pkey);
            return;
        }

        // Write the key to file in PEM format
        FILE* fp = fopen(private_key_file.c_str(), "wb");
        if (fp) {
            if (PEM_write_PrivateKey(fp, pkey, NULL, NULL, 0, NULL, NULL) != 1) {
                std::cerr << "Error writing private key to file" << std::endl;
            }
            fclose(fp);
        } else {
            std::cerr << "Failed to open file for writing private key: " << private_key_file << std::endl;
        }

        // Clean up
        EVP_PKEY_free(pkey); // This also frees the RSA structure
    }
    catch (const CryptoPP::Exception& e) {
        std::cerr << "Crypto++ exception: " << e.what() << std::endl;
    }
    catch (const std::exception& e) {
        std::cerr << "Standard exception: " << e.what() << std::endl;
    }
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

    if (!pkey) {
        std::cerr << "Error reading PEM private key" << std::endl;
        return nullptr;
    }

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
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)HOSTNAME, -1, -1, 0);

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

int send_record(Ssl* cnx, uint8_t type, uint16_t version, char* data, size_t length) {
    Ssl::Record send_record;
    send_record.hdr.type = type;
    send_record.hdr.version = version;
    send_record.hdr.length = length;
    send_record.data = data;

    // send
    if(cnx->send(send_record) != 0) {
        return -1;
    }

    return 0;
}

int send_client_hello(Ssl* cnx, char* hello, size_t length) {
    return send_record(cnx, Ssl::HS_CLIENT_HELLO, Ssl::VER_99, hello, length);
}

int send_server_hello(Ssl* cnx, char* hello, size_t length) {
    return send_record(cnx, Ssl::HS_SERVER_HELLO, Ssl::VER_99, hello, length);
}

int send_cert(Ssl* cnx, char* cert) {
    return send_record(cnx, Ssl::HS_CERTIFICATE, Ssl::VER_99, cert, strlen(cert));
}

int send_cert_request(Ssl* cnx) {
    return send_record(cnx, Ssl::HS_CERTIFICATE_REQUEST, Ssl::VER_99, nullptr, 0);
}

int recv_data(Ssl* cnx, char*& data,const uint8_t type,const uint16_t version) {
    // receive record
    Ssl::Record recv_record;
    if ( cnx->recv(&recv_record) == -1 ) {
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
    // cout << "Received data of length " << recv_record.hdr.length << endl;
    memcpy(data, recv_record.data, recv_record.hdr.length);

    return 0;
}

int recv_client_key_exchange(Ssl* cnx, char*& data) {
    // cout << "Received client key exchange" << endl;
    return recv_data(cnx, data, Ssl::HS_CLIENT_KEY_EXCHANGE, Ssl::VER_99);
}

int recv_server_hello(Ssl* cnx, char*& data) {
    // cout << "Received server hello" << endl;
    return recv_data(cnx, data, Ssl::HS_SERVER_HELLO, Ssl::VER_99);
}

int send_client_key_exchange(Ssl* cnx, char*& data, size_t length) {
    // cout << "Sending client key exchange. len: " << length << endl;
    return send_record(cnx, Ssl::HS_CLIENT_KEY_EXCHANGE, Ssl::VER_99, data, length);
}

int recv_client_hello(Ssl* cnx, char*& data) {
    // cout << "Received client hello" << endl;
    return recv_data(cnx, data, Ssl::HS_CLIENT_HELLO, Ssl::VER_99);
}

int recv_cert(Ssl* cnx, char*& data) {
    // cout << "Received certificate" << endl;
    return recv_data(cnx, data, Ssl::HS_CERTIFICATE, Ssl::VER_99);
}

int recv_server_hello_done(Ssl* cnx, char* data) {
    // cout << "Received server hello done" << endl;
    return recv_data(cnx, data, Ssl::HS_SERVER_HELLO_DONE, Ssl::VER_99);
}

int load_and_verify_certificate(char *&certificate, CryptoPP::RSA::PublicKey& cryptopp_key) {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    int result = -1;
    X509* cert = nullptr;
    X509_STORE* store = nullptr;
    X509_STORE_CTX* ctx = nullptr;
    BIO* cert_bio = nullptr;
    EVP_PKEY* pkey = nullptr;
    RSA* rsa = nullptr;
    BIGNUM *n = nullptr;
    BIGNUM *e = nullptr;

    // Create a BIO for the PEM certificate string
    cert_bio = BIO_new_mem_buf(certificate, -1);
    if (!cert_bio) {
        std::cerr << "Error creating BIO for certificate" << std::endl;
        goto cleanup;
    }

    // Read the PEM certificate
    cert = PEM_read_bio_X509(cert_bio, nullptr, nullptr, nullptr);
    if (!cert) {
        std::cerr << "Error parsing PEM certificate" << std::endl;
        goto cleanup;
    }

    // 1. Check certificate expiration
    if (X509_cmp_current_time(X509_get_notBefore(cert)) >= 0) {
        std::cerr << "Certificate is not yet valid" << std::endl;
        goto cleanup;
    }

    if (X509_cmp_current_time(X509_get_notAfter(cert)) <= 0) {
        std::cerr << "Certificate has expired" << std::endl;
        goto cleanup;
    }

    // 2. Check hostname match
    if (X509_check_host(cert, HOSTNAME, strlen(HOSTNAME), 0, nullptr) <= 0) {
        std::cerr << "Certificate hostname does not match expected hostname: " << HOSTNAME << std::endl;
        goto cleanup;
    }

    // Skip verification unless we are creating an actual signed CA certificate.
    // // 3. Set up the certificate store with default trusted CAs
    // store = X509_STORE_new();
    // if (!store) {
    //     std::cerr << "Error creating X509_STORE" << std::endl;
    //     goto cleanup;
    // }
    //
    // // Load default trusted CAs
    // if (X509_STORE_set_default_paths(store) != 1) {
    //     std::cerr << "Error loading trusted CA certificates" << std::endl;
    //     goto cleanup;
    // }
    //
    // // Create a verification context
    // ctx = X509_STORE_CTX_new();
    // if (!ctx) {
    //     std::cerr << "Error creating X509_STORE_CTX" << std::endl;
    //     goto cleanup;
    // }
    //
    // // Initialize the verification context
    // if (X509_STORE_CTX_init(ctx, store, cert, nullptr) != 1) {
    //     std::cerr << "Error initializing verification context" << std::endl;
    //     goto cleanup;
    // }
    //
    // // Perform actual certificate verification against trusted CAs
    // if (X509_verify_cert(ctx) != 1) {
    //     int error = X509_STORE_CTX_get_error(ctx);
    //     std::cerr << "Certificate verification failed: "
    //               << X509_verify_cert_error_string(error) << std::endl;
    //     goto cleanup;
    // }

    // Extract public key
    pkey = X509_get_pubkey(cert);
    if (!pkey) {
        X509_free(cert);
        throw std::runtime_error("Cannot extract public key");
    }

    // Extract RSA key parameters
    EVP_PKEY_get_bn_param(pkey, "n", &n);    // Modulus
    EVP_PKEY_get_bn_param(pkey, "e", &e);    // Public Exponent

    if (!n || !e) {
        cerr << "Error extracting RSA key parameters" << endl;
        goto cleanup;
    }

    // Convert OpenSSL BIGNUM to Crypto++ Integer
    cryptopp_key.SetModulus(convert_bignum_to_integer(n));
    cryptopp_key.SetPublicExponent(convert_bignum_to_integer(e));

    // All verification steps passed successfully
    // std::cout << "Certificate verified successfully!" << std::endl;
    result = 0;

cleanup:
    // Free all allocated resources
    // if (ctx) X509_STORE_CTX_free(ctx);
    // if (store) X509_STORE_free(store);
    if (cert) X509_free(cert);
    if (cert_bio) BIO_free(cert_bio);

    return result;
}

size_t pack_uint8_at_offset(char* buffer, size_t offset, uint8_t value) {
    buffer[offset] = static_cast<char>(value);
    return offset + 1;
}

size_t pack_uint16_at_offset(char* buffer, size_t offset, uint16_t value) {
    // Store the value in big-endian format
    buffer[offset]     = static_cast<char>((value >> 8) & 0xFF); // High byte
    buffer[offset + 1] = static_cast<char>(value & 0xFF);        // Low byte
    return offset + 2;
}

// Unpack uint8_t from a buffer
size_t unpack_uint8(const char* buffer, size_t offset, uint8_t& value) {
    value = static_cast<uint8_t>(buffer[offset]);
    return offset + 1;
}

// Unpack uint16_t from a buffer (little-endian)
size_t unpack_uint16(const char* buffer, size_t offset, uint16_t& value) {
    value = static_cast<uint16_t>(
        (static_cast<uint8_t>(buffer[offset]) << 8) |     // High byte
        (static_cast<uint8_t>(buffer[offset + 1]))        // Low byte
    );
    return offset + 2;
}

static size_t pack_bytes(char* buffer, size_t offset, const char* data, size_t length) {
    std::memcpy(buffer + offset, data, length);
    return offset + length;
}

int pack_client_key_exchange(char*& buffer, const char* data, size_t length) {
    size_t offset = 0;

    offset = pack_uint16_at_offset(buffer, offset, (uint16_t) length);
    offset = pack_bytes(buffer, offset, data, length);

    cout << "Client key exchange length: " << offset << endl;
    return offset;
}

int unpack_client_key_exchange(char* buffer, char*& data) {
    size_t offset = 0;

    // Read total length from first 2 bytes (big-endian)
    uint16_t total_length = (static_cast<uint16_t>(buffer[offset]) << 8 & 0xFFFF) |
                       static_cast<uint16_t>(buffer[offset + 1] & 0xFF);
    // cout << "Server Client key exchange length: " << total_length << endl;
    offset += 2;

    data = (char*)malloc(total_length*sizeof(char));
    memcpy(data, buffer + offset, total_length);
    offset += total_length;

    return total_length;
}


int pack_client_hello(
    char*& buffer,
    uint16_t version,
    char* random,      // 32 bytes
    std::vector<uint8_t>& cipher_suites
) {
    size_t offset = 0;

    // Placeholder for total handshake message length (2 bytes)
    size_t length_offset = offset;
    offset = pack_uint16_at_offset(buffer, offset, 0x0000);  // Placeholder for length

    // Protocol version
    offset = pack_uint16_at_offset(buffer, offset, version);

    // Random (32 bytes)
    offset = pack_bytes(buffer, offset, random, 32);

    // Cipher Suites
    size_t cipher_suites_length_offset = offset;
    offset = pack_uint16_at_offset(buffer, offset, 0x0000);  // Placeholder for length

    uint16_t total_cipher_suites_length = 0;
    for (uint8_t suite : cipher_suites) {
        offset = pack_uint8_at_offset(buffer, offset, suite);
        total_cipher_suites_length += 1;
    }

    // Go back and write actual cipher suites length
    pack_uint16_at_offset(buffer, cipher_suites_length_offset, total_cipher_suites_length);

    // Calculate and write total handshake message length (excluding message type and length bytes)
    uint16_t total_length = offset - (length_offset + 2);
    pack_uint16_at_offset(buffer, length_offset, total_length);

    return offset;
}

int pack_server_hello(
    char*& buffer,
    uint16_t version,
    char* random,      // 32 bytes
    uint8_t selected_suite
) {
    size_t offset = 0;

    // Placeholder for total handshake message length (2 bytes)
    size_t length_offset = offset;
    offset = pack_uint16_at_offset(buffer, offset, 0x0000);  // Placeholder for length

    // Protocol version
    offset = pack_uint16_at_offset(buffer, offset, version);

    // Random (32 bytes)
    offset = pack_bytes(buffer, offset, random, 32);

    // Cipher Suites
    offset = pack_uint8_at_offset(buffer, offset, selected_suite);

    // Calculate and write total handshake message length (excluding message type and length bytes)
    uint16_t total_length = offset - (length_offset + 2);
    pack_uint16_at_offset(buffer, length_offset, total_length);

    return offset;
}

int unpack_server_hello(
    const char* buffer,
    uint16_t& version,
    char* random,
    uint8_t& selected_suite
) {
    size_t offset = 0;

    // Read total length from first 2 bytes (big-endian)
    uint16_t total_length = (static_cast<uint16_t>(buffer[0]) << 8) |
                            static_cast<uint16_t>(buffer[1]);
    offset += 2;

    // Read protocol version
    version = (static_cast<uint16_t>(buffer[offset]) << 8) |
                       static_cast<uint16_t>(buffer[offset + 1]);
    offset += 2;

    // Read random (32 bytes)
    memcpy(random, buffer + offset, 32);
    offset += 32;

    selected_suite = static_cast<uint8_t>(buffer[offset]);
    offset += 1;

    return 0;
}

int unpack_client_hello(
    const char* buffer,
    uint16_t& protocol_version,
    char* random,
    std::vector<uint8_t>& cipher_suites
) {
    size_t offset = 0;

    // Read total length from first 2 bytes (big-endian)
    uint16_t total_length = (static_cast<uint16_t>(buffer[0])) |
                            static_cast<uint16_t>(buffer[1]);
    offset += 2;

    // Read protocol version
    protocol_version = (static_cast<uint16_t>(buffer[offset]) << 8) |
                       static_cast<uint16_t>(buffer[offset + 1]);
    offset += 2;

    // Read random (32 bytes)
    memcpy(random, buffer + offset, 32);
    offset += 32;

    // Read cipher suites
    cipher_suites.clear();

    // Read cipher suites length (2 bytes)
    uint16_t cipher_suites_length = (static_cast<uint16_t>(buffer[offset]) << 8) |
                                    static_cast<uint16_t>(buffer[offset + 1]);
    offset += 2;

    // Read individual cipher suites
    for (size_t i = 0; i < cipher_suites_length; ++i) {
        cipher_suites.push_back(static_cast<uint8_t>(buffer[offset + i]));
    }

    return 0;
}

void print_buffer_hex(char* buffer, size_t length) {
    std::cout << std::hex << std::setfill('0');
    for (size_t i = 0; i < length; ++i) {
        std::cout << std::setw(2)
                  << (int)(unsigned char)buffer[i] << " ";
    }
    std::cout << std::dec << std::endl;  // Reset to decimal
}

int generate_premaster_secret(string& premaster_secret) {
    CryptoPP::AutoSeededRandomPool rng;
    premaster_secret.clear();

    try {
        byte buffer[PREMASTER_SECRET_LENGTH];

        rng.GenerateBlock(buffer, PREMASTER_SECRET_LENGTH);

        // The first 2 bytes should be the client's version (typically 0x03, 0x03 for TLS 1.2)
        buffer[0] = 0x01;  // Major version
        buffer[1] = 0x02;  // Minor version

        // Convert the buffer to a string
        premaster_secret.assign((const char*)buffer, PREMASTER_SECRET_LENGTH);

        return 0;
    } catch(const CryptoPP::Exception& e) {
        cerr << "Error generating premaster secret: " << e.what() << endl;
        return -1;
    }
}

void printRSAPublicKey(const CryptoPP::RSA::PublicKey& key) {
    std::cout << "RSA Public Key Details:" << std::endl;

    // Print the modulus (n)
    std::cout << "Modulus (n): " << key.GetModulus() << std::endl;

    // Print the public exponent (e)
    std::cout << "Public Exponent (e): " << key.GetPublicExponent() << std::endl;

    // Print the key bit length
    std::cout << "Key Size: " << key.GetModulus().BitCount() << " bits" << std::endl;
}