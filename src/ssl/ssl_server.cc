#include "ssl_server.h"

#include <hex.h>
#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <sstream>

#include "dh.h"
#include "integer.h"
#include "osrng.h"
#include "ssl.h"

#include "crypto_adaptor.h"
#include "tcp.h"
#include "logger.h"
#include "utils.h"
#include "ssl_handshake.h"
#include <openssl/dh.h> // have to homebrew install openssl to use this
#include <openssl/bn.h>
#include <vector>

using namespace std;

SslServer::SslServer() {
    string datetime;
    if (get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0) {
        exit(1);
    }
    this->logger_ = new Logger(("ssl_server_" + datetime + ".log"));
    this->tcp_->set_logger(this->logger_);

    get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
    this->logger_->log("Server Log at " + datetime);

    this->closed_ = false;

    // init rsa
    generate_rsa_keys(this->private_key_, this->public_key_);
    // generate self-signed cert for every instance
    string instance_name = "server_cert";
    string private_key_file = instance_name + ".priv";
    string public_key_file = instance_name + ".pub";
    save_rsa_private_key(this->private_key_, private_key_file); // Update for multiple clients or servers
    generate_self_signed_cert(private_key_file.c_str(), public_key_file.c_str());
    if (!read_cert_file(cert_file_contents, public_key_file)) {
        this->logger_->log("Failed to read certificate file");
    }
    // init dhe
    // generate_pqg(this->dh_p_, this->dh_q_, this->dh_g_);

    // construct DH object for encryption
    // dh = DH_new();
    // if (!dh) handleErrors("Failed to create DH structure");
    // if (!DH_generate_parameters_ex(dh, 3072, DH_GENERATOR_2, nullptr))
    // handleErrors("Failed to generate DH parameters");
    //
    // // grab DH parameters and keys
    // if (!DH_generate_key(dh)) handleErrors("Failed to generate DH key pair");
    // dh_pub_key = DH_get0_pub_key(dh);
    // dh_priv_key = DH_get0_priv_key(dh);
    //
    // std::cout << "DH Public Key: " << BN_bn2hex(dh_pub_key) << std::endl;
    // std::cout << "DH Private Key: " << BN_bn2hex(dh_priv_key) << std::endl;
}

SslServer::~SslServer() {
    if (!this->closed_) {
        this->shutdown();
    }
    delete this->logger_;
}

void SslServer::handleErrors(const std::string &msg) {
    std::cerr << "Error: " << msg << std::endl;
    exit(EXIT_FAILURE);
}

int SslServer::start(int num_clients) {
    if (this->closed_) {
        return -1;
    }

    return this->tcp_->socket_listen(num_clients);
}

Ssl *SslServer::accept() {
    if (this->closed_) {
        return NULL;
    }

    TCP *cxn = this->tcp_->socket_accept();
    if (cxn == NULL) {
        cerr << "error when accepting" << endl;
        return NULL;
    }

    cxn->set_logger(this->logger_);

    Ssl *new_ssl_cxn = new Ssl(cxn);
    this->clients_.push_back(new_ssl_cxn);

    // cout << "Connection build" << endl;

    // IMPLEMENT HANDSHAKE HERE
    // Wait for Client Hello and print
    char *client_hello;
    if (recv_client_hello(new_ssl_cxn, client_hello) != 0) {
        cerr << "Could not receive Client Hello" << endl;
        return NULL;
    }
    uint16_t client_version;
    char client_random[32];
    std::vector<uint8_t> cipher_suites;
    unpack_client_hello(client_hello, client_version, client_random, cipher_suites);
    // cout << "Client Random: " << client_random << endl;
    // cout << "Client Random: " << client_random << endl;
    // cout << "Version: " << client_version << endl;
    // for (auto suite : cipher_suites) {
    //     cout << "Cipher Suite: " << suite << endl;
    // }


    // 2. Send server Hello
    char *server_hello = (char *) malloc(1024);
    char *server_random;
    generate_random(server_random);
    // cout << "Server Random: " << server_random << endl;
    // cout << "Server cipher suite: " << cipher_suites[0] << endl;
    int server_hello_length = pack_server_hello(
        server_hello,
        client_version,
        server_random,
        cipher_suites[0] // Select first cipher suite
    );
    if (send_server_hello(new_ssl_cxn, server_hello, server_hello_length) != 0) {
        cout << "Could not send Server Hello" << endl;
        return NULL;
    }
    // cout << "Sent Server Hello: " << endl;

    /**
     * Server Key Exchange message contains params signed with private key
     * key exchange params, signature
     **/


    /**
     * Certificate request containing certificate types, signature algos,
     * cert authorities
     **/


    /**
     *  Send Certificate
     **/
    CryptoPP::RSA::PublicKey cert_public_key;
    load_and_verify_certificate(cert_file_contents, cert_public_key);
    if (send_cert(new_ssl_cxn, cert_file_contents) != 0) {
        cerr << "Error sending certificate file" << endl;
        return NULL;
    }
    // cout << "Sent certificate file: " << endl;


    /**
     *  Send SERVER_HELLO_DONE
     **/
    if (send_record(new_ssl_cxn, HS_SERVER_HELLO_DONE, VER_99, nullptr, 0) != 0) {
        cerr << "Error sending server hello done" << endl;
        return NULL;
    }
    // cout << "Sent server hello done" << endl;

    /**
     * Receive CLIENT_KEY_EXCHANGE
     **/
    char *client_key_exchange;
    // cout << "Waiting for client key exchange" << endl;
    if (recv_client_key_exchange(new_ssl_cxn, client_key_exchange)) {
        cerr << "Error receiving client key exchange" << endl;
        return NULL;
    }

    char* encrypted_premaster_secret = (char*)malloc(1024*(sizeof(char)));
    int len = unpack_client_key_exchange(client_key_exchange, encrypted_premaster_secret);
    string premaster_secret;
    string encrypted_premaster_secret_str(encrypted_premaster_secret, len);
    rsa_decrypt(this->private_key_, &premaster_secret, encrypted_premaster_secret_str);
    // cout << "Server premaster Secret: " << premaster_secret << endl;
    // cout << "Server premaster Secret length: " << premaster_secret.length() << endl;

    CryptoPP::SecByteBlock premaster_secret_block(
        reinterpret_cast<const byte*>(premaster_secret.c_str()), 48);
    CryptoPP::SecByteBlock server_random_block(
            reinterpret_cast<const byte*>(server_random), 32);
    CryptoPP::SecByteBlock client_random_block(
            reinterpret_cast<const byte*>(client_random), 32);

    // Buffers for generated keys
    CryptoPP::SecByteBlock master_secret;
    CryptoPP::SecByteBlock client_write_key;
    CryptoPP::SecByteBlock server_write_key;
    CryptoPP::SecByteBlock client_write_iv;
    CryptoPP::SecByteBlock server_write_iv;
    if (TLS12_KDF_AES256(
        premaster_secret_block, client_random_block, server_random_block,
        master_secret, client_write_key, server_write_key,
        client_write_iv, server_write_iv
        ) != 0) {
        cout << "Error generating keys" << endl;
        return NULL;
    }
    new_ssl_cxn->set_shared_key(client_write_key.data(), client_write_key.size());

    // cout << "Server master secret: " << FormatKeyData(master_secret) << endl;
    // cout << "Server write key: " << FormatKeyData(server_write_key) << endl;
    // cout << "Server write iv: " << FormatKeyData(server_write_iv) << endl;
    // cout << "Client write key: " << FormatKeyData(client_write_key) << endl;
    // cout << "Client write iv: " << FormatKeyData(client_write_iv) << endl;

    // Handle RSA/DHE
    // Handle handshake
    // Handle key exchange
    // Save key and key len

    free(server_hello);
    free(server_random);
    free(client_key_exchange);
    return new_ssl_cxn;
}

int SslServer::shutdown() {
    if (this->closed_) {
        return -1;
    }

    // pop all clients
    while (!this->clients_.empty()) {
        Ssl *cxn = this->clients_.back();
        this->clients_.pop_back();
        if (cxn != NULL) {
            delete cxn;
        }
    }
    return 0;
}

vector<Ssl *> SslServer::get_clients() const {
    return vector<Ssl *>(this->clients_);
}

int SslServer::broadcast(const string &msg) {
    if (this->closed_) {
        return -1;
    }

    int num_sent = 0;

    // this->logger_->log("broadcast:");
    // this->logger_->log_raw(msg);

    for (vector<Ssl *>::iterator it = this->clients_.begin();
         it != this->clients_.end(); ++it) {
        ssize_t send_len;
        send_len = (*it)->send(msg);
        if (send_len == (unsigned int) msg.length()) {
            num_sent += 1;
        }
    }

    return num_sent;
}
