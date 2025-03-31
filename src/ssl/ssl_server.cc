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
#include <openssl/bn.h>
#include <vector>
#include <unistd.h>

using namespace std;

SslServer::SslServer() {
    string datetime;
    if (get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0) {
        exit(1);
    }
    this->logger_ = new Logger(("ssl_server_" + datetime + ".log"));
    this->tcp_->set_logger(this->logger_);
    string instance_name = "server_cert_" + datetime;


    get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
    this->logger_->log("Server Log at " + datetime);

    this->closed_ = false;

    // init rsa
    generate_rsa_keys(this->private_key_, this->public_key_);
    // generate self-signed cert for every instance
    string private_key_file = instance_name + ".priv";
    string public_key_file = instance_name + ".pub";
    save_rsa_private_key(this->private_key_, private_key_file); // Update for multiple clients or servers
    generate_self_signed_cert(private_key_file.c_str(), public_key_file.c_str());
    if (read_cert_file(cert_file_contents, public_key_file) != 0) {
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
    uint8_t key_exchange;

    std::vector<pair<char*, size_t> > hs_messages;
    TCP *cxn = this->tcp_->socket_accept();
    if (cxn == NULL) {
        cerr << "error when accepting" << endl;
        return NULL;
    }

    cxn->set_logger(this->logger_);
    Ssl *new_ssl_cxn = new Ssl(cxn);
    this->clients_.push_back(new_ssl_cxn);

    // 1. Receive Client Hello message.
    this->logger_->log("Client Hello");
    char *client_hello;
    if (recv_client_hello(new_ssl_cxn, client_hello) != 0) {
        cerr << "Could not receive Client Hello" << endl;
        return NULL;
    }
    uint16_t client_version;
    char client_random[32]; // Validate length of the client random
    std::vector<uint8_t> cipher_suites;
    size_t len = unpack_client_hello(client_hello, client_version, client_random, cipher_suites);
    hs_messages.push_back(make_pair(client_hello, len+2)); // +2 for length byte


    uint8_t cipher_suite = cipher_suites[0];

    if (cipher_suite == 0x35) {
        key_exchange = Ssl::KE_DHE;
    } else if (cipher_suite == 0x2F) {
        key_exchange = Ssl::KE_RSA;
    } else {
        cerr << "Invalid cipher suite" << endl;
        return NULL;
    }


    // 2. Send server Hello
    char *server_hello = (char *) malloc(1024);
    char *server_random;
    generate_random(server_random);
    int server_hello_length = pack_server_hello(
        server_hello,
        client_version,
        server_random,
        cipher_suites[0] // Select first cipher suite
    );

    this->logger_->log("Server Hello: ");
    hs_messages.push_back(make_pair(server_hello, server_hello_length));
    if (send_server_hello(new_ssl_cxn, server_hello, server_hello_length) != 0) {
        cout << "Could not send Server Hello" << endl;
        return NULL;
    }

    /**
     *  Send Certificate
     **/
    // 5. Send Certificate
    CryptoPP::RSA::PublicKey cert_public_key;
    this->logger_->log("Certificate: ");
    hs_messages.push_back(make_pair(cert_file_contents, strlen(cert_file_contents)));
    if (send_cert(new_ssl_cxn, cert_file_contents) != 0) {
        cerr << "Error sending certificate file" << endl;
        return NULL;
    }

    /**
     * Server Key Exchange message contains params signed with private key
     * key exchange params, signature
     **/
    // 3. Send Server Key Exchange.
    CryptoPP::DH* out_dh;
    CryptoPP::SecByteBlock server_public_dhe_key, server_private_dhe_key;
    std::vector<unsigned char> server_key_exchange;
    char* server_key_exchange_ptr;
    if (key_exchange == Ssl::KE_DHE) {
        this->logger_->log("Server Key Exchange");
        server_key_exchange = generate_dhe_server_key_exchange(
            client_random, server_random, private_key_, out_dh, server_private_dhe_key, server_public_dhe_key
        );

        server_key_exchange_ptr = reinterpret_cast<char*>(server_key_exchange.data());
        hs_messages.push_back(make_pair(server_key_exchange_ptr, server_key_exchange.size()));
        if (send_server_key_exchange(new_ssl_cxn, server_key_exchange_ptr, server_key_exchange.size()) != 0) {
            cerr << "Error sending server key exchange" << endl;
            return NULL;
        }
    }

    /**
     * Certificate request containing certificate types, signature algos,
     * cert authorities
     **/
    // 4. Send Certificate Request.
    vector<unsigned char> certificate_request = generate_certificate_request();
    std::string certificate_request_msg(certificate_request.begin(), certificate_request.end());
    hs_messages.push_back(make_pair((char*)certificate_request_msg.c_str(), certificate_request_msg.size()));
    if (send_record(new_ssl_cxn, HS_CERTIFICATE_REQUEST,
        VER_99, (char*)certificate_request_msg.c_str(),
        certificate_request_msg.size()) != 0
    ) {
        cerr << "Error sending certificate request" << endl;
        return NULL;
    }

    /**
     *  Send SERVER_HELLO_DONE
     **/
    // 6. Send Server Hello Done
    if (send_record(new_ssl_cxn, HS_SERVER_HELLO_DONE, VER_99, nullptr, 0) != 0) {
        cerr << "Error sending server hello done" << endl;
        return NULL;
    }

    // 7. Receive Certificate and verify
    char* certificate;
    if (recv_cert(new_ssl_cxn, certificate) != 0) {
        cerr << "Couldn't receive Certificate" << endl;
        return NULL;
    }
    hs_messages.push_back(make_pair(certificate, strlen(certificate)));
    // Convert to Crypto++ key
    CryptoPP::RSA::PublicKey client_rsa_public_key;
    load_and_verify_certificate(certificate, client_rsa_public_key);
    // cout << "Server: Received client certificate" << endl;
    // print_RSA_public_key(client_rsa_public_key);

    /**
     * Receive CLIENT_KEY_EXCHANGE
     **/
    // 8. Receive Client Key Exchange
    char *client_key_exchange;
    this->logger_->log("Client key excahnge");
    if (recv_client_key_exchange(new_ssl_cxn, client_key_exchange)) {
        cerr << "Error receiving client key exchange" << endl;
        return NULL;
    }
    CryptoPP::SecByteBlock premaster_secret_block;
    if (key_exchange == KE_DHE) {
        CryptoPP::SecByteBlock client_public_key;
        size_t pub_len = ((static_cast<unsigned char>(client_key_exchange[0]) << 8) & 0xFF00) |
                          (static_cast<unsigned char>(client_key_exchange[1]) & 0xFF);
        unpack_client_key_exchange_dhe(client_key_exchange, client_public_key);
        hs_messages.push_back(make_pair(client_key_exchange, pub_len+2)); // +2 for length byte

        CryptoPP::SecByteBlock shared_secret(out_dh->AgreedValueLength());
        if (!out_dh->Agree(shared_secret, server_private_dhe_key, client_public_key)) {
            cerr << "Error agreeing on shared secret" << endl;
            return NULL;
        }
        premaster_secret_block.Assign(shared_secret);
    } else if (key_exchange == KE_RSA) {
        char* encrypted_premaster_secret = (char*)malloc(1024*(sizeof(char)));
        int len = unpack_client_key_exchange(client_key_exchange, encrypted_premaster_secret);
        hs_messages.push_back(make_pair(client_key_exchange, len+2)); // +2 for length byte
        string premaster_secret;
        string encrypted_premaster_secret_str(encrypted_premaster_secret, len);
        rsa_decrypt(this->private_key_, &premaster_secret, encrypted_premaster_secret_str);
        premaster_secret_block.Assign(reinterpret_cast<const byte*>(premaster_secret.c_str()), 48);
        free(encrypted_premaster_secret);
    } else {
        cout << "Client key exchange not supported" << endl;
        return NULL;
    }


    // 9. Receivd and verify Certificate Verify message
    char* certificate_verify;
    if (recv_cert_verify(new_ssl_cxn, certificate_verify) != 0) {
        cerr << "Couldn't receive Certificate Verify" << endl;
        return NULL;
    }
    uint16_t sig_len = ((static_cast<uint16_t>(certificate_verify[0]) << 8) & 0xFF00) |
                       (static_cast<uint16_t>(certificate_verify[1]) & 0xFF);
    if (validate_certificate_verify(certificate_verify, hs_messages, client_rsa_public_key) != 0 ) {
        cout << "Certificate verify failed" << endl;
        return NULL;
    }
    hs_messages.push_back(make_pair(certificate_verify, sig_len+2));

    CryptoPP::SecByteBlock server_random_block(
            reinterpret_cast<const byte*>(server_random), 32);
    CryptoPP::SecByteBlock client_random_block(
            reinterpret_cast<const byte*>(client_random), 32);

    // Buffers for generated keys
    CryptoPP::SecByteBlock master_secret;
    CryptoPP::SecByteBlock client_write_key;
    CryptoPP::SecByteBlock server_write_key;
    CryptoPP::SecByteBlock client_mac_key;
    CryptoPP::SecByteBlock server_mac_key;
    CryptoPP::SecByteBlock client_write_iv;
    CryptoPP::SecByteBlock server_write_iv;
    if (TLS12_KDF_AES256(
        premaster_secret_block, client_random_block, server_random_block,
        master_secret, client_write_key, server_write_key, client_mac_key,
        server_mac_key, client_write_iv, server_write_iv
        ) != 0) {
        cout << "Error generating keys" << endl;
        return NULL;
    }

    // cout << "Client master secret: " << format_key_data(master_secret) << endl;
    // cout << "Server write key: " << format_key_data(server_write_key) << endl;
    // cout << "Server write iv: " << format_key_data(server_write_iv) << endl;
    // cout << "Client write key: " << format_key_data(client_write_key) << endl;
    // cout << "Client write iv: " << format_key_data(client_write_iv) << endl;

    // 9. Receive Certificate Verify

    // Handle RSA/DHE
    // Handle handshake
    // Handle key exchange
    // Save key and key len

    // Receive Finished message
    // 10. Receive Finished
    char* client_finished;
    if (recv_finished(new_ssl_cxn, client_finished) != 0) {
        cerr << "Couldn't receive Finished" << endl;
        return NULL;
    }

    // Check Finished message
    if (verify_tls_finished_msg(
        hs_messages, master_secret, reinterpret_cast<const unsigned char *>(client_finished), 12, true
    ) != 0) {
        cerr << "Finished message verification failed" << endl;
        return NULL;
    }
    // cout << "Successfully verified client finished message" << endl;

    // Send Finished message
    std::vector<unsigned char> finished_msg = compute_tls_finished_msg(hs_messages, master_secret, false, 12);
    std::string message(finished_msg.begin(), finished_msg.end());

    // Send Finished message
    if (send_finished(new_ssl_cxn, (char*)message.c_str(), message.size()) != 0) {
        cerr << "Couldn't send Finished" << endl;
        return NULL;
    }

    new_ssl_cxn->set_shared_write_mac_key(server_mac_key.data(), server_mac_key.size());
    new_ssl_cxn->set_shared_write_key(server_write_key.data(), server_write_key.size());
    new_ssl_cxn->set_shared_write_iv(server_write_iv.data(), server_write_iv.size());
    new_ssl_cxn->set_shared_read_key(client_write_key.data(), client_write_key.size());
    new_ssl_cxn->set_shared_read_mac_key(client_mac_key.data(), client_mac_key.size());
    new_ssl_cxn->set_shared_read_iv(client_write_iv.data(), client_write_iv.size());

    free(certificate);
    free(certificate_verify);
    free(client_hello);
    free(client_finished);
    hs_messages.clear();
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