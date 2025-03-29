#include "ssl_client.h"

#include "stdlib.h"
#include "string.h"

#include <iostream>
#include <unistd.h>

#include "dh.h"
#include "integer.h"
#include "osrng.h"
#include "rsa.h"
#include "ssl.h"

#include "tcp.h"
#include "crypto_adaptor.h"
#include "logger.h"
#include "utils.h"
#include "ssl_handshake.h"

using namespace std;

SslClient::SslClient() {
  string datetime;
  if ( get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0 ) {
    exit(1);
  }
  this->logger_ = new Logger(("ssl_client_"+datetime+".log"));
  this->tcp_->set_logger(this->logger_);

  get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
  this->logger_->log("Client Log at " + datetime);
}

SslClient::~SslClient() {
  if ( this->logger_ ) {
    delete this->logger_;
    this->logger_ = NULL;
    this->tcp_->set_logger(NULL);
  }
}

int SslClient::connect(const std::string &ip, int port, uint16_t cxntype) {
  // connect
  if ( this->tcp_->socket_connect(ip, port) != 0 ) {
    cerr << "Couldn't connect" << endl;
    return -1;
  }

  std::vector<char*> hs_messages;
  uint8_t key_exchange;

  // IMPLEMENT HANDSHAKE HERE
  // 1. Sent Client Hello message
  char* client_random;
  generate_random(client_random);
  char* client_hello = (char*)malloc(1024);
  std::vector<uint8_t> cipher_suites;

  if (cxntype == Ssl::KE_DHE) {
    key_exchange = Ssl::KE_DHE;
    cipher_suites.push_back(0x35);
  } else if (cxntype == Ssl::KE_RSA) {
    key_exchange = Ssl::KE_RSA;
    cipher_suites.push_back(0x2F);
  } else {
    cerr << "Invalid connection type" << endl;
    return -1;
  }
  int data_length = pack_client_hello(
    client_hello,
    Ssl::TLS_1_2,
    client_random,
    cipher_suites
  );
  this->logger_->log(("Client Hello: "));
  hs_messages.push_back(client_hello);
  if (send_client_hello(this, client_hello, data_length) != 0) {
    cerr << "Couldn't send Client Hello" << endl;
    return -1;
  }

  // 2. Receive Server Hello message
  this->logger_->log(("Server Hello: "));
  char* server_hello;
  if (recv_server_hello(this, server_hello) != 0) {
    cerr << "Couldn't receive Server Hello" << endl;
    return -1;
  }
  hs_messages.push_back(server_hello);
  uint16_t version;
  char server_random[32];
  uint8_t cipher_suite;
  unpack_server_hello(server_hello, version, server_random, cipher_suite);

  // 3. Receive Certificate message
  this->logger_->log(("Certificate: "));
  char* certificate;
  if (recv_cert(this, certificate) != 0) {
    cerr << "Couldn't receive Certificate" << endl;
    return -1;
  }
  hs_messages.push_back(certificate);

  // Convert to Crypto++ key
  CryptoPP::RSA::PublicKey cryptoPPKey;
  load_and_verify_certificate(certificate, cryptoPPKey);

  // 4. Receive Server Key Exchange message
//  if (recv_server_key_exchange(this, nullptr) != 0) {
//    cerr << "Couldn't receive Server Key Exchange" << endl;
//    return -1;
//  }

  // 5. Receive Certificate Request message


  // 6. Receive Server Hello Done message
  if (recv_server_hello_done(this, nullptr) != 0) {
    cerr << "Couldn't receive Server Hello Done" << endl;
    return -1;
  }

//  cout << "Received server hello done: " << endl;

  string premaster_secret;
  string encrypted_premaster_secret;
  generate_premaster_secret(premaster_secret);
//  cout << "Client Premaster Secret: " << premaster_secret << endl;
//  cout << "Client Premaster Secret length: " << premaster_secret.length() << endl;
//  printRSAPublicKey(cryptoPPKey);
  if (rsa_encrypt(cryptoPPKey, &encrypted_premaster_secret, premaster_secret) != 0) {
    cerr << "Couldn't encrypt premaster secret" << endl;
    return -1;
  }
//  cout << "Client Encrypted Premaster Secret: " << encrypted_premaster_secret << endl;
//  cout << "Client Encrypted Premaster Secret length: " << encrypted_premaster_secret.length() << endl;
  char* client_key_exchange = (char*)malloc(1024*(sizeof(char)));
  int len = pack_client_key_exchange(client_key_exchange, encrypted_premaster_secret.c_str(), encrypted_premaster_secret.length());
  //  cout << "Client key exchange length: " << len << endl;
  this->logger_->log(("Client Key Exchange"));
  hs_messages.push_back(client_key_exchange);
  if (send_client_key_exchange(this, client_key_exchange, len) != 0) {
    cerr << "Couldn't send Client Key Exchange" << endl;
    return -1;
  }

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
        return -1;
    }

   // cout << "Client master secret: " << FormatKeyData(master_secret) << endl;
   // cout << "Server write key: " << FormatKeyData(server_write_key) << endl;
   // cout << "Server write iv: " << FormatKeyData(server_write_iv) << endl;
   // cout << "Client write key: " << FormatKeyData(client_write_key) << endl;
   // cout << "Client write iv: " << FormatKeyData(client_write_iv) << endl;
   // cout << "Sent Client Key Exchange: " << endl;

  // Handle RSA/DHE

  // Handle handshake

  // Handle key exchange

  // Save key and key len

  // cout << "Client Number of handshake messages: " << hs_messages.size() << endl;
  // Send Finished message
  std::vector<unsigned char> finished_msg = compute_tls_finished_msg(hs_messages, master_secret, true, 12);
  std::string message(finished_msg.begin(), finished_msg.end());
  //  cout << "Finished message length: " << message.size() << endl;
//  cout << "Finished message: " << message.c_str() << endl;

  // Send Finished message
  if (send_finished(this, (char*)message.c_str(), message.size()) != 0) {
    cerr << "Couldn't send Finished" << endl;
    return -1;
  }

  this->set_shared_key(client_write_key.data(), client_write_key.size());

  // Receive Finished message
  char* server_finished;
  if (recv_finished(this, server_finished) != 0) {
    cerr << "Couldn't receive Finished" << endl;
    return -1;
  }
  // Check Finished message
  if (verify_tls_finished_msg(hs_messages, master_secret, reinterpret_cast<const unsigned char*>(server_finished), 12, false) != 0) {
    cerr << "Finished message verification failed" << endl;
    return -1;
  }
  cout << "Sucessfully verified server finished message" << endl;

  free(certificate);
  free(server_hello);
  free(server_finished);
  hs_messages.clear();
  free(client_hello);
  free(client_random);
  free(client_key_exchange);
  return 0;
}

int SslClient::close() {
  int ret_code;
  ret_code = this->tcp_->socket_close();
  return ret_code;
}
