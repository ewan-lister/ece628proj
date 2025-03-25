#include "ssl_client.h"

#include "stdlib.h"
#include "string.h"

#include <iostream>

#include "dh.h"
#include "integer.h"
#include "osrng.h"
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

  // IMPLEMENT HANDSHAKE HERE
  // 1. Sent Client Hello message
  char* client_random;
  generate_random(client_random);
  char* client_hello = (char*)malloc(1024);
  std::vector<uint8_t> cipher_suites;
  cipher_suites.push_back(0x2F);
  cipher_suites.push_back(0x35);
  int data_length = pack_client_hello(
    client_hello,
    Ssl::TLS_1_2,
    client_random,
    cipher_suites
  );
  if (send_client_hello(this, client_hello, data_length) != 0) {
    cerr << "Couldn't send Client Hello" << endl;
    return -1;
  }
  cout << "Sent Client Hello: " << endl;

  char* server_hello;
  if (recv_server_hello(this, server_hello) != 0) {
    cerr << "Couldn't receive Server Hello" << endl;
    return -1;
  }
  cout << "Received Server Hello: " << endl;
  uint16_t version;
  char server_random[32];
  uint8_t cipher_suite;
  unpack_server_hello(server_hello, version, server_random, cipher_suite);
  cout << "Server Version: " << version << endl;
  cout << "Server Random: " << server_random << endl;
  cout << "Server Cipher Suite: " << cipher_suite << endl;

  char* certificate;
  if (recv_cert(this, certificate) != 0) {
    cerr << "Couldn't receive Certificate" << endl;
    return -1;
  }
  cout << "Received Certificate: " << endl;


  load_and_verify_certificate(certificate);
  /**
   * Verify certificate is not expired
   * Ensure certificate is signed by the CA
   * Maybe check Cert is not revoked
   * certificate matches server domain
   */
  if (recv_server_hello_done(this, nullptr) != 0) {
    cerr << "Couldn't receive Server Hello Done" << endl;
  }
  cout << "Received server hello done: " << endl;

  // Handle RSA/DHE

  // Handle handshake

  // Handle key exchange

  // Save key and key len
  
  free(client_hello);
  free(client_random);
  return 0;
}

int SslClient::close() {
  int ret_code;
  ret_code = this->tcp_->socket_close();
  return ret_code;
}
