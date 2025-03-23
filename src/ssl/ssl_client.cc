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
  if (send_client_hello(this, client_random) != 0) {
    cerr << "Couldn't send Client Hello" << endl;
    return -1;
  }
  cout << "Sent Client Hello: " << client_random << endl;

  char* server_random;
  if (recv_server_hello(this, server_random) != 0) {
    cerr << "Couldn't receive Server Hello" << endl;
    return -1;
  }
  cout << "Received Server Hello: " << server_random << endl;

  char* certificate;
  if (recv_cert(this, certificate) != 0) {
    cerr << "Couldn't receive Certificate" << endl;
    return -1;
  }
  cout << "Received Certificate: " << certificate << endl;

  // Handle RSA/DHE

  // Handle handshake

  // Handle key exchange

  // Save key and key len
  
  free(client_random);
  free(server_random);
  return 0;
}

int SslClient::close() {
  int ret_code;
  ret_code = this->tcp_->socket_close();
  return ret_code;
}
