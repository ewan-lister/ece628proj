#include "ssl_server.h"

#include <stdlib.h>
#include <string.h>

#include <iostream>
#include <sstream>

#include "dh.h"
#include "integer.h"
#include "osrng.h"

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
  if ( get_datetime(&datetime, "%Y%m%d-%H%M%S") != 0 ) {
    exit(1);
  }
  this->logger_ = new Logger(("ssl_server_"+datetime+".log"));
  this->tcp_->set_logger(this->logger_);

  get_datetime(&datetime, "%Y/%m/%d %H:%M:%S");
  this->logger_->log("Server Log at " + datetime);

  this->closed_ = false;

  // init dhe
  // generate_pqg(this->dh_p_, this->dh_q_, this->dh_g_);

  // construct DH object for encryption
  dh = DH_new();
  if (!dh) handleErrors("Failed to create DH structure");
  if (!DH_generate_parameters_ex(dh, 3072, DH_GENERATOR_2, nullptr))
  handleErrors("Failed to generate DH parameters");

  // grab DH parameters and keys
  if (!DH_generate_key(dh)) handleErrors("Failed to generate DH key pair");
  dh_pub_key = DH_get0_pub_key(dh);
  dh_priv_key = DH_get0_priv_key(dh);

  std::cout << "DH Public Key: " << BN_bn2hex(dh_pub_key) << std::endl;
  std::cout << "DH Private Key: " << BN_bn2hex(dh_priv_key) << std::endl;

  // init rsa
  generate_rsa_keys(this->private_key_, this->public_key_);
}

SslServer::~SslServer() {
  if ( !this->closed_ ) {
    this->shutdown();
  }
  delete this->logger_;
}

void SslServer::handleErrors(const std::string& msg) {
  std::cerr << "Error: " << msg << std::endl;
  exit(EXIT_FAILURE);
}

int SslServer::start(int num_clients) {
  if ( this->closed_ ) {
    return -1;
  }

  return this->tcp_->socket_listen(num_clients);
}

SSL* SslServer::accept() {
  if ( this->closed_ ) {
    return NULL;
  }

  cout << "Server accept" << endl;

  TCP* cxn = this->tcp_->socket_accept();
  if ( cxn == NULL ) {
    cerr << "error when accepting" << endl;
    return NULL;
  }

  cxn->set_logger(this->logger_);

  SSL* new_ssl_cxn = new SSL(cxn);
  this->clients_.push_back(new_ssl_cxn);

  // cout << "Connection build" << endl;

  // IMPLEMENT HANDSHAKE HERE
  // Wait for Client Hello and print
  char* client_random;
  if(recv_hello(new_ssl_cxn, client_random) != 0) { 
    cout << "Could not receive Client Hello" << endl;
    return NULL;
  }

  char* server_random;
  generate_random(server_random);
  if(send_hello(new_ssl_cxn, server_random) != 0) {
    cout << "Could not send Server Hello" << endl;
    return NULL;
  }


  // Handle RSA/DHE

  // Handle handshake

  // Handle key exchange

  // Save key and key len

  return new_ssl_cxn;
}

int SslServer::shutdown() {
  if ( this->closed_ ) {
    return -1;
  }

  // pop all clients
  while ( !this->clients_.empty() ) {
    SSL* cxn = this->clients_.back();
    this->clients_.pop_back();
    if ( cxn != NULL ) {
      delete cxn;
    }
  }
  return 0;
}

vector<SSL*> SslServer::get_clients() const {
  return vector<SSL*>(this->clients_);
}

int SslServer::broadcast(const string &msg) {
  if ( this->closed_ ) {
    return -1;
  }

  int num_sent = 0;

  // this->logger_->log("broadcast:");
  // this->logger_->log_raw(msg);

  for ( vector<SSL*>::iterator it = this->clients_.begin() ;
        it != this->clients_.end() ; ++it ) {
    ssize_t send_len;
    send_len = (*it)->send(msg);
    if ( send_len == (unsigned int)msg.length() ) {
      num_sent += 1;
    }
  }

  return num_sent;
}
