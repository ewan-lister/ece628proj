#ifndef SSL_SERVER_H
#define SSL_SERVER_H

#include "ssl.h"

#include <string>
#include <vector>

#include "integer.h"
#include "rsa.h"

class SslServer: public SSL {
 public:
  SslServer();
  virtual ~SslServer();

  virtual int start(int num_clients=1000);
  virtual SSL* accept(); // blocking call
  virtual int shutdown();

  virtual std::vector<SSL*> get_clients() const;

  virtual int broadcast(const std::string &msg);

  void SslServer::handleErrors(const std::string& msg);

  const BIGNUM* dh_pub_key;

 private:
  std::vector<SSL*> clients_;
  bool closed_;

  // for DHE
  // CryptoPP::Integer dh_p_;
  // CryptoPP::Integer dh_q_;
  // CryptoPP::Integer dh_g_;
  DH* dh;
  const BIGNUM* dh_priv_key; // pub_key is in public field

  // for RSA
  CryptoPP::RSA::PrivateKey private_key_;
  CryptoPP::RSA::PublicKey public_key_;
};

#endif // SSL_SERVER_H