#ifndef SSL_SERVER_H
#define SSL_SERVER_H

#include "ssl.h"

#include <string>
#include <vector>
#include <openssl/types.h>

#include "integer.h"
#include "rsa.h"
#include "ssl.h"

class SslServer: public Ssl {
 public:
  SslServer();
  virtual ~SslServer();

  virtual int start(int num_clients=1000);

  virtual Ssl* accept(); // blocking call
  virtual int shutdown();

  virtual std::vector<Ssl*> get_clients() const;

  virtual int broadcast(const std::string &msg);

  void handleErrors(const std::string& msg);

 // const BIGNUM* dh_pub_key;
 private:
  std::vector<Ssl*> clients_;
  bool closed_;

  // for DHE
  // CryptoPP::Integer dh_p_;
  // CryptoPP::Integer dh_q_;
  // CryptoPP::Integer dh_g_;
  // DH* dh;
  // const BIGNUM* dh_priv_key; // pub_key is in public field
};

#endif // SSL_SERVER_H