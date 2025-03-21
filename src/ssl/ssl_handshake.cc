#include "stdlib.h"
#include "string.h"
#include "integer.h"

#include <iostream>
#include <iomanip>
#include <ctime>
#include <cryptlib.h>
#include <osrng.h>


#include "ssl_client.h"
#include "ssl.h"

using namespace std;
using namespace CryptoPP;


void generate_random(char*& random) {
    byte temp[32];
    // UNIX timestamp (4 bytes)
    std::time_t currentTime = std::time(nullptr);
    temp[0] = (currentTime >> 24) & 0xFF;
    temp[1] = (currentTime >> 16) & 0xFF;
    temp[2] = (currentTime >> 8) & 0xFF;
    temp[3] = currentTime & 0xFF;

    // 28 secure random bytes
    AutoSeededRandomPool rng;
    rng.GenerateBlock(temp + 4, 28); // Fill remaining 28 bytes

    int size = sizeof(temp);
    random = (char*)malloc(size+1);
    memcpy(random, temp, size);
}

int send_hello(Ssl* client, char* random) {
    Ssl::Record send_record;
    send_record.hdr.type = Ssl::HS_CLIENT_HELLO;
    send_record.hdr.version = Ssl::VER_99;
    // string client_hello = "Client hello";
    // char* data = (char*)malloc(client_hello.length()*sizeof(char));
    // Replace client_hello with random
    // memcpy(data, client_hello.c_str(), client_hello.length());
    send_record.data = random;
    
    // send
    if(client->send(send_record) != 0) {
      // free(send_record.data);
      return -1;
    }
    
    // free(send_record.data);
    return 0;
}

int recv_hello(Ssl* server, char*& client_random) { 
    // receive record
    Ssl::Record recv_record;
    if ( server->recv(&recv_record) == -1 ) {
      cerr << "Couldn't receive." << endl;
      return -1;
    }
  
    // check type
    if (recv_record.hdr.type != Ssl::HS_CLIENT_HELLO) {
      cerr << "Not client Hello." << endl;
      return -1;
    }
  
    // check version
    if (recv_record.hdr.version != Ssl::VER_99) {
      cerr << "Not VER_99." << endl;
      return -1;
    }
  
    client_random = (char*)malloc(recv_record.hdr.length);
    memcpy(client_random, recv_record.data, recv_record.hdr.length);
    cout << "Received: " << client_random << endl;
  
    return 0;
}