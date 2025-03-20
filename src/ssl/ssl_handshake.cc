#include "stdlib.h"
#include "string.h"
#include "integer.h"

#include <iostream>

#include "ssl_client.h"
#include "ssl.h"

using namespace std;

int send_hello(SslClient* client) {
    SSL::Record send_record;
    send_record.hdr.type = SSL::HS_CLIENT_HELLO;
    send_record.hdr.version = SSL::VER_99;
    
    string client_hello = "Client hello";
    char* data = (char*)malloc(client_hello.length()*sizeof(char));
    // Replace client_hello with random
    memcpy(data, client_hello.c_str(), client_hello.length());
    send_record.data = data;
    
    // send
    if(client->send(send_record) != 0) {
      free(send_record.data);
      return -1;
    }
    
    free(send_record.data);
    return 0;
}

int recv_hello(SSL* server, char*& client_random) { 
    // receive record
    SSL::Record recv_record;
    if ( server->recv(&recv_record) == -1 ) {
      cerr << "Couldn't receive." << endl;
      return -1;
    }
  
    // check type
    if (recv_record.hdr.type != SSL::HS_CLIENT_HELLO) {
      cerr << "Not client Hello." << endl;
      return -1;
    }
  
    // check version
    if (recv_record.hdr.version != SSL::VER_99) {
      cerr << "Not VER_99." << endl;
      return -1;
    }
  
    client_random = (char*)malloc(recv_record.hdr.length);
    memcpy(client_random, recv_record.data, recv_record.hdr.length);
    cout << "Received: " << client_random << endl;
  
    return 0;
}