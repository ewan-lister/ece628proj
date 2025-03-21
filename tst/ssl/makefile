CC = g++
CFLAGS = -c -Wall -g \
         -I../../src/tcp \
         -I../../src/ssl \
         -I../../src/cryptopp \
         -I/usr/include/openssl     # Add OpenSSL include path

LDFLAGS = -L../../src/ssl -lmyssl \
          -L../../src/cryptopp -lcryptopp \
          -lpthread \
          -lssl -lcrypto             # Add OpenSSL libraries

.PHONY: lib clean

TARGET = main_server main_client1 main_client2

all: $(TARGET)

main_server: main_server.o
	$(CC) $< $(LDFLAGS) -o $@

main_client1: main_client1.o
	$(CC) $< $(LDFLAGS) -o $@

main_client2: main_client2.o
	$(CC) $< $(LDFLAGS) -o $@

clean:
	rm -f *.o *.d $(TARGET)

%.o: %.cc
	$(CC) $(CFLAGS) $< -o $@
