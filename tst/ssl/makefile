CC = g++
CFLAGS = -c -Wall -g \
		-I../../src/tcp \
		-I../../src/ssl \
		-I../../src/cryptopp \
		-I/usr/local/opt/openssl@3/include

LDFLAGS = -L../../src/ssl -lmyssl \
		-L../../src/cryptopp -lcryptopp \
		-L/usr/local/opt/openssl@3/lib \
		-lpthread \
		-lssl -lcrypto

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
