from projectclasses.tcp import TCP
from projectclasses.tls import TLS
import os
import struct
import time
import logging

class Client:

    RSA_SUITE = "TLS_RSA_WITH_AES_256_CBC_SHA256"
    DHE_SUITE = "TLS_DHE_RSA_WITH_AES_256_CBC_SHA256"

    CIPHER_SUITE_MAP = {
        RSA_SUITE: 0x003D,
        DHE_SUITE: 0x006B
    }

    def __init__(self, host, port, supported_suite = None):  
        self.tcp = TCP(host, port)
        self.tls = None
        self.client_random = None
        self.server_random = None
        self.connection_id = id
        self.supported_suite = supported_suite
        self.logger = logging.getLogger('Client')

    def connect(self):
        """Establish connection and perform TLS handshake"""
        try:
            # Step 1: Establish TCP connection
            self.tcp.connect()
            self.logger.info("TCP connection established")

            # Step 2: Initialize TLS instance and perform handshake
            self.client_random = self._generate_client_random()
            self.tls = TLS(self.tcp,supported_suites=self.supported_suite)  # or DHE_SUITE
            
            # Start TLS handshake
            print("Do we reach this point?")
            self.tls.send_client_hello(self.client_random)
            print("2")
            self.logger.info("TLS handshake initiated")

            # Receive and process server response
            server_random, chosen_cipher = self.tls.receive_server_hello()

            if chosen_cipher == self.CIPHER_SUITE_MAP[self.RSA_SUITE]:
                shared_secret = self.rsa_handshake(self.client_random, server_random)
            else:
                shared_secret = self.dhe_handshake(self.client_random, server_random)

            # Complete remaining handshake steps...
            self.logger.info("TLS handshake completed")

        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            self.close()
            raise

    def send(self, data: bytes):
        """Send encrypted application data"""
        if not self.tls:
            raise RuntimeError("TLS connection not established")
        self.tls.send_tls_record(23, (3, 3), data)  # 23 = Application Data
        self.logger.debug(f"Sent {len(data)} bytes")

    def receive(self) -> bytes:
        """Receive and decrypt application data"""
        if not self.tls:
            raise RuntimeError("TLS connection not established")
        content_type, version, data = self.tls.receive_tls_record()
        self.logger.debug(f"Received {len(data)} bytes")
        return data

    def close(self):
        """Close connection and cleanup"""
        if self.tcp:
            self.tcp.close()
            self.logger.info("Connection closed")

    def _generate_client_random(self) -> bytes:
        """Generate the client random (32 bytes: 4 byte timestamp + 28 random bytes)"""
        timestamp = struct.pack("!I", int(time.time()))
        random_bytes = os.urandom(28)
        return timestamp + random_bytes
    
    def rsa_handshake(self, client_random, server_random):
        """Perform RSA handshake"""
        # Placeholder for RSA handshake logic
        server_certificate = self.tls.receive_server_certificate()
        valid, server_signing_key = self.tls.verify_certificate(server_certificate)
        if not valid:
            raise Exception("Invalid server certificate")
        # receive server certificate request
        self.tls.receive_certificate_request()
        #receive server hello done
        self.tls.receive_server_hello_done()

        

    # def dhe_handshake(self, random):
    #     """Perform DHE handshake"""
    #     # Placeholder for DHE handshake logic
    #     pass